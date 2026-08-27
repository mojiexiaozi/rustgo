#![forbid(unsafe_code)]

use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    path::PathBuf,
    process::Command,
    time::Duration,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use rustgo_crypto::DeviceKeypair;
use rustgo_e2e::{
    EchoServer, ProcessFixture, ScriptedProtocolClient, TcpTunnelSpec, TestResult, UdpEchoServer,
    UdpTunnelSpec, authentication_message, begin_authentication_with_fingerprint,
    client_binary_path, finish_authentication, server_binary_path,
};
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, DataChannelBind, DataChannelKind,
    MAX_BINDING_TOKEN_BYTES, MAX_CLIENT_NAME_BYTES, MAX_SESSION_ID_BYTES, Message,
    ProtocolErrorCode, ProtocolVersion,
};

const READY_TIMEOUT: Duration = Duration::from_secs(8);
const SENTINEL_PAYLOAD: &[u8] = b"RUSTGO_APPLICATION_PAYLOAD_SENTINEL_8d1d";
const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const PRIVATE_KEY_SENTINEL: [u8; 32] = *b"RUSTGO_PRIVATE_KEY_SENTINEL_1234";
const BINDING_TOKEN_SENTINEL: [u8; 64] =
    *b"RUSTGO_BINDING_TOKEN_SENTINEL_0123456789_ABCDEFGHIJKLMNOPQRSTUVW";
const INJECTED_CLIENT_NAME: &str = "untrusted\r\nFORGED event=tcp_open\x1b[31m";
const INJECTED_FINGERPRINT: &[u8] = b"fp\r\nFORGED\x1b!fingerprint-suffix";
const INJECTED_TUNNEL_NAME: &str = "relay\r\nFORGED event=auth_ok\x1b[31m";

#[test]
fn tcp_lifecycle_is_visible_at_info_with_context_on_each_process_stderr() -> TestResult {
    let echo = EchoServer::start()?;
    let mut fixture = ProcessFixture::single_tcp(echo.address())?
        .with_server_env("RUST_LOG", "info")
        .with_client_env("RUST_LOG", "info");
    let mut server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    client.wait_for_stderr_line("event=registration_ready", READY_TIMEOUT)?;

    let mut public = TcpStream::connect_timeout(&fixture.public_address(), READY_TIMEOUT)?;
    public.set_read_timeout(Some(READY_TIMEOUT))?;
    public.write_all(SENTINEL_PAYLOAD)?;
    let mut echoed = vec![0_u8; SENTINEL_PAYLOAD.len()];
    public.read_exact(&mut echoed)?;
    assert_eq!(echoed, SENTINEL_PAYLOAD);

    server.wait_for_stderr_line("event=tcp_open", READY_TIMEOUT)?;
    client.wait_for_stderr_line("event=tcp_open", READY_TIMEOUT)?;
    let server_output = server.stderr_output();
    let client_output = client.stderr_output();
    let output = format!("{server_output}\n{client_output}");
    assert_lifecycle_context(&server_output, "tcp_open")?;
    assert_lifecycle_context(&client_output, "tcp_open")?;
    assert!(
        output
            .lines()
            .all(|line| !line.trim_start().starts_with('{') && !line.contains("\"level\":")),
        "logs must not expose a JSON interface: {output}"
    );
    assert!(
        !output.contains(std::str::from_utf8(SENTINEL_PAYLOAD)?),
        "application payload leaked to process output: {output}"
    );

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn udp_lifecycle_is_visible_at_info_with_context_on_each_process_stderr() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let mut fixture = ProcessFixture::single_udp(echo.address(), 8, 1024)?
        .with_server_env("RUST_LOG", "info")
        .with_client_env("RUST_LOG", "info");
    let mut server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    client.wait_for_stderr_line("event=registration_ready", READY_TIMEOUT)?;

    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    socket.set_read_timeout(Some(READY_TIMEOUT))?;
    socket.send_to(SENTINEL_PAYLOAD, fixture.public_address())?;
    let mut echoed = [0_u8; 128];
    let (received, source) = socket.recv_from(&mut echoed)?;
    assert_eq!(source, fixture.public_address());
    assert_eq!(&echoed[..received], SENTINEL_PAYLOAD);

    server.wait_for_stderr_line("event=udp_session_open", READY_TIMEOUT)?;
    client.wait_for_stderr_line("event=udp_session_open", READY_TIMEOUT)?;
    let server_output = server.stderr_output();
    let client_output = client.stderr_output();
    assert_lifecycle_context(&server_output, "udp_session_open")?;
    assert_lifecycle_context(&client_output, "udp_session_open")?;
    assert!(!server_output.contains(std::str::from_utf8(SENTINEL_PAYLOAD)?));
    assert!(!client_output.contains(std::str::from_utf8(SENTINEL_PAYLOAD)?));

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn cli_and_toml_expose_no_json_or_log_format_interface() -> TestResult {
    let server_binary = server_binary_path()?;
    let client_binary = client_binary_path()?;
    for (name, binary) in [("rustgos", &server_binary), ("rustgoc", &client_binary)] {
        let help = Command::new(binary).arg("--help").output()?;
        assert!(help.status.success(), "{name} --help failed");
        let help = format!(
            "{}\n{}",
            String::from_utf8_lossy(&help.stdout),
            String::from_utf8_lossy(&help.stderr)
        );
        for option in ["--json", "--log-format", "--log_format", "--format"] {
            assert!(
                !help.contains(option),
                "{name} unexpectedly exposed {option}:\n{help}"
            );
        }
    }

    let echo = EchoServer::start()?;
    let fixture = ProcessFixture::single_tcp(echo.address())?;
    let server_config = fs::read_to_string(fixture.server_config_path())?;
    let client_config = fs::read_to_string(fixture.client_config_path())?;
    for (field, value) in [
        ("json", "true"),
        ("log_format", "\"json\""),
        ("format", "\"json\""),
    ] {
        fs::write(
            fixture.server_config_path(),
            format!("{field} = {value}\n{server_config}"),
        )?;
        let server = Command::new(&server_binary)
            .args(["check", "-c"])
            .arg(fixture.server_config_path())
            .output()?;
        assert!(!server.status.success(), "server accepted `{field}`");
        assert!(
            String::from_utf8_lossy(&server.stderr).contains("invalid TOML configuration"),
            "server did not reject unknown `{field}`:\n{}",
            String::from_utf8_lossy(&server.stderr)
        );

        fs::write(
            fixture.client_config_path(),
            format!("{field} = {value}\n{client_config}"),
        )?;
        let client = Command::new(&client_binary)
            .args(["check", "-c"])
            .arg(fixture.client_config_path())
            .output()?;
        assert!(!client.status.success(), "client accepted `{field}`");
        assert!(
            String::from_utf8_lossy(&client.stderr).contains("invalid TOML configuration"),
            "client did not reject unknown `{field}`:\n{}",
            String::from_utf8_lossy(&client.stderr)
        );
    }
    Ok(())
}

#[test]
fn authenticated_tcp_tunnel_context_cannot_inject_physical_log_lines() -> TestResult {
    let echo = EchoServer::start()?;
    let mut fixture = ProcessFixture::tcp_tunnels(
        vec![TcpTunnelSpec::available(
            INJECTED_TUNNEL_NAME,
            echo.address(),
        )],
        1,
    )?
    .with_server_env("RUST_LOG", "info")
    .with_client_env("RUST_LOG", "info");
    let mut server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    client.wait_for_stderr_line("event=registration_ready", READY_TIMEOUT)?;

    let mut first = TcpStream::connect_timeout(&fixture.public_address(), READY_TIMEOUT)?;
    first.set_read_timeout(Some(READY_TIMEOUT))?;
    first.write_all(SENTINEL_PAYLOAD)?;
    let mut echoed = vec![0_u8; SENTINEL_PAYLOAD.len()];
    first.read_exact(&mut echoed)?;
    assert_eq!(echoed, SENTINEL_PAYLOAD);
    server.wait_for_stderr_line("event=tcp_open", READY_TIMEOUT)?;
    client.wait_for_stderr_line("event=tcp_open", READY_TIMEOUT)?;

    let _second = TcpStream::connect_timeout(&fixture.public_address(), READY_TIMEOUT)?;
    server.wait_for_stderr_line("TCP tunnel connection limit reached", READY_TIMEOUT)?;

    let server_stderr = server.stderr_bytes();
    let client_stderr = client.stderr_bytes();
    assert_physical_log_bytes_are_single_line(&server_stderr)?;
    assert_physical_log_bytes_are_single_line(&client_stderr)?;
    let server_text = std::str::from_utf8(&server_stderr)?;
    let client_text = std::str::from_utf8(&client_stderr)?;
    assert!(server_text.contains(r"tunnel=relay\r\nFORGED event=auth_ok\u{1b}[31m"));
    assert!(client_text.contains(r"tunnel=relay\r\nFORGED event=auth_ok\u{1b}[31m"));

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn authenticated_udp_tunnel_context_cannot_inject_physical_log_lines() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let mut fixture = ProcessFixture::udp_tunnels(
        vec![UdpTunnelSpec::available(
            INJECTED_TUNNEL_NAME,
            echo.address(),
        )],
        8,
        1024,
    )?
    .with_server_env("RUST_LOG", "info")
    .with_client_env("RUST_LOG", "info");
    let mut server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    client.wait_for_stderr_line("event=registration_ready", READY_TIMEOUT)?;
    server.wait_for_stderr_line("event=udp_channel_ready", READY_TIMEOUT)?;

    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    socket.set_read_timeout(Some(READY_TIMEOUT))?;
    socket.send_to(SENTINEL_PAYLOAD, fixture.public_address())?;
    let mut echoed = [0_u8; 128];
    let (received, source) = socket.recv_from(&mut echoed)?;
    assert_eq!(source, fixture.public_address());
    assert_eq!(&echoed[..received], SENTINEL_PAYLOAD);
    server.wait_for_stderr_line("event=udp_session_open", READY_TIMEOUT)?;
    client.wait_for_stderr_line("event=udp_session_open", READY_TIMEOUT)?;

    let server_stderr = server.stderr_bytes();
    let client_stderr = client.stderr_bytes();
    assert_physical_log_bytes_are_single_line(&server_stderr)?;
    assert_physical_log_bytes_are_single_line(&client_stderr)?;
    let server_text = std::str::from_utf8(&server_stderr)?;
    let client_text = std::str::from_utf8(&client_stderr)?;
    assert!(server_text.contains(r"tunnel=relay\r\nFORGED event=auth_ok\u{1b}[31m"));
    assert!(client_text.contains(r"tunnel=relay\r\nFORGED event=auth_ok\u{1b}[31m"));

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn scripted_tls_logs_escape_context_and_redact_auth_and_binding_material() -> TestResult {
    let echo = EchoServer::start()?;
    let mut fixture = ProcessFixture::single_tcp(echo.address())?
        .with_server_env("RUST_LOG", "trace")
        .with_client_env("RUST_LOG", "trace");
    let original_config = fs::read_to_string(fixture.client_config_path())?;
    let authorized_key_path = configured_private_key_path(&original_config)?;
    let authorized_private_key = fs::read_to_string(&authorized_key_path)?;
    let authorized_fingerprint = DeviceKeypair::load_private_file(&authorized_key_path)?
        .public_key()
        .fingerprint()
        .to_string();

    let mut server = fixture.start_server()?;
    let mut authorized_client = fixture.start_client()?;
    authorized_client.wait_for_stderr_line("event=registration_ready", READY_TIMEOUT)?;
    authorized_client.terminate()?;

    let scripted_key = DeviceKeypair::from_secret_bytes(PRIVATE_KEY_SENTINEL);
    let scripted_fingerprint = scripted_key.public_key().fingerprint().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (challenge, signature) = runtime.block_on(async {
        let mut control = ScriptedProtocolClient::connect(
            fixture.certificate_authority_path(),
            "tunnel.example.test",
            fixture.control_address(),
        )
        .await?;
        let challenge = begin_authentication_with_fingerprint(
            &mut control,
            VERSION,
            INJECTED_CLIENT_NAME,
            INJECTED_FINGERPRINT,
        )
        .await?;
        let authentication = authentication_message(
            &challenge,
            &scripted_key,
            &scripted_key,
            VERSION,
            INJECTED_CLIENT_NAME,
        );
        let Message::ClientAuthenticate(authenticate) = &authentication else {
            return Err("scripted authentication helper returned the wrong message".into());
        };
        let signature = authenticate.signature.as_slice().to_vec();
        assert_eq!(
            finish_authentication(&mut control, VERSION, authentication).await?,
            AuthResult {
                accepted: false,
                error: Some(ProtocolErrorCode::AUTHENTICATION_FAILED),
            }
        );

        let mut data = ScriptedProtocolClient::connect(
            fixture.certificate_authority_path(),
            "tunnel.example.test",
            fixture.control_address(),
        )
        .await?;
        data.send(
            VERSION,
            Message::DataChannelBind(DataChannelBind {
                client_name: BoundedString::<MAX_CLIENT_NAME_BYTES>::try_from("home-pc")?,
                session_id: BoundedBytes::<MAX_SESSION_ID_BYTES>::try_from(&[0x44; 32][..])?,
                kind: DataChannelKind::TCP,
                tunnel_id: 1,
                target_id: 1,
                binding_token: BoundedBytes::<MAX_BINDING_TOKEN_BYTES>::try_from(
                    BINDING_TOKEN_SENTINEL.as_slice(),
                )?,
            }),
        )
        .await?;
        let closed = tokio::time::timeout(Duration::from_secs(2), data.receive()).await?;
        assert!(
            closed.is_err(),
            "an unknown binding token unexpectedly received a protocol frame"
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((challenge, signature))
    })?;

    server.wait_for_stderr_line("event=auth_failed", READY_TIMEOUT)?;
    server.wait_for_stderr_line("invalid control protocol state", READY_TIMEOUT)?;
    let server_stderr_bytes = server.stderr_bytes();
    let server_stdout_bytes = server.stdout_bytes();
    let authorized_client_stderr_bytes = authorized_client.stderr_bytes();
    let authorized_client_stdout_bytes = authorized_client.stdout_bytes();
    let server_stderr = std::str::from_utf8(&server_stderr_bytes)?;
    let authorized_client_stderr = std::str::from_utf8(&authorized_client_stderr_bytes)?;
    let output = format!(
        "{server_stderr}\n{}\n{authorized_client_stderr}\n{}",
        std::str::from_utf8(&server_stdout_bytes)?,
        std::str::from_utf8(&authorized_client_stdout_bytes)?,
    );
    let streams = [
        ("server stderr", server_stderr_bytes.as_slice()),
        ("server stdout", server_stdout_bytes.as_slice()),
        (
            "authorized client stderr",
            authorized_client_stderr_bytes.as_slice(),
        ),
        (
            "authorized client stdout",
            authorized_client_stdout_bytes.as_slice(),
        ),
    ];
    let short_fingerprint = &authorized_fingerprint[.."sha256:".len() + 12];
    assert!(output.contains(&format!("fingerprint={short_fingerprint}")));
    assert_bytes_absent(
        &streams,
        "authorized fingerprint",
        authorized_fingerprint.as_bytes(),
    );
    assert_bytes_absent(
        &streams,
        "authorized private key",
        authorized_private_key.as_bytes(),
    );
    assert_bytes_absent(
        &streams,
        "scripted fingerprint",
        scripted_fingerprint.as_bytes(),
    );
    assert!(server_stderr.contains(r"untrusted\r\nFORGED"));
    assert!(server_stderr.contains(r"\u{1b}"));
    assert!(
        server_stderr.contains(r"fingerprint=sha256:fp\r\nFORGED\u{1b}!"),
        "malicious claimed fingerprint was not escaped: {server_stderr}"
    );
    assert_physical_log_bytes_are_single_line(&server_stderr_bytes)?;
    assert_physical_log_bytes_are_single_line(&authorized_client_stderr_bytes)?;
    assert_secret_representations_absent(&streams, "private key", &PRIVATE_KEY_SENTINEL);
    assert_secret_representations_absent(&streams, "challenge", &challenge.challenge);
    assert_secret_representations_absent(&streams, "signature", &signature);
    assert_secret_representations_absent(&streams, "binding token", &BINDING_TOKEN_SENTINEL);

    server.terminate()?;
    Ok(())
}

fn configured_private_key_path(config: &str) -> TestResult<PathBuf> {
    let value = config
        .lines()
        .find_map(|line| line.strip_prefix("private_key_file = "))
        .ok_or("client configuration did not contain private_key_file")?;
    let value = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .ok_or("client private key path was not TOML single-quoted")?;
    Ok(PathBuf::from(value))
}

fn has_offset_timestamp_and_level(line: &str) -> bool {
    let Some((timestamp, rest)) = line.split_once(' ') else {
        return false;
    };
    let offset = timestamp
        .rsplit_once(['+', '-'])
        .map(|(_, offset)| offset)
        .filter(|offset| {
            offset.len() == 5
                && offset.as_bytes().get(2) == Some(&b':')
                && offset
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| index == 2 || byte.is_ascii_digit())
        });
    offset.is_some()
        && matches!(
            rest.split_whitespace().next(),
            Some("ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE")
        )
}

fn assert_lifecycle_context(output: &str, event: &str) -> TestResult {
    let line = output
        .lines()
        .find(|line| line.contains(&format!("event={event}")))
        .ok_or_else(|| format!("missing event={event} lifecycle line in:\n{output}"))?;
    assert!(
        has_offset_timestamp_and_level(line),
        "expected offset ISO-8601 timestamp and level in: {line}"
    );
    assert!(line.contains("client=home-pc"), "missing client in: {line}");
    assert!(line.contains("tunnel=echo"), "missing tunnel in: {line}");
    let conn = field_value(line, "conn").ok_or("missing conn field")?;
    assert!(
        conn.len() == 4 && conn.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "conn must be a four-hex short id, got `{conn}` in: {line}"
    );
    Ok(())
}

fn field_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{field}=")))
        .map(|value| value.trim_end_matches([':', '}']))
}

fn assert_physical_log_bytes_are_single_line(output: &[u8]) -> TestResult {
    assert!(
        !output.contains(&b'\r'),
        "raw carriage return in logs: {}",
        String::from_utf8_lossy(output)
    );
    assert!(
        !output.contains(&b'\x1b'),
        "ANSI/control escape in logs: {}",
        String::from_utf8_lossy(output)
    );
    for raw_line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let line =
            std::str::from_utf8(raw_line).map_err(|_| "process log contained non-UTF-8 bytes")?;
        assert!(
            has_offset_timestamp_and_level(line),
            "injected or malformed physical log line: {line}"
        );
    }
    Ok(())
}

fn assert_secret_representations_absent(outputs: &[(&str, &[u8])], label: &str, secret: &[u8]) {
    assert_bytes_absent(outputs, &format!("{label} raw bytes"), secret);
    let lowercase_hex = hex(secret);
    let representations = [
        ("base64", STANDARD.encode(secret)),
        ("base64 without padding", STANDARD_NO_PAD.encode(secret)),
        ("URL-safe base64", URL_SAFE.encode(secret)),
        (
            "URL-safe base64 without padding",
            URL_SAFE_NO_PAD.encode(secret),
        ),
        ("lowercase hex", lowercase_hex.clone()),
        ("uppercase hex", lowercase_hex.to_uppercase()),
        ("debug byte array", format!("{secret:?}")),
    ];
    for (representation, value) in representations {
        assert_bytes_absent(
            outputs,
            &format!("{label} {representation}: {value}"),
            value.as_bytes(),
        );
    }
}

fn assert_bytes_absent(outputs: &[(&str, &[u8])], label: &str, needle: &[u8]) {
    assert!(!needle.is_empty(), "secret sentinel must not be empty");
    for (stream, output) in outputs {
        assert!(
            !contains_subslice(output, needle),
            "{label} leaked on {stream}; output:\n{}",
            String::from_utf8_lossy(output)
        );
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

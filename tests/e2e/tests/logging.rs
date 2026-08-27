#![forbid(unsafe_code)]

use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    time::Duration,
};

use rustgo_crypto::{DeviceKeypair, generate_key_file};
use rustgo_e2e::{EchoServer, ProcessFixture, TestResult};

const READY_TIMEOUT: Duration = Duration::from_secs(8);
const SENTINEL_PAYLOAD: &[u8] = b"RUSTGO_APPLICATION_PAYLOAD_SENTINEL_8d1d";

#[test]
fn successful_relay_logs_text_lifecycle_context_without_payload() -> TestResult {
    let echo = EchoServer::start()?;
    let mut fixture =
        ProcessFixture::single_tcp(echo.address())?.with_server_env("RUST_LOG", "trace");
    let mut server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    client.wait_for_line("event=registration_ready", READY_TIMEOUT)?;

    let mut public = TcpStream::connect_timeout(&fixture.public_address(), READY_TIMEOUT)?;
    public.set_read_timeout(Some(READY_TIMEOUT))?;
    public.write_all(SENTINEL_PAYLOAD)?;
    let mut echoed = vec![0_u8; SENTINEL_PAYLOAD.len()];
    public.read_exact(&mut echoed)?;
    assert_eq!(echoed, SENTINEL_PAYLOAD);

    server.wait_for_line("event=tcp_open", READY_TIMEOUT)?;
    let output = format!("{}\n{}", server.output(), client.output());
    let lifecycle_line = output
        .lines()
        .find(|line| line.contains("event=tcp_open"))
        .ok_or("missing TCP lifecycle log")?;
    assert!(
        has_offset_timestamp_and_level(lifecycle_line),
        "expected offset ISO-8601 timestamp and level in: {lifecycle_line}"
    );
    assert!(lifecycle_line.contains("client=home-pc"));
    assert!(lifecycle_line.contains("tunnel=echo"));
    assert!(lifecycle_line.contains("conn="));
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
fn trace_authentication_logs_redact_private_keys_and_full_fingerprints() -> TestResult {
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
    authorized_client.wait_for_line("event=registration_ready", READY_TIMEOUT)?;
    authorized_client.terminate()?;

    let replacement_directory = tempfile::tempdir()?;
    generate_key_file(replacement_directory.path())?;
    let replacement_key_path = replacement_directory.path().join("device.key");
    let replacement_private_key = fs::read_to_string(&replacement_key_path)?;
    let rejected_config = original_config.replace(
        &format!("private_key_file = '{}'", authorized_key_path.display()),
        &format!("private_key_file = '{}'", replacement_key_path.display()),
    );
    fs::write(fixture.client_config_path(), rejected_config)?;

    let mut rejected_client = fixture.start_client()?;
    server.wait_for_line("event=auth_failed", READY_TIMEOUT)?;
    let output = format!(
        "{}\n{}\n{}",
        server.output(),
        authorized_client.output(),
        rejected_client.output()
    );
    let short_fingerprint = &authorized_fingerprint[.."sha256:".len() + 12];
    assert!(output.contains(&format!("fingerprint={short_fingerprint}")));
    assert!(!output.contains(&authorized_fingerprint));
    assert!(!output.contains(&authorized_private_key));
    assert!(!output.contains(&replacement_private_key));
    assert!(!output.contains("RUSTGO_APPLICATION_PAYLOAD_SENTINEL_8d1d"));

    rejected_client.terminate()?;
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

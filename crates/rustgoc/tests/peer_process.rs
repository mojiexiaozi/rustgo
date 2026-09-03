use std::{
    env,
    error::Error,
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_crypto::generate_key_file;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};

const SERVER_NAME: &str = "peer-process.test";

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rustgos_and_two_rustgoc_processes_transfer_tcp_and_udp_direct_and_relay()
-> Result<(), Box<dyn Error>> {
    build_process_binaries()?;
    run_scenario(true, false).await?;
    run_scenario(false, false).await?;
    run_scenario(false, true).await?;
    Ok(())
}

async fn run_scenario(
    prefer_direct: bool,
    delay_identity_binding: bool,
) -> Result<(), Box<dyn Error>> {
    eprintln!(
        "peer process scenario prefer_direct={prefer_direct} delay_identity_binding={delay_identity_binding}"
    );
    let root = tempfile::tempdir()?;
    let (ca, certificate, server_key) = pki(root.path())?;
    let consumer_keys = root.path().join("consumer-keys");
    let provider_keys = root.path().join("provider-keys");
    let consumer_public = generate_key_file(&consumer_keys)?;
    let provider_public = generate_key_file(&provider_keys)?;
    let server_port = unused_tcp_port()?;
    let observation_primary = unused_udp_port()?;
    let mut observation_alternate = unused_udp_port()?;
    while observation_alternate == observation_primary {
        observation_alternate = unused_udp_port()?;
    }
    let tcp_forward = unused_tcp_port()?;
    let udp_forward = unused_udp_port()?;
    let tcp_echo = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_echo_addr = tcp_echo.local_addr()?;
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let echo_shutdown = tokio_util::sync::CancellationToken::new();
    let tcp_task = spawn_tcp_echo(tcp_echo, echo_shutdown.clone());
    let udp_task = spawn_udp_echo(udp_echo, echo_shutdown.clone());

    let server_config = root.path().join("server.toml");
    fs::write(
        &server_config,
        format!(
            r#"
[server]
bind_addr = "127.0.0.1:{server_port}"
p2p_observation_bind = "127.0.0.1:{observation_primary}"
p2p_observation_alternate_bind = "127.0.0.1:{observation_alternate}"
certificate_file = '{}'
private_key_file = '{}'
heartbeat_timeout_secs = 10

[limits]
max_clients = 8
max_tunnels_per_client = 8
max_tcp_connections_per_tunnel = 32
max_udp_sessions_per_tunnel = 32
max_udp_payload_bytes = 65507

[[clients]]
name = "consumer"
public_key = "{consumer_public}"
enabled = true

[[clients]]
name = "provider"
public_key = "{provider_public}"
enabled = true
"#,
            certificate.display(),
            server_key.display()
        ),
    )?;

    let provider_config = root.path().join("provider.toml");
    fs::write(
        &provider_config,
        client_config(
            "provider",
            server_port,
            &ca,
            &provider_keys.join("device.key"),
            prefer_direct,
            observation_primary,
            observation_alternate,
            "31000-31099",
            "31100-31199",
            &format!(
                r#"
[[exports]]
name = "tcp-echo"
protocol = "tcp"
local_addr = "{tcp_echo_addr}"
allowed_peers = ["consumer"]

[[exports]]
name = "udp-echo"
protocol = "udp"
local_addr = "{udp_echo_addr}"
allowed_peers = ["consumer"]
"#
            ),
        ),
    )?;
    let consumer_config = root.path().join("consumer.toml");
    fs::write(
        &consumer_config,
        client_config(
            "consumer",
            server_port,
            &ca,
            &consumer_keys.join("device.key"),
            prefer_direct,
            observation_primary,
            observation_alternate,
            "32000-32099",
            "32100-32199",
            &format!(
                r#"
[[forwards]]
name = "tcp-forward"
peer = "provider"
export = "tcp-echo"
listen_addr = "127.0.0.1:{tcp_forward}"

[[forwards]]
name = "udp-forward"
peer = "provider"
export = "udp-echo"
listen_addr = "127.0.0.1:{udp_forward}"
"#
            ),
        ),
    )?;

    let mut children = Children(Vec::new());
    children.0.push(spawn("rustgos", &server_config, false)?);
    wait_tcp(SocketAddr::from(([127, 0, 0, 1], server_port))).await?;
    children
        .0
        .push(spawn("rustgoc", &provider_config, delay_identity_binding)?);
    wait_for_log(
        &provider_config.with_extension("log"),
        "client tunnel registration ready",
        1,
    )
    .await?;
    children
        .0
        .push(spawn("rustgoc", &consumer_config, delay_identity_binding)?);

    let mut stream = match wait_tcp(SocketAddr::from(([127, 0, 0, 1], tcp_forward))).await {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!(
                "consumer log:\n{}",
                fs::read_to_string(consumer_config.with_extension("log")).unwrap_or_default()
            );
            eprintln!(
                "provider log:\n{}",
                fs::read_to_string(provider_config.with_extension("log")).unwrap_or_default()
            );
            return Err(error);
        }
    };
    eprintln!("tcp forward accepted");
    stream.write_all(b"tcp-process-e2e").await?;
    let mut echoed = vec![0_u8; 15];
    if let Err(error) =
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut echoed)).await?
    {
        eprintln!(
            "consumer log:\n{}\nprovider log:\n{}\nserver log:\n{}",
            fs::read_to_string(consumer_config.with_extension("log")).unwrap_or_default(),
            fs::read_to_string(provider_config.with_extension("log")).unwrap_or_default(),
            fs::read_to_string(server_config.with_extension("log")).unwrap_or_default()
        );
        return Err(error.into());
    }
    assert_eq!(echoed, b"tcp-process-e2e");
    eprintln!("initial tcp echoed");

    let mut direct_tcp = None;
    if prefer_direct {
        // The first stream stays on relay while generation 2 authenticates. A new
        // open then consumes the atomically promoted direct preference.
        wait_for_log_pair(
            &consumer_config.with_extension("log"),
            &provider_config.with_extension("log"),
            "fresh direct path promoted for subsequent service opens",
            1,
        )
        .await?;
        let mut promoted =
            TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], tcp_forward))).await?;
        promoted.write_all(b"tcp-promoted").await?;
        let mut promoted_echo = vec![0_u8; 12];
        let promoted_result = tokio::time::timeout(
            Duration::from_secs(15),
            promoted.read_exact(&mut promoted_echo),
        )
        .await;
        if let Err(error) = promoted_result
            .as_ref()
            .map_err(|_| "timeout")
            .and_then(|value| value.as_ref().map(|_| ()).map_err(|_| "io"))
        {
            eprintln!(
                "promoted TCP failed ({error}); consumer:\n{}\nprovider:\n{}",
                fs::read_to_string(consumer_config.with_extension("log")).unwrap_or_default(),
                fs::read_to_string(provider_config.with_extension("log")).unwrap_or_default()
            );
        }
        promoted_result??;
        assert_eq!(promoted_echo, b"tcp-promoted");
        eprintln!("promoted tcp echoed");
        direct_tcp = Some(promoted);
    }

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    udp.send_to(
        b"udp-process-e2e",
        SocketAddr::from(([127, 0, 0, 1], udp_forward)),
    )
    .await?;
    let mut buffer = [0_u8; 64];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(15), udp.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..length], b"udp-process-e2e");
    eprintln!("initial udp echoed");

    if delay_identity_binding {
        let provider_lifecycle_log = fs::read_to_string(provider_config.with_extension("log"))?;
        let consumer_lifecycle_log = fs::read_to_string(consumer_config.with_extension("log"))?;
        let observation_ready = provider_lifecycle_log
            .find("authenticated NAT observation candidates ready")
            .expect("provider did not finish observation before the delayed identity binding");
        let binding_released = provider_lifecycle_log
            .find("test-delayed peer identity binding released")
            .expect("provider identity binding was not deterministically delayed");
        assert!(
            observation_ready < binding_released,
            "identity binding was released before the early-observation race was exercised:\n{provider_lifecycle_log}"
        );
        assert!(
            !provider_lifecycle_log.contains("server rejected rendezvous with code"),
            "early observation emitted an invalid pre-decision candidate set:\n{provider_lifecycle_log}"
        );
        assert!(
            !consumer_lifecycle_log.contains("peer orchestration event rejected"),
            "resolve-only terminal pending envelopes produced a spurious state error:\n{consumer_lifecycle_log}"
        );
        let candidate_events = provider_lifecycle_log
            .lines()
            .filter(|line| line.contains("event=\"candidate_set_sent\""))
            .filter_map(|line| {
                let session = line
                    .split_whitespace()
                    .find(|field| field.starts_with("session_id="))?;
                let generation = line
                    .split_whitespace()
                    .find(|field| field.starts_with("generation="))?;
                Some(format!("{session}:{generation}"))
            })
            .collect::<Vec<_>>();
        let unique_candidate_events = candidate_events
            .iter()
            .collect::<std::collections::HashSet<_>>();
        assert!(
            !candidate_events.is_empty(),
            "no candidate emission was observed"
        );
        assert_eq!(
            candidate_events.len(),
            unique_candidate_events.len(),
            "a candidate set was emitted more than once for one session generation:\n{provider_lifecycle_log}"
        );
    }

    if prefer_direct {
        wait_for_log_pair(
            &consumer_config.with_extension("log"),
            &provider_config.with_extension("log"),
            "fresh direct path promoted for subsequent service opens",
            2,
        )
        .await?;
        let promoted_udp = UdpSocket::bind("127.0.0.1:0").await?;
        promoted_udp
            .send_to(
                b"udp-promoted",
                SocketAddr::from(([127, 0, 0, 1], udp_forward)),
            )
            .await?;
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(15), promoted_udp.recv_from(&mut buffer))
                .await??;
        assert_eq!(&buffer[..length], b"udp-promoted");
        eprintln!("promoted udp echoed");
        let consumer_log = fs::read_to_string(consumer_config.with_extension("log"))?;
        let provider_log = fs::read_to_string(provider_config.with_extension("log"))?;
        let server_log = fs::read_to_string(server_config.with_extension("log"))?;
        assert!(
            consumer_log.contains("authenticated NAT observation candidates ready"),
            "consumer log did not record observation success:\n{consumer_log}"
        );
        assert!(
            consumer_log.contains("fresh direct path promoted for subsequent service opens"),
            "direct promotion missing:\nCONSUMER\n{consumer_log}\nPROVIDER\n{provider_log}\nSERVER\n{server_log}"
        );
        let flows = selected_flows(&consumer_log);
        let tcp = flows
            .iter()
            .filter(|flow| flow.export == "tcp-echo")
            .collect::<Vec<_>>();
        let udp = flows
            .iter()
            .filter(|flow| flow.export == "udp-echo")
            .collect::<Vec<_>>();
        assert_eq!(
            tcp.len(),
            2,
            "expected exactly initial/promoted TCP selections: {flows:?}"
        );
        assert_eq!(
            udp.len(),
            2,
            "expected exactly initial/promoted UDP selections: {flows:?}"
        );
        assert_flow(tcp[0], "Tcp", "Relay");
        assert_flow(tcp[1], "Tcp", "NativeTcp");
        assert_flow(udp[0], "Udp", "Relay");
        assert_flow(udp[1], "Udp", "QuicV4");
        let ids = flows
            .iter()
            .map(|flow| flow.session_id.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            ids.len(),
            4,
            "each transferred open must have a distinct correlated session: {flows:?}"
        );

        children.0[0].kill()?;
        children.0[0].wait()?;
        wait_for_log_pair(
            &consumer_config.with_extension("log"),
            &provider_config.with_extension("log"),
            "peer_control_detached",
            1,
        )
        .await?;

        let direct_tcp = direct_tcp.as_mut().expect("direct TCP flow is retained");
        direct_tcp.write_all(b"tcp-control-down").await?;
        let mut down_tcp_echo = [0_u8; 16];
        tokio::time::timeout(
            Duration::from_secs(3),
            direct_tcp.read_exact(&mut down_tcp_echo),
        )
        .await??;
        assert_eq!(&down_tcp_echo, b"tcp-control-down");

        let direct_udp = &promoted_udp;
        direct_udp
            .send_to(
                b"udp-control-down",
                SocketAddr::from(([127, 0, 0, 1], udp_forward)),
            )
            .await?;
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(3), direct_udp.recv_from(&mut buffer))
                .await??;
        assert_eq!(&buffer[..length], b"udp-control-down");

        let mut blocked_open =
            TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], tcp_forward))).await?;
        blocked_open.write_all(b"new-open-control-down").await?;
        let mut blocked_buffer = [0_u8; 21];
        let blocked_result = tokio::time::timeout(
            Duration::from_secs(2),
            blocked_open.read_exact(&mut blocked_buffer),
        )
        .await;
        assert!(
            !matches!(blocked_result, Ok(Ok(_))) || blocked_buffer != *b"new-open-control-down",
            "new rendezvous/open must remain fenced while control is detached"
        );

        let mut relay_buffer = [0_u8; 18];
        let relay_survived = if stream.write_all(b"relay-control-down").await.is_ok() {
            matches!(
                tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut relay_buffer))
                    .await,
                Ok(Ok(_))
            ) && relay_buffer == *b"relay-control-down"
        } else {
            false
        };
        assert!(
            !relay_survived,
            "relay flow must not survive loss of its control transport"
        );

        children.0[0] = spawn("rustgos", &server_config, false)?;
        wait_tcp(SocketAddr::from(([127, 0, 0, 1], server_port))).await?;
        wait_for_log_pair(
            &consumer_config.with_extension("log"),
            &provider_config.with_extension("log"),
            "peer_control_rebound",
            1,
        )
        .await?;

        direct_tcp.write_all(b"tcp-control-back").await?;
        let mut back_tcp_echo = [0_u8; 16];
        tokio::time::timeout(
            Duration::from_secs(3),
            direct_tcp.read_exact(&mut back_tcp_echo),
        )
        .await??;
        assert_eq!(&back_tcp_echo, b"tcp-control-back");
        direct_udp
            .send_to(
                b"udp-control-back",
                SocketAddr::from(([127, 0, 0, 1], udp_forward)),
            )
            .await?;
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(3), direct_udp.recv_from(&mut buffer))
                .await??;
        assert_eq!(&buffer[..length], b"udp-control-back");
    }

    drop(children);
    echo_shutdown.cancel();
    tcp_task.await?;
    udp_task.await?;
    Ok(())
}

#[derive(Debug)]
struct SelectedFlow {
    session_id: String,
    open_id: String,
    protocol: String,
    generation: String,
    path: String,
    export: String,
}

fn selected_flows(log: &str) -> Vec<SelectedFlow> {
    log.lines()
        .filter(|line| {
            line.contains("peer service flow") && line.contains("lifecycle=\"selected\"")
        })
        .filter_map(|line| {
            Some(SelectedFlow {
                session_id: log_field(line, "session_id")?,
                open_id: log_field(line, "open_id")?,
                protocol: log_field(line, "protocol")?,
                generation: log_field(line, "generation")?,
                path: log_field(line, "path")?,
                export: log_field(line, "export")?,
            })
        })
        .collect()
}

fn log_field(line: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(&prefix))
        .map(|value| value.trim_matches('"').to_owned())
}

fn assert_flow(flow: &SelectedFlow, protocol: &str, path: &str) {
    assert_eq!(flow.open_id, "1", "{flow:?}");
    assert_eq!(flow.generation, "1", "{flow:?}");
    assert_eq!(flow.protocol, protocol, "{flow:?}");
    assert_eq!(flow.path, path, "{flow:?}");
    assert_eq!(flow.session_id.len(), 64, "{flow:?}");
}

#[allow(clippy::too_many_arguments)]
fn client_config(
    name: &str,
    server_port: u16,
    ca: &Path,
    key: &Path,
    prefer_direct: bool,
    observation_primary: u16,
    observation_alternate: u16,
    udp_range: &str,
    tcp_range: &str,
    body: &str,
) -> String {
    format!(
        r#"
[client]
name = "{name}"
server_addr = "127.0.0.1:{server_port}"
server_name = "{SERVER_NAME}"
certificate_authority_file = '{}'
private_key_file = '{}'
heartbeat_interval_secs = 1

[p2p]
enabled = true
prefer_direct = {prefer_direct}
direct_timeout_secs = 2
reconnect_timeout_secs = 1
allow_relay_fallback = true
udp_port_range = "{udp_range}"
tcp_port_range = "{tcp_range}"
observation_primary_addr = "127.0.0.1:{observation_primary}"
observation_alternate_addr = "127.0.0.1:{observation_alternate}"
{body}
"#,
        ca.display(),
        key.display()
    )
}

fn spawn(
    package: &str,
    config: &Path,
    delay_identity_binding: bool,
) -> Result<Child, Box<dyn Error>> {
    let workspace = workspace();
    let mut target = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target"));
    if target.is_relative() {
        target = workspace.join(target);
    }
    let binary = target
        .join("debug")
        .join(format!("{package}{}", env::consts::EXE_SUFFIX));
    let mut command = Command::new(binary);
    let log = fs::File::create(config.with_extension("log"))?;
    command
        .current_dir(&workspace)
        .arg("-c")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log));
    if package == "rustgoc" {
        command.env("RUST_LOG", "info");
        command.env("RUSTGO_INTERNAL_TESTING", "1");
        command.env("RUSTGO_INTERNAL_TEST_FORCE_INITIAL_RELAY", "1");
        if delay_identity_binding {
            command.env("RUSTGO_INTERNAL_TEST_DELAY_IDENTITY_BINDING_MS", "500");
        }
    }
    Ok(command.spawn()?)
}

fn build_process_binaries() -> Result<(), Box<dyn Error>> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for attempt in 1..=3 {
        let status = Command::new(&cargo)
            .current_dir(workspace())
            .args(["build", "--quiet", "-p", "rustgos", "-p", "rustgoc"])
            .status()?;
        if status.success() {
            return Ok(());
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Err("failed to build rustgos and rustgoc process fixtures after 3 attempts".into())
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

async fn wait_for_log_pair(
    first: &Path,
    second: &Path,
    needle: &str,
    count: usize,
) -> Result<(), Box<dyn Error>> {
    let waited = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let first_ready =
                fs::read_to_string(first).is_ok_and(|value| value.matches(needle).count() >= count);
            let second_ready = fs::read_to_string(second)
                .is_ok_and(|value| value.matches(needle).count() >= count);
            if first_ready && second_ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if waited.is_err() {
        eprintln!(
            "log wait failed first:\n{}\nsecond:\n{}",
            fs::read_to_string(first).unwrap_or_default(),
            fs::read_to_string(second).unwrap_or_default()
        );
    }
    waited?;
    Ok(())
}

async fn wait_for_log(path: &Path, needle: &str, count: usize) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if fs::read_to_string(path).is_ok_and(|value| value.matches(needle).count() >= count) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    Ok(())
}

async fn wait_tcp(address: SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(Into::into)
}

fn spawn_tcp_echo(
    listener: TcpListener,
    shutdown: tokio_util::sync::CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! { () = shutdown.cancelled() => return, value = listener.accept() => value };
            let Ok((mut stream, _)) = accepted else {
                return;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    })
}

fn spawn_udp_echo(
    socket: UdpSocket,
    shutdown: tokio_util::sync::CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = [0_u8; 65_507];
        loop {
            let received = tokio::select! { () = shutdown.cancelled() => return, value = socket.recv_from(&mut buffer) => value };
            let Ok((length, peer)) = received else {
                return;
            };
            let _ = socket.send_to(&buffer[..length], peer).await;
        }
    })
}

fn unused_tcp_port() -> Result<u16, Box<dyn Error>> {
    Ok(StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}
fn unused_udp_port() -> Result<u16, Box<dyn Error>> {
    Ok(StdUdpSocket::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn pki(directory: &Path) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn Error>> {
    let ca_path = directory.join("ca.pem");
    let certificate_path = directory.join("server.pem");
    let key_path = directory.join("server.key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate()?;
    let ca_certificate = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let mut server_params = CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server_certificate = server_params.signed_by(&server_key, &issuer)?;
    fs::write(&ca_path, ca_certificate.pem())?;
    fs::write(&certificate_path, server_certificate.pem())?;
    fs::write(&key_path, server_key.serialize_pem())?;
    Ok((ca_path, certificate_path, key_path))
}

use std::{
    error::Error,
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use rustgo_crypto::generate_key_file;
use rustgo_e2e::{client_binary_path, generate_ephemeral_pki, server_binary_path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};

const SERVER_NAME: &str = "peer-process.test";

struct Children(Vec<Child>);
impl Children {
    async fn shutdown(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        for child in &mut self.0 {
            if let Some(status) = child.try_wait()? {
                return Err(format!(
                    "owned process {} exited before shutdown: {status}",
                    child.id()
                )
                .into());
            }
            child.kill()?;
            let status = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(status) = child.try_wait()? {
                        return Ok::<_, std::io::Error>(status);
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .map_err(|_| format!("timed out reaping owned process {}", child.id()))??;
            if status.success() {
                return Err(format!("killed owned process {} reported success", child.id()).into());
            }
        }
        self.0.clear();
        Ok(())
    }
}
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
-> Result<(), Box<dyn Error + Send + Sync>> {
    run_scenario(true).await?;
    run_scenario(false).await?;
    Ok(())
}

async fn run_scenario(prefer_direct: bool) -> Result<(), Box<dyn Error + Send + Sync>> {
    eprintln!("peer process scenario prefer_direct={prefer_direct}");
    let root = tempfile::tempdir()?;
    let pki = generate_ephemeral_pki(root.path(), SERVER_NAME)?;
    let ca = pki.certificate_authority_file;
    let certificate = pki.certificate_file;
    let server_key = pki.private_key_file;
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
    children.0.push(spawn("rustgos", &server_config)?);
    wait_tcp(SocketAddr::from(([127, 0, 0, 1], server_port))).await?;
    children.0.push(spawn("rustgoc", &provider_config)?);
    wait_for_log(
        &provider_config.with_extension("log"),
        "client tunnel registration ready",
        1,
    )
    .await?;
    wait_for_log(
        &provider_config.with_extension("log"),
        "P2P_EXPORT_ALLOW_ALL",
        1,
    )
    .await?;
    children.0.push(spawn("rustgoc", &consumer_config)?);

    let forward = SocketAddr::from(([127, 0, 0, 1], tcp_forward));
    let stream = match tcp_round_trip(forward, b"tcp-process-e2e").await {
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
    eprintln!("initial tcp echoed");

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
        let mut promoted_tcp_streams = Vec::new();
        for attempt in 1..=5 {
            let promoted = tcp_round_trip(forward, b"tcp-promoted").await?;
            promoted_tcp_streams.push(promoted);
            let consumer_log = fs::read_to_string(consumer_config.with_extension("log"))?;
            if selected_flows(&consumer_log)
                .iter()
                .any(|flow| flow.export == "tcp-echo" && flow.path == "NativeTcp")
            {
                break;
            }
            if attempt < 5 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        eprintln!("promoted tcp echoed");
    }

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let mut buffer = [0_u8; 64];
    let (length, _) = udp_round_trip(
        &udp,
        SocketAddr::from(([127, 0, 0, 1], udp_forward)),
        b"udp-process-e2e",
        &mut buffer,
    )
    .await?;
    assert_eq!(&buffer[..length], b"udp-process-e2e");
    eprintln!("initial udp echoed");

    if prefer_direct {
        wait_for_log_pair(
            &consumer_config.with_extension("log"),
            &provider_config.with_extension("log"),
            "fresh direct path promoted for subsequent service opens",
            2,
        )
        .await?;
        let mut promoted_udp_sockets = Vec::new();
        for attempt in 1..=5 {
            let promoted_udp = UdpSocket::bind("127.0.0.1:0").await?;
            let (length, _) = udp_round_trip(
                &promoted_udp,
                SocketAddr::from(([127, 0, 0, 1], udp_forward)),
                b"udp-promoted",
                &mut buffer,
            )
            .await?;
            assert_eq!(&buffer[..length], b"udp-promoted");
            promoted_udp_sockets.push(promoted_udp);
            let consumer_log = fs::read_to_string(consumer_config.with_extension("log"))?;
            if selected_flows(&consumer_log)
                .iter()
                .any(|flow| flow.export == "udp-echo" && flow.path == "QuicV4")
            {
                break;
            }
            if attempt < 5 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
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
        assert!(
            tcp.len() >= 2,
            "expected initial relay and an eventually promoted TCP selection: {flows:?}"
        );
        assert!(
            (2..=6).contains(&udp.len()),
            "expected initial relay and an eventually promoted UDP selection: {flows:?}"
        );
        assert_flow(tcp[0], "Tcp", "Relay");
        assert_flow(tcp[tcp.len() - 1], "Tcp", "NativeTcp");
        assert_flow(udp[0], "Udp", "Relay");
        assert_flow(udp[udp.len() - 1], "Udp", "QuicV4");
        let ids = flows
            .iter()
            .map(|flow| flow.session_id.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            ids.len(),
            flows.len(),
            "each transferred open must have a distinct correlated session: {flows:?}"
        );
    } else {
        let consumer_log = fs::read_to_string(consumer_config.with_extension("log"))?;
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
            1,
            "forced relay must select exactly one transferred TCP open: {flows:?}"
        );
        assert_eq!(
            udp.len(),
            1,
            "forced relay must select exactly one transferred UDP open: {flows:?}"
        );
        assert_flow(tcp[0], "Tcp", "Relay");
        assert_flow(udp[0], "Udp", "Relay");
        assert_ne!(
            tcp[0].session_id, udp[0].session_id,
            "TCP and UDP opens must be independently correlated"
        );
    }

    drop(stream);
    drop(udp);
    children.shutdown().await?;
    echo_shutdown.cancel();
    tcp_task.await?;
    udp_task.await?;
    StdTcpListener::bind(("127.0.0.1", server_port))?;
    StdTcpListener::bind(("127.0.0.1", tcp_forward))?;
    StdUdpSocket::bind(("127.0.0.1", udp_forward))?;
    StdUdpSocket::bind(("127.0.0.1", observation_primary))?;
    StdUdpSocket::bind(("127.0.0.1", observation_alternate))?;
    let root_path = root.path().to_path_buf();
    root.close()?;
    assert!(
        !root_path.exists(),
        "owned temporary directory remains: {}",
        root_path.display()
    );
    Ok(())
}

async fn tcp_round_trip(
    forward: SocketAddr,
    payload: &[u8],
) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let error = match TcpStream::connect(forward).await {
            Ok(mut stream) => {
                let mut echoed = vec![0_u8; payload.len()];
                match tokio::time::timeout(Duration::from_secs(3), async {
                    stream.write_all(payload).await?;
                    stream.read_exact(&mut echoed).await
                })
                .await
                {
                    Ok(Ok(_)) if echoed == payload => return Ok(stream),
                    Ok(Ok(_)) => "TCP echo changed the payload".to_owned(),
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "TCP echo timed out".to_owned(),
                }
            }
            Err(error) => error.to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("TCP forward remained unavailable: {error}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn udp_round_trip(
    socket: &UdpSocket,
    forward: SocketAddr,
    payload: &[u8],
    buffer: &mut [u8],
) -> Result<(usize, SocketAddr), Box<dyn Error + Send + Sync>> {
    Ok(tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            socket.send_to(payload, forward).await?;
            match tokio::time::timeout(Duration::from_millis(250), socket.recv_from(buffer)).await {
                Ok(received) => return received,
                Err(_) => continue,
            }
        }
    })
    .await??)
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

fn spawn(package: &str, config: &Path) -> Result<Child, Box<dyn Error + Send + Sync>> {
    let binary = match package {
        "rustgos" => server_binary_path()?,
        "rustgoc" => client_binary_path()?,
        _ => return Err(format!("unsupported process fixture `{package}`").into()),
    };
    let mut command = Command::new(binary);
    let log = fs::File::create(config.with_extension("log"))?;
    command
        .current_dir(config.parent().ok_or("configuration has no parent")?)
        .arg("-c")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log));
    if package == "rustgoc" {
        command.env("RUST_LOG", "info");
        command.env("RUSTGO_INTERNAL_TESTING", "1");
        command.env("RUSTGO_INTERNAL_TEST_FORCE_INITIAL_RELAY", "1");
    }
    Ok(command.spawn()?)
}

async fn wait_for_log_pair(
    first: &Path,
    second: &Path,
    needle: &str,
    count: usize,
) -> Result<(), Box<dyn Error + Send + Sync>> {
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

async fn wait_for_log(
    path: &Path,
    needle: &str,
    count: usize,
) -> Result<(), Box<dyn Error + Send + Sync>> {
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

async fn wait_tcp(address: SocketAddr) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
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

fn unused_tcp_port() -> Result<u16, Box<dyn Error + Send + Sync>> {
    Ok(StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}
fn unused_udp_port() -> Result<u16, Box<dyn Error + Send + Sync>> {
    Ok(StdUdpSocket::bind("127.0.0.1:0")?.local_addr()?.port())
}

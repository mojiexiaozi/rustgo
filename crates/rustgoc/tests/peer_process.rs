use std::{
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
    run_scenario(true).await?;
    run_scenario(false).await?;
    Ok(())
}

async fn run_scenario(prefer_direct: bool) -> Result<(), Box<dyn Error>> {
    eprintln!("peer process scenario prefer_direct={prefer_direct}");
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
    children.0.push(spawn("rustgos", &server_config)?);
    wait_tcp(SocketAddr::from(([127, 0, 0, 1], server_port))).await?;
    children.0.push(spawn("rustgoc", &provider_config)?);
    wait_for_log(
        &provider_config.with_extension("log"),
        "client tunnel registration ready",
        1,
    )
    .await?;
    children.0.push(spawn("rustgoc", &consumer_config)?);

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
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, b"tcp-process-e2e");
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
        assert!(consumer_log.contains("selected promoted direct path for new service open"));
        assert!(consumer_log.contains("path=NativeTcp"));
        assert!(consumer_log.contains("path=QuicV4"));
    }

    drop(children);
    echo_shutdown.cancel();
    tcp_task.await?;
    udp_task.await?;
    Ok(())
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

fn spawn(package: &str, config: &Path) -> Result<Child, Box<dyn Error>> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = Command::new("cargo");
    let log = fs::File::create(config.with_extension("log"))?;
    command
        .current_dir(workspace)
        .args(["run", "--quiet", "-p", package, "--", "-c"])
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

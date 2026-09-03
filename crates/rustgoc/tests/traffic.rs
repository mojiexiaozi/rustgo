#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_config::{
    AuthorizedClient, ClientConfig, ClientSection, Limits, ServerConfig, ServerSection,
    TelemetryConfig, TunnelConfig, TunnelProtocol as ConfigProtocol,
};
use rustgo_crypto::{DeviceKeypair, generate_key_file};
use rustgoc::{ClientApp, ClientStatus, TrafficHandle, TrafficSnapshot};
use rustgos::ServerApp;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{Instant, sleep},
};
use tokio_util::sync::CancellationToken;

const SERVER_NAME: &str = "traffic.example.test";
type AnyError = Box<dyn Error + Send + Sync>;

struct TestPki {
    _directory: TempDir,
    ca_file: PathBuf,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl TestPki {
    fn generate() -> Result<Self, AnyError> {
        let directory = tempfile::tempdir()?;
        let ca_file = directory.path().join("ca.pem");
        let certificate_file = directory.path().join("server.pem");
        let private_key_file = directory.path().join("server.key");
        let (ca_pem, issuer) = certificate_authority()?;
        let (server_pem, server_key_pem) = server_certificate(&issuer)?;
        fs::write(&ca_file, ca_pem)?;
        fs::write(&certificate_file, server_pem)?;
        fs::write(&private_key_file, server_key_pem)?;
        Ok(Self {
            _directory: directory,
            ca_file,
            certificate_file,
            private_key_file,
        })
    }
}

fn certificate_authority() -> Result<(String, Issuer<'static, KeyPair>), AnyError> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Rustgo traffic test CA");
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    let certificate = parameters.self_signed(&key)?;
    Ok((certificate.pem(), Issuer::new(parameters, key)))
}

fn server_certificate(issuer: &Issuer<'static, KeyPair>) -> Result<(String, String), AnyError> {
    let mut parameters = CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, SERVER_NAME);
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let certificate = parameters.signed_by(&key, issuer)?;
    Ok((certificate.pem(), key.serialize_pem()))
}

struct ClientKeys {
    _directory: TempDir,
    keypair: DeviceKeypair,
}

fn generate_client_keys() -> Result<ClientKeys, AnyError> {
    let directory = tempfile::tempdir()?;
    generate_key_file(directory.path())?;
    let keypair = DeviceKeypair::load_private_file(&directory.path().join("device.key"))?;
    Ok(ClientKeys {
        _directory: directory,
        keypair,
    })
}

fn client_fixture(
    pki: &TestPki,
    keys: &ClientKeys,
    server_addr: String,
    echo_addr: SocketAddr,
    public_port: u16,
    telemetry: Option<TelemetryConfig>,
) -> Result<ClientConfig, AnyError> {
    Ok(ClientConfig {
        client: ClientSection {
            name: "traffic-client".to_owned(),
            server_addr,
            server_name: SERVER_NAME.to_owned(),
            certificate_authority_file: pki.ca_file.clone(),
            private_key_file: keys._directory.path().join("device.key"),
            heartbeat_interval_secs: 1,
        },
        p2p: None,
        tunnels: vec![TunnelConfig {
            name: "echo".to_owned(),
            protocol: ConfigProtocol::Tcp,
            local_addr: echo_addr.to_string(),
            remote_port: u32::from(public_port),
        }],
        exports: Vec::new(),
        forwards: Vec::new(),
        telemetry,
    })
}

fn server_config(pki: &TestPki, key: &DeviceKeypair, heartbeat_timeout_secs: u64) -> ServerConfig {
    ServerConfig {
        server: ServerSection {
            bind_addr: "127.0.0.1:0".to_owned(),
            udp_bind_ip: None,
            p2p_observation_bind: None,
            p2p_observation_alternate_bind: None,
            certificate_file: pki.certificate_file.clone(),
            private_key_file: pki.private_key_file.clone(),
            heartbeat_timeout_secs,
        },
        limits: Limits {
            max_clients: 4,
            max_tunnels_per_client: 4,
            max_tcp_connections_per_tunnel: 4,
            max_udp_sessions_per_tunnel: 4,
            max_udp_payload_bytes: 65_507,
        },
        clients: vec![AuthorizedClient {
            name: "traffic-client".to_owned(),
            public_key: key.public_key().to_string(),
            enabled: true,
        }],
        web: None,
    }
}

async fn spawn_echo_service() -> Result<SocketAddr, AnyError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(length) => {
                            if socket.write_all(&buffer[..length]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(address)
}

fn reserve_public_port() -> Result<u16, AnyError> {
    let reservation = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(reservation.local_addr()?.port())
}

async fn wait_for_status<F>(
    status: &mut watch::Receiver<ClientStatus>,
    predicate: F,
    timeout: Duration,
) -> Result<(), AnyError>
where
    F: Fn(&ClientStatus) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if predicate(&status.borrow_and_update()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for client status".into());
        }
        if status.changed().await.is_err() {
            return Err("client status channel closed".into());
        }
    }
}

async fn wait_until<F>(mut predicate: F, timeout: Duration) -> Result<(), AnyError>
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while !predicate() {
        if Instant::now() >= deadline {
            return Err("timed out waiting for traffic counters".into());
        }
        sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

async fn echo_round_trip(mut stream: TcpStream, payload: &[u8]) -> Result<(), AnyError> {
    stream.write_all(payload).await?;
    let mut echoed = vec![0_u8; payload.len()];
    stream.read_exact(&mut echoed).await?;
    if echoed != payload {
        return Err("echo payload changed in transit".into());
    }
    Ok(())
}

async fn connect_with_retry(address: SocketAddr) -> Result<TcpStream, AnyError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                if Instant::now() >= deadline {
                    return Err(error.into());
                }
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[tokio::test]
async fn traffic_snapshot_counts_live_relay_bytes_monotonically() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let echo_addr = spawn_echo_service().await?;
    let public_port = reserve_public_port()?;
    let keys = generate_client_keys()?;
    let server_app = ServerApp::bind(server_config(&pki, &keys.keypair, 5)).await?;
    let server_addr = server_app.local_addr()?.to_string();
    let server_shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server_app.run_until(server_shutdown.clone()));

    let config = client_fixture(
        &pki,
        &keys,
        server_addr,
        echo_addr,
        public_port,
        Some(TelemetryConfig::default()),
    )?;
    let app = ClientApp::from_config(config)?;
    let handle: TrafficHandle = app
        .traffic_handle()
        .expect("default telemetry enables the traffic handle");
    let initial: TrafficSnapshot = app.traffic_snapshot().expect("snapshot before run");
    assert_eq!(initial.sent_bytes(), 0);
    assert_eq!(initial.received_bytes(), 0);

    let mut status = app.subscribe();
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));
    wait_for_status(
        &mut status,
        |status| status.active().is_some(),
        Duration::from_secs(5),
    )
    .await?;

    let public_address = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    echo_round_trip(connect_with_retry(public_address).await?, b"first probe").await?;
    wait_until(
        || handle.snapshot().sent_bytes() > 0 && handle.snapshot().received_bytes() > 0,
        Duration::from_secs(5),
    )
    .await?;
    let first = handle.snapshot();

    echo_round_trip(
        connect_with_retry(public_address).await?,
        b"second probe grows the counters",
    )
    .await?;
    wait_until(
        || handle.snapshot().sent_bytes() > first.sent_bytes(),
        Duration::from_secs(5),
    )
    .await?;
    let second = handle.snapshot();
    assert!(
        second.sent_bytes() > first.sent_bytes(),
        "sent bytes must grow: {first:?} -> {second:?}"
    );
    assert!(
        second.received_bytes() > first.received_bytes(),
        "received bytes must grow: {first:?} -> {second:?}"
    );

    shutdown.cancel();
    server_shutdown.cancel();
    assert!(app_task.await?.is_ok());
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn disabled_telemetry_reports_no_traffic_surfaces() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let echo_addr = spawn_echo_service().await?;
    let public_port = reserve_public_port()?;
    let keys = generate_client_keys()?;
    let server_app = ServerApp::bind(server_config(&pki, &keys.keypair, 5)).await?;
    let server_addr = server_app.local_addr()?.to_string();
    let server_shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server_app.run_until(server_shutdown.clone()));

    let config = client_fixture(
        &pki,
        &keys,
        server_addr,
        echo_addr,
        public_port,
        Some(TelemetryConfig {
            enabled: false,
            ..TelemetryConfig::default()
        }),
    )?;
    let app = ClientApp::from_config(config)?;
    assert!(
        app.traffic_handle().is_none(),
        "explicitly disabled telemetry must expose no traffic handle"
    );
    assert!(
        app.traffic_snapshot().is_none(),
        "explicitly disabled telemetry must expose no traffic snapshot"
    );

    let mut status = app.subscribe();
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));
    wait_for_status(
        &mut status,
        |status| status.active().is_some(),
        Duration::from_secs(5),
    )
    .await?;

    shutdown.cancel();
    server_shutdown.cancel();
    assert!(app_task.await?.is_ok());
    server_task.await??;
    Ok(())
}

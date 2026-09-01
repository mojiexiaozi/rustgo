#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    future::Future,
    net::Ipv4Addr,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_config::{
    AuthorizedClient, ClientConfig, ClientSection, ExportConfig, ForwardConfig, Limits, P2pConfig,
    PortRange, ServerConfig, ServerSection, TelemetryConfig, TunnelConfig,
    TunnelProtocol as ConfigTunnelProtocol,
};
use rustgo_crypto::generate_key_file;
use rustgo_observability::{ObservabilityStore, SessionKind, SessionPath, TrafficCounters};
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedVec, DataChannelKind, Frame, FrameCodec, Heartbeat,
    MAX_BINDING_TOKEN_BYTES, Message, OpenTcpStream, OpenUdpChannel, ProtocolVersion,
    ServerChallenge, SocketAddress, TcpStreamReady, TelemetryReport, TunnelResult, TunnelResults,
    UdpDatagram,
};
use rustgo_transport::TlsServer;
use rustgoc::{ClientApp, TelemetryControlWriteGate, TelemetryRuntimeHook};
use rustgos::ServerApp;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Notify, Semaphore},
};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

const SERVER_NAME: &str = "telemetry.example.test";
const FRAME_MAX: usize = 70 * 1024;
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
        .push(rcgen::DnType::CommonName, "Rustgo telemetry test CA");
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

struct FramedServer {
    version: ProtocolVersion,
    stream: TlsStream<TcpStream>,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl FramedServer {
    fn new(version: ProtocolVersion, stream: TlsStream<TcpStream>) -> Self {
        Self {
            version,
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(FRAME_MAX),
        }
    }

    async fn send(&mut self, message: Message) -> Result<(), AnyError> {
        let encoded = self.codec.encode(self.version, 0, &message)?;
        self.stream.write_all(&encoded).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Frame, AnyError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.read_buffer)? {
                return Ok(frame);
            }
            if self.stream.read_buf(&mut self.read_buffer).await? == 0 {
                return Err("control connection closed".into());
            }
        }
    }
}

struct Fixture {
    _keys: TempDir,
    config: ClientConfig,
}

fn client_fixture(
    pki: &TestPki,
    server_addr: String,
    telemetry: Option<TelemetryConfig>,
) -> Result<Fixture, AnyError> {
    let keys = tempfile::tempdir()?;
    generate_key_file(keys.path())?;
    Ok(Fixture {
        config: ClientConfig {
            client: ClientSection {
                name: "telemetry-client".to_owned(),
                server_addr,
                server_name: SERVER_NAME.to_owned(),
                certificate_authority_file: pki.ca_file.clone(),
                private_key_file: keys.path().join("device.key"),
                heartbeat_interval_secs: 1,
            },
            p2p: None,
            telemetry,
            tunnels: Vec::new(),
            exports: Vec::new(),
            forwards: Vec::new(),
        },
        _keys: keys,
    })
}

fn bytes<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(value).unwrap()
}

async fn accept_registered_session(
    tls_server: &TlsServer,
    version: ProtocolVersion,
) -> Result<FramedServer, AnyError> {
    let (socket, _) = tls_server.accept_tcp().await?;
    let mut server = FramedServer::new(version, tls_server.handshake(socket).await?);
    let hello = server.receive().await?;
    if !matches!(hello.message, Message::ClientHello(_)) {
        return Err("first message was not ClientHello".into());
    }
    server
        .send(Message::ServerChallenge(ServerChallenge {
            challenge: bytes(&[0x51; 32]),
            session_id: bytes(&[0x52; 32]),
        }))
        .await?;
    if !matches!(
        server.receive().await?.message,
        Message::ClientAuthenticate(_)
    ) {
        return Err("second message was not ClientAuthenticate".into());
    }
    server
        .send(Message::AuthResult(AuthResult {
            accepted: true,
            error: None,
        }))
        .await?;
    let Message::RegisterTunnels(registration) = server.receive().await?.message else {
        return Err("third message was not RegisterTunnels".into());
    };
    let results = registration
        .tunnels
        .as_slice()
        .iter()
        .map(|tunnel| TunnelResult {
            tunnel_id: tunnel.tunnel_id,
            accepted: true,
            error: None,
        })
        .collect::<Vec<_>>();
    server
        .send(Message::TunnelResults(TunnelResults {
            results: BoundedVec::try_from(results).unwrap(),
        }))
        .await?;
    Ok(server)
}

fn enabled_telemetry() -> TelemetryConfig {
    TelemetryConfig {
        enabled: true,
        sample_interval_secs: 1,
        report_interval_secs: 1,
    }
}

#[derive(Default)]
struct TrafficSnapshotHook {
    totals: Mutex<(u64, u64)>,
    changed: Notify,
    snapshots: std::sync::atomic::AtomicU64,
    sampler_active: AtomicBool,
    sampler_changed: Notify,
}

impl TelemetryRuntimeHook for TrafficSnapshotHook {
    fn sampler_started(&self) {
        self.sampler_active.store(true, Ordering::Release);
        self.sampler_changed.notify_waiters();
    }

    fn after_traffic_snapshot(&self, sent: u64, received: u64) {
        *self.totals.lock().unwrap() = (sent, received);
        self.snapshots.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
}

async fn wait_for_sampler(hook: &TrafficSnapshotHook) -> Result<(), AnyError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if hook.sampler_active.load(Ordering::Acquire) {
                return;
            }
            hook.sampler_changed.notified().await;
        }
    })
    .await
    .map_err(|_| "host sampler did not start for the V0.3 generation")?;
    Ok(())
}

async fn wait_for_traffic_totals(
    hook: &TrafficSnapshotHook,
    expected: (u64, u64),
) -> Result<(), AnyError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if hook.snapshots.load(Ordering::Acquire) > 0
                && *hook.totals.lock().unwrap() == expected
            {
                return;
            }
            hook.changed.notified().await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "logical traffic totals did not reach {expected:?}; actual {:?}",
            *hook.totals.lock().unwrap()
        )
    })?;
    Ok(())
}

async fn wait_for_online_clients(
    store: &ObservabilityStore,
    expected: &[&str],
) -> Result<(), AnyError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = store.snapshot();
            if expected.iter().all(|name| {
                snapshot
                    .clients
                    .iter()
                    .any(|client| client.name.as_str() == *name && client.online)
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "clients did not become online: {:?}",
            store.snapshot().clients
        )
    })?;
    Ok(())
}

async fn wait_for_fallback_traffic(
    store: &ObservabilityStore,
    expected: TrafficCounters,
) -> Result<(), AnyError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if store.snapshot().sessions.iter().any(|session| {
                session.kind == SessionKind::P2p
                    && session.path == SessionPath::P2pFallback
                    && session.traffic == expected
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "fallback traffic did not reach {expected:?}; sessions {:?}",
            store.snapshot().sessions
        )
    })?;
    Ok(())
}

fn relay_only_client(
    pki: &TestPki,
    server_addr: String,
    name: &str,
    private_key_file: PathBuf,
    port_offset: u16,
    exports: Vec<ExportConfig>,
    forwards: Vec<ForwardConfig>,
) -> ClientConfig {
    ClientConfig {
        client: ClientSection {
            name: name.to_owned(),
            server_addr,
            server_name: SERVER_NAME.to_owned(),
            certificate_authority_file: pki.ca_file.clone(),
            private_key_file,
            heartbeat_interval_secs: 1,
        },
        p2p: Some(P2pConfig {
            enabled: true,
            prefer_direct: false,
            direct_timeout_secs: 2,
            reconnect_timeout_secs: 1,
            allow_relay_fallback: true,
            udp_port_range: PortRange {
                start: 40_000 + port_offset,
                end: 40_000 + port_offset,
            },
            tcp_port_range: PortRange {
                start: 41_000 + port_offset,
                end: 41_000 + port_offset,
            },
            observation_primary_addr: None,
            observation_alternate_addr: None,
        }),
        telemetry: None,
        tunnels: Vec::new(),
        exports,
        forwards,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_p2p_fallback_counts_only_application_payload() -> Result<(), AnyError> {
    const REQUEST: &[u8] = b"fallback-application-request";
    const RESPONSE: &[u8] = b"fallback-application-response";

    let pki = TestPki::generate()?;
    let consumer_keys = tempfile::tempdir()?;
    let provider_keys = tempfile::tempdir()?;
    let consumer_public = generate_key_file(consumer_keys.path())?;
    let provider_public = generate_key_file(provider_keys.path())?;
    let server_config = ServerConfig {
        server: ServerSection {
            bind_addr: "127.0.0.1:0".to_owned(),
            udp_bind_ip: Some(Ipv4Addr::LOCALHOST.into()),
            p2p_observation_bind: None,
            p2p_observation_alternate_bind: None,
            certificate_file: pki.certificate_file.clone(),
            private_key_file: pki.private_key_file.clone(),
            heartbeat_timeout_secs: 10,
        },
        limits: Limits {
            max_clients: 8,
            max_tunnels_per_client: 8,
            max_tcp_connections_per_tunnel: 8,
            max_udp_sessions_per_tunnel: 8,
            max_udp_payload_bytes: 65_507,
        },
        clients: vec![
            AuthorizedClient {
                name: "consumer".to_owned(),
                public_key: consumer_public.to_string(),
                enabled: true,
            },
            AuthorizedClient {
                name: "provider".to_owned(),
                public_key: provider_public.to_string(),
                enabled: true,
            },
        ],
        web: None,
    };
    let (store, sink, worker) = ObservabilityStore::new();
    let server = ServerApp::bind(server_config)
        .await?
        .with_observability_sink(sink)?;
    let server_addr = server.local_addr()?;
    let server_shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server.run_until(server_shutdown.clone()));
    let worker_task = tokio::spawn(worker.run());

    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    let forward_reservation = TcpListener::bind("127.0.0.1:0").await?;
    let forward_addr = forward_reservation.local_addr()?;
    drop(forward_reservation);
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await?;
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await?;
        Ok::<_, AnyError>(())
    });

    let provider_hook = Arc::new(TrafficSnapshotHook::default());
    let provider_shutdown = CancellationToken::new();
    let provider = ClientApp::from_config(relay_only_client(
        &pki,
        server_addr.to_string(),
        "provider",
        provider_keys.path().join("device.key"),
        1,
        vec![ExportConfig {
            name: "echo".to_owned(),
            protocol: ConfigTunnelProtocol::Tcp,
            local_addr: echo_addr.to_string(),
            allowed_peers: vec!["consumer".to_owned()],
        }],
        Vec::new(),
    ))?
    .with_telemetry_test_runtime(Duration::from_millis(100), provider_hook.clone())?;
    let provider_task = tokio::spawn(provider.run_until(provider_shutdown.clone()));
    wait_for_online_clients(&store, &["provider"]).await?;

    let consumer_hook = Arc::new(TrafficSnapshotHook::default());
    let consumer_shutdown = CancellationToken::new();
    let consumer = ClientApp::from_config(relay_only_client(
        &pki,
        server_addr.to_string(),
        "consumer",
        consumer_keys.path().join("device.key"),
        2,
        Vec::new(),
        vec![ForwardConfig {
            name: "echo-forward".to_owned(),
            peer: "provider".to_owned(),
            export: "echo".to_owned(),
            listen_addr: forward_addr.to_string(),
        }],
    ))?
    .with_telemetry_test_runtime(Duration::from_millis(100), consumer_hook.clone())?;
    let consumer_task = tokio::spawn(consumer.run_until(consumer_shutdown.clone()));
    wait_for_online_clients(&store, &["consumer", "provider"]).await?;

    let mut stream = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match TcpStream::connect(forward_addr).await {
                Ok(stream) => return stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await?;
    stream.write_all(REQUEST).await?;
    let mut response = vec![0; RESPONSE.len()];
    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut response)).await??;
    assert_eq!(response, RESPONSE);
    echo_task.await??;

    wait_for_traffic_totals(
        &consumer_hook,
        (REQUEST.len() as u64, RESPONSE.len() as u64),
    )
    .await?;
    wait_for_traffic_totals(
        &provider_hook,
        (RESPONSE.len() as u64, REQUEST.len() as u64),
    )
    .await?;
    wait_for_fallback_traffic(
        &store,
        TrafficCounters {
            sent_bytes: REQUEST.len() as u64,
            received_bytes: RESPONSE.len() as u64,
        },
    )
    .await?;

    drop(stream);
    consumer_shutdown.cancel();
    provider_shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), consumer_task).await???;
    tokio::time::timeout(Duration::from_secs(3), provider_task).await???;
    server_shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    tokio::time::timeout(Duration::from_secs(3), worker_task).await??;
    Ok(())
}

struct ProductionTcpFlow<'a> {
    version: ProtocolVersion,
    connection_id: u64,
    binding_marker: u8,
    to_local: &'a [u8],
    from_local: &'a [u8],
}

async fn drive_production_tcp(
    tls_server: &TlsServer,
    control: &mut FramedServer,
    flow: ProductionTcpFlow<'_>,
) -> Result<(), AnyError> {
    let binding = bytes::<MAX_BINDING_TOKEN_BYTES>(&[flow.binding_marker; MAX_BINDING_TOKEN_BYTES]);
    control
        .send(Message::OpenTcpStream(OpenTcpStream {
            tunnel_id: 1,
            connection_id: flow.connection_id,
            peer: SocketAddress::V4 {
                octets: [198, 51, 100, 1],
                port: 51_001,
            },
            binding_token: binding.clone(),
        }))
        .await?;
    let (socket, _) = tls_server.accept_tcp().await?;
    let mut data = FramedServer::new(flow.version, tls_server.handshake(socket).await?);
    let Message::DataChannelBind(bind) = data.receive().await?.message else {
        return Err("production TCP child did not authenticate its data channel".into());
    };
    assert_eq!(bind.kind, DataChannelKind::TCP);
    assert_eq!(bind.target_id, flow.connection_id);
    assert_eq!(bind.binding_token, binding);
    data.send(Message::TcpStreamReady(TcpStreamReady {
        connection_id: flow.connection_id,
        accepted: true,
        error: None,
    }))
    .await?;
    data.stream.write_all(flow.to_local).await?;
    let mut reply = vec![0; flow.from_local.len()];
    data.stream.read_exact(&mut reply).await?;
    assert_eq!(reply, flow.from_local);
    Ok(())
}

#[tokio::test]
async fn absent_config_starts_only_for_v03_and_counts_production_payload_once()
-> Result<(), AnyError> {
    const V02_TCP_TO_LOCAL: &[u8] = b"v02-tcp-to-local";
    const V02_TCP_FROM_LOCAL: &[u8] = b"v02-tcp-from-local";
    const TCP_TO_LOCAL: &[u8] = b"tcp-to-local";
    const TCP_FROM_LOCAL: &[u8] = b"tcp-from-local";
    const UDP_TO_LOCAL: &[u8] = b"udp-to-local";
    const UDP_FROM_LOCAL: &[u8] = b"udp-from-local";

    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let tcp_local = TcpListener::bind("127.0.0.1:0").await?;
    let udp_local = UdpSocket::bind("127.0.0.1:0").await?;
    let tcp_local_address = tcp_local.local_addr()?;
    let udp_local_address = udp_local.local_addr()?;
    let tcp_echo = tokio::spawn(async move {
        let exchanges: [(&[u8], &[u8]); 2] = [
            (V02_TCP_TO_LOCAL, V02_TCP_FROM_LOCAL),
            (TCP_TO_LOCAL, TCP_FROM_LOCAL),
        ];
        for (expected, response) in exchanges {
            let (mut stream, _) = tcp_local.accept().await?;
            let mut received = vec![0; expected.len()];
            stream.read_exact(&mut received).await?;
            assert_eq!(received, expected);
            stream.write_all(response).await?;
        }
        Ok::<_, AnyError>(())
    });
    let udp_echo = tokio::spawn(async move {
        let mut received = vec![0; UDP_TO_LOCAL.len()];
        let (length, peer) = udp_local.recv_from(&mut received).await?;
        assert_eq!(&received[..length], UDP_TO_LOCAL);
        udp_local.send_to(UDP_FROM_LOCAL, peer).await?;
        Ok::<_, AnyError>(())
    });

    let mut fixture = client_fixture(&pki, tls_server.local_addr()?.to_string(), None)?;
    fixture.config.tunnels = vec![
        TunnelConfig {
            name: "production-tcp".to_owned(),
            protocol: ConfigTunnelProtocol::Tcp,
            local_addr: tcp_local_address.to_string(),
            remote_port: 45_001,
        },
        TunnelConfig {
            name: "production-udp".to_owned(),
            protocol: ConfigTunnelProtocol::Udp,
            local_addr: udp_local_address.to_string(),
            remote_port: 45_002,
        },
    ];
    let hook = Arc::new(TrafficSnapshotHook::default());
    let shutdown = CancellationToken::new();
    let app = ClientApp::from_config(fixture.config)?
        .with_telemetry_test_runtime(Duration::from_millis(100), hook.clone())?;
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));
    let mut control = accept_registered_session(&tls_server, ProtocolVersion::V0_2).await?;
    drive_production_tcp(
        &tls_server,
        &mut control,
        ProductionTcpFlow {
            version: ProtocolVersion::V0_2,
            connection_id: 40,
            binding_marker: 0x30,
            to_local: V02_TCP_TO_LOCAL,
            from_local: V02_TCP_FROM_LOCAL,
        },
    )
    .await?;
    assert!(
        !hook.sampler_active.load(Ordering::Acquire),
        "absent config must not start sampling for a V0.2 generation"
    );

    drop(control);
    let mut control = tokio::time::timeout(
        Duration::from_secs(4),
        accept_registered_session(&tls_server, ProtocolVersion::V0_3),
    )
    .await??;
    wait_for_sampler(&hook).await?;
    wait_for_traffic_totals(&hook, (0, 0)).await?;

    drive_production_tcp(
        &tls_server,
        &mut control,
        ProductionTcpFlow {
            version: ProtocolVersion::V0_3,
            connection_id: 41,
            binding_marker: 0x31,
            to_local: TCP_TO_LOCAL,
            from_local: TCP_FROM_LOCAL,
        },
    )
    .await?;
    tcp_echo.await??;

    let udp_binding = bytes::<MAX_BINDING_TOKEN_BYTES>(&[0x32; MAX_BINDING_TOKEN_BYTES]);
    let udp_open = OpenUdpChannel {
        tunnel_id: 2,
        channel_id: 42,
        binding_token: udp_binding.clone(),
        max_sessions: 8,
        idle_timeout_millis: 60_000,
        max_payload_bytes: 65_507,
        queue_capacity: 32,
    };
    control
        .send(Message::OpenUdpChannel(udp_open.clone()))
        .await?;
    let (socket, _) = tls_server.accept_tcp().await?;
    let mut udp_data =
        FramedServer::new(ProtocolVersion::V0_3, tls_server.handshake(socket).await?);
    let Message::DataChannelBind(bind) = udp_data.receive().await?.message else {
        return Err("production UDP child did not authenticate its data channel".into());
    };
    assert_eq!(bind.kind, DataChannelKind::UDP);
    assert_eq!(bind.target_id, 42);
    assert_eq!(bind.binding_token, udp_binding);
    udp_data.send(Message::OpenUdpChannel(udp_open)).await?;
    udp_data
        .send(Message::UdpDatagram(UdpDatagram {
            tunnel_id: 2,
            session_id: 43,
            source: SocketAddress::V4 {
                octets: [203, 0, 113, 2],
                port: 53_002,
            },
            payload: bytes(UDP_TO_LOCAL),
        }))
        .await?;
    let Message::UdpDatagram(reply) = udp_data.receive().await?.message else {
        return Err("production UDP child did not return the local reply".into());
    };
    assert_eq!(reply.payload.as_slice(), UDP_FROM_LOCAL);
    udp_echo.await??;

    wait_for_traffic_totals(
        &hook,
        (
            (TCP_FROM_LOCAL.len() + UDP_FROM_LOCAL.len()) as u64,
            (TCP_TO_LOCAL.len() + UDP_TO_LOCAL.len()) as u64,
        ),
    )
    .await?;

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), app_task).await???;
    Ok(())
}

#[tokio::test]
async fn v03_heartbeat_preempts_telemetry_and_shutdown_joins_publishers() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(
        &pki,
        tls_server.local_addr()?.to_string(),
        Some(enabled_telemetry()),
    )?;
    let shutdown = CancellationToken::new();
    let app_task =
        tokio::spawn(ClientApp::from_config(fixture.config)?.run_until(shutdown.clone()));
    let mut server = accept_registered_session(&tls_server, ProtocolVersion::V0_3).await?;

    // Hold reads across the first simultaneous heartbeat/report tick. The
    // first wire frame must still be the high-priority heartbeat.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let first = tokio::time::timeout(Duration::from_secs(1), server.receive()).await??;
    let Message::Heartbeat(first_heartbeat) = first.message else {
        return Err("telemetry overtook the first heartbeat".into());
    };
    server
        .send(Message::Heartbeat(Heartbeat {
            sequence: first_heartbeat.sequence,
        }))
        .await?;

    let first_report = receive_report_and_ack_heartbeats(&mut server).await?;
    let second_report = receive_report_and_ack_heartbeats(&mut server).await?;
    assert!(first_report.sequence >= 1);
    assert!(second_report.sequence > first_report.sequence);
    assert!(second_report.sampled_unix_millis >= first_report.sampled_unix_millis);
    assert!(second_report.cpu_basis_points <= 10_000);
    assert!(second_report.memory_used_bytes <= second_report.memory_total_bytes);
    assert!(second_report.disk_used_bytes <= second_report.disk_total_bytes);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), app_task)
        .await
        .expect("cancellation must join the sampler and generation publisher")??;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), server.receive())
            .await?
            .is_err(),
        "joined client ownership must close the fake-server control stream"
    );
    Ok(())
}

#[tokio::test]
async fn older_negotiation_and_disabled_v03_emit_no_telemetry() -> Result<(), AnyError> {
    assert_no_telemetry(ProtocolVersion::V0_2, None).await?;
    assert_no_telemetry(
        ProtocolVersion::V0_3,
        Some(TelemetryConfig {
            enabled: false,
            ..enabled_telemetry()
        }),
    )
    .await
}

struct CoalescingHook {
    first_read_waiting: Notify,
    allow_first_read: Semaphore,
    second_publish_waiting: Notify,
    allow_second_publish: Semaphore,
    first_read: AtomicBool,
}

impl Default for CoalescingHook {
    fn default() -> Self {
        Self {
            first_read_waiting: Notify::new(),
            allow_first_read: Semaphore::new(0),
            second_publish_waiting: Notify::new(),
            allow_second_publish: Semaphore::new(0),
            first_read: AtomicBool::new(false),
        }
    }
}

impl TelemetryRuntimeHook for CoalescingHook {
    fn after_publish(&self, sequence: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if sequence == 2 {
                self.second_publish_waiting.notify_one();
                self.allow_second_publish.acquire().await.unwrap().forget();
            }
        })
    }

    fn before_read_latest(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if !self.first_read.swap(true, Ordering::SeqCst) {
                self.first_read_waiting.notify_one();
                self.allow_first_read.acquire().await.unwrap().forget();
            }
        })
    }
}

#[tokio::test]
async fn saturated_watch_coalesces_to_newest_without_duplicate_sequence() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(
        &pki,
        tls_server.local_addr()?.to_string(),
        Some(enabled_telemetry()),
    )?;
    let hook = Arc::new(CoalescingHook::default());
    let shutdown = CancellationToken::new();
    let app = ClientApp::from_config(fixture.config)?
        .with_telemetry_test_runtime(Duration::from_millis(10), hook.clone())?;
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));
    let mut server = accept_registered_session(&tls_server, ProtocolVersion::V0_3).await?;

    tokio::time::timeout(Duration::from_secs(1), hook.first_read_waiting.notified())
        .await
        .expect("control loop must observe the first watch version");
    tokio::time::timeout(
        Duration::from_secs(1),
        hook.second_publish_waiting.notified(),
    )
    .await
    .expect("publisher must replace the unread value with sequence two");
    hook.allow_first_read.add_permits(1);

    let coalesced = receive_report_and_ack_heartbeats(&mut server).await?;
    assert_eq!(
        coalesced.sequence, 2,
        "the unread first value must be replaced"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), server.receive())
            .await
            .is_err(),
        "consuming sequence two must also mark its watch version seen"
    );

    hook.allow_second_publish.add_permits(1);
    let next = receive_report_and_ack_heartbeats(&mut server).await?;
    assert!(next.sequence > coalesced.sequence);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), app_task)
        .await
        .expect("coalescing scenario must join every client task")??;
    Ok(())
}

#[derive(Default)]
struct BlockingWriteGate {
    armed: AtomicBool,
    started: Notify,
}

impl TelemetryControlWriteGate for BlockingWriteGate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn poll_write(&self, _context: &mut Context<'_>) -> Poll<()> {
        if self.armed.load(Ordering::SeqCst) {
            self.started.notify_one();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

#[derive(Default)]
struct BlockingWriteHook {
    gate: Arc<BlockingWriteGate>,
}

impl TelemetryRuntimeHook for BlockingWriteHook {
    fn control_write_gate(&self) -> Option<Arc<dyn TelemetryControlWriteGate>> {
        Some(self.gate.clone())
    }
}

#[tokio::test]
async fn blocked_telemetry_write_fail_stops_before_heartbeat_deadline() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let mut fixture = client_fixture(
        &pki,
        tls_server.local_addr()?.to_string(),
        Some(enabled_telemetry()),
    )?;
    fixture.config.client.heartbeat_interval_secs = 2;
    let hook = Arc::new(BlockingWriteHook::default());
    let shutdown = CancellationToken::new();
    let app = ClientApp::from_config(fixture.config)?
        .with_telemetry_test_runtime(Duration::from_millis(10), hook.clone())?;
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));
    let mut server = accept_registered_session(&tls_server, ProtocolVersion::V0_3).await?;

    tokio::time::timeout(Duration::from_secs(1), hook.gate.started.notified())
        .await
        .expect("actual control AsyncWrite::poll_write must become pending");
    let blocked_at = tokio::time::Instant::now();
    let closed = tokio::time::timeout(Duration::from_millis(500), server.receive())
        .await
        .expect("telemetry write budget must expire well before heartbeat deadline");
    assert!(
        closed.is_err(),
        "timed-out telemetry framing must close the generation"
    );
    assert!(blocked_at.elapsed() < Duration::from_millis(500));

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), app_task)
        .await
        .expect("reconnect wait and all telemetry children must cancel")??;
    Ok(())
}

async fn receive_report_and_ack_heartbeats(
    server: &mut FramedServer,
) -> Result<TelemetryReport, AnyError> {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(2), server.receive()).await??;
        match frame.message {
            Message::TelemetryReport(report) => return Ok(report),
            Message::Heartbeat(heartbeat) => {
                server.send(Message::Heartbeat(heartbeat)).await?;
            }
            _ => return Err("unexpected control frame while awaiting telemetry".into()),
        }
    }
}

async fn assert_no_telemetry(
    version: ProtocolVersion,
    telemetry: Option<TelemetryConfig>,
) -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string(), telemetry)?;
    let hook = Arc::new(TrafficSnapshotHook::default());
    let shutdown = CancellationToken::new();
    let app = ClientApp::from_config(fixture.config)?
        .with_telemetry_test_runtime(Duration::from_millis(50), hook.clone())?;
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));
    let mut server = accept_registered_session(&tls_server, version).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1_300);
    let mut heartbeat_seen = false;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(frame) = tokio::time::timeout(remaining, server.receive()).await else {
            break;
        };
        match frame?.message {
            Message::Heartbeat(heartbeat) => {
                heartbeat_seen = true;
                server.send(Message::Heartbeat(heartbeat)).await?;
            }
            Message::TelemetryReport(_) => {
                return Err(format!("version {version:?} unexpectedly received telemetry").into());
            }
            _ => return Err("unexpected control frame during no-telemetry window".into()),
        }
    }
    assert!(
        heartbeat_seen,
        "control generation must remain alive during the observation window"
    );
    assert!(
        !hook.sampler_active.load(Ordering::Acquire),
        "an older or explicitly disabled generation must not start the host sampler"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), app_task)
        .await
        .expect("cancellation must join all client tasks")??;
    Ok(())
}

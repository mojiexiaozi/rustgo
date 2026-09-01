#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::BytesMut;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_config::{AuthorizedClient, Limits, ServerConfig, ServerSection};
use rustgo_crypto::DeviceKeypair;
use rustgo_e2e::{
    ScriptedProtocolClient, authentication_message, begin_authentication, finish_authentication,
};
use rustgo_observability::{
    ObservabilityStore, OverviewSnapshot, SessionKind, SessionPath, ShortSessionId,
};
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, BoundedVec, DataChannelBind, DataChannelKind, Frame,
    FrameCodec, FrameError, Message, OpenTcpStream, OpenUdpChannel, ProtocolVersion,
    RegisterTunnels, TelemetryReport, TunnelProtocol, TunnelRegistration, UdpDatagram,
};
use rustgo_rendezvous::{
    CandidateGeneration, CandidateTransport, ConnectivityResult, PeerRelayFlags, PeerRelayFrame,
    ProviderDecision, RelayRequest, RendezvousClose, RendezvousEnvelope, RendezvousPayload,
    RendezvousRequest, SessionId,
};
use rustgo_transport::TlsClient;
use rustgos::{ServerApp, ServerRuntimeLimits};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

const SERVER_NAME: &str = "observability.example.test";
const VERSION: ProtocolVersion = ProtocolVersion::V0_3;
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
        .push(rcgen::DnType::CommonName, "Rustgo observability test CA");
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

fn authorized(name: &str, key: &DeviceKeypair) -> AuthorizedClient {
    AuthorizedClient {
        name: name.to_owned(),
        public_key: key.public_key().to_string(),
        enabled: true,
    }
}

fn server_config(pki: &TestPki, clients: Vec<AuthorizedClient>) -> Result<ServerConfig, AnyError> {
    Ok(ServerConfig {
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
        clients,
        web: None,
    })
}

struct Client {
    wire: ScriptedProtocolClient,
    name: String,
    session_id: Vec<u8>,
}

impl Client {
    async fn connect(
        pki: &TestPki,
        address: SocketAddr,
        name: &str,
        key: &DeviceKeypair,
        tunnels: Vec<TunnelRegistration>,
    ) -> Result<Self, AnyError> {
        let mut wire = ScriptedProtocolClient::connect(&pki.ca_file, SERVER_NAME, address).await?;
        let challenge = begin_authentication(&mut wire, VERSION, name, key).await?;
        assert_eq!(
            finish_authentication(
                &mut wire,
                VERSION,
                authentication_message(&challenge, key, key, VERSION, name),
            )
            .await?,
            AuthResult {
                accepted: true,
                error: None,
            }
        );
        wire.send(
            VERSION,
            Message::RegisterTunnels(RegisterTunnels {
                tunnels: BoundedVec::try_from(tunnels)?,
            }),
        )
        .await?;
        let Frame {
            message: Message::TunnelResults(results),
            ..
        } = timeout(Duration::from_secs(2), wire.receive()).await??
        else {
            return Err("server did not complete tunnel registration".into());
        };
        assert!(
            results
                .results
                .as_slice()
                .iter()
                .all(|result| result.accepted)
        );
        Ok(Self {
            wire,
            name: name.to_owned(),
            session_id: challenge.session_id,
        })
    }

    async fn send(&mut self, message: Message) -> Result<(), AnyError> {
        self.wire.send(VERSION, message).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message, AnyError> {
        Ok(timeout(Duration::from_secs(2), self.wire.receive())
            .await??
            .message)
    }

    async fn send_envelope(&mut self, envelope: &RendezvousEnvelope) -> Result<(), AnyError> {
        self.send(envelope.to_protocol_message()?).await
    }

    async fn receive_envelope(&mut self) -> Result<RendezvousEnvelope, AnyError> {
        Ok(RendezvousEnvelope::from_protocol_message(
            self.receive().await?,
        )?)
    }
}

fn tunnel(id: u32, name: &str, protocol: TunnelProtocol, port: u16) -> TunnelRegistration {
    TunnelRegistration {
        tunnel_id: id,
        name: BoundedString::try_from(name).unwrap(),
        protocol,
        remote_port: port,
    }
}

fn envelope(
    marker: u8,
    sender: &str,
    target: &str,
    step: u64,
    expiry: u64,
    payload: RendezvousPayload,
) -> RendezvousEnvelope {
    RendezvousEnvelope {
        version: VERSION,
        session_id: SessionId::from([marker; 32]),
        sender: BoundedString::try_from(sender).unwrap(),
        target: BoundedString::try_from(target).unwrap(),
        step,
        generation: CandidateGeneration::INITIAL,
        expires_unix_secs: expiry,
        payload,
        signature: BoundedBytes::try_from([0x44; 64].as_slice()).unwrap(),
    }
}

async fn open_fallback(
    consumer: &mut Client,
    provider: &mut Client,
    marker: u8,
    expiry: u64,
    provider_preselection_bytes: usize,
) -> Result<(), AnyError> {
    let messages = [
        (
            true,
            1,
            RendezvousPayload::Request(RendezvousRequest {
                export: BoundedString::try_from("fallback")?,
            }),
        ),
        (
            false,
            2,
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
        ),
        (
            true,
            3,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: false }),
        ),
        (
            false,
            4,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: false }),
        ),
        (
            true,
            5,
            RendezvousPayload::ConnectivityResult(ConnectivityResult {
                connected: true,
                transport: Some(CandidateTransport::Relay),
                detail: None,
            }),
        ),
    ];
    for (from_consumer, step, payload) in messages {
        let message = if from_consumer {
            envelope(marker, "alpha", "beta", step, expiry, payload)
        } else {
            envelope(marker, "beta", "alpha", step, expiry, payload)
        };
        if from_consumer {
            consumer.send_envelope(&message).await?;
            assert_eq!(provider.receive_envelope().await?, message);
        } else {
            provider.send_envelope(&message).await?;
            assert_eq!(consumer.receive_envelope().await?, message);
        }
        if step == 4 {
            // AUTH_RECORD is sent once by each endpoint after relay authorization. The
            // provider then sends OPEN_OK before the initiator reports fallback selection.
            relay_frame(consumer, provider, marker, 1, 21).await?;
            relay_frame(provider, consumer, marker, 1, 21).await?;
            relay_frame(provider, consumer, marker, 2, 21).await?;
            if provider_preselection_bytes > 0 {
                relay_frame(provider, consumer, marker, 3, provider_preselection_bytes).await?;
            }
        }
    }
    Ok(())
}

async fn relay_frame(
    sender: &mut Client,
    receiver: &mut Client,
    marker: u8,
    sequence: u64,
    logical_bytes: usize,
) -> Result<(), AnyError> {
    let frame = PeerRelayFrame::new(
        SessionId::from([marker; 32]),
        1,
        sequence,
        PeerRelayFlags::RELIABLE,
        vec![marker; logical_bytes + 16],
    )?;
    sender.send(frame.to_protocol_message()?).await?;
    assert_eq!(
        PeerRelayFrame::from_protocol_message(receiver.receive().await?)?,
        frame
    );
    Ok(())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn telemetry(sequence: u64, cpu_basis_points: u16, tx: u64, rx: u64) -> TelemetryReport {
    TelemetryReport {
        sampled_unix_millis: now_millis(),
        sequence,
        cpu_basis_points,
        memory_used_bytes: 512,
        memory_total_bytes: 1_024,
        disk_used_bytes: 2_048,
        disk_total_bytes: 4_096,
        tx_bytes_per_sec: tx,
        rx_bytes_per_sec: rx,
    }
}

async fn connect_data_channel(
    pki: &TestPki,
    address: SocketAddr,
    client: &Client,
    kind: DataChannelKind,
    tunnel_id: u32,
    target_id: u64,
    binding_token: BoundedBytes<{ rustgo_protocol::MAX_BINDING_TOKEN_BYTES }>,
) -> Result<TlsStream<TcpStream>, AnyError> {
    let tls = TlsClient::from_ca_file(&pki.ca_file, SERVER_NAME)?;
    let mut stream = tls.connect(address).await?;
    let bind = Message::DataChannelBind(DataChannelBind {
        client_name: BoundedString::try_from(client.name.as_str())?,
        session_id: BoundedBytes::try_from(client.session_id.as_slice())?,
        kind,
        tunnel_id,
        target_id,
        binding_token,
    });
    let encoded = FrameCodec::new(FRAME_MAX).encode(VERSION, 0, &bind)?;
    stream.write_all(&encoded).await?;
    Ok(stream)
}

async fn read_frame_exact<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Frame, AnyError> {
    let codec = FrameCodec::new(FRAME_MAX);
    let mut header = [0_u8; rustgo_protocol::HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let needed = match codec.decode_exact(&header) {
        Err(FrameError::Truncated { needed, .. }) => needed,
        Ok(frame) => return Ok(frame),
        Err(error) => return Err(error.into()),
    };
    let mut frame = BytesMut::from(header.as_slice());
    frame.resize(needed, 0);
    stream
        .read_exact(&mut frame[rustgo_protocol::HEADER_LEN..])
        .await?;
    Ok(codec.decode_exact(&frame)?)
}

async fn wait_for<F>(
    store: &ObservabilityStore,
    stage: &'static str,
    predicate: F,
) -> Result<OverviewSnapshot, AnyError>
where
    F: Fn(&OverviewSnapshot) -> bool,
{
    match timeout(Duration::from_secs(4), async {
        loop {
            let snapshot = store.snapshot();
            if predicate(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    {
        Ok(snapshot) => Ok(snapshot),
        Err(_) => Err(format!(
            "observability stage {stage} timed out; snapshot: {:#?}",
            store.snapshot()
        )
        .into()),
    }
}

fn free_tcp_port() -> Result<u16, AnyError> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

fn free_udp_port() -> Result<u16, AnyError> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(socket.local_addr()?.port())
}

#[tokio::test]
async fn authenticated_runtime_activity_projects_without_trusting_client_identity()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let alpha_key = DeviceKeypair::from_secret_bytes([61; 32]);
    let beta_key = DeviceKeypair::from_secret_bytes([62; 32]);
    let tcp_port = free_tcp_port()?;
    let udp_port = free_udp_port()?;
    let (store, sink, worker) = ObservabilityStore::new();
    let worker_task = tokio::spawn(worker.run());
    let app = ServerApp::bind_with_runtime_limits(
        server_config(
            &pki,
            vec![
                authorized("alpha", &alpha_key),
                authorized("beta", &beta_key),
            ],
        )?,
        ServerRuntimeLimits::default(),
    )
    .await?
    .with_observability_sink(sink.clone())?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut alpha = Client::connect(
        &pki,
        address,
        "alpha",
        &alpha_key,
        vec![
            tunnel(1, "alpha-tcp", TunnelProtocol::TCP, tcp_port),
            tunnel(2, "alpha-udp", TunnelProtocol::UDP, udp_port),
        ],
    )
    .await?;
    let mut beta = Client::connect(&pki, address, "beta", &beta_key, Vec::new()).await?;
    wait_for(&store, "clients-online", |snapshot| {
        snapshot.server.online_clients == 2
    })
    .await?;

    alpha
        .send(Message::TelemetryReport(telemetry(7, 1_111, 11, 12)))
        .await?;
    wait_for(&store, "alpha-telemetry", |snapshot| {
        snapshot
            .clients
            .iter()
            .any(|client| client.name.as_str() == "alpha" && client.telemetry_sequence == Some(7))
    })
    .await?;
    let early_report = telemetry(8, 9_999, 99, 99);
    alpha
        .send(Message::TelemetryReport(early_report.clone()))
        .await?;
    let attempted_cross_client_report = telemetry(7, 2_222, 21, 22);
    beta.send(Message::TelemetryReport(attempted_cross_client_report))
        .await?;
    wait_for(&store, "beta-telemetry", |snapshot| {
        snapshot
            .clients
            .iter()
            .any(|client| client.name.as_str() == "beta" && client.telemetry_sequence == Some(7))
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    alpha.send(Message::TelemetryReport(early_report)).await?;
    let mut invalid = telemetry(9, 10_001, 77, 77);
    invalid.memory_used_bytes = invalid.memory_total_bytes + 1;
    alpha.send(Message::TelemetryReport(invalid)).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snapshot = store.snapshot();
    let alpha_projection = snapshot
        .clients
        .iter()
        .find(|client| client.name.as_str() == "alpha")
        .unwrap();
    let beta_projection = snapshot
        .clients
        .iter()
        .find(|client| client.name.as_str() == "beta")
        .unwrap();
    assert_eq!(alpha_projection.telemetry_sequence, Some(7));
    assert_eq!(
        alpha_projection.metrics.as_ref().unwrap().cpu_basis_points,
        Some(1_111)
    );
    assert_eq!(beta_projection.telemetry_sequence, Some(7));
    assert_eq!(
        beta_projection.metrics.as_ref().unwrap().cpu_basis_points,
        Some(2_222)
    );

    let Message::OpenUdpChannel(OpenUdpChannel {
        tunnel_id: 2,
        channel_id,
        binding_token,
        ..
    }) = alpha.receive().await?
    else {
        return Err("server did not request the UDP data channel".into());
    };
    let mut udp_data = connect_data_channel(
        &pki,
        address,
        &alpha,
        DataChannelKind::UDP,
        2,
        channel_id,
        binding_token,
    )
    .await?;
    assert!(matches!(
        read_frame_exact(&mut udp_data).await?.message,
        Message::OpenUdpChannel(_)
    ));

    let mut public_tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, tcp_port)).await?;
    let Message::OpenTcpStream(OpenTcpStream {
        tunnel_id: 1,
        connection_id,
        binding_token,
        ..
    }) = alpha.receive().await?
    else {
        return Err("server did not request the TCP data channel".into());
    };
    let mut tcp_data = connect_data_channel(
        &pki,
        address,
        &alpha,
        DataChannelKind::TCP,
        1,
        connection_id,
        binding_token,
    )
    .await?;
    assert!(matches!(
        read_frame_exact(&mut tcp_data).await?.message,
        Message::TcpStreamReady(_)
    ));
    public_tcp.write_all(b"tcp-to-alpha").await?;
    let mut tcp_received = [0_u8; 12];
    tcp_data.read_exact(&mut tcp_received).await?;
    assert_eq!(&tcp_received, b"tcp-to-alpha");
    tcp_data.write_all(b"tcp-from-alpha").await?;
    let mut tcp_sent = [0_u8; 14];
    public_tcp.read_exact(&mut tcp_sent).await?;
    assert_eq!(&tcp_sent, b"tcp-from-alpha");
    let public_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    public_udp
        .send_to(b"udp-to-alpha", (Ipv4Addr::LOCALHOST, udp_port))
        .await?;
    let Frame {
        message: Message::UdpDatagram(datagram),
        ..
    } = read_frame_exact(&mut udp_data).await?
    else {
        return Err("server did not relay the UDP datagram".into());
    };
    assert_eq!(datagram.payload.as_slice(), b"udp-to-alpha");
    let reply = Message::UdpDatagram(UdpDatagram {
        tunnel_id: 2,
        session_id: datagram.session_id,
        source: datagram.source,
        payload: BoundedBytes::try_from(b"udp-from-alpha".as_slice())?,
    });
    udp_data
        .write_all(&FrameCodec::new(FRAME_MAX).encode(VERSION, 0, &reply)?)
        .await?;
    let mut udp_received = [0_u8; 14];
    let (received, _) = timeout(
        Duration::from_secs(2),
        public_udp.recv_from(&mut udp_received),
    )
    .await??;
    assert_eq!(&udp_received[..received], b"udp-from-alpha");

    let expiry = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 20;
    let request = envelope(
        0x71,
        "alpha",
        "beta",
        1,
        expiry,
        RendezvousPayload::Request(RendezvousRequest {
            export: BoundedString::try_from("database")?,
        }),
    );
    alpha.send_envelope(&request).await?;
    assert_eq!(beta.receive_envelope().await?, request);
    let decision = envelope(
        0x71,
        "beta",
        "alpha",
        2,
        expiry,
        RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
    );
    beta.send_envelope(&decision).await?;
    assert_eq!(alpha.receive_envelope().await?, decision);
    let connected = envelope(
        0x71,
        "alpha",
        "beta",
        3,
        expiry,
        RendezvousPayload::ConnectivityResult(ConnectivityResult {
            connected: true,
            transport: Some(CandidateTransport::NativeTcp),
            detail: None,
        }),
    );
    alpha.send_envelope(&connected).await?;
    assert_eq!(beta.receive_envelope().await?, connected);
    let p2p_id = ShortSessionId::from_bytes(&[0x71; 32]);
    wait_for(&store, "p2p-open", |snapshot| {
        snapshot.sessions.iter().any(|session| {
            session.id == p2p_id
                && session.client.as_str() == "alpha"
                && session.peer.as_ref().map(|peer| peer.as_str()) == Some("beta")
                && session.path == SessionPath::P2pDirect
                && session.closed_unix_millis.is_none()
        })
    })
    .await?;
    let close = envelope(
        0x71,
        "alpha",
        "beta",
        4,
        expiry,
        RendezvousPayload::Close(RendezvousClose { detail: None }),
    );
    alpha.send_envelope(&close).await?;
    assert_eq!(beta.receive_envelope().await?, close);

    open_fallback(&mut alpha, &mut beta, 0x72, expiry, 0).await?;
    let zero_fallback_id = ShortSessionId::from_bytes(&[0x72; 32]);
    let zero_close = envelope(
        0x72,
        "alpha",
        "beta",
        6,
        expiry,
        RendezvousPayload::Close(RendezvousClose { detail: None }),
    );
    alpha.send_envelope(&zero_close).await?;
    assert_eq!(beta.receive_envelope().await?, zero_close);

    open_fallback(&mut alpha, &mut beta, 0x73, expiry, 7).await?;
    let data_fallback_id = ShortSessionId::from_bytes(&[0x73; 32]);
    wait_for(&store, "provider-first-fallback-traffic", |snapshot| {
        snapshot.sessions.iter().any(|session| {
            session.id == data_fallback_id
                && session.path == SessionPath::P2pFallback
                && session.traffic.received_bytes == 7
                && session.traffic.sent_bytes == 0
                && session.closed_unix_millis.is_none()
        })
    })
    .await?;
    relay_frame(&mut alpha, &mut beta, 0x73, 2, 5).await?;
    let data_close = envelope(
        0x73,
        "alpha",
        "beta",
        6,
        expiry,
        RendezvousPayload::Close(RendezvousClose { detail: None }),
    );
    alpha.send_envelope(&data_close).await?;
    assert_eq!(beta.receive_envelope().await?, data_close);

    drop(beta);
    wait_for(&store, "beta-and-p2p-closed", |snapshot| {
        let beta_offline = snapshot
            .clients
            .iter()
            .any(|client| client.name.as_str() == "beta" && !client.online);
        let p2p = snapshot
            .sessions
            .iter()
            .any(|session| session.id == p2p_id && session.closed_unix_millis.is_some());
        let zero_fallback = snapshot.sessions.iter().any(|session| {
            session.id == zero_fallback_id
                && session.traffic.received_bytes == 0
                && session.traffic.sent_bytes == 0
                && session.closed_unix_millis.is_some()
        });
        let data_fallback = snapshot.sessions.iter().any(|session| {
            session.id == data_fallback_id
                && session.traffic.received_bytes == 7
                && session.traffic.sent_bytes == 5
                && session.closed_unix_millis.is_some()
        });
        beta_offline && p2p && zero_fallback && data_fallback
    })
    .await?;

    // Drop the authenticated control owner while both TCP and UDP children are
    // still live. Their final traffic deltas must be projected before offline.
    drop(alpha);
    let snapshot = wait_for(&store, "live-session-disconnect-finalized", |snapshot| {
        let alpha_offline = snapshot
            .clients
            .iter()
            .any(|client| client.name.as_str() == "alpha" && !client.online);
        let tcp = snapshot.sessions.iter().any(|session| {
            session.kind == SessionKind::Tcp
                && session.client.as_str() == "alpha"
                && session.traffic.received_bytes == 12
                && session.traffic.sent_bytes == 14
                && session.closed_unix_millis.is_some()
        });
        let udp = snapshot.sessions.iter().any(|session| {
            session.kind == SessionKind::Udp
                && session.client.as_str() == "alpha"
                && session.traffic.received_bytes == 12
                && session.traffic.sent_bytes == 14
                && session.closed_unix_millis.is_some()
        });
        alpha_offline && tcp && udp
    })
    .await?;
    assert!(snapshot.sessions.iter().all(|session| {
        session.id.as_str().len() == 16
            && !session.id.as_str().contains("tcp-to-alpha")
            && !session.id.as_str().contains("udp-to-alpha")
    }));
    assert_eq!(snapshot.dropped_events, 0);

    drop(tcp_data);
    drop(public_tcp);
    drop(udp_data);
    shutdown.cancel();
    server_task.await??;
    drop(sink);
    worker_task.await?;
    Ok(())
}

#[tokio::test]
async fn queued_udp_receive_is_not_counted_when_writer_is_cancelled() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([63; 32]);
    let udp_port = free_udp_port()?;
    let (store, sink, worker) = ObservabilityStore::new();
    let worker_task = tokio::spawn(worker.run());
    let limits = ServerRuntimeLimits {
        udp_writer_delay: Duration::from_secs(2),
        ..ServerRuntimeLimits::default()
    };
    let app = ServerApp::bind_with_runtime_limits(
        server_config(&pki, vec![authorized("alpha", &key)])?,
        limits,
    )
    .await?
    .with_observability_sink(sink.clone())?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut client = Client::connect(
        &pki,
        address,
        "alpha",
        &key,
        vec![tunnel(1, "delayed-udp", TunnelProtocol::UDP, udp_port)],
    )
    .await?;
    let Message::OpenUdpChannel(OpenUdpChannel {
        channel_id,
        binding_token,
        ..
    }) = client.receive().await?
    else {
        return Err("server did not request delayed UDP channel".into());
    };
    let mut data = connect_data_channel(
        &pki,
        address,
        &client,
        DataChannelKind::UDP,
        1,
        channel_id,
        binding_token,
    )
    .await?;
    assert!(matches!(
        read_frame_exact(&mut data).await?.message,
        Message::OpenUdpChannel(_)
    ));

    let public = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    public
        .send_to(b"queued-but-never-written", (Ipv4Addr::LOCALHOST, udp_port))
        .await?;
    wait_for(&store, "udp-queued", |snapshot| {
        snapshot.sessions.iter().any(|session| {
            session.kind == SessionKind::Udp
                && session.client.as_str() == "alpha"
                && session.traffic == Default::default()
                && session.closed_unix_millis.is_none()
        })
    })
    .await?;
    drop(client);
    let snapshot = wait_for(&store, "udp-writer-cancelled", |snapshot| {
        snapshot.clients.iter().any(|client| !client.online)
            && snapshot.sessions.iter().any(|session| {
                session.kind == SessionKind::Udp
                    && session.traffic == Default::default()
                    && session.closed_unix_millis.is_some()
            })
    })
    .await?;
    assert_eq!(snapshot.dropped_events, 0);

    drop(data);
    shutdown.cancel();
    server_task.await??;
    drop(sink);
    worker_task.await?;
    Ok(())
}

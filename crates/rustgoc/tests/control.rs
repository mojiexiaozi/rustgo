#![forbid(unsafe_code)]

use std::{error::Error, fs, future::Future, path::PathBuf, pin::Pin, sync::Arc, time::Duration};

use bytes::BytesMut;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_config::{
    AuthorizedClient, ClientConfig, ClientSection, Limits, ServerConfig, ServerSection,
    TunnelConfig, TunnelProtocol as ConfigProtocol,
};
use rustgo_crypto::{
    AuthTranscript, DeviceKeypair, generate_key_file, sign_peer_envelope, verify_auth,
    verify_peer_envelope,
};
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, BoundedVec, Frame, FrameCodec,
    MAX_BINDING_TOKEN_BYTES, Message, OpenTcpStream, OpenUdpChannel, ProtocolErrorCode,
    ProtocolVersion, ServerChallenge, SocketAddress, TunnelResult, TunnelResults,
};
use rustgo_rendezvous::{
    CandidateGeneration, ObservationGrant, RendezvousEnvelope, RendezvousPayload,
    RendezvousRequest, SessionId,
};
use rustgo_transport::{Backoff, BackoffClock, BackoffConfig, JitterSource, TlsServer};
use rustgoc::{
    ChildSessionContext, ChildSessionRequest, ChildSessionSupervisor, ClientApp, ClientError,
    ClientStatus, ControlClient, ControlEvent, NoopChildSessionSupervisor, PeerGenerationHandler,
    SessionGeneration,
};
use rustgos::ServerApp;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::Instant;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

const SERVER_NAME: &str = "tunnel.example.test";
const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const FRAME_MAX: usize = 70 * 1024;
type AnyError = Box<dyn Error + Send + Sync>;

struct ManualTimeGuard(tokio::task::JoinHandle<()>);

impl Drop for ManualTimeGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ManualTimeGuard {
    async fn advance(&mut self, duration: Duration) {
        self.0.abort();
        let _ = (&mut self.0).await;
        tokio::time::advance(duration).await;
        self.0 = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
    }
}

fn keep_paused_time_manual() -> ManualTimeGuard {
    ManualTimeGuard(tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    }))
}

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
        .push(rcgen::DnType::CommonName, "Rustgo client control test CA");
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
    stream: TlsStream<TcpStream>,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl FramedServer {
    fn new(stream: TlsStream<TcpStream>) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(FRAME_MAX),
        }
    }

    async fn send(&mut self, message: Message) -> Result<(), AnyError> {
        let encoded = self.codec.encode(VERSION, 0, &message)?;
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
    verification_key: DeviceKeypair,
}

fn client_fixture(pki: &TestPki, server_addr: String) -> Result<Fixture, AnyError> {
    let keys = tempfile::tempdir()?;
    generate_key_file(keys.path())?;
    let private_key_file = keys.path().join("device.key");
    let verification_key = DeviceKeypair::load_private_file(&private_key_file)?;
    Ok(Fixture {
        _keys: keys,
        config: ClientConfig {
            client: ClientSection {
                name: "home-pc".to_owned(),
                identity_mode: None,
                server_addr,
                server_name: SERVER_NAME.to_owned(),
                certificate_authority_file: pki.ca_file.clone(),
                trust_mode: None,
                server_certificate_fingerprint: None,
                private_key_file,
                heartbeat_interval_secs: 1,
            },
            p2p: None,
            tunnels: vec![
                TunnelConfig {
                    name: "ssh".to_owned(),
                    protocol: ConfigProtocol::Tcp,
                    local_addr: "127.0.0.1:22".to_owned(),
                    remote_port: 2222,
                },
                TunnelConfig {
                    name: "game".to_owned(),
                    protocol: ConfigProtocol::Udp,
                    local_addr: "127.0.0.1:27015".to_owned(),
                    remote_port: 27015,
                },
            ],
            exports: Vec::new(),
            forwards: Vec::new(),
            telemetry: None,
        },
        verification_key,
    })
}

fn real_server_config(
    pki: &TestPki,
    key: &DeviceKeypair,
    heartbeat_timeout_secs: u64,
) -> ServerConfig {
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
            max_clients: 8,
            max_tunnels_per_client: 8,
            max_tcp_connections_per_tunnel: 8,
            max_udp_sessions_per_tunnel: 8,
            max_udp_payload_bytes: 65_507,
        },
        clients: vec![AuthorizedClient {
            name: "home-pc".to_owned(),
            public_key: key.public_key().to_string(),
            enabled: true,
        }],
        web: None,
        enrollment: None,
        managed_tunnels: None,
    }
}

fn bytes<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(value).unwrap()
}

fn transcript_version(version: ProtocolVersion) -> u16 {
    (version.major << 8) | version.minor
}

async fn accept_registered_session(
    tls_server: &TlsServer,
    marker: u8,
) -> Result<(FramedServer, Vec<String>), AnyError> {
    let (socket, _) = tls_server.accept_tcp().await?;
    let mut server = FramedServer::new(tls_server.handshake(socket).await?);
    let Message::ClientHello(_) = server.receive().await?.message else {
        return Err("first message was not ClientHello".into());
    };
    server
        .send(Message::ServerChallenge(ServerChallenge {
            challenge: bytes(&[marker; 32]),
            session_id: bytes(&[marker.wrapping_add(1); 32]),
        }))
        .await?;
    let Message::ClientAuthenticate(_) = server.receive().await?.message else {
        return Err("second message was not ClientAuthenticate".into());
    };
    server
        .send(Message::AuthResult(AuthResult {
            accepted: true,
            error: None,
        }))
        .await?;
    let Message::RegisterTunnels(registration) = server.receive().await?.message else {
        return Err("third message was not RegisterTunnels".into());
    };
    let names = registration
        .tunnels
        .as_slice()
        .iter()
        .map(|tunnel| tunnel.name.as_str().to_owned())
        .collect::<Vec<_>>();
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
    Ok((server, names))
}

async fn accept_and_drop_after_hello(tls_server: &TlsServer) -> Result<(), AnyError> {
    let (socket, _) = tls_server.accept_tcp().await?;
    let mut server = FramedServer::new(tls_server.handshake(socket).await?);
    let Message::ClientHello(_) = server.receive().await?.message else {
        return Err("first message was not ClientHello".into());
    };
    Ok(())
}

async fn wait_for_status<F>(status: &mut tokio::sync::watch::Receiver<ClientStatus>, predicate: F)
where
    F: Fn(&ClientStatus) -> bool,
{
    loop {
        if predicate(&status.borrow_and_update()) {
            return;
        }
        status.changed().await.unwrap();
    }
}

struct MaximumJitter;

impl JitterSource for MaximumJitter {
    fn sample(&mut self, upper_inclusive_nanoseconds: u128) -> u128 {
        upper_inclusive_nanoseconds
    }
}

#[derive(Clone)]
struct TokioClock {
    origin: Instant,
}

impl TokioClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl BackoffClock for TokioClock {
    fn now(&self) -> Duration {
        Instant::now().saturating_duration_since(self.origin)
    }
}

fn test_backoff() -> Backoff<MaximumJitter, TokioClock> {
    Backoff::with_sources(
        BackoffConfig {
            initial_delay: Duration::from_millis(100),
            maximum_delay: Duration::from_millis(200),
            jitter: Duration::from_millis(20),
            stable_connection_reset_after: Duration::from_secs(5),
        },
        MaximumJitter,
        TokioClock::new(),
    )
    .unwrap()
}

#[derive(Clone)]
struct TrackingSupervisor {
    started: mpsc::UnboundedSender<(SessionGeneration, &'static str, Vec<u8>)>,
    cancelled: mpsc::UnboundedSender<SessionGeneration>,
    release: Arc<Semaphore>,
}

impl ChildSessionSupervisor for TrackingSupervisor {
    fn run_child(
        &self,
        context: ChildSessionContext,
        request: ChildSessionRequest,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let kind = match request {
            ChildSessionRequest::Tcp(_) => "tcp",
            ChildSessionRequest::Udp(_) => "udp",
        };
        let started = self.started.clone();
        let cancelled = self.cancelled.clone();
        let release = self.release.clone();
        Box::pin(async move {
            started
                .send((context.generation(), kind, context.session_id().to_vec()))
                .unwrap();
            shutdown.cancelled().await;
            cancelled.send(context.generation()).unwrap();
            release.acquire_owned().await.unwrap().forget();
        })
    }
}

struct SlowFailingPeerOwner {
    started: mpsc::UnboundedSender<SessionGeneration>,
    cancelled: mpsc::UnboundedSender<SessionGeneration>,
    release: Arc<Semaphore>,
}

impl PeerGenerationHandler for SlowFailingPeerOwner {
    fn run_generation(
        &self,
        context: ChildSessionContext,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<(), ClientError>> + Send + 'static>> {
        let started = self.started.clone();
        let cancelled = self.cancelled.clone();
        let release = self.release.clone();
        Box::pin(async move {
            started.send(context.generation()).unwrap();
            shutdown.cancelled().await;
            cancelled.send(context.generation()).unwrap();
            release.acquire_owned().await.unwrap().forget();
            Err(ClientError::PeerGenerationFailed)
        })
    }

    fn run_event(
        &self,
        _context: ChildSessionContext,
        _event: ControlEvent,
        _shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async {})
    }
}

#[tokio::test]
async fn strict_tls_authentication_precedes_complete_per_tunnel_registration()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let expected_public_key = fixture.verification_key.public_key();
    let expected_fingerprint = expected_public_key.fingerprint().to_string();
    let expected_fingerprint = expected_fingerprint
        .strip_prefix("sha256:")
        .unwrap()
        .as_bytes()
        .to_vec();
    let server = tokio::spawn(async move {
        let (socket, _) = tls_server.accept_tcp().await?;
        let mut server = FramedServer::new(tls_server.handshake(socket).await?);

        let hello_frame = server.receive().await?;
        assert_eq!(hello_frame.version, rustgoc::CLIENT_VERSION);
        let Message::ClientHello(hello) = hello_frame.message else {
            return Err("first message was not ClientHello".into());
        };
        assert_eq!(hello.client_name.as_str(), "home-pc");
        assert_eq!(hello.fingerprint.as_slice(), expected_fingerprint);
        assert_eq!(hello.heartbeat_interval_secs, 1);

        let challenge = vec![0x11; 32];
        let session_id = vec![0x22; 32];
        server
            .send(Message::ServerChallenge(ServerChallenge {
                challenge: bytes(&challenge),
                session_id: bytes(&session_id),
            }))
            .await?;

        let authentication_frame = server.receive().await?;
        assert_eq!(authentication_frame.version, VERSION);
        let Message::ClientAuthenticate(authentication) = authentication_frame.message else {
            return Err("second message was not ClientAuthenticate".into());
        };
        assert_eq!(
            authentication.public_key.as_slice(),
            expected_public_key.to_string().as_bytes()
        );
        let transcript = AuthTranscript::new(
            challenge,
            session_id,
            transcript_version(VERSION),
            "home-pc".to_owned(),
        );
        verify_auth(
            &expected_public_key,
            &transcript,
            authentication.signature.as_slice(),
        )?;

        server
            .send(Message::AuthResult(AuthResult {
                accepted: true,
                error: None,
            }))
            .await?;
        let registration = server.receive().await?;
        let Message::RegisterTunnels(registration) = registration.message else {
            return Err("third message was not RegisterTunnels".into());
        };
        let tunnels = registration.tunnels.as_slice();
        assert_eq!(tunnels.len(), 2);
        assert_eq!(tunnels[0].tunnel_id, 1);
        assert_eq!(tunnels[0].name.as_str(), "ssh");
        assert_eq!(tunnels[0].remote_port, 2222);
        assert_eq!(tunnels[1].tunnel_id, 2);
        assert_eq!(tunnels[1].name.as_str(), "game");
        assert_eq!(tunnels[1].remote_port, 27015);

        server
            .send(Message::TunnelResults(TunnelResults {
                results: BoundedVec::try_from(vec![
                    TunnelResult {
                        tunnel_id: 1,
                        accepted: false,
                        error: Some(ProtocolErrorCode::TUNNEL_REJECTED),
                    },
                    TunnelResult {
                        tunnel_id: 2,
                        accepted: true,
                        error: None,
                    },
                ])
                .unwrap(),
            }))
            .await?;
        Ok::<_, AnyError>(())
    });

    let client = ControlClient::from_config(fixture.config)?;
    let session = client.connect().await?;
    let results = session.registered_tunnels();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].name(), "ssh");
    assert!(!results[0].accepted());
    assert_eq!(results[0].error(), Some(ProtocolErrorCode::TUNNEL_REJECTED));
    assert_eq!(results[1].name(), "game");
    assert!(results[1].accepted());
    assert_eq!(results[1].error(), None);

    server.await??;
    Ok(())
}

#[tokio::test]
async fn rejected_authentication_never_reaches_tunnel_registration() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let server = tokio::spawn(async move {
        let (socket, _) = tls_server.accept_tcp().await?;
        let mut server = FramedServer::new(tls_server.handshake(socket).await?);
        let Message::ClientHello(_) = server.receive().await?.message else {
            return Err("first message was not ClientHello".into());
        };
        server
            .send(Message::ServerChallenge(ServerChallenge {
                challenge: bytes(&[0x33; 32]),
                session_id: bytes(&[0x44; 32]),
            }))
            .await?;
        let Message::ClientAuthenticate(_) = server.receive().await?.message else {
            return Err("second message was not ClientAuthenticate".into());
        };
        server
            .send(Message::AuthResult(AuthResult {
                accepted: false,
                error: Some(ProtocolErrorCode::AUTHENTICATION_FAILED),
            }))
            .await?;
        let no_registration =
            tokio::time::timeout(Duration::from_millis(250), server.receive()).await;
        assert!(no_registration.is_err() || no_registration.unwrap().is_err());
        Ok::<_, AnyError>(())
    });

    let client = ControlClient::from_config(fixture.config)?;
    assert!(matches!(
        client.connect().await,
        Err(ClientError::AuthenticationRejected)
    ));
    server.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn stalled_control_handshake_times_out_instead_of_blocking_reconnect_forever()
-> Result<(), AnyError> {
    let mut time_guard = keep_paused_time_manual();
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let (hello_tx, mut hello_rx) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let (socket, _) = tls_server.accept_tcp().await?;
        let mut server = FramedServer::new(tls_server.handshake(socket).await?);
        let Message::ClientHello(_) = server.receive().await?.message else {
            return Err("first message was not ClientHello".into());
        };
        hello_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok::<_, AnyError>(())
    });

    let client = ControlClient::from_config(fixture.config)?;
    let connection = tokio::spawn(async move { client.connect().await });
    hello_rx.recv().await.unwrap();
    if !connection.is_finished() {
        time_guard.advance(Duration::from_secs(10)).await;
    }
    assert!(matches!(
        connection.await?,
        Err(ClientError::HandshakeTimeout)
    ));

    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn connection_failures_wait_for_injected_jittered_capped_backoff_and_stop_interrupts_retry()
-> Result<(), AnyError> {
    let mut time_guard = keep_paused_time_manual();
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let (attempted_tx, mut attempted_rx) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        for attempt in 1..=4 {
            accept_and_drop_after_hello(&tls_server).await?;
            attempted_tx.send(attempt).unwrap();
        }
        Ok::<_, AnyError>(())
    });

    let control = ControlClient::from_config(fixture.config)?;
    let app = ClientApp::with_runtime(
        control,
        test_backoff(),
        Arc::new(NoopChildSessionSupervisor),
    );
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));

    assert_eq!(attempted_rx.recv().await, Some(1));
    tokio::task::yield_now().await;
    time_guard.advance(Duration::from_millis(119)).await;
    assert!(attempted_rx.try_recv().is_err());
    time_guard.advance(Duration::from_millis(1)).await;
    assert_eq!(attempted_rx.recv().await, Some(2));

    tokio::task::yield_now().await;
    time_guard.advance(Duration::from_millis(199)).await;
    assert!(attempted_rx.try_recv().is_err());
    time_guard.advance(Duration::from_millis(1)).await;
    assert_eq!(attempted_rx.recv().await, Some(3));

    tokio::task::yield_now().await;
    time_guard.advance(Duration::from_millis(199)).await;
    assert!(attempted_rx.try_recv().is_err());
    time_guard.advance(Duration::from_millis(1)).await;
    assert_eq!(attempted_rx.recv().await, Some(4));

    shutdown.cancel();
    assert!(app_task.await?.is_ok());
    server.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn stable_generation_resets_backoff_and_reconnect_reregisters_every_tunnel()
-> Result<(), AnyError> {
    let mut time_guard = keep_paused_time_manual();
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (heartbeat_tx, mut heartbeat_rx) = mpsc::unbounded_channel();
    let (drop_tx, drop_rx) = oneshot::channel();
    let stop_server = CancellationToken::new();
    let server_stop = stop_server.clone();
    let server = tokio::spawn(async move {
        accept_and_drop_after_hello(&tls_server).await?;
        event_tx.send(("failed", Vec::new())).unwrap();
        accept_and_drop_after_hello(&tls_server).await?;
        event_tx.send(("failed", Vec::new())).unwrap();

        let (mut first, names) = accept_registered_session(&tls_server, 0x51).await?;
        event_tx.send(("active-1", names)).unwrap();
        tokio::pin!(drop_rx);
        loop {
            tokio::select! {
                _ = &mut drop_rx => break,
                frame = first.receive() => {
                    let frame = frame?;
                    let Message::Heartbeat(heartbeat) = frame.message else {
                        return Err("active client sent a non-heartbeat message".into());
                    };
                    let sequence = heartbeat.sequence;
                    first.send(Message::Heartbeat(heartbeat)).await?;
                    heartbeat_tx.send(sequence).unwrap();
                }
            }
        }
        drop(first);

        let (mut second, names) = accept_registered_session(&tls_server, 0x61).await?;
        event_tx.send(("active-2", names)).unwrap();
        loop {
            tokio::select! {
                biased;
                () = server_stop.cancelled() => break,
                frame = second.receive() => {
                    let frame = frame?;
                    let Message::Heartbeat(heartbeat) = frame.message else {
                        return Err("active client sent a non-heartbeat message".into());
                    };
                    let sequence = heartbeat.sequence;
                    second.send(Message::Heartbeat(heartbeat)).await?;
                    heartbeat_tx.send(sequence).unwrap();
                }
            }
        }
        Ok::<_, AnyError>(())
    });

    let control = ControlClient::from_config(fixture.config)?;
    let app = ClientApp::with_runtime(
        control,
        test_backoff(),
        Arc::new(NoopChildSessionSupervisor),
    );
    let mut status = app.subscribe();
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));

    assert_eq!(event_rx.recv().await, Some(("failed", Vec::new())));
    time_guard.advance(Duration::from_millis(120)).await;
    assert_eq!(event_rx.recv().await, Some(("failed", Vec::new())));
    time_guard.advance(Duration::from_millis(200)).await;
    let (event, first_names) = event_rx.recv().await.unwrap();
    assert_eq!(event, "active-1");
    assert_eq!(first_names, ["ssh", "game"]);
    wait_for_status(&mut status, |status| status.active().is_some()).await;
    assert_eq!(status.borrow().active().unwrap().generation().get(), 1);

    for sequence in 1..=5 {
        time_guard.advance(Duration::from_secs(1)).await;
        assert_eq!(heartbeat_rx.recv().await, Some(sequence));
        assert_eq!(status.borrow().active().unwrap().generation().get(), 1);
    }
    drop_tx.send(()).unwrap();
    wait_for_status(&mut status, |status| status.active().is_none()).await;

    time_guard.advance(Duration::from_millis(119)).await;
    assert!(event_rx.try_recv().is_err());
    time_guard.advance(Duration::from_millis(1)).await;
    let (event, second_names) = event_rx.recv().await.unwrap();
    assert_eq!(event, "active-2");
    assert_eq!(second_names, ["ssh", "game"]);
    wait_for_status(&mut status, |status| {
        status
            .active()
            .is_some_and(|active| active.generation().get() == 2)
    })
    .await;

    stop_server.cancel();
    tokio::task::yield_now().await;
    shutdown.cancel();
    assert!(app_task.await?.is_ok());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn peer_owner_teardown_failure_fail_stops_before_generation_or_socket_reuse()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let (registered_tx, registered_rx) = oneshot::channel();
    let (drop_tx, drop_rx) = oneshot::channel();
    let (reconnected_tx, reconnected_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (first, _) = accept_registered_session(&tls_server, 0xd1).await?;
        registered_tx.send(()).unwrap();
        let _ = drop_rx.await;
        drop(first);
        let reconnected = tokio::time::timeout(Duration::from_millis(500), tls_server.accept_tcp())
            .await
            .is_ok();
        reconnected_tx.send(reconnected).unwrap();
        Ok::<_, AnyError>(())
    });

    let (started_tx, mut started_rx) = mpsc::unbounded_channel();
    let (cancelled_tx, mut cancelled_rx) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let peer_owner = Arc::new(SlowFailingPeerOwner {
        started: started_tx,
        cancelled: cancelled_tx,
        release: release.clone(),
    });
    let control = ControlClient::from_config(fixture.config)?;
    let app = ClientApp::with_runtime(
        control,
        test_backoff(),
        Arc::new(NoopChildSessionSupervisor),
    )
    .with_peer_handler(peer_owner);
    let mut status = app.subscribe();
    let app_task = tokio::spawn(app.run_until(CancellationToken::new()));

    registered_rx.await?;
    assert_eq!(started_rx.recv().await.unwrap().get(), 1);
    wait_for_status(&mut status, |status| status.active().is_some()).await;
    drop_tx.send(()).unwrap();
    assert_eq!(cancelled_rx.recv().await.unwrap().get(), 1);

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        status.borrow().active().is_some(),
        "generation must remain authoritative while its peer owner is not joined"
    );
    assert!(
        !app_task.is_finished(),
        "teardown result cannot escape before join"
    );

    release.add_permits(1);
    let result = tokio::time::timeout(Duration::from_secs(1), app_task)
        .await
        .expect("peer teardown failure must be visible")
        .expect("app task must join");
    assert!(matches!(result, Err(ClientError::PeerGenerationFailed)));
    assert!(
        !reconnected_rx.await?,
        "failed ownership must prevent reconnect"
    );
    server.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn slow_child_drain_does_not_turn_a_short_generation_into_a_stable_one()
-> Result<(), AnyError> {
    let mut time_guard = keep_paused_time_manual();
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (drop_tx, drop_rx) = oneshot::channel();
    let stop_server = CancellationToken::new();
    let server_stop = stop_server.clone();
    let server = tokio::spawn(async move {
        accept_and_drop_after_hello(&tls_server).await?;
        event_tx.send("failed-1").unwrap();
        accept_and_drop_after_hello(&tls_server).await?;
        event_tx.send("failed-2").unwrap();

        let (mut active, _) = accept_registered_session(&tls_server, 0xb1).await?;
        active
            .send(Message::OpenTcpStream(OpenTcpStream {
                tunnel_id: 1,
                connection_id: 51,
                peer: SocketAddress::V4 {
                    octets: [203, 0, 113, 51],
                    port: 443,
                },
                binding_token: bytes(&[0xb2; MAX_BINDING_TOKEN_BYTES]),
            }))
            .await?;
        event_tx.send("active").unwrap();
        let _ = drop_rx.await;
        drop(active);

        let (socket, _) = tls_server.accept_tcp().await?;
        event_tx.send("reconnect").unwrap();
        server_stop.cancelled().await;
        drop(socket);
        Ok::<_, AnyError>(())
    });

    let (started_tx, mut started_rx) = mpsc::unbounded_channel();
    let (cancelled_tx, mut cancelled_rx) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let supervisor = TrackingSupervisor {
        started: started_tx,
        cancelled: cancelled_tx,
        release: release.clone(),
    };
    let control = ControlClient::from_config(fixture.config)?;
    let app = ClientApp::with_runtime(control, test_backoff(), Arc::new(supervisor));
    let mut status = app.subscribe();
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));

    assert_eq!(event_rx.recv().await, Some("failed-1"));
    time_guard.advance(Duration::from_millis(120)).await;
    assert_eq!(event_rx.recv().await, Some("failed-2"));
    time_guard.advance(Duration::from_millis(200)).await;
    assert_eq!(event_rx.recv().await, Some("active"));
    wait_for_status(&mut status, |status| status.active().is_some()).await;
    assert_eq!(started_rx.recv().await.unwrap().0.get(), 1);

    drop_tx.send(()).unwrap();
    assert_eq!(cancelled_rx.recv().await.unwrap().get(), 1);
    assert!(
        status.borrow().active().is_some(),
        "generation remains active until its slow child is joined"
    );
    time_guard.advance(Duration::from_secs(10)).await;
    assert!(event_rx.try_recv().is_err());

    release.add_permits(1);
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    wait_for_status(&mut status, |status| status.active().is_none()).await;
    time_guard.advance(Duration::from_millis(120)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(event_rx.try_recv().is_err());
    time_guard.advance(Duration::from_millis(80)).await;
    assert_eq!(event_rx.recv().await, Some("reconnect"));

    shutdown.cancel();
    stop_server.cancel();
    assert!(app_task.await?.is_ok());
    server.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn heartbeat_loss_joins_all_children_before_clearing_and_starting_next_generation()
-> Result<(), AnyError> {
    let mut time_guard = keep_paused_time_manual();
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
    let stop_server = CancellationToken::new();
    let server_stop = stop_server.clone();
    let server = tokio::spawn(async move {
        let (mut first, names) = accept_registered_session(&tls_server, 0x71).await?;
        assert_eq!(names, ["ssh", "game"]);
        accepted_tx.send(1_u64).unwrap();
        first
            .send(Message::OpenTcpStream(OpenTcpStream {
                tunnel_id: 1,
                connection_id: 11,
                peer: SocketAddress::V4 {
                    octets: [203, 0, 113, 1],
                    port: 443,
                },
                binding_token: bytes(&[0x81; MAX_BINDING_TOKEN_BYTES]),
            }))
            .await?;
        first
            .send(Message::OpenUdpChannel(OpenUdpChannel {
                tunnel_id: 2,
                channel_id: 12,
                binding_token: bytes(&[0x82; MAX_BINDING_TOKEN_BYTES]),
                max_sessions: 8,
                idle_timeout_millis: 60_000,
                max_payload_bytes: 65_507,
                queue_capacity: 1024,
            }))
            .await?;

        let (mut second, names) = accept_registered_session(&tls_server, 0x91).await?;
        assert_eq!(names, ["ssh", "game"]);
        accepted_tx.send(2_u64).unwrap();
        second
            .send(Message::OpenTcpStream(OpenTcpStream {
                tunnel_id: 1,
                connection_id: 21,
                peer: SocketAddress::V4 {
                    octets: [203, 0, 113, 2],
                    port: 443,
                },
                binding_token: bytes(&[0x92; MAX_BINDING_TOKEN_BYTES]),
            }))
            .await?;
        loop {
            tokio::select! {
                () = server_stop.cancelled() => break,
                frame = second.receive() => {
                    let Ok(frame) = frame else { break };
                    let Message::Heartbeat(heartbeat) = frame.message else {
                        return Err("active client sent a non-heartbeat message".into());
                    };
                    second.send(Message::Heartbeat(heartbeat)).await?;
                }
            }
        }
        drop(first);
        Ok::<_, AnyError>(())
    });

    let (started_tx, mut started_rx) = mpsc::unbounded_channel();
    let (cancelled_tx, mut cancelled_rx) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let supervisor = TrackingSupervisor {
        started: started_tx,
        cancelled: cancelled_tx,
        release: release.clone(),
    };
    let control = ControlClient::from_config(fixture.config)?;
    let app = ClientApp::with_runtime(control, test_backoff(), Arc::new(supervisor));
    let mut status = app.subscribe();
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));

    assert_eq!(accepted_rx.recv().await, Some(1));
    wait_for_status(&mut status, |status| status.active().is_some()).await;
    let mut started = [
        started_rx.recv().await.unwrap(),
        started_rx.recv().await.unwrap(),
    ];
    started.sort_by_key(|(_, kind, _)| *kind);
    assert_eq!(started[0].0.get(), 1);
    assert_eq!(started[1].0.get(), 1);
    assert_eq!([started[0].1, started[1].1], ["tcp", "udp"]);
    assert_eq!(started[0].2, [0x72; 32]);
    assert_eq!(started[1].2, [0x72; 32]);

    time_guard.advance(Duration::from_secs(2)).await;
    assert_eq!(cancelled_rx.recv().await.unwrap().get(), 1);
    assert_eq!(cancelled_rx.recv().await.unwrap().get(), 1);
    assert!(status.borrow().active().is_some());
    assert!(accepted_rx.try_recv().is_err());

    release.add_permits(2);
    wait_for_status(&mut status, |status| status.active().is_none()).await;
    time_guard.advance(Duration::from_millis(119)).await;
    assert!(accepted_rx.try_recv().is_err());
    time_guard.advance(Duration::from_millis(1)).await;
    assert_eq!(accepted_rx.recv().await, Some(2));
    wait_for_status(&mut status, |status| {
        status
            .active()
            .is_some_and(|active| active.generation().get() == 2)
    })
    .await;

    let (generation, kind, session_id) = started_rx.recv().await.unwrap();
    assert_eq!(generation.get(), 2);
    assert_eq!(kind, "tcp");
    assert_eq!(session_id, [0x92; 32]);

    shutdown.cancel();
    assert_eq!(cancelled_rx.recv().await.unwrap().get(), 2);
    assert!(status.borrow().active().is_some());
    tokio::task::yield_now().await;
    assert!(!app_task.is_finished());
    release.add_permits(1);
    wait_for_status(&mut status, |status| status.active().is_none()).await;
    stop_server.cancel();
    assert!(app_task.await?.is_ok());
    server.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn business_frames_cannot_mask_missing_heartbeat_acknowledgements() -> Result<(), AnyError> {
    let mut time_guard = keep_paused_time_manual();
    let pki = TestPki::generate()?;
    let tls_server =
        TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls_server.local_addr()?.to_string())?;
    let (registered_tx, mut registered_rx) = mpsc::unbounded_channel();
    let (business_tx, mut business_rx) = mpsc::unbounded_channel();
    let stop_server = CancellationToken::new();
    let server_stop = stop_server.clone();
    let server = tokio::spawn(async move {
        let (mut control, _) = accept_registered_session(&tls_server, 0xa1).await?;
        registered_tx.send(()).unwrap();
        let mut connection_id = 40_u64;
        loop {
            tokio::select! {
                biased;
                () = server_stop.cancelled() => break,
                command = business_rx.recv() => {
                    let Some(()) = command else { break };
                    connection_id += 1;
                    control
                        .send(Message::OpenTcpStream(OpenTcpStream {
                            tunnel_id: 1,
                            connection_id,
                            peer: SocketAddress::V4 {
                                octets: [203, 0, 113, 41],
                                port: 443,
                            },
                            binding_token: bytes(&[0xa2; MAX_BINDING_TOKEN_BYTES]),
                        }))
                        .await?;
                }
            }
        }
        Ok::<_, AnyError>(())
    });

    let (started_tx, mut started_rx) = mpsc::unbounded_channel();
    let (cancelled_tx, mut cancelled_rx) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let supervisor = TrackingSupervisor {
        started: started_tx,
        cancelled: cancelled_tx,
        release: release.clone(),
    };
    let control = ControlClient::from_config(fixture.config)?;
    let app = ClientApp::with_runtime(control, test_backoff(), Arc::new(supervisor));
    let mut status = app.subscribe();
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));

    registered_rx.recv().await.unwrap();
    wait_for_status(&mut status, |status| status.active().is_some()).await;
    for _ in 0..3 {
        time_guard.advance(Duration::from_millis(500)).await;
        business_tx.send(()).unwrap();
        assert_eq!(started_rx.recv().await.unwrap().0.get(), 1);
    }

    time_guard.advance(Duration::from_millis(500)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(status.borrow().active().is_some());
    for _ in 0..3 {
        assert_eq!(cancelled_rx.recv().await.unwrap().get(), 1);
    }

    shutdown.cancel();
    release.add_permits(3);
    wait_for_status(&mut status, |status| status.active().is_none()).await;
    stop_server.cancel();
    assert!(app_task.await?.is_ok());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn real_server_heartbeat_echo_keeps_one_generation_active() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let keys = tempfile::tempdir()?;
    generate_key_file(keys.path())?;
    let key = DeviceKeypair::load_private_file(&keys.path().join("device.key"))?;
    let server_app = ServerApp::bind(real_server_config(&pki, &key, 2)).await?;
    let server_addr = server_app.local_addr()?.to_string();
    let server_shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server_app.run_until(server_shutdown.clone()));

    let config = ClientConfig {
        client: ClientSection {
            name: "home-pc".to_owned(),
            identity_mode: None,
            server_addr,
            server_name: SERVER_NAME.to_owned(),
            certificate_authority_file: pki.ca_file.clone(),
            trust_mode: None,
            server_certificate_fingerprint: None,
            private_key_file: keys.path().join("device.key"),
            heartbeat_interval_secs: 1,
        },
        p2p: None,
        tunnels: Vec::new(),
        exports: Vec::new(),
        forwards: Vec::new(),
        telemetry: None,
    };
    let control = ControlClient::from_config(config)?;
    let app = ClientApp::with_runtime(
        control,
        test_backoff(),
        Arc::new(NoopChildSessionSupervisor),
    );
    let mut status = app.subscribe();
    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));
    tokio::time::timeout(
        Duration::from_secs(5),
        wait_for_status(&mut status, |status| status.active().is_some()),
    )
    .await?;

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(status.borrow().active().unwrap().generation().get(), 1);
    }

    shutdown.cancel();
    server_shutdown.cancel();
    assert!(app_task.await?.is_ok());
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn client_control_api_requests_grants_and_decodes_rendezvous_events() -> Result<(), AnyError>
{
    let pki = TestPki::generate()?;
    let keys = tempfile::tempdir()?;
    generate_key_file(keys.path())?;
    let key = DeviceKeypair::load_private_file(&keys.path().join("device.key"))?;
    let mut server_config = real_server_config(&pki, &key, 2);
    server_config.server.p2p_observation_bind = Some("127.0.0.1:0".to_owned());
    server_config.server.p2p_observation_alternate_bind = Some("127.0.0.1:0".to_owned());
    let server_app = ServerApp::bind(server_config).await?;
    let server_addr = server_app.local_addr()?.to_string();
    let server_shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server_app.run_until(server_shutdown.clone()));

    let config = ClientConfig {
        client: ClientSection {
            name: "home-pc".to_owned(),
            identity_mode: None,
            server_addr,
            server_name: SERVER_NAME.to_owned(),
            certificate_authority_file: pki.ca_file.clone(),
            trust_mode: None,
            server_certificate_fingerprint: None,
            private_key_file: keys.path().join("device.key"),
            heartbeat_interval_secs: 1,
        },
        p2p: None,
        tunnels: Vec::new(),
        exports: Vec::new(),
        forwards: Vec::new(),
        telemetry: None,
    };
    let mut session = ControlClient::from_config(config)?.connect().await?;
    assert_eq!(session.protocol_version(), ProtocolVersion::SUPPORTED);

    session.request_observation_grant().await?;
    let ControlEvent::ObservationGrant(grant) = session.next_control_event().await? else {
        return Err("client did not decode the observation grant event".into());
    };
    let _: ObservationGrant = grant;

    let mut request = RendezvousEnvelope {
        version: session.protocol_version(),
        session_id: SessionId::from([0x91; 32]),
        sender: BoundedString::try_from("home-pc")?,
        target: BoundedString::try_from("home-pc")?,
        step: 1,
        generation: CandidateGeneration::INITIAL,
        expires_unix_secs: u64::MAX,
        payload: RendezvousPayload::Request(RendezvousRequest {
            export: BoundedString::try_from("ssh")?,
        }),
        signature: BoundedBytes::try_from(Vec::new())?,
    };
    assert!(verify_peer_envelope(&key.public_key(), &request).is_err());
    request.signature = sign_peer_envelope(&key, &request)?;
    verify_peer_envelope(&key.public_key(), &request)?;
    session.send_rendezvous_envelope(&request).await?;
    let ControlEvent::ServerNotice(response) = session.next_control_event().await? else {
        return Err("client did not decode the distinct server notice event".into());
    };
    assert_eq!(response.session_id, *request.session_id.as_bytes());
    assert_eq!(
        response.code,
        rustgos::RendezvousErrorCode::SELF_TARGET.as_u16()
    );

    server_shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn managed_empty_snapshot_overrides_local_tunnels_before_registration() -> Result<(), AnyError>
{
    let pki = TestPki::generate()?;
    let tls = TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls.local_addr()?.to_string())?;
    let server = tokio::spawn(async move {
        let (socket, _) = tls.accept_tcp().await?;
        let mut server = FramedServer::new(tls.handshake(socket).await?);
        assert!(matches!(
            server.receive().await?.message,
            Message::ClientHello(_)
        ));
        let version = ProtocolVersion::V0_4;
        let challenge = Message::ServerChallenge(ServerChallenge {
            challenge: bytes(&[5; 32]),
            session_id: bytes(&[6; 32]),
        });
        server
            .stream
            .write_all(&server.codec.encode(version, 0, &challenge)?)
            .await?;
        assert!(matches!(
            server.receive().await?.message,
            Message::ClientAuthenticate(_)
        ));
        server
            .stream
            .write_all(&server.codec.encode(
                version,
                0,
                &Message::AuthResult(AuthResult {
                    accepted: true,
                    error: None,
                }),
            )?)
            .await?;
        assert!(matches!(
            server.receive().await?.message,
            Message::ManagedConfigRequest(_)
        ));
        let snapshot = Message::ManagedConfigSnapshot(rustgo_protocol::ManagedConfigSnapshot {
            revision: 7,
            configuration: Some(bytes(
                br#"{"tunnels":[],"exports":[],"forwards":[],"p2p_enabled":false}"#,
            )),
        });
        server
            .stream
            .write_all(&server.codec.encode(version, 0, &snapshot)?)
            .await?;
        let Message::RegisterTunnels(registration) = server.receive().await?.message else {
            panic!("expected registration")
        };
        assert!(registration.tunnels.as_slice().is_empty());
        server
            .stream
            .write_all(&server.codec.encode(
                version,
                0,
                &Message::TunnelResults(TunnelResults {
                    results: BoundedVec::try_from(vec![]).unwrap(),
                }),
            )?)
            .await?;
        Ok::<_, AnyError>(())
    });
    let session = ControlClient::from_config(fixture.config)?
        .connect()
        .await?;
    assert!(session.registered_tunnels().is_empty());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn managed_reconnect_applies_removal_and_reports_current_revision() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let tls = TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls.local_addr()?.to_string())?;
    let initial = rustgo_config::ManagedConfiguration::from_client(&fixture.config);
    let shutdown = CancellationToken::new();
    let app = ClientApp::from_config(fixture.config)?;
    let status = app.subscribe();
    let running = tokio::spawn(app.run_until(shutdown.clone()));
    for revision in 1..=2 {
        let (socket, _) = tls.accept_tcp().await?;
        let mut server = FramedServer::new(tls.handshake(socket).await?);
        let version = ProtocolVersion::V0_4;
        assert!(matches!(
            server.receive().await?.message,
            Message::ClientHello(_)
        ));
        let challenge = Message::ServerChallenge(ServerChallenge {
            challenge: bytes(&[8; 32]),
            session_id: bytes(&[9; 32]),
        });
        server
            .stream
            .write_all(&server.codec.encode(version, 0, &challenge)?)
            .await?;
        assert!(matches!(
            server.receive().await?.message,
            Message::ClientAuthenticate(_)
        ));
        server
            .stream
            .write_all(&server.codec.encode(
                version,
                0,
                &Message::AuthResult(AuthResult {
                    accepted: true,
                    error: None,
                }),
            )?)
            .await?;
        assert!(matches!(
            server.receive().await?.message,
            Message::ManagedConfigRequest(_)
        ));
        let mut desired = initial.clone();
        if revision == 2 {
            desired.tunnels.clear();
        }
        let snapshot = Message::ManagedConfigSnapshot(rustgo_protocol::ManagedConfigSnapshot {
            revision,
            configuration: Some(bytes(&serde_json::to_vec(&desired)?)),
        });
        server
            .stream
            .write_all(&server.codec.encode(version, 0, &snapshot)?)
            .await?;
        let Message::RegisterTunnels(registration) = server.receive().await?.message else {
            panic!("expected registration")
        };
        assert_eq!(registration.tunnels.as_slice().len(), desired.tunnels.len());
        let results = registration
            .tunnels
            .as_slice()
            .iter()
            .map(|t| TunnelResult {
                tunnel_id: t.tunnel_id,
                accepted: true,
                error: None,
            })
            .collect::<Vec<_>>();
        server
            .stream
            .write_all(&server.codec.encode(
                version,
                0,
                &Message::TunnelResults(TunnelResults {
                    results: BoundedVec::try_from(results).unwrap(),
                }),
            )?)
            .await?;
        loop {
            if let Message::ManagedConfigReport(report) = server.receive().await?.message {
                assert_eq!(report.revision, revision);
                let rows: Vec<serde_json::Value> =
                    serde_json::from_slice(report.results.as_slice())?;
                assert_eq!(rows.len(), desired.tunnels.len());
                assert!(rows.iter().all(|r| r["state"] == "ready"));
                assert_eq!(status.borrow().managed_revision(), Some(revision));
                assert_eq!(
                    status
                        .borrow()
                        .effective_configuration()
                        .unwrap()
                        .tunnels
                        .len(),
                    desired.tunnels.len()
                );
                break;
            }
        }
    }
    shutdown.cancel();
    running.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_real_server_reconnect_remaps_tcp_udp_and_removes_listeners() -> Result<(), AnyError>
{
    tokio::time::timeout(Duration::from_secs(25), async {
        let pki = TestPki::generate()?;
        let mut fixture = client_fixture(&pki, "127.0.0.1:1".into())?;
        let tcp_target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let udp_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let tcp_address = tcp_target.local_addr()?;
        let udp_address = udp_target.local_addr()?;
        let tcp_port = {
            let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
            socket.local_addr()?.port()
        };
        let udp_port = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            socket.local_addr()?.port()
        };
        fixture.config.tunnels[0].remote_port = u32::from(tcp_port);
        fixture.config.tunnels[1].remote_port = u32::from(udp_port);
        // Initial targets deliberately cannot serve data. Only the managed replacement can pass.
        fixture.config.tunnels[0].local_addr = "127.0.0.1:1".into();
        fixture.config.tunnels[1].local_addr = "127.0.0.1:1".into();
        let database = pki._directory.path().join("managed.db");
        let mut server_config = real_server_config(&pki, &fixture.verification_key, 5);
        server_config.managed_tunnels = Some(rustgo_config::ManagedTunnelsConfig {
            database_path: database.clone(),
        });
        let server = ServerApp::bind(server_config.clone()).await?;
        server_config.server.bind_addr = server.local_addr()?.to_string();
        fixture.config.client.server_addr = server_config.server.bind_addr.clone();
        let mut server_stop = CancellationToken::new();
        let mut server_task = tokio::spawn(server.run_until(server_stop.clone()));
        let app = ClientApp::from_config(fixture.config)?;
        let mut status = app.subscribe();
        let client_stop = CancellationToken::new();
        let client_task = tokio::spawn(app.run_until(client_stop.clone()));
        wait_for_status(&mut status, |s| {
            s.managed_revision() == Some(1) && s.active().is_some()
        })
        .await;
        let store = rustgos::managed::ManagedStore::open(&database)?;
        let mut desired = store.get("home-pc")?.unwrap().configuration;
        desired.tunnels[0].local_addr = tcp_address.to_string();
        desired.tunnels[1].local_addr = udp_address.to_string();
        store.replace("home-pc", 1, &desired)?;
        server_stop.cancel();
        server_task.await??;
        let server = ServerApp::bind(server_config.clone()).await?;
        server_stop = CancellationToken::new();
        server_task = tokio::spawn(server.run_until(server_stop.clone()));
        wait_for_status(&mut status, |s| {
            s.managed_revision() == Some(2) && s.active().is_some()
        })
        .await;
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await?;
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            stream.write_all(&bytes).await?;
            Ok::<_, std::io::Error>(())
        });
        let mut tcp = TcpStream::connect(("127.0.0.1", tcp_port)).await?;
        tcp.write_all(b"test").await?;
        let mut received = [0; 4];
        tcp.read_exact(&mut received).await?;
        assert_eq!(&received, b"test");
        drop(tcp);
        tcp_echo.await??;
        let udp_echo = tokio::spawn(async move {
            let mut bytes = [0; 32];
            let (length, peer) = udp_target.recv_from(&mut bytes).await?;
            udp_target.send_to(&bytes[..length], peer).await?;
            Ok::<_, std::io::Error>(())
        });
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        udp.send_to(b"test", ("127.0.0.1", udp_port)).await?;
        let mut received = [0; 32];
        let (length, _) = udp.recv_from(&mut received).await?;
        assert_eq!(&received[..length], b"test");
        udp_echo.await??;
        desired.tunnels.clear();
        store.replace("home-pc", 2, &desired)?;
        server_stop.cancel();
        server_task.await??;
        let server = ServerApp::bind(server_config).await?;
        server_stop = CancellationToken::new();
        server_task = tokio::spawn(server.run_until(server_stop.clone()));
        wait_for_status(&mut status, |s| {
            s.managed_revision() == Some(3) && s.active().is_some()
        })
        .await;
        assert!(
            status
                .borrow()
                .active()
                .unwrap()
                .registered_tunnels()
                .is_empty()
        );
        let _released_tcp = tokio::net::TcpListener::bind(("127.0.0.1", tcp_port)).await?;
        let _released_udp = tokio::net::UdpSocket::bind(("127.0.0.1", udp_port)).await?;
        client_stop.cancel();
        server_stop.cancel();
        client_task.await??;
        server_task.await??;
        Ok::<_, AnyError>(())
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_p2p_rebuilds_exports_and_forwards_reports_bind_failure_and_releases_ports()
-> Result<(), AnyError> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let pki = TestPki::generate()?;
        let mut provider = client_fixture(&pki, "127.0.0.1:1".into())?;
        let mut consumer = client_fixture(&pki, "127.0.0.1:1".into())?;
        provider.config.client.name = "provider".into();
        consumer.config.client.name = "consumer".into();
        for config in [&mut provider.config, &mut consumer.config] {
            config.tunnels.clear();
            config.p2p = Some(rustgo_config::P2pConfig {
                enabled: true,
                prefer_direct: false,
                direct_timeout_secs: 1,
                reconnect_timeout_secs: 5,
                allow_relay_fallback: true,
                udp_port_range: rustgo_config::PortRange {
                    start: 40000,
                    end: 40010,
                },
                tcp_port_range: rustgo_config::PortRange {
                    start: 40100,
                    end: 40110,
                },
                observation_primary_addr: None,
                observation_alternate_addr: None,
            });
        }
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let echo_address = echo.local_addr()?.to_string();
        let listen = {
            let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
            socket.local_addr()?.to_string()
        };
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        provider.config.exports = vec![rustgo_config::ExportConfig {
            name: "echo".into(),
            protocol: ConfigProtocol::Tcp,
            local_addr: echo_address,
            allowed_peers: vec!["consumer".into()],
        }];
        consumer.config.forwards = vec![
            rustgo_config::ForwardConfig {
                name: "good".into(),
                peer: "provider".into(),
                export: "echo".into(),
                listen_addr: listen.clone(),
            },
            rustgo_config::ForwardConfig {
                name: "busy".into(),
                peer: "provider".into(),
                export: "echo".into(),
                listen_addr: occupied.local_addr()?.to_string(),
            },
        ];
        let database = pki._directory.path().join("managed-p2p.db");
        let mut config = real_server_config(&pki, &provider.verification_key, 5);
        config.clients = vec![
            AuthorizedClient {
                name: "provider".into(),
                public_key: provider.verification_key.public_key().to_string(),
                enabled: true,
            },
            AuthorizedClient {
                name: "consumer".into(),
                public_key: consumer.verification_key.public_key().to_string(),
                enabled: true,
            },
        ];
        config.managed_tunnels = Some(rustgo_config::ManagedTunnelsConfig {
            database_path: database.clone(),
        });
        let server = ServerApp::bind(config.clone()).await?;
        config.server.bind_addr = server.local_addr()?.to_string();
        provider.config.client.server_addr = config.server.bind_addr.clone();
        consumer.config.client.server_addr = config.server.bind_addr.clone();
        let mut server_stop = CancellationToken::new();
        let mut server_task = tokio::spawn(server.run_until(server_stop.clone()));
        let provider_app = ClientApp::from_config(provider.config)?;

        let provider_stop = CancellationToken::new();

        let consumer_stop = CancellationToken::new();
        let consumer_task =
            tokio::spawn(ClientApp::from_config(consumer.config)?.run_until(consumer_stop.clone()));
        let store = rustgos::managed::ManagedStore::open(&database)?;
        loop {
            if let Some(snapshot) = store.get("consumer")?
                && snapshot.applied_revision == Some(1)
            {
                assert!(
                    snapshot
                        .results
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|r| r["state"] == "pending")
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let provider_task = tokio::spawn(provider_app.run_until(provider_stop.clone()));
        for revision in 1..=3 {
            loop {
                if store.get("consumer")?.is_some_and(|s| {
                    s.applied_revision == Some(revision)
                        && !s
                            .results
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|r| r["state"] == "pending")
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let snapshot = store.get("consumer")?.unwrap();
            eprintln!("revision {revision}: {}", snapshot.results);
            if revision == 1 {
                let results = snapshot.results.as_array().unwrap();
                assert!(
                    results
                        .iter()
                        .any(|r| r["name"] == "good" && r["state"] == "ready")
                );
                assert!(results.iter().any(|r| r["name"] == "busy"
                    && r["state"] == "failed"
                    && r["error"].as_str().unwrap().contains("bind")));
            }
            if revision < 3 {
                let mut client = TcpStream::connect(&listen).await?;
                client.write_all(b"ping").await?;
                let (mut target, _) = echo.accept().await?;
                let mut bytes = [0; 4];
                target.read_exact(&mut bytes).await?;
                target.write_all(&bytes).await?;
                client.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"ping");
                let mut forwards = snapshot.configuration;
                let mut exports = store.get("provider")?.unwrap().configuration;
                if revision == 1 {
                    forwards.forwards.truncate(1);
                    forwards.forwards[0].export = "new-echo".into();
                    exports.exports[0].name = "new-echo".into();
                } else {
                    forwards.forwards.clear();
                    exports.exports.clear();
                }
                store.replace("consumer", revision, &forwards)?;
                store.replace("provider", revision, &exports)?;
                server_stop.cancel();
                server_task.await??;
                let server = ServerApp::bind(config.clone()).await?;
                server_stop = CancellationToken::new();
                server_task = tokio::spawn(server.run_until(server_stop.clone()));
            } else {
                assert!(snapshot.results.as_array().unwrap().is_empty());
            }
        }
        let _released = tokio::net::TcpListener::bind(&listen).await?;
        consumer_stop.cancel();
        provider_stop.cancel();
        server_stop.cancel();
        consumer_task.await??;
        provider_task.await??;
        server_task.await??;
        Ok::<_, AnyError>(())
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabling_management_drains_unmanaged_forward_before_empty_snapshot() -> Result<(), AnyError>
{
    tokio::time::timeout(Duration::from_secs(20), async {
        let pki = TestPki::generate()?;
        let mut provider = client_fixture(&pki, "127.0.0.1:1".into())?;
        let mut consumer = client_fixture(&pki, "127.0.0.1:1".into())?;
        provider.config.client.name = "provider".into();
        consumer.config.client.name = "consumer".into();
        for config in [&mut provider.config, &mut consumer.config] {
            config.tunnels.clear();
            config.p2p = Some(rustgo_config::P2pConfig {
                enabled: true,
                prefer_direct: false,
                direct_timeout_secs: 1,
                reconnect_timeout_secs: 5,
                allow_relay_fallback: true,
                udp_port_range: rustgo_config::PortRange {
                    start: 40000,
                    end: 40010,
                },
                tcp_port_range: rustgo_config::PortRange {
                    start: 40100,
                    end: 40110,
                },
                observation_primary_addr: None,
                observation_alternate_addr: None,
            });
        }
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let echo_address = echo.local_addr()?.to_string();
        let listen = {
            let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
            socket.local_addr()?.to_string()
        };
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        provider.config.exports = vec![rustgo_config::ExportConfig {
            name: "echo".into(),
            protocol: ConfigProtocol::Tcp,
            local_addr: echo_address,
            allowed_peers: vec!["consumer".into()],
        }];
        consumer.config.forwards = vec![
            rustgo_config::ForwardConfig {
                name: "good".into(),
                peer: "provider".into(),
                export: "echo".into(),
                listen_addr: listen.clone(),
            },
            rustgo_config::ForwardConfig {
                name: "busy".into(),
                peer: "provider".into(),
                export: "echo".into(),
                listen_addr: occupied.local_addr()?.to_string(),
            },
        ];
        let database = pki._directory.path().join("managed-p2p.db");
        let mut config = real_server_config(&pki, &provider.verification_key, 5);
        config.clients = vec![
            AuthorizedClient {
                name: "provider".into(),
                public_key: provider.verification_key.public_key().to_string(),
                enabled: true,
            },
            AuthorizedClient {
                name: "consumer".into(),
                public_key: consumer.verification_key.public_key().to_string(),
                enabled: true,
            },
        ];

        consumer.config.forwards.truncate(1);
        let consumer_identity = format!(
            "static:{}",
            consumer.verification_key.public_key().fingerprint()
        );
        let mut empty = rustgo_config::ManagedConfiguration::from_client(&consumer.config);
        empty.forwards.clear();
        let store = rustgos::managed::ManagedStore::open(&database)?;
        store.sync(&consumer_identity, "consumer", &empty)?;
        let server = ServerApp::bind(config.clone()).await?;
        config.server.bind_addr = server.local_addr()?.to_string();
        provider.config.client.server_addr = config.server.bind_addr.clone();
        consumer.config.client.server_addr = config.server.bind_addr.clone();
        let mut server_stop = CancellationToken::new();
        let mut server_task = tokio::spawn(server.run_until(server_stop.clone()));
        let provider_stop = CancellationToken::new();
        let provider_app = ClientApp::from_config(provider.config)?;
        let mut provider_status = provider_app.subscribe();
        let provider_task = tokio::spawn(provider_app.run_until(provider_stop.clone()));
        wait_for_status(&mut provider_status, |s| s.active().is_some()).await;
        let consumer_stop = CancellationToken::new();
        let consumer_app = ClientApp::from_config(consumer.config)?;
        let mut consumer_status = consumer_app.subscribe();
        let consumer_task = tokio::spawn(consumer_app.run_until(consumer_stop.clone()));
        let mut client = loop {
            if let Ok(stream) = TcpStream::connect(&listen).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        client.write_all(b"ping").await?;
        let (mut target, _) = echo.accept().await?;
        let mut bytes = [0; 4];
        target.read_exact(&mut bytes).await?;
        target.write_all(&bytes).await?;
        client.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"ping");
        assert_eq!(consumer_status.borrow().managed_revision(), None);
        drop(client);
        drop(target);
        config.managed_tunnels = Some(rustgo_config::ManagedTunnelsConfig {
            database_path: database,
        });
        server_stop.cancel();
        server_task.await??;
        let server = ServerApp::bind(config).await?;
        server_stop = CancellationToken::new();
        server_task = tokio::spawn(server.run_until(server_stop.clone()));
        wait_for_status(&mut consumer_status, |s| {
            s.active().is_some() && s.managed_revision() == Some(1)
        })
        .await;
        let _released = tokio::net::TcpListener::bind(&listen).await?;
        consumer_stop.cancel();
        provider_stop.cancel();
        server_stop.cancel();
        consumer_task.await??;
        provider_task.await??;
        server_task.await??;
        Ok::<_, AnyError>(())
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_only_protocol_change_rebinds_consumer_without_reconnect() -> Result<(), AnyError>
{
    tokio::time::timeout(Duration::from_secs(20), async {
        let pki = TestPki::generate()?;
        let mut provider = client_fixture(&pki, "127.0.0.1:1".into())?;
        let mut consumer = client_fixture(&pki, "127.0.0.1:1".into())?;
        provider.config.client.name = "provider".into();
        consumer.config.client.name = "consumer".into();
        for config in [&mut provider.config, &mut consumer.config] {
            config.tunnels.clear();
            config.p2p = Some(rustgo_config::P2pConfig {
                enabled: true,
                prefer_direct: false,
                direct_timeout_secs: 1,
                reconnect_timeout_secs: 5,
                allow_relay_fallback: true,
                udp_port_range: rustgo_config::PortRange {
                    start: 40000,
                    end: 40010,
                },
                tcp_port_range: rustgo_config::PortRange {
                    start: 40100,
                    end: 40110,
                },
                observation_primary_addr: None,
                observation_alternate_addr: None,
            });
        }
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let echo_address = echo.local_addr()?.to_string();
        let listen = {
            let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
            socket.local_addr()?.to_string()
        };
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        provider.config.exports = vec![rustgo_config::ExportConfig {
            name: "echo".into(),
            protocol: ConfigProtocol::Tcp,
            local_addr: echo_address,
            allowed_peers: vec!["consumer".into()],
        }];
        consumer.config.forwards = vec![
            rustgo_config::ForwardConfig {
                name: "good".into(),
                peer: "provider".into(),
                export: "echo".into(),
                listen_addr: listen.clone(),
            },
            rustgo_config::ForwardConfig {
                name: "busy".into(),
                peer: "provider".into(),
                export: "echo".into(),
                listen_addr: occupied.local_addr()?.to_string(),
            },
        ];
        let database = pki._directory.path().join("managed-p2p.db");
        let mut config = real_server_config(&pki, &provider.verification_key, 5);
        config.clients = vec![
            AuthorizedClient {
                name: "provider".into(),
                public_key: provider.verification_key.public_key().to_string(),
                enabled: true,
            },
            AuthorizedClient {
                name: "consumer".into(),
                public_key: consumer.verification_key.public_key().to_string(),
                enabled: true,
            },
        ];

        consumer.config.forwards.truncate(1);
        config.managed_tunnels = Some(rustgo_config::ManagedTunnelsConfig {
            database_path: database.clone(),
        });
        let server = ServerApp::bind(config).await?;
        provider.config.client.server_addr = server.local_addr()?.to_string();
        consumer.config.client.server_addr = server.local_addr()?.to_string();
        let server_stop = CancellationToken::new();
        let server_task = tokio::spawn(server.run_until(server_stop.clone()));
        let provider_config = provider.config.clone();
        let mut provider_stop = CancellationToken::new();
        let mut provider_task =
            tokio::spawn(ClientApp::from_config(provider.config)?.run_until(provider_stop.clone()));
        let consumer_stop = CancellationToken::new();
        let consumer_app = ClientApp::from_config(consumer.config)?;
        let consumer_status = consumer_app.subscribe();
        let consumer_task = tokio::spawn(consumer_app.run_until(consumer_stop.clone()));
        let store = rustgos::managed::ManagedStore::open(&database)?;
        loop {
            if store.get("consumer")?.is_some_and(|s| {
                s.results
                    .as_array()
                    .is_some_and(|r| r.iter().any(|r| r["state"] == "ready"))
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut client = TcpStream::connect(&listen).await?;
        client.write_all(b"ping").await?;
        let (mut target, _) = echo.accept().await?;
        let mut bytes = [0; 4];
        target.read_exact(&mut bytes).await?;
        target.write_all(&bytes).await?;
        client.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"ping");
        drop(client);
        drop(target);
        let generation = consumer_status.borrow().active().unwrap().generation();
        let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let mut desired = store.get("provider")?.unwrap().configuration;
        desired.exports[0].protocol = ConfigProtocol::Udp;
        desired.exports[0].local_addr = udp_echo.local_addr()?.to_string();
        store.replace("provider", 1, &desired)?;
        provider_stop.cancel();
        provider_task.await??;
        provider_stop = CancellationToken::new();
        provider_task = tokio::spawn(
            ClientApp::from_config(provider_config.clone())?.run_until(provider_stop.clone()),
        );
        loop {
            match tokio::net::UdpSocket::bind(&listen).await {
                Ok(probe) => {
                    drop(probe);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => break,
                Err(error) => return Err(error.into()),
            }
        }
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        loop {
            udp.send_to(b"pong", &listen).await?;
            let mut bytes = [0; 32];
            if let Ok(Ok((length, peer))) =
                tokio::time::timeout(Duration::from_millis(200), udp_echo.recv_from(&mut bytes))
                    .await
            {
                udp_echo.send_to(&bytes[..length], peer).await?;
                break;
            }
        }
        let mut bytes = [0; 32];
        let (length, _) = udp.recv_from(&mut bytes).await?;
        assert_eq!(&bytes[..length], b"pong");
        assert_eq!(
            consumer_status.borrow().active().unwrap().generation(),
            generation
        );
        assert_eq!(consumer_status.borrow().managed_revision(), Some(1));
        desired.exports.clear();
        store.replace("provider", 2, &desired)?;
        provider_stop.cancel();
        provider_task.await??;
        provider_stop = CancellationToken::new();
        provider_task =
            tokio::spawn(ClientApp::from_config(provider_config)?.run_until(provider_stop.clone()));
        loop {
            if store
                .get("consumer")?
                .unwrap()
                .results
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["state"] == "pending")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let _released = tokio::net::UdpSocket::bind(&listen).await?;
        consumer_stop.cancel();
        provider_stop.cancel();
        server_stop.cancel();
        consumer_task.await??;
        provider_task.await??;
        server_task.await??;
        Ok::<_, AnyError>(())
    })
    .await?
}

#[tokio::test]
async fn rejected_managed_local_policy_reports_failure_before_registration() -> Result<(), AnyError>
{
    let pki = TestPki::generate()?;
    let tls = TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
    let fixture = client_fixture(&pki, tls.local_addr()?.to_string())?;
    let server = tokio::spawn(async move {
        let (socket, _) = tls.accept_tcp().await?;
        let mut server = FramedServer::new(tls.handshake(socket).await?);
        assert!(matches!(
            server.receive().await?.message,
            Message::ClientHello(_)
        ));
        let version = ProtocolVersion::V0_4;
        let challenge = Message::ServerChallenge(ServerChallenge {
            challenge: bytes(&[5; 32]),
            session_id: bytes(&[6; 32]),
        });
        server
            .stream
            .write_all(&server.codec.encode(version, 0, &challenge)?)
            .await?;
        assert!(matches!(
            server.receive().await?.message,
            Message::ClientAuthenticate(_)
        ));
        server
            .stream
            .write_all(&server.codec.encode(
                version,
                0,
                &Message::AuthResult(AuthResult {
                    accepted: true,
                    error: None,
                }),
            )?)
            .await?;
        assert!(matches!(
            server.receive().await?.message,
            Message::ManagedConfigRequest(_)
        ));
        let snapshot = Message::ManagedConfigSnapshot(rustgo_protocol::ManagedConfigSnapshot {
            revision: 7,
            configuration: Some(bytes(
                br#"{"tunnels":[],"exports":[{"name":"blocked","protocol":"tcp","local_addr":"127.0.0.1:22","allowed_peers":[]}],"forwards":[],"p2p_enabled":true}"#,
            )),
        });
        server
            .stream
            .write_all(&server.codec.encode(version, 0, &snapshot)?)
            .await?;
        let Message::ManagedConfigReport(report) = server.receive().await?.message else {
            panic!("expected failed report before registration");
        };
        assert_eq!(report.revision, 7);
        let rows: Vec<serde_json::Value> = serde_json::from_slice(report.results.as_slice())?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["kind"], "export");
        assert_eq!(rows[0]["name"], "blocked");
        assert_eq!(rows[0]["state"], "failed");
        assert!(!rows[0]["error"].as_str().unwrap().is_empty());
        Ok::<_, AnyError>(())
    });
    assert!(matches!(
        ControlClient::from_config(fixture.config)?.connect().await,
        Err(ClientError::InvalidConfiguration)
    ));
    server.await??;
    Ok(())
}

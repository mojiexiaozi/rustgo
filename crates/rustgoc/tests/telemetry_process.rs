#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
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
use rustgo_config::{ClientConfig, ClientSection, TelemetryConfig};
use rustgo_crypto::generate_key_file;
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedVec, Frame, FrameCodec, Heartbeat, Message, ProtocolVersion,
    ServerChallenge, TelemetryReport, TunnelResults,
};
use rustgo_transport::TlsServer;
use rustgoc::{ClientApp, TelemetryControlWriteGate, TelemetryRuntimeHook};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
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
    if !matches!(server.receive().await?.message, Message::RegisterTunnels(_)) {
        return Err("third message was not RegisterTunnels".into());
    }
    server
        .send(Message::TunnelResults(TunnelResults {
            results: BoundedVec::try_from(Vec::new()).unwrap(),
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
    assert_no_telemetry(ProtocolVersion::V0_2, Some(enabled_telemetry())).await?;
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
    let shutdown = CancellationToken::new();
    let app_task =
        tokio::spawn(ClientApp::from_config(fixture.config)?.run_until(shutdown.clone()));
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

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), app_task)
        .await
        .expect("cancellation must join all client tasks")??;
    Ok(())
}

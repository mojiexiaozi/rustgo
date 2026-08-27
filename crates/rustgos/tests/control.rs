use std::{error::Error, fs, path::PathBuf, time::Duration};

use bytes::BytesMut;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_config::{AuthorizedClient, Limits, ServerConfig, ServerSection};
use rustgo_crypto::{AuthTranscript, DeviceKeypair, sign_auth};
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, BoundedVec, ClientAuthenticate, ClientHello, Frame,
    FrameCodec, Heartbeat, Message, ProtocolErrorCode, ProtocolVersion, RegisterTunnels,
    ServerChallenge, TunnelProtocol, TunnelRegistration, TunnelResults,
};
use rustgo_transport::{TlsClient, TlsError};
use rustgos::{ServerApp, ServerRuntimeLimits};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

const SERVER_NAME: &str = "tunnel.example.test";
const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const FRAME_MAX: usize = 70 * 1024;

struct TestPki {
    _directory: TempDir,
    ca_file: PathBuf,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl TestPki {
    fn generate() -> Result<Self, Box<dyn Error>> {
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

fn certificate_authority() -> Result<(String, Issuer<'static, KeyPair>), Box<dyn Error>> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Rustgo control test CA");
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    let certificate = parameters.self_signed(&key)?;
    Ok((certificate.pem(), Issuer::new(parameters, key)))
}

fn server_certificate(
    issuer: &Issuer<'static, KeyPair>,
) -> Result<(String, String), Box<dyn Error>> {
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

fn server_config(pki: &TestPki, clients: Vec<AuthorizedClient>) -> ServerConfig {
    ServerConfig {
        server: ServerSection {
            bind_addr: "127.0.0.1:0".to_owned(),
            certificate_file: pki.certificate_file.clone(),
            private_key_file: pki.private_key_file.clone(),
            heartbeat_timeout_secs: 2,
        },
        limits: Limits {
            max_clients: 8,
            max_tunnels_per_client: 8,
            max_tcp_connections_per_tunnel: 8,
            max_udp_sessions_per_tunnel: 8,
            max_udp_payload_bytes: 65_507,
        },
        clients,
    }
}

fn authorized(name: &str, key: &DeviceKeypair, enabled: bool) -> AuthorizedClient {
    AuthorizedClient {
        name: name.to_owned(),
        public_key: key.public_key().to_string(),
        enabled,
    }
}

fn text<const MAX: usize>(value: &str) -> BoundedString<MAX> {
    BoundedString::try_from(value).unwrap()
}

fn bytes<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(value).unwrap()
}

fn wire_fingerprint(key: &DeviceKeypair) -> Vec<u8> {
    key.public_key()
        .fingerprint()
        .to_string()
        .strip_prefix("sha256:")
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn transcript_version(version: ProtocolVersion) -> u16 {
    assert!(version.major <= u8::MAX.into() && version.minor <= u8::MAX.into());
    (version.major << 8) | version.minor
}

struct FramedClient {
    stream: TlsStream<TcpStream>,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl FramedClient {
    async fn connect(pki: &TestPki, address: std::net::SocketAddr) -> Result<Self, TlsError> {
        let tls = TlsClient::from_ca_file(&pki.ca_file, SERVER_NAME)?;
        let stream = tls.connect(address).await?;
        Ok(Self {
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(FRAME_MAX),
        })
    }

    async fn connect_from(
        pki: &TestPki,
        address: std::net::SocketAddr,
        source: std::net::Ipv4Addr,
    ) -> Result<Self, Box<dyn Error>> {
        let socket = TcpSocket::new_v4()?;
        socket.bind((source, 0).into())?;
        let socket = socket.connect(address).await?;
        let tls = TlsClient::from_ca_file(&pki.ca_file, SERVER_NAME)?;
        let stream = tls.handshake(socket).await?;
        Ok(Self {
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(FRAME_MAX),
        })
    }

    async fn send(
        &mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        let encoded = self.codec.encode(version, 0, &message)?;
        self.stream.write_all(&encoded).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Frame, Box<dyn Error>> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.read_buffer)? {
                return Ok(frame);
            }
            if self.stream.read_buf(&mut self.read_buffer).await? == 0 {
                return Err("control connection closed".into());
            }
        }
    }

    async fn abort_after_response(
        mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        self.send(version, message).await?;
        let response = self.receive().await?;
        if response.message != Message::AuthResult(rejected_authentication()) {
            return Err("server did not reject authentication before abort".into());
        }
        self.stream.get_ref().0.set_zero_linger()?;
        drop(self);
        Ok(())
    }
}

#[derive(Clone)]
struct AuthenticationChallenge {
    challenge: Vec<u8>,
    session_id: Vec<u8>,
}

async fn begin_authentication(
    client: &mut FramedClient,
    version: ProtocolVersion,
    name: &str,
    fingerprint_key: &DeviceKeypair,
) -> Result<AuthenticationChallenge, Box<dyn Error>> {
    client
        .send(
            version,
            Message::ClientHello(ClientHello {
                client_name: text(name),
                fingerprint: bytes(&wire_fingerprint(fingerprint_key)),
                heartbeat_interval_secs: 1,
            }),
        )
        .await?;
    let Frame {
        message:
            Message::ServerChallenge(ServerChallenge {
                challenge,
                session_id,
            }),
        ..
    } = client.receive().await?
    else {
        return Err("server did not send a challenge".into());
    };
    Ok(AuthenticationChallenge {
        challenge: challenge.into_vec(),
        session_id: session_id.into_vec(),
    })
}

fn authentication_message(
    challenge: &AuthenticationChallenge,
    public_key: &DeviceKeypair,
    signing_key: &DeviceKeypair,
    transcript_version_value: ProtocolVersion,
    transcript_name: &str,
) -> Message {
    let transcript = AuthTranscript::new(
        challenge.challenge.clone(),
        challenge.session_id.clone(),
        transcript_version(transcript_version_value),
        transcript_name.to_owned(),
    );
    Message::ClientAuthenticate(ClientAuthenticate {
        public_key: bytes(public_key.public_key().to_string().as_bytes()),
        signature: bytes(&sign_auth(signing_key, &transcript)),
    })
}

async fn finish_authentication(
    client: &mut FramedClient,
    version: ProtocolVersion,
    authentication: Message,
) -> Result<AuthResult, Box<dyn Error>> {
    client.send(version, authentication).await?;
    let Frame {
        message: Message::AuthResult(result),
        ..
    } = client.receive().await?
    else {
        return Err("server did not send an authentication result".into());
    };
    Ok(result)
}

async fn authenticate(
    client: &mut FramedClient,
    name: &str,
    key: &DeviceKeypair,
) -> Result<AuthResult, Box<dyn Error>> {
    let challenge = begin_authentication(client, VERSION, name, key).await?;
    finish_authentication(
        client,
        VERSION,
        authentication_message(&challenge, key, key, VERSION, name),
    )
    .await
}

fn rejected_authentication() -> AuthResult {
    AuthResult {
        accepted: false,
        error: Some(ProtocolErrorCode::AUTHENTICATION_FAILED),
    }
}

fn tcp_tunnel(tunnel_id: u32, name: &str, remote_port: u16) -> TunnelRegistration {
    TunnelRegistration {
        tunnel_id,
        name: text(name),
        protocol: TunnelProtocol::TCP,
        remote_port,
    }
}

async fn register_tunnels(
    client: &mut FramedClient,
    tunnels: Vec<TunnelRegistration>,
) -> Result<TunnelResults, Box<dyn Error>> {
    client
        .send(
            VERSION,
            Message::RegisterTunnels(RegisterTunnels {
                tunnels: BoundedVec::try_from(tunnels).unwrap(),
            }),
        )
        .await?;
    let Frame {
        message: Message::TunnelResults(results),
        ..
    } = client.receive().await?
    else {
        return Err("server did not send tunnel results".into());
    };
    Ok(results)
}

fn unused_tcp_port() -> Result<u16, Box<dyn Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_for_active_count(
    registry: &rustgos::ClientRegistry,
    expected: usize,
) -> Result<(), Box<dyn Error>> {
    timeout(Duration::from_secs(3), async {
        loop {
            if registry.active_count() == expected {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn valid_authentication_uses_tls_frames_and_accepts_heartbeats() -> Result<(), Box<dyn Error>>
{
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([7; 32]);
    let app = ServerApp::bind(server_config(&pki, vec![authorized("home-pc", &key, true)])).await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut client = FramedClient::connect(&pki, address).await?;
    assert_eq!(
        authenticate(&mut client, "home-pc", &key).await?,
        AuthResult {
            accepted: true,
            error: None,
        }
    );
    client
        .send(
            VERSION,
            Message::RegisterTunnels(RegisterTunnels {
                tunnels: BoundedVec::try_from(Vec::new()).unwrap(),
            }),
        )
        .await?;
    let Frame {
        message: Message::TunnelResults(results),
        ..
    } = client.receive().await?
    else {
        return Err("server did not send tunnel results".into());
    };
    assert!(results.results.as_slice().is_empty());
    client
        .send(VERSION, Message::Heartbeat(Heartbeat { sequence: 1 }))
        .await?;

    drop(client);
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn unknown_mismatched_and_disabled_clients_share_one_public_rejection()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let home = DeviceKeypair::from_secret_bytes([7; 32]);
    let unknown = DeviceKeypair::from_secret_bytes([8; 32]);
    let disabled = DeviceKeypair::from_secret_bytes([9; 32]);
    let laptop = DeviceKeypair::from_secret_bytes([10; 32]);
    let app = ServerApp::bind(server_config(
        &pki,
        vec![
            authorized("home-pc", &home, true),
            authorized("disabled-pc", &disabled, false),
            authorized("laptop", &laptop, true),
        ],
    ))
    .await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    for (name, key) in [
        ("unknown-pc", &unknown),
        ("home-pc", &laptop),
        ("disabled-pc", &disabled),
    ] {
        let mut client = FramedClient::connect(&pki, address).await?;
        assert_eq!(
            authenticate(&mut client, name, key).await?,
            rejected_authentication()
        );
    }

    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn modified_and_replayed_transcripts_are_rejected() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([11; 32]);
    let app = ServerApp::bind(server_config(&pki, vec![authorized("home-pc", &key, true)])).await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut modified = FramedClient::connect(&pki, address).await?;
    let challenge = begin_authentication(&mut modified, VERSION, "home-pc", &key).await?;
    assert_eq!(
        finish_authentication(
            &mut modified,
            VERSION,
            authentication_message(&challenge, &key, &key, VERSION, "other-name"),
        )
        .await?,
        rejected_authentication()
    );

    let changed_version = ProtocolVersion::new(1, 1);
    let mut version_modified = FramedClient::connect(&pki, address).await?;
    let challenge = begin_authentication(&mut version_modified, VERSION, "home-pc", &key).await?;
    assert_eq!(
        finish_authentication(
            &mut version_modified,
            changed_version,
            authentication_message(&challenge, &key, &key, changed_version, "home-pc",),
        )
        .await?,
        rejected_authentication()
    );

    let mut original = FramedClient::connect(&pki, address).await?;
    let original_challenge = begin_authentication(&mut original, VERSION, "home-pc", &key).await?;
    let replay = authentication_message(&original_challenge, &key, &key, VERSION, "home-pc");
    drop(original);

    let mut replayed = FramedClient::connect(&pki, address).await?;
    let fresh_challenge = begin_authentication(&mut replayed, VERSION, "home-pc", &key).await?;
    assert_ne!(fresh_challenge.challenge, original_challenge.challenge);
    assert_ne!(fresh_challenge.session_id, original_challenge.session_id);
    assert_eq!(
        finish_authentication(&mut replayed, VERSION, replay).await?,
        rejected_authentication()
    );

    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn protocol_major_mismatch_is_rejected_before_authentication() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([12; 32]);
    let app = ServerApp::bind(server_config(&pki, vec![authorized("home-pc", &key, true)])).await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut client = FramedClient::connect(&pki, address).await?;
    client
        .send(
            ProtocolVersion::new(2, 0),
            Message::ClientHello(ClientHello {
                client_name: text("home-pc"),
                fingerprint: bytes(&wire_fingerprint(&key)),
                heartbeat_interval_secs: 1,
            }),
        )
        .await?;
    let Frame {
        message: Message::Error(error),
        ..
    } = client.receive().await?
    else {
        return Err("server did not send a protocol error".into());
    };
    assert_eq!(error.code, ProtocolErrorCode::UNSUPPORTED_VERSION);

    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn heartbeat_interval_must_be_strictly_below_server_timeout_before_challenge()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([24; 32]);
    let mut config = server_config(&pki, vec![authorized("home-pc", &key, true)]);
    config.server.heartbeat_timeout_secs = 20;
    let app = ServerApp::bind(config).await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    for interval in [0, 20, 21] {
        let mut client = FramedClient::connect(&pki, address).await?;
        client
            .send(
                VERSION,
                Message::ClientHello(ClientHello {
                    client_name: text("home-pc"),
                    fingerprint: bytes(&wire_fingerprint(&key)),
                    heartbeat_interval_secs: interval,
                }),
            )
            .await?;
        let Frame {
            message: Message::Error(error),
            ..
        } = client.receive().await?
        else {
            return Err("server did not return a heartbeat compatibility error".into());
        };
        assert_eq!(error.code, ProtocolErrorCode::INCOMPATIBLE_HEARTBEAT);
    }

    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn handshake_timeout_releases_the_bounded_unauthenticated_permit()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([13; 32]);
    let runtime_limits = ServerRuntimeLimits {
        handshake_timeout: Duration::from_millis(120),
        max_unauthenticated_connections: 2,
        max_unauthenticated_connections_per_peer: 1,
        ..ServerRuntimeLimits::default()
    };
    let app = ServerApp::bind_with_runtime_limits(
        server_config(&pki, vec![authorized("home-pc", &key, true)]),
        runtime_limits,
    )
    .await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let stalled_plaintext = TcpStream::connect(address).await?;
    sleep(Duration::from_millis(25)).await;
    let tls = TlsClient::from_ca_file(&pki.ca_file, SERVER_NAME)?;
    let while_full = timeout(Duration::from_secs(1), tls.connect(address)).await?;
    assert!(while_full.is_err());

    sleep(Duration::from_millis(150)).await;
    let mut recovered = FramedClient::connect(&pki, address).await?;
    assert_eq!(
        authenticate(&mut recovered, "home-pc", &key).await?,
        AuthResult {
            accepted: true,
            error: None,
        }
    );

    drop(stalled_plaintext);
    drop(recovered);
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn tls_aborts_malformed_inputs_and_timeout_do_not_consume_auth_failures()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([22; 32]);
    let runtime_limits = ServerRuntimeLimits {
        handshake_timeout: Duration::from_millis(80),
        max_failed_auth_attempts_per_peer: 1,
        ..ServerRuntimeLimits::default()
    };
    let app = ServerApp::bind_with_runtime_limits(
        server_config(&pki, vec![authorized("home-pc", &key, true)]),
        runtime_limits,
    )
    .await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    for _ in 0..4 {
        drop(TcpStream::connect(address).await?);
    }
    for _ in 0..3 {
        let mut malformed = TcpStream::connect(address).await?;
        malformed.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
        drop(malformed);
    }
    let stalled = TcpStream::connect(address).await?;
    sleep(Duration::from_millis(120)).await;
    drop(stalled);

    let mut client = FramedClient::connect(&pki, address).await?;
    assert_eq!(
        authenticate(&mut client, "home-pc", &key).await?,
        AuthResult {
            accepted: true,
            error: None,
        }
    );

    drop(client);
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn one_slow_peer_cannot_consume_the_tls_slot_reserved_for_another_peer()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([23; 32]);
    let runtime_limits = ServerRuntimeLimits {
        handshake_timeout: Duration::from_millis(300),
        max_unauthenticated_connections: 2,
        max_unauthenticated_connections_per_peer: 1,
        ..ServerRuntimeLimits::default()
    };
    let app = ServerApp::bind_with_runtime_limits(
        server_config(&pki, vec![authorized("home-pc", &key, true)]),
        runtime_limits,
    )
    .await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let first_slow = TcpStream::connect(address).await?;
    let second_slow = TcpStream::connect(address).await?;
    sleep(Duration::from_millis(25)).await;

    let mut other_peer =
        FramedClient::connect_from(&pki, address, std::net::Ipv4Addr::new(127, 0, 0, 2)).await?;
    assert!(
        authenticate(&mut other_peer, "home-pc", &key)
            .await?
            .accepted
    );

    drop(other_peer);
    drop(second_slow);
    drop(first_slow);
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn failed_authentication_is_rate_limited_per_peer_and_recovers_after_window()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([14; 32]);
    let unknown = DeviceKeypair::from_secret_bytes([15; 32]);
    let runtime_limits = ServerRuntimeLimits {
        max_failed_auth_attempts_per_peer: 1,
        failed_auth_window: Duration::from_millis(120),
        ..ServerRuntimeLimits::default()
    };
    let app = ServerApp::bind_with_runtime_limits(
        server_config(&pki, vec![authorized("home-pc", &key, true)]),
        runtime_limits,
    )
    .await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut failed = FramedClient::connect(&pki, address).await?;
    assert_eq!(
        authenticate(&mut failed, "unknown-pc", &unknown).await?,
        rejected_authentication()
    );
    drop(failed);

    let mut limited = FramedClient::connect(&pki, address).await?;
    assert!(
        begin_authentication(&mut limited, VERSION, "home-pc", &key)
            .await
            .is_err()
    );

    sleep(Duration::from_millis(150)).await;
    let mut recovered = FramedClient::connect(&pki, address).await?;
    assert_eq!(
        authenticate(&mut recovered, "home-pc", &key).await?,
        AuthResult {
            accepted: true,
            error: None,
        }
    );

    drop(recovered);
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn fully_sent_auth_failure_remains_charged_after_abortive_close() -> Result<(), Box<dyn Error>>
{
    let pki = TestPki::generate()?;
    let authorized_key = DeviceKeypair::from_secret_bytes([20; 32]);
    let unknown_key = DeviceKeypair::from_secret_bytes([21; 32]);
    let runtime_limits = ServerRuntimeLimits {
        max_failed_auth_attempts_per_peer: 1,
        failed_auth_window: Duration::from_secs(5),
        ..ServerRuntimeLimits::default()
    };
    let app = ServerApp::bind_with_runtime_limits(
        server_config(&pki, vec![authorized("home-pc", &authorized_key, true)]),
        runtime_limits,
    )
    .await?;
    let address = app.local_addr()?;
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut failed = FramedClient::connect(&pki, address).await?;
    let challenge = begin_authentication(&mut failed, VERSION, "unknown-pc", &unknown_key).await?;
    failed
        .abort_after_response(
            VERSION,
            authentication_message(
                &challenge,
                &unknown_key,
                &unknown_key,
                VERSION,
                "unknown-pc",
            ),
        )
        .await?;
    sleep(Duration::from_millis(100)).await;

    let mut limited = FramedClient::connect(&pki, address).await?;
    assert!(
        begin_authentication(&mut limited, VERSION, "home-pc", &authorized_key)
            .await
            .is_err()
    );

    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn later_duplicate_login_cannot_evict_owner_and_disconnect_releases_listener()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([16; 32]);
    let port = unused_tcp_port()?;
    let app = ServerApp::bind(server_config(&pki, vec![authorized("home-pc", &key, true)])).await?;
    let address = app.local_addr()?;
    let registry = app.registry();
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut first = FramedClient::connect(&pki, address).await?;
    assert!(authenticate(&mut first, "home-pc", &key).await?.accepted);
    let first_results = register_tunnels(&mut first, vec![tcp_tunnel(1, "ssh", port)]).await?;
    assert!(first_results.results.as_slice()[0].accepted);
    assert_eq!(registry.active_count(), 1);
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());

    let mut second = FramedClient::connect(&pki, address).await?;
    assert_eq!(
        authenticate(&mut second, "home-pc", &key).await?,
        rejected_authentication()
    );
    assert_eq!(registry.active_count(), 1);
    assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
    first
        .send(VERSION, Message::Heartbeat(Heartbeat { sequence: 2 }))
        .await?;

    drop(second);
    drop(first);
    wait_for_active_count(&registry, 0).await?;
    let released = std::net::TcpListener::bind(("127.0.0.1", port))?;
    drop(released);

    let mut third = FramedClient::connect(&pki, address).await?;
    assert!(authenticate(&mut third, "home-pc", &key).await?.accepted);
    let third_results = register_tunnels(&mut third, vec![tcp_tunnel(1, "ssh", port)]).await?;
    assert!(third_results.results.as_slice()[0].accepted);

    drop(third);
    wait_for_active_count(&registry, 0).await?;
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn heartbeat_timeout_drops_the_control_owner_and_its_listener() -> Result<(), Box<dyn Error>>
{
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([17; 32]);
    let port = unused_tcp_port()?;
    let mut config = server_config(&pki, vec![authorized("home-pc", &key, true)]);
    config.server.heartbeat_timeout_secs = 2;
    let app = ServerApp::bind(config).await?;
    let address = app.local_addr()?;
    let registry = app.registry();
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut client = FramedClient::connect(&pki, address).await?;
    assert!(authenticate(&mut client, "home-pc", &key).await?.accepted);
    let results = register_tunnels(&mut client, vec![tcp_tunnel(1, "ssh", port)]).await?;
    assert!(results.results.as_slice()[0].accepted);
    assert_eq!(registry.active_count(), 1);

    wait_for_active_count(&registry, 0).await?;
    let released = std::net::TcpListener::bind(("127.0.0.1", port))?;
    drop(released);

    drop(client);
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn tunnel_conflict_is_rejected_without_discarding_unrelated_tunnels()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([18; 32]);
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
    let occupied_port = occupied.local_addr()?.port();
    let available_port = unused_tcp_port()?;
    let app = ServerApp::bind(server_config(&pki, vec![authorized("home-pc", &key, true)])).await?;
    let address = app.local_addr()?;
    let registry = app.registry();
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut client = FramedClient::connect(&pki, address).await?;
    assert!(authenticate(&mut client, "home-pc", &key).await?.accepted);
    let results = register_tunnels(
        &mut client,
        vec![
            tcp_tunnel(1, "conflict", occupied_port),
            tcp_tunnel(2, "healthy", available_port),
        ],
    )
    .await?;
    assert_eq!(results.results.as_slice().len(), 2);
    assert!(!results.results.as_slice()[0].accepted);
    assert_eq!(
        results.results.as_slice()[0].error,
        Some(ProtocolErrorCode::TUNNEL_REJECTED)
    );
    assert!(results.results.as_slice()[1].accepted);
    assert_eq!(results.results.as_slice()[1].error, None);
    assert!(std::net::TcpListener::bind(("127.0.0.1", available_port)).is_err());

    drop(client);
    wait_for_active_count(&registry, 0).await?;
    let released = std::net::TcpListener::bind(("127.0.0.1", available_port))?;
    drop(released);
    drop(occupied);
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn invalid_and_over_limit_tunnels_are_rejected_individually() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let key = DeviceKeypair::from_secret_bytes([19; 32]);
    let healthy_port = unused_tcp_port()?;
    let over_limit_port = unused_tcp_port()?;
    let mut config = server_config(&pki, vec![authorized("home-pc", &key, true)]);
    config.limits.max_tunnels_per_client = 1;
    let app = ServerApp::bind(config).await?;
    let address = app.local_addr()?;
    let registry = app.registry();
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(app.run_until(shutdown.clone()));

    let mut client = FramedClient::connect(&pki, address).await?;
    assert!(authenticate(&mut client, "home-pc", &key).await?.accepted);
    let results = register_tunnels(
        &mut client,
        vec![
            tcp_tunnel(1, "", healthy_port),
            tcp_tunnel(2, "zero", 0),
            tcp_tunnel(3, "healthy", healthy_port),
            tcp_tunnel(4, "over-limit", over_limit_port),
        ],
    )
    .await?;
    let results = results.results.as_slice();
    assert_eq!(results.len(), 4);
    assert!(!results[0].accepted);
    assert!(!results[1].accepted);
    assert!(results[2].accepted);
    assert!(!results[3].accepted);

    drop(client);
    wait_for_active_count(&registry, 0).await?;
    shutdown.cancel();
    server_task.await??;
    Ok(())
}

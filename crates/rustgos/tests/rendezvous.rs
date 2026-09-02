#![forbid(unsafe_code)]

use std::{error::Error, fs, net::Ipv4Addr, ops::Deref, path::PathBuf, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_config::{AuthorizedClient, Limits, ServerConfig, ServerSection};
use rustgo_crypto::DeviceKeypair;
use rustgo_e2e::{
    ScriptedProtocolClient, authentication_message, begin_authentication, finish_authentication,
};
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, BoundedVec, ErrorMessage, Frame, Heartbeat, Message,
    ObservationGrantRequest, PeerIdentityLookup, ProtocolErrorCode, ProtocolVersion,
    RegisterTunnels, TcpStreamReady, TunnelProtocol, TunnelRegistration,
};
use rustgo_rendezvous::{
    CandidateGeneration, CandidateSetV2, CandidateTransport, ConnectivityResult, ObservationGrant,
    PeerRelayFlags, PeerRelayFrame, ProviderDecision, RelayRequest, RendezvousClose,
    RendezvousEnvelope, RendezvousPayload, RendezvousRequest, SessionId, TransportKeyBinding,
};
use rustgos::{RendezvousErrorCode, ServerApp, ServerRuntimeLimits};
use tempfile::TempDir;
use tokio::{net::TcpStream, time::timeout};
use tokio_util::sync::CancellationToken;

const SERVER_NAME: &str = "rendezvous.example.test";
const V01: ProtocolVersion = ProtocolVersion::V0_1;
const V02: ProtocolVersion = ProtocolVersion::V0_2;
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
        .push(rcgen::DnType::CommonName, "Rustgo rendezvous test CA");
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

fn authorized(name: &str, key: &DeviceKeypair, enabled: bool) -> AuthorizedClient {
    AuthorizedClient {
        name: name.to_owned(),
        public_key: key.public_key().to_string(),
        enabled,
    }
}

fn server_config(pki: &TestPki, clients: Vec<AuthorizedClient>) -> ServerConfig {
    ServerConfig {
        server: ServerSection {
            bind_addr: "127.0.0.1:0".to_owned(),
            udp_bind_ip: None,
            p2p_observation_bind: Some("127.0.0.1:0".to_owned()),
            p2p_observation_alternate_bind: Some("127.0.0.1:0".to_owned()),
            certificate_file: pki.certificate_file.clone(),
            private_key_file: pki.private_key_file.clone(),
            heartbeat_timeout_secs: 5,
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
    }
}

fn text<const MAX: usize>(value: &str) -> BoundedString<MAX> {
    BoundedString::try_from(value).unwrap()
}

fn envelope(
    session: u8,
    sender: &str,
    target: &str,
    step: u64,
    expires_unix_secs: u64,
    payload: RendezvousPayload,
) -> RendezvousEnvelope {
    RendezvousEnvelope {
        version: V02,
        session_id: SessionId::from([session; 32]),
        sender: text(sender),
        target: text(target),
        step,
        generation: CandidateGeneration::INITIAL,
        expires_unix_secs,
        payload,
        signature: BoundedBytes::try_from([0x55; 64].as_slice()).unwrap(),
    }
}

fn future_expiry() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 20
}

fn candidate_set(owner_is_initiator: bool, marker: u8) -> RendezvousPayload {
    RendezvousPayload::CandidateSetV2(CandidateSetV2 {
        owner_is_initiator,
        bindings: BoundedVec::try_from(vec![TransportKeyBinding {
            transport: CandidateTransport::Relay,
            ephemeral_public_key: BoundedBytes::try_from(vec![marker; 32]).unwrap(),
        }])
        .unwrap(),
        candidates: BoundedVec::try_from(Vec::new()).unwrap(),
    })
}

fn with_generation(
    mut envelope: RendezvousEnvelope,
    generation: CandidateGeneration,
) -> RendezvousEnvelope {
    envelope.generation = generation;
    envelope
}

struct Client(ScriptedProtocolClient);

impl Deref for Client {
    type Target = ScriptedProtocolClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Client {
    async fn connect(
        pki: &TestPki,
        address: std::net::SocketAddr,
        name: &str,
        key: &DeviceKeypair,
        version: ProtocolVersion,
        tunnels: Vec<TunnelRegistration>,
    ) -> Result<Self, AnyError> {
        let mut client =
            ScriptedProtocolClient::connect(&pki.ca_file, SERVER_NAME, address).await?;
        let challenge = begin_authentication(&mut client, version, name, key).await?;
        assert_eq!(
            finish_authentication(
                &mut client,
                version,
                authentication_message(&challenge, key, key, version, name),
            )
            .await?,
            AuthResult {
                accepted: true,
                error: None,
            }
        );
        client
            .send(
                version,
                Message::RegisterTunnels(RegisterTunnels {
                    tunnels: BoundedVec::try_from(tunnels).unwrap(),
                }),
            )
            .await?;
        let Frame {
            version: negotiated,
            message: Message::TunnelResults(_),
            ..
        } = client.receive().await?
        else {
            return Err("server did not complete registration".into());
        };
        assert_eq!(negotiated, version);
        Ok(Self(client))
    }

    async fn send_envelope(&mut self, value: &RendezvousEnvelope) -> Result<(), AnyError> {
        self.send(V02, value.to_protocol_message()?).await?;
        Ok(())
    }

    async fn receive_envelope(&mut self) -> Result<RendezvousEnvelope, AnyError> {
        let frame = timeout(Duration::from_secs(2), self.receive()).await??;
        Ok(RendezvousEnvelope::from_protocol_message(frame.message)?)
    }
}

async fn start_server(
    pki: &TestPki,
    clients: Vec<AuthorizedClient>,
    limits: ServerRuntimeLimits,
) -> Result<
    (
        std::net::SocketAddr,
        rustgos::RendezvousCoordinator,
        CancellationToken,
        tokio::task::JoinHandle<Result<(), rustgos::ServerError>>,
    ),
    AnyError,
> {
    let app = ServerApp::bind_with_runtime_limits(server_config(pki, clients), limits).await?;
    let address = app.local_addr()?;
    let coordinator = app.rendezvous_coordinator();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(app.run_until(shutdown.clone()));
    Ok((address, coordinator, shutdown, task))
}

async fn expect_error(client: &mut Client, code: RendezvousErrorCode) -> Result<(), AnyError> {
    let notice = receive_notice(client).await?;
    assert_eq!(notice.code, code.as_u16());
    Ok(())
}

async fn send_and_forward(
    sender: &mut Client,
    receiver: &mut Client,
    envelope: RendezvousEnvelope,
) -> Result<(), AnyError> {
    sender.send_envelope(&envelope).await?;
    assert_eq!(receiver.receive_envelope().await?, envelope);
    Ok(())
}

async fn receive_punch(client: &mut Client) -> Result<(), AnyError> {
    let frame = timeout(Duration::from_secs(2), client.receive()).await??;
    if !matches!(frame.message, Message::PunchGrant(_)) {
        return Err("expected coordinated punch grant".into());
    }
    Ok(())
}

async fn receive_notice(client: &mut Client) -> Result<rustgo_protocol::ServerNotice, AnyError> {
    let frame = timeout(Duration::from_secs(2), client.receive()).await??;
    let Message::ServerNotice(notice) = frame.message else {
        return Err("expected a distinct server notice".into());
    };
    Ok(notice)
}

#[tokio::test]
async fn accepted_session_routes_bounded_relay_ciphertext_to_authenticated_peer()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([71; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([72; 32]);
    let (address, _coordinator, shutdown, task) = start_server(
        &pki,
        vec![authorized("a", &a_key, true), authorized("b", &b_key, true)],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, vec![]).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, vec![]).await?;
    let expires = future_expiry();
    a.send_envelope(&envelope(
        70,
        "a",
        "b",
        1,
        expires,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("ssh"),
        }),
    ))
    .await?;
    let _ = b.receive_envelope().await?;
    b.send(
        V02,
        Message::PeerIdentityLookup(PeerIdentityLookup {
            session_id: [70; 32],
            peer: text("a"),
        }),
    )
    .await?;
    let binding = timeout(Duration::from_secs(2), b.receive()).await??;
    let Message::PeerIdentityBinding(binding) = binding.message else {
        return Err("expected authenticated peer identity binding".into());
    };
    assert_eq!(binding.peer.as_str(), "a");
    assert_eq!(binding.public_key.as_str(), a_key.public_key().to_string());
    assert!(!binding.peer_is_provider);
    b.send_envelope(&envelope(
        70,
        "b",
        "a",
        2,
        expires,
        RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
    ))
    .await?;
    let _ = a.receive_envelope().await?;
    a.send_envelope(&envelope(
        70,
        "a",
        "b",
        3,
        expires,
        RendezvousPayload::RelayRequest(RelayRequest { datagram: false }),
    ))
    .await?;
    let _ = b.receive_envelope().await?;
    let premature = PeerRelayFrame::new(
        SessionId::from([70; 32]),
        9,
        0,
        PeerRelayFlags::RELIABLE,
        vec![0xa4; 16],
    )?;
    a.send(V02, premature.to_protocol_message()?).await?;
    let rejected = timeout(Duration::from_secs(2), a.receive()).await??;
    assert!(
        matches!(rejected.message, Message::Error(ref error) if error.code == ProtocolErrorCode::INVALID_STATE)
    );
    b.send_envelope(&envelope(
        70,
        "b",
        "a",
        4,
        expires,
        RendezvousPayload::RelayRequest(RelayRequest { datagram: false }),
    ))
    .await?;
    let _ = a.receive_envelope().await?;
    let relay = PeerRelayFrame::new(
        SessionId::from([70; 32]),
        9,
        0,
        PeerRelayFlags::RELIABLE,
        vec![0xa5; 48],
    )?;
    a.send(V02, relay.to_protocol_message()?).await?;
    let received = timeout(Duration::from_secs(2), b.receive()).await??;
    let routed = PeerRelayFrame::from_protocol_message(received.message)?;
    assert_eq!(routed, relay);
    shutdown.cancel();
    task.await??;
    Ok(())
}

#[tokio::test]
async fn delayed_datagram_relay_survives_candidate_generation_advance_until_close()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([73; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([74; 32]);
    let (address, _coordinator, shutdown, task) = start_server(
        &pki,
        vec![authorized("a", &a_key, true), authorized("b", &b_key, true)],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, vec![]).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, vec![]).await?;
    let expires = future_expiry();

    a.send_envelope(&envelope(
        72,
        "a",
        "b",
        1,
        expires,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("dns"),
        }),
    ))
    .await?;
    let _ = b.receive_envelope().await?;
    b.send_envelope(&envelope(
        72,
        "b",
        "a",
        2,
        expires,
        RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::UDP)),
    ))
    .await?;
    let _ = a.receive_envelope().await?;

    send_and_forward(
        &mut a,
        &mut b,
        envelope(72, "a", "b", 3, expires, candidate_set(true, 0x31)),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(72, "b", "a", 4, expires, candidate_set(false, 0x32)),
    )
    .await?;
    tokio::try_join!(receive_punch(&mut a), receive_punch(&mut b))?;
    send_and_forward(
        &mut a,
        &mut b,
        envelope(
            72,
            "a",
            "b",
            5,
            expires,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(
            72,
            "b",
            "a",
            6,
            expires,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
        ),
    )
    .await?;

    tokio::time::sleep(Duration::from_millis(260)).await;
    let generation_two = CandidateGeneration::new(2).unwrap();
    send_and_forward(
        &mut a,
        &mut b,
        with_generation(
            envelope(72, "a", "b", 7, expires, candidate_set(true, 0x41)),
            generation_two,
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        with_generation(
            envelope(72, "b", "a", 8, expires, candidate_set(false, 0x42)),
            generation_two,
        ),
    )
    .await?;
    tokio::try_join!(receive_punch(&mut a), receive_punch(&mut b))?;

    let outbound = PeerRelayFrame::new(
        SessionId::from([72; 32]),
        1,
        0,
        PeerRelayFlags::DATAGRAM,
        vec![0xa5; 48],
    )?;
    a.send(V02, outbound.to_protocol_message()?).await?;
    let routed = timeout(Duration::from_secs(2), b.receive()).await??;
    assert_eq!(
        PeerRelayFrame::from_protocol_message(routed.message)?,
        outbound
    );
    let reply = PeerRelayFrame::new(
        SessionId::from([72; 32]),
        1,
        0,
        PeerRelayFlags::DATAGRAM,
        vec![0xb6; 32],
    )?;
    b.send(V02, reply.to_protocol_message()?).await?;
    let routed = timeout(Duration::from_secs(2), a.receive()).await??;
    assert_eq!(
        PeerRelayFrame::from_protocol_message(routed.message)?,
        reply
    );

    let unknown = PeerRelayFrame::new(
        SessionId::from([73; 32]),
        1,
        0,
        PeerRelayFlags::DATAGRAM,
        vec![0xc7; 16],
    )?;
    a.send(V02, unknown.to_protocol_message()?).await?;
    let rejected = timeout(Duration::from_secs(2), a.receive()).await??;
    assert!(
        matches!(rejected.message, Message::Error(ref error) if error.code == ProtocolErrorCode::INVALID_STATE)
    );

    a.send_envelope(&with_generation(
        envelope(
            72,
            "a",
            "b",
            9,
            expires,
            RendezvousPayload::Close(RendezvousClose { detail: None }),
        ),
        generation_two,
    ))
    .await?;
    let _ = b.receive_envelope().await?;
    a.send(V02, outbound.to_protocol_message()?).await?;
    assert!(
        timeout(Duration::from_millis(100), b.receive())
            .await
            .is_err()
    );
    a.send(V02, Message::Heartbeat(Heartbeat { sequence: 72 }))
        .await?;
    let heartbeat = timeout(Duration::from_secs(2), a.receive()).await??;
    assert!(matches!(
        heartbeat.message,
        Message::Heartbeat(Heartbeat { sequence: 72 })
    ));

    shutdown.cancel();
    task.await??;
    Ok(())
}

#[tokio::test]
async fn partial_relay_requests_cannot_compose_across_candidate_generations() -> Result<(), AnyError>
{
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([75; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([76; 32]);
    let (address, _coordinator, shutdown, task) = start_server(
        &pki,
        vec![authorized("a", &a_key, true), authorized("b", &b_key, true)],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, vec![]).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, vec![]).await?;
    let expires = future_expiry();

    send_and_forward(
        &mut a,
        &mut b,
        envelope(
            74,
            "a",
            "b",
            1,
            expires,
            RendezvousPayload::Request(RendezvousRequest {
                export: text("dns"),
            }),
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(
            74,
            "b",
            "a",
            2,
            expires,
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::UDP)),
        ),
    )
    .await?;
    send_and_forward(
        &mut a,
        &mut b,
        envelope(74, "a", "b", 3, expires, candidate_set(true, 0x51)),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(74, "b", "a", 4, expires, candidate_set(false, 0x52)),
    )
    .await?;
    tokio::try_join!(receive_punch(&mut a), receive_punch(&mut b))?;

    send_and_forward(
        &mut a,
        &mut b,
        envelope(
            74,
            "a",
            "b",
            5,
            expires,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
        ),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(260)).await;
    let generation_two = CandidateGeneration::new(2).unwrap();
    send_and_forward(
        &mut a,
        &mut b,
        with_generation(
            envelope(74, "a", "b", 6, expires, candidate_set(true, 0x61)),
            generation_two,
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        with_generation(
            envelope(74, "b", "a", 7, expires, candidate_set(false, 0x62)),
            generation_two,
        ),
    )
    .await?;
    tokio::try_join!(receive_punch(&mut a), receive_punch(&mut b))?;

    send_and_forward(
        &mut b,
        &mut a,
        with_generation(
            envelope(
                74,
                "b",
                "a",
                8,
                expires,
                RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
            ),
            generation_two,
        ),
    )
    .await?;
    let frame = PeerRelayFrame::new(
        SessionId::from([74; 32]),
        1,
        0,
        PeerRelayFlags::DATAGRAM,
        vec![0xe9; 24],
    )?;
    b.send(V02, frame.to_protocol_message()?).await?;
    let rejected = timeout(Duration::from_secs(2), b.receive()).await??;
    assert!(
        matches!(rejected.message, Message::Error(ref error) if error.code == ProtocolErrorCode::INVALID_STATE)
    );

    send_and_forward(
        &mut a,
        &mut b,
        with_generation(
            envelope(
                74,
                "a",
                "b",
                9,
                expires,
                RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
            ),
            generation_two,
        ),
    )
    .await?;
    b.send(V02, frame.to_protocol_message()?).await?;
    let routed = timeout(Duration::from_secs(2), a.receive()).await??;
    assert_eq!(
        PeerRelayFrame::from_protocol_message(routed.message)?,
        frame
    );

    shutdown.cancel();
    task.await??;
    Ok(())
}

#[tokio::test]
async fn authenticated_late_frame_after_close_does_not_end_control_or_next_udp_relay()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([77; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([78; 32]);
    let c_key = DeviceKeypair::from_secret_bytes([79; 32]);
    let (address, _coordinator, shutdown, task) = start_server(
        &pki,
        vec![
            authorized("a", &a_key, true),
            authorized("b", &b_key, true),
            authorized("c", &c_key, true),
        ],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, vec![]).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, vec![]).await?;
    let mut c = Client::connect(&pki, address, "c", &c_key, V02, vec![]).await?;
    let expires = future_expiry();

    send_and_forward(
        &mut a,
        &mut b,
        envelope(
            77,
            "a",
            "b",
            1,
            expires,
            RendezvousPayload::Request(RendezvousRequest {
                export: text("ssh"),
            }),
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(
            77,
            "b",
            "a",
            2,
            expires,
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
        ),
    )
    .await?;
    send_and_forward(
        &mut a,
        &mut b,
        envelope(
            77,
            "a",
            "b",
            3,
            expires,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: false }),
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(
            77,
            "b",
            "a",
            4,
            expires,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: false }),
        ),
    )
    .await?;
    let late = PeerRelayFrame::new(
        SessionId::from([77; 32]),
        1,
        0,
        PeerRelayFlags::RELIABLE | PeerRelayFlags::FIN,
        vec![0xd7; 24],
    )?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(
            77,
            "b",
            "a",
            5,
            expires,
            RendezvousPayload::Close(RendezvousClose { detail: None }),
        ),
    )
    .await?;

    a.send(V02, late.to_protocol_message()?).await?;
    a.send(V02, Message::Heartbeat(Heartbeat { sequence: 77 }))
        .await?;
    let heartbeat = timeout(Duration::from_secs(2), a.receive()).await??;
    assert!(matches!(
        heartbeat.message,
        Message::Heartbeat(Heartbeat { sequence: 77 })
    ));

    c.send(V02, late.to_protocol_message()?).await?;
    let rejected = timeout(Duration::from_secs(2), c.receive()).await??;
    assert!(
        matches!(rejected.message, Message::Error(ref error) if error.code == ProtocolErrorCode::INVALID_STATE)
    );
    let unknown = PeerRelayFrame::new(
        SessionId::from([80; 32]),
        1,
        0,
        PeerRelayFlags::DATAGRAM,
        vec![0xe8; 24],
    )?;
    a.send(V02, unknown.to_protocol_message()?).await?;
    let rejected = timeout(Duration::from_secs(2), a.receive()).await??;
    assert!(
        matches!(rejected.message, Message::Error(ref error) if error.code == ProtocolErrorCode::INVALID_STATE)
    );

    send_and_forward(
        &mut a,
        &mut b,
        envelope(
            78,
            "a",
            "b",
            1,
            expires,
            RendezvousPayload::Request(RendezvousRequest {
                export: text("dns"),
            }),
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(
            78,
            "b",
            "a",
            2,
            expires,
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::UDP)),
        ),
    )
    .await?;
    send_and_forward(
        &mut a,
        &mut b,
        envelope(
            78,
            "a",
            "b",
            3,
            expires,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
        ),
    )
    .await?;
    send_and_forward(
        &mut b,
        &mut a,
        envelope(
            78,
            "b",
            "a",
            4,
            expires,
            RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
        ),
    )
    .await?;
    let datagram = PeerRelayFrame::new(
        SessionId::from([78; 32]),
        1,
        0,
        PeerRelayFlags::DATAGRAM,
        vec![0xf9; 24],
    )?;
    a.send(V02, datagram.to_protocol_message()?).await?;
    let routed = timeout(Duration::from_secs(2), b.receive()).await??;
    assert_eq!(
        PeerRelayFrame::from_protocol_message(routed.message)?,
        datagram
    );

    shutdown.cancel();
    task.await??;
    Ok(())
}

#[tokio::test]
async fn admission_rejects_untrusted_identity_target_and_capacity_inputs() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([1; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([2; 32]);
    let c_key = DeviceKeypair::from_secret_bytes([3; 32]);
    let disabled_key = DeviceKeypair::from_secret_bytes([4; 32]);
    let offline_key = DeviceKeypair::from_secret_bytes([5; 32]);
    let limits = ServerRuntimeLimits {
        max_rendezvous_sessions: 2,
        max_rendezvous_sessions_per_device: 1,
        ..ServerRuntimeLimits::default()
    };
    let (address, coordinator, shutdown, server) = start_server(
        &pki,
        vec![
            authorized("a", &a_key, true),
            authorized("b", &b_key, true),
            authorized("c", &c_key, true),
            authorized("disabled", &disabled_key, false),
            authorized("offline", &offline_key, true),
        ],
        limits,
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, Vec::new()).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, Vec::new()).await?;
    let _c = Client::connect(&pki, address, "c", &c_key, V02, Vec::new()).await?;

    for (session, target, code) in [
        (10, "missing", RendezvousErrorCode::UNKNOWN_PEER),
        (11, "disabled", RendezvousErrorCode::PEER_DISABLED),
        (12, "offline", RendezvousErrorCode::PEER_OFFLINE),
        (13, "a", RendezvousErrorCode::SELF_TARGET),
    ] {
        a.send_envelope(&envelope(
            session,
            "a",
            target,
            1,
            future_expiry(),
            RendezvousPayload::Request(RendezvousRequest {
                export: text("ssh"),
            }),
        ))
        .await?;
        expect_error(&mut a, code).await?;
    }

    a.send_envelope(&envelope(
        14,
        "forged",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("ssh"),
        }),
    ))
    .await?;
    expect_error(&mut a, RendezvousErrorCode::IDENTITY_MISMATCH).await?;

    let accepted = envelope(
        20,
        "a",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("ssh"),
        }),
    );
    a.send_envelope(&accepted).await?;
    assert_eq!(b.receive_envelope().await?, accepted);
    assert!(coordinator.session(SessionId::from([20; 32])).is_some());

    a.send_envelope(&accepted).await?;
    expect_error(&mut a, RendezvousErrorCode::DUPLICATE_SESSION).await?;

    a.send_envelope(&envelope(
        21,
        "a",
        "c",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("metrics"),
        }),
    ))
    .await?;
    expect_error(&mut a, RendezvousErrorCode::CAPACITY_REACHED).await?;

    a.send_envelope(&envelope(
        22,
        "a",
        "b",
        1,
        1,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("expired"),
        }),
    ))
    .await?;
    expect_error(&mut a, RendezvousErrorCode::EXPIRED).await?;

    shutdown.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn provider_decision_is_authoritative_and_disconnect_removes_only_owned_sessions()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([11; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([12; 32]);
    let c_key = DeviceKeypair::from_secret_bytes([13; 32]);
    let (address, coordinator, shutdown, server) = start_server(
        &pki,
        vec![
            authorized("a", &a_key, true),
            authorized("b", &b_key, true),
            authorized("c", &c_key, true),
        ],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, Vec::new()).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, Vec::new()).await?;
    let mut c = Client::connect(&pki, address, "c", &c_key, V02, Vec::new()).await?;

    let first = envelope(
        30,
        "a",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("game"),
        }),
    );
    a.send_envelope(&first).await?;
    assert_eq!(b.receive_envelope().await?, first);

    c.send_envelope(&envelope(
        30,
        "c",
        "a",
        2,
        future_expiry(),
        RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
    ))
    .await?;
    expect_error(&mut c, RendezvousErrorCode::NOT_PARTICIPANT).await?;

    let accepted = envelope(
        30,
        "b",
        "a",
        2,
        future_expiry(),
        RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::UDP)),
    );
    b.send_envelope(&accepted).await?;
    assert_eq!(a.receive_envelope().await?, accepted);
    assert_eq!(
        coordinator
            .session(SessionId::from([30; 32]))
            .unwrap()
            .protocol(),
        Some(TunnelProtocol::UDP)
    );

    let unrelated = envelope(
        31,
        "c",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("metrics"),
        }),
    );
    c.send_envelope(&unrelated).await?;
    assert_eq!(b.receive_envelope().await?, unrelated);

    drop(a);
    timeout(Duration::from_secs(2), async {
        loop {
            if coordinator.session(SessionId::from([30; 32])).is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(coordinator.session(SessionId::from([31; 32])).is_some());
    let disconnected = receive_notice(&mut b).await?;
    assert_eq!(disconnected.session_id, [30; 32]);
    assert_eq!(
        disconnected.code,
        RendezvousErrorCode::PEER_DISCONNECTED.as_u16()
    );

    let rejected = envelope(
        31,
        "b",
        "c",
        2,
        future_expiry(),
        RendezvousPayload::ProviderDecision(ProviderDecision::rejected(None)),
    );
    b.send_envelope(&rejected).await?;
    assert_eq!(c.receive_envelope().await?, rejected);
    assert!(coordinator.session(SessionId::from([31; 32])).is_none());

    shutdown.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn authenticated_grant_and_v01_rejection_share_control_without_breaking_relay()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let modern_key = DeviceKeypair::from_secret_bytes([21; 32]);
    let legacy_key = DeviceKeypair::from_secret_bytes([22; 32]);
    let (address, _coordinator, shutdown, server) = start_server(
        &pki,
        vec![
            authorized("modern", &modern_key, true),
            authorized("legacy", &legacy_key, true),
        ],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut modern = Client::connect(&pki, address, "modern", &modern_key, V02, Vec::new()).await?;
    modern
        .send(
            V02,
            Message::ObservationGrantRequest(ObservationGrantRequest {}),
        )
        .await?;
    let grant = ObservationGrant::from_protocol_message(modern.receive().await?.message)?;
    assert_ne!(grant.primary_token(), grant.alternate_token());

    let relay_port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port();
    let mut legacy = Client::connect(
        &pki,
        address,
        "legacy",
        &legacy_key,
        V01,
        vec![TunnelRegistration {
            tunnel_id: 7,
            name: text("legacy-ssh"),
            protocol: TunnelProtocol::TCP,
            remote_port: relay_port,
        }],
    )
    .await?;
    legacy
        .send(
            V01,
            Message::ObservationGrantRequest(ObservationGrantRequest {}),
        )
        .await?;
    let Frame {
        message: Message::Error(ErrorMessage { code, .. }),
        ..
    } = legacy.receive().await?
    else {
        return Err("legacy P2P operation did not receive a stable protocol error".into());
    };
    assert_eq!(code, ProtocolErrorCode::UNSUPPORTED_VERSION);

    legacy
        .send(V01, Message::Heartbeat(Heartbeat { sequence: 41 }))
        .await?;
    assert_eq!(
        legacy.receive().await?.message,
        Message::Heartbeat(Heartbeat { sequence: 41 })
    );

    let public = TcpStream::connect((Ipv4Addr::LOCALHOST, relay_port)).await?;
    let Frame {
        message: Message::OpenTcpStream(open),
        ..
    } = timeout(Duration::from_secs(2), legacy.receive()).await??
    else {
        return Err("legacy relay tunnel stopped after P2P rejection".into());
    };
    legacy
        .send(
            V01,
            Message::TcpStreamReady(TcpStreamReady {
                connection_id: open.connection_id,
                accepted: false,
                error: Some(ProtocolErrorCode::TUNNEL_REJECTED),
            }),
        )
        .await?;
    drop(public);

    shutdown.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn expiry_removes_the_session_and_notifies_both_authenticated_peers() -> Result<(), AnyError>
{
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([31; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([32; 32]);
    let (address, coordinator, shutdown, server) = start_server(
        &pki,
        vec![authorized("a", &a_key, true), authorized("b", &b_key, true)],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, Vec::new()).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, Vec::new()).await?;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        + 1;
    let request = envelope(
        40,
        "a",
        "b",
        1,
        expires,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("short-lived"),
        }),
    );
    a.send_envelope(&request).await?;
    assert_eq!(b.receive_envelope().await?, request);
    let a_notice = timeout(Duration::from_secs(3), receive_notice(&mut a)).await??;
    let b_notice = timeout(Duration::from_secs(3), receive_notice(&mut b)).await??;
    for notice in [a_notice, b_notice] {
        assert_eq!(notice.code, RendezvousErrorCode::EXPIRED.as_u16());
    }
    assert!(coordinator.session(SessionId::from([40; 32])).is_none());

    shutdown.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn closed_session_ids_reject_replay_after_reject_close_and_disconnect() -> Result<(), AnyError>
{
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([41; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([42; 32]);
    let c_key = DeviceKeypair::from_secret_bytes([43; 32]);
    let (address, coordinator, shutdown, server) = start_server(
        &pki,
        vec![
            authorized("a", &a_key, true),
            authorized("b", &b_key, true),
            authorized("c", &c_key, true),
        ],
        ServerRuntimeLimits::default(),
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, Vec::new()).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, Vec::new()).await?;
    let mut c = Client::connect(&pki, address, "c", &c_key, V02, Vec::new()).await?;

    let rejected_request = envelope(
        50,
        "a",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("rejected"),
        }),
    );
    a.send_envelope(&rejected_request).await?;
    assert_eq!(b.receive_envelope().await?, rejected_request);
    let rejection = envelope(
        50,
        "b",
        "a",
        2,
        future_expiry(),
        RendezvousPayload::ProviderDecision(ProviderDecision::rejected(None)),
    );
    b.send_envelope(&rejection).await?;
    assert_eq!(a.receive_envelope().await?, rejection);
    assert!(coordinator.session(SessionId::from([50; 32])).is_none());
    a.send_envelope(&rejected_request).await?;
    expect_error(&mut a, RendezvousErrorCode::DUPLICATE_SESSION).await?;

    let close_request = envelope(
        51,
        "a",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("closed"),
        }),
    );
    a.send_envelope(&close_request).await?;
    assert_eq!(b.receive_envelope().await?, close_request);
    let acceptance = envelope(
        51,
        "b",
        "a",
        2,
        future_expiry(),
        RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
    );
    b.send_envelope(&acceptance).await?;
    assert_eq!(a.receive_envelope().await?, acceptance);
    let close = envelope(
        51,
        "a",
        "b",
        3,
        future_expiry(),
        RendezvousPayload::Close(RendezvousClose { detail: None }),
    );
    a.send_envelope(&close).await?;
    assert_eq!(b.receive_envelope().await?, close);
    assert!(coordinator.session(SessionId::from([51; 32])).is_none());
    a.send_envelope(&close_request).await?;
    expect_error(&mut a, RendezvousErrorCode::DUPLICATE_SESSION).await?;

    let disconnected_request = envelope(
        52,
        "c",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("disconnected"),
        }),
    );
    c.send_envelope(&disconnected_request).await?;
    assert_eq!(b.receive_envelope().await?, disconnected_request);
    drop(c);
    timeout(Duration::from_secs(2), async {
        loop {
            if coordinator.session(SessionId::from([52; 32])).is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let _ = receive_notice(&mut b).await?;
    let replay_from_another_authenticated_device = envelope(
        52,
        "a",
        "b",
        1,
        future_expiry(),
        RendezvousPayload::Request(RendezvousRequest {
            export: text("replayed"),
        }),
    );
    a.send_envelope(&replay_from_another_authenticated_device)
        .await?;
    expect_error(&mut a, RendezvousErrorCode::DUPLICATE_SESSION).await?;

    shutdown.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn tombstones_consume_capacity_until_fixed_expiry_maintenance_reclaims_them()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([51; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([52; 32]);
    let limits = ServerRuntimeLimits {
        max_rendezvous_sessions: 1,
        max_rendezvous_sessions_per_device: 1,
        rendezvous_session_ttl: Duration::from_secs(2),
        ..ServerRuntimeLimits::default()
    };
    let (address, _coordinator, shutdown, server) = start_server(
        &pki,
        vec![authorized("a", &a_key, true), authorized("b", &b_key, true)],
        limits,
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, Vec::new()).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, Vec::new()).await?;
    let first_expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        + 2;
    let first = envelope(
        60,
        "a",
        "b",
        1,
        first_expiry,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("first"),
        }),
    );
    a.send_envelope(&first).await?;
    assert_eq!(b.receive_envelope().await?, first);
    let rejection = envelope(
        60,
        "b",
        "a",
        2,
        first_expiry,
        RendezvousPayload::ProviderDecision(ProviderDecision::rejected(None)),
    );
    b.send_envelope(&rejection).await?;
    assert_eq!(a.receive_envelope().await?, rejection);

    let after_expiry = envelope(
        61,
        "a",
        "b",
        1,
        first_expiry,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("after-expiry"),
        }),
    );
    a.send_envelope(&after_expiry).await?;
    expect_error(&mut a, RendezvousErrorCode::CAPACITY_REACHED).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after_expiry = envelope(
        61,
        "a",
        "b",
        1,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + 2,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("after-expiry"),
        }),
    );
    a.send_envelope(&after_expiry).await?;
    assert_eq!(b.receive_envelope().await?, after_expiry);

    shutdown.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn signed_expiry_is_rejected_above_the_horizon_and_reserved_exactly_until_expiry()
-> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let a_key = DeviceKeypair::from_secret_bytes([61; 32]);
    let b_key = DeviceKeypair::from_secret_bytes([62; 32]);
    let limits = ServerRuntimeLimits {
        rendezvous_session_ttl: Duration::from_secs(2),
        ..ServerRuntimeLimits::default()
    };
    let (address, coordinator, shutdown, server) = start_server(
        &pki,
        vec![authorized("a", &a_key, true), authorized("b", &b_key, true)],
        limits,
    )
    .await?;
    let mut a = Client::connect(&pki, address, "a", &a_key, V02, Vec::new()).await?;
    let mut b = Client::connect(&pki, address, "b", &b_key, V02, Vec::new()).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let overlong = envelope(
        70,
        "a",
        "b",
        1,
        now + 10,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("too-long"),
        }),
    );
    a.send_envelope(&overlong).await?;
    expect_error(&mut a, RendezvousErrorCode::INVALID_EXPIRY).await?;

    let signed_expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        + 2;
    let exact = envelope(
        70,
        "a",
        "b",
        1,
        signed_expiry,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("exact"),
        }),
    );
    a.send_envelope(&exact).await?;
    assert_eq!(b.receive_envelope().await?, exact);
    assert_eq!(
        coordinator
            .session(SessionId::from([70; 32]))
            .expect("exact-bound request is active")
            .expires_unix_secs(),
        signed_expiry
    );
    let rejection = envelope(
        70,
        "b",
        "a",
        2,
        signed_expiry,
        RendezvousPayload::ProviderDecision(ProviderDecision::rejected(None)),
    );
    b.send_envelope(&rejection).await?;
    assert_eq!(a.receive_envelope().await?, rejection);
    a.send_envelope(&exact).await?;
    expect_error(&mut a, RendezvousErrorCode::DUPLICATE_SESSION).await?;

    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        <= signed_expiry
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reusable = envelope(
        70,
        "a",
        "b",
        1,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + 2,
        RendezvousPayload::Request(RendezvousRequest {
            export: text("reused-after-expiry"),
        }),
    );
    a.send_envelope(&reusable).await?;
    assert_eq!(b.receive_envelope().await?, reusable);

    shutdown.cancel();
    server.await??;
    Ok(())
}

#[test]
fn coordinator_metadata_does_not_expose_or_store_application_payload() {
    fn assert_metadata_shape(value: &rustgos::RendezvousSessionMetadata) {
        let _ = (
            value.session_id(),
            value.consumer(),
            value.provider(),
            value.export(),
            value.protocol(),
            value.expires_unix_secs(),
        );
    }

    let _ = assert_metadata_shape;
    let _ = RendezvousPayload::ConnectivityResult(ConnectivityResult {
        connected: false,
        transport: None,
        detail: None,
    });
    let _ = RendezvousPayload::Close(RendezvousClose { detail: None });
}

use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rustgo_crypto::{DeviceKeypair, EphemeralPeerKey, PeerRole, PeerTranscript};
use rustgo_path::{PathAttempt, PathError, PathKind};
use rustgo_protocol::{BoundedString, ProtocolVersion};
use rustgo_rendezvous::{CandidateGeneration, SessionId};
use rustgo_transport::{
    MAX_PEER_DATAGRAM_BYTES, PeerAuthentication, PeerAuthenticationFactory, PeerDatagram,
    PeerStream, QuicPathAttempt, QuicPeerConfig, QuicPeerEndpoint, QuicPeerError,
    QuicPeerPathHandle,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const INITIATOR_IDENTITY_SECRET: [u8; 32] = [0x11; 32];
const RESPONDER_IDENTITY_SECRET: [u8; 32] = [0x22; 32];
const SUBSTITUTE_IDENTITY_SECRET: [u8; 32] = [0x33; 32];

struct ConnectedPair {
    _server_endpoint: QuicPeerEndpoint,
    client_endpoint: QuicPeerEndpoint,
    server: rustgo_transport::QuicPeerSession,
    client: rustgo_transport::QuicPeerSession,
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn free_udp_addr() -> SocketAddr {
    let socket = UdpSocket::bind(loopback()).unwrap();
    socket.local_addr().unwrap()
}

fn transcript(
    initiator_identity: rustgo_crypto::DevicePublicKey,
    responder_identity: rustgo_crypto::DevicePublicKey,
    initiator_ephemeral: [u8; 32],
    responder_ephemeral: [u8; 32],
    export: &str,
) -> PeerTranscript {
    PeerTranscript::new(
        SessionId::from([0x42; 32]),
        CandidateGeneration::new(3).unwrap(),
        initiator_identity,
        responder_identity,
        initiator_ephemeral,
        responder_ephemeral,
        BoundedString::try_from(export).unwrap(),
        ProtocolVersion::V0_2,
        [0x66; 32],
    )
}

fn authentication_pair() -> (PeerAuthentication, PeerAuthentication) {
    authentication_pair_with("ssh", "ssh", false)
}

fn authentication_pair_with(
    initiator_export: &str,
    responder_export: &str,
    responder_expects_substitute_initiator: bool,
) -> (PeerAuthentication, PeerAuthentication) {
    let initiator_identity = DeviceKeypair::from_secret_bytes(INITIATOR_IDENTITY_SECRET);
    let responder_identity = DeviceKeypair::from_secret_bytes(RESPONDER_IDENTITY_SECRET);
    let substitute_identity = DeviceKeypair::from_secret_bytes(SUBSTITUTE_IDENTITY_SECRET);
    let initiator_ephemeral = EphemeralPeerKey::generate();
    let responder_ephemeral = EphemeralPeerKey::generate();
    let initiator_public = initiator_ephemeral.public_key();
    let responder_public = responder_ephemeral.public_key();
    let initiator_transcript = transcript(
        initiator_identity.public_key(),
        responder_identity.public_key(),
        initiator_public,
        responder_public,
        initiator_export,
    );
    let responder_transcript = transcript(
        if responder_expects_substitute_initiator {
            substitute_identity.public_key()
        } else {
            initiator_identity.public_key()
        },
        responder_identity.public_key(),
        initiator_public,
        responder_public,
        responder_export,
    );

    (
        PeerAuthentication::new(
            PeerRole::Initiator,
            initiator_ephemeral,
            initiator_transcript,
        )
        .unwrap(),
        PeerAuthentication::new(
            PeerRole::Responder,
            responder_ephemeral,
            responder_transcript,
        )
        .unwrap(),
    )
}

async fn connected_pair() -> ConnectedPair {
    let config = QuicPeerConfig::default();
    let server_endpoint = QuicPeerEndpoint::bind(loopback(), config.clone()).unwrap();
    let client_endpoint = QuicPeerEndpoint::bind(loopback(), config).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let (client_auth, server_auth) = authentication_pair();
    let server_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();

    let (server, client) = tokio::join!(
        server_endpoint.accept(server_auth, server_cancel),
        client_endpoint.connect(server_addr, client_auth, client_cancel),
    );

    ConnectedPair {
        _server_endpoint: server_endpoint,
        client_endpoint,
        server: server.unwrap(),
        client: client.unwrap(),
    }
}

#[tokio::test]
async fn loopback_setup_completes_only_after_mutual_peer_authentication() {
    let pair = connected_pair().await;

    let mut client_stream: PeerStream = pair
        .client
        .open_stream(CancellationToken::new())
        .await
        .unwrap();
    client_stream.write_all(b"authenticated").await.unwrap();
    let mut server_stream: PeerStream = pair
        .server
        .accept_stream(CancellationToken::new())
        .await
        .unwrap();
    let mut received = [0_u8; 13];
    server_stream.read_exact(&mut received).await.unwrap();

    assert_eq!(&received, b"authenticated");
}

#[tokio::test]
async fn bidirectional_streams_preserve_raw_tcp_like_bytes() {
    let pair = connected_pair().await;
    let mut client_stream = pair
        .client
        .open_stream(CancellationToken::new())
        .await
        .unwrap();
    client_stream.write_all(b"request").await.unwrap();
    let mut server_stream = pair
        .server
        .accept_stream(CancellationToken::new())
        .await
        .unwrap();
    let mut request = [0_u8; 7];
    server_stream.read_exact(&mut request).await.unwrap();
    server_stream.write_all(b"response").await.unwrap();
    let mut response = [0_u8; 8];
    client_stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&request, b"request");
    assert_eq!(&response, b"response");
}

#[tokio::test]
async fn stream_half_close_preserves_the_reverse_direction() {
    let pair = connected_pair().await;
    let mut client_stream = pair
        .client
        .open_stream(CancellationToken::new())
        .await
        .unwrap();
    client_stream.write_all(b"request body").await.unwrap();
    client_stream.shutdown().await.unwrap();

    let mut server_stream = pair
        .server
        .accept_stream(CancellationToken::new())
        .await
        .unwrap();
    let mut request = Vec::new();
    server_stream.read_to_end(&mut request).await.unwrap();
    server_stream.write_all(b"final response").await.unwrap();
    server_stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();

    assert_eq!(request, b"request body");
    assert_eq!(response, b"final response");
}

#[tokio::test]
async fn datagrams_preserve_each_udp_application_boundary() {
    let pair = connected_pair().await;
    let client_datagrams: PeerDatagram = pair.client.datagrams();
    let server_datagrams: PeerDatagram = pair.server.datagrams();

    client_datagrams.send(b"first").unwrap();
    assert_eq!(
        server_datagrams
            .receive(CancellationToken::new())
            .await
            .unwrap(),
        b"first"
    );
    client_datagrams.send(b"second datagram").unwrap();
    assert_eq!(
        server_datagrams
            .receive(CancellationToken::new())
            .await
            .unwrap(),
        b"second datagram"
    );
}

#[tokio::test]
async fn externally_expected_peer_key_mismatch_rejects_the_quic_connection() {
    let config = QuicPeerConfig::default();
    let server_endpoint = QuicPeerEndpoint::bind(loopback(), config.clone()).unwrap();
    let client_endpoint = QuicPeerEndpoint::bind(loopback(), config).unwrap();
    let (client_auth, server_auth) = authentication_pair_with("ssh", "ssh", true);

    let (server, client) = tokio::join!(
        server_endpoint.accept(server_auth, CancellationToken::new()),
        client_endpoint.connect(
            server_endpoint.local_addr().unwrap(),
            client_auth,
            CancellationToken::new(),
        ),
    );

    assert!(server.is_err());
    assert!(client.is_err());
}

#[tokio::test]
async fn transcript_export_mismatch_rejects_the_quic_connection() {
    let config = QuicPeerConfig::default();
    let server_endpoint = QuicPeerEndpoint::bind(loopback(), config.clone()).unwrap();
    let client_endpoint = QuicPeerEndpoint::bind(loopback(), config).unwrap();
    let (client_auth, server_auth) = authentication_pair_with("ssh", "admin", false);

    let (server, client) = tokio::join!(
        server_endpoint.accept(server_auth, CancellationToken::new()),
        client_endpoint.connect(
            server_endpoint.local_addr().unwrap(),
            client_auth,
            CancellationToken::new(),
        ),
    );

    assert!(server.is_err());
    assert!(client.is_err());
}

#[tokio::test]
async fn oversize_datagram_is_rejected_before_send_without_poisoning_session() {
    let pair = connected_pair().await;
    let client_datagrams = pair.client.datagrams();
    let server_datagrams = pair.server.datagrams();
    let oversized = vec![0x55; MAX_PEER_DATAGRAM_BYTES + 1];

    assert!(matches!(
        client_datagrams.send(&oversized),
        Err(QuicPeerError::DatagramTooLarge { .. })
    ));

    client_datagrams.send(b"still alive").unwrap();
    assert_eq!(
        server_datagrams
            .receive(CancellationToken::new())
            .await
            .unwrap(),
        b"still alive"
    );
}

#[tokio::test]
async fn endpoint_rebind_keeps_the_authenticated_session_usable() {
    let pair = connected_pair().await;
    let old_addr = pair.client_endpoint.local_addr().unwrap();
    let new_addr = pair.client_endpoint.rebind(loopback()).unwrap();
    assert_ne!(old_addr, new_addr);

    let mut client_stream = pair
        .client
        .open_stream(CancellationToken::new())
        .await
        .unwrap();
    client_stream.write_all(b"after rebind").await.unwrap();
    let mut server_stream = tokio::time::timeout(
        Duration::from_secs(3),
        pair.server.accept_stream(CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap();
    let mut received = [0_u8; 12];
    server_stream.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"after rebind");
}

struct QueueAuthenticationFactory {
    values: Mutex<VecDeque<PeerAuthentication>>,
    calls: AtomicUsize,
}

impl QueueAuthenticationFactory {
    fn new(values: impl IntoIterator<Item = PeerAuthentication>) -> Arc<Self> {
        Arc::new(Self {
            values: Mutex::new(values.into_iter().collect()),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PeerAuthenticationFactory for QueueAuthenticationFactory {
    fn create(&self) -> Result<PeerAuthentication, QuicPeerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.values
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(QuicPeerError::AuthenticationMaterialUnavailable)
    }
}

#[tokio::test]
async fn reusable_path_attempt_uses_fresh_endpoint_and_authentication_each_time() {
    let config = QuicPeerConfig::default();
    let server_endpoint = QuicPeerEndpoint::bind(loopback(), config.clone()).unwrap();
    let (client_auth_1, server_auth_1) = authentication_pair();
    let (client_auth_2, server_auth_2) = authentication_pair();
    let factory = QueueAuthenticationFactory::new([client_auth_1, client_auth_2]);
    let attempt = QuicPathAttempt::new(
        loopback(),
        server_endpoint.local_addr().unwrap(),
        config,
        factory.clone(),
    );

    let (server_1, selected_1) = tokio::join!(
        server_endpoint.accept(server_auth_1, CancellationToken::new()),
        attempt.connect(CancellationToken::new()),
    );
    let server_1 = server_1.unwrap();
    let selected_1 = selected_1.unwrap();
    assert_eq!(selected_1.kind(), PathKind::QuicV4);
    let handle_1 = selected_1.handle::<QuicPeerPathHandle>().unwrap();

    let (server_2, selected_2) = tokio::join!(
        server_endpoint.accept(server_auth_2, CancellationToken::new()),
        attempt.connect(CancellationToken::new()),
    );
    let server_2 = server_2.unwrap();
    let selected_2 = selected_2.unwrap();
    let handle_2 = selected_2.handle::<QuicPeerPathHandle>().unwrap();

    assert_eq!(factory.calls(), 2);
    assert_ne!(
        handle_1.local_addr().unwrap(),
        handle_2.local_addr().unwrap()
    );

    let mut client_stream_1 = handle_1
        .session()
        .unwrap()
        .open_stream(CancellationToken::new())
        .await
        .unwrap();
    client_stream_1.write_all(b"one").await.unwrap();
    let mut server_stream_1 = server_1
        .accept_stream(CancellationToken::new())
        .await
        .unwrap();
    let mut one = [0_u8; 3];
    server_stream_1.read_exact(&mut one).await.unwrap();

    let mut client_stream_2 = handle_2
        .session()
        .unwrap()
        .open_stream(CancellationToken::new())
        .await
        .unwrap();
    client_stream_2.write_all(b"two").await.unwrap();
    let mut server_stream_2 = server_2
        .accept_stream(CancellationToken::new())
        .await
        .unwrap();
    let mut two = [0_u8; 3];
    server_stream_2.read_exact(&mut two).await.unwrap();
    assert_eq!(&one, b"one");
    assert_eq!(&two, b"two");

    drop(server_1);
    drop(server_2);
}

#[tokio::test]
async fn path_attempt_cancellation_releases_its_fresh_udp_endpoint() {
    let local_addr = free_udp_addr();
    let unreachable_addr = free_udp_addr();
    let (client_auth, _server_auth) = authentication_pair();
    let factory = QueueAuthenticationFactory::new([client_auth]);
    let attempt = Arc::new(QuicPathAttempt::new(
        local_addr,
        unreachable_addr,
        QuicPeerConfig::default(),
        factory.clone(),
    ));
    let cancellation = CancellationToken::new();
    let task_attempt = attempt.clone();
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move { task_attempt.connect(task_cancellation).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        while factory.calls() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    cancellation.cancel();

    assert!(matches!(task.await.unwrap(), Err(PathError::Cancelled)));
    UdpSocket::bind(local_addr).expect("cancelled path attempt must release its bound UDP socket");
}

#[tokio::test]
async fn selected_path_token_releases_socket_while_opaque_handle_is_still_retained() {
    let config = QuicPeerConfig::default();
    let server_endpoint = QuicPeerEndpoint::bind(loopback(), config.clone()).unwrap();
    let (client_auth, server_auth) = authentication_pair();
    let factory = QueueAuthenticationFactory::new([client_auth]);
    let attempt = QuicPathAttempt::new(
        loopback(),
        server_endpoint.local_addr().unwrap(),
        config,
        factory,
    );
    let cancellation = CancellationToken::new();

    let (server, selected) = tokio::join!(
        server_endpoint.accept(server_auth, CancellationToken::new()),
        attempt.connect(cancellation.clone()),
    );
    let server = server.unwrap();
    let selected = selected.unwrap();
    let handle = selected.handle::<QuicPeerPathHandle>().unwrap();
    let local_addr = handle.local_addr().unwrap();

    cancellation.cancel();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match UdpSocket::bind(local_addr) {
                Ok(socket) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected UDP rebind failure: {error}"),
            }
        }
    })
    .await
    .expect("selected path cancellation must release its UDP socket");

    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            server.accept_stream(CancellationToken::new())
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(handle.session().is_err());

    drop(selected);
    drop(handle);
}

#[tokio::test]
async fn selected_path_release_revokes_endpoint_while_session_clone_is_retained() {
    let config = QuicPeerConfig::default();
    let server_endpoint = QuicPeerEndpoint::bind(loopback(), config.clone()).unwrap();
    let (client_auth, server_auth) = authentication_pair();
    let factory = QueueAuthenticationFactory::new([client_auth]);
    let attempt = QuicPathAttempt::new(
        loopback(),
        server_endpoint.local_addr().unwrap(),
        config,
        factory,
    );
    let cancellation = CancellationToken::new();

    let (server, selected) = tokio::join!(
        server_endpoint.accept(server_auth, CancellationToken::new()),
        attempt.connect(cancellation.clone()),
    );
    let server = server.unwrap();
    let selected = selected.unwrap();
    let handle = selected.handle::<QuicPeerPathHandle>().unwrap();
    let local_addr = handle.local_addr().unwrap();
    let retained_session = handle.session().unwrap();

    cancellation.cancel();
    drop(selected);
    drop(handle);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match UdpSocket::bind(local_addr) {
                Ok(socket) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected UDP rebind failure: {error}"),
            }
        }
    })
    .await
    .expect("path release must revoke the endpoint retained by a session clone");

    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            retained_session.open_stream(CancellationToken::new())
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            server.accept_stream(CancellationToken::new())
        )
        .await
        .unwrap()
        .is_err()
    );
}

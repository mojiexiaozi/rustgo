use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use rustgo_crypto::{DeviceKeypair, EphemeralPeerKey, PeerRole, PeerTranscript};
use rustgo_path::{PathAttempt, PathKind};
use rustgo_protocol::{BoundedString, ProtocolVersion};
use rustgo_rendezvous::{CandidateGeneration, SessionId};
use rustgo_transport::{
    EncryptedPeerTcp, MAX_PEER_TCP_PLAINTEXT_BYTES, PeerTcpAuthentication,
    PeerTcpAuthenticationFactory, PeerTcpError, TcpPathAttempt,
};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_util::sync::CancellationToken;

#[test]
fn native_tcp_type_is_public() {
    let _ = std::mem::size_of::<EncryptedPeerTcp>();
}

fn authentication_pair(exports: (&str, &str)) -> (PeerTcpAuthentication, PeerTcpAuthentication) {
    let initiator_identity = DeviceKeypair::from_secret_bytes([0x11; 32]);
    let responder_identity = DeviceKeypair::from_secret_bytes([0x22; 32]);
    let initiator_ephemeral = EphemeralPeerKey::generate();
    let responder_ephemeral = EphemeralPeerKey::generate();
    let initiator_public = initiator_ephemeral.public_key();
    let responder_public = responder_ephemeral.public_key();
    let make_transcript = |export: &str| {
        PeerTranscript::new(
            SessionId::from([0x42; 32]),
            CandidateGeneration::new(3).unwrap(),
            initiator_identity.public_key(),
            responder_identity.public_key(),
            initiator_public,
            responder_public,
            BoundedString::try_from(export).unwrap(),
            ProtocolVersion::V0_2,
            [0x66; 32],
        )
    };
    (
        PeerTcpAuthentication::new(
            PeerRole::Initiator,
            initiator_ephemeral,
            make_transcript(exports.0),
        )
        .unwrap(),
        PeerTcpAuthentication::new(
            PeerRole::Responder,
            responder_ephemeral,
            make_transcript(exports.1),
        )
        .unwrap(),
    )
}

async fn connected_pair(
    exports: (&str, &str),
) -> (
    Result<EncryptedPeerTcp, rustgo_transport::PeerTcpError>,
    Result<EncryptedPeerTcp, rustgo_transport::PeerTcpError>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (initiator_auth, responder_auth) = authentication_pair(exports);
    let responder = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap().0;
        EncryptedPeerTcp::authenticate(
            stream,
            responder_auth,
            Duration::from_secs(2),
            CancellationToken::new(),
        )
        .await
    });
    let stream = TcpStream::connect(address).await.unwrap();
    let initiator = EncryptedPeerTcp::authenticate(
        stream,
        initiator_auth,
        Duration::from_secs(2),
        CancellationToken::new(),
    )
    .await;
    (initiator, responder.await.unwrap())
}

#[tokio::test]
async fn mutual_authentication_gates_encrypted_frames_and_preserves_half_close() {
    let (initiator, responder) = connected_pair(("ssh", "ssh")).await;
    let initiator = initiator.unwrap();
    let responder = responder.unwrap();
    initiator.send(b"secret bytes").await.unwrap();
    assert_eq!(responder.receive().await.unwrap().unwrap(), b"secret bytes");
    initiator.shutdown().await.unwrap();
    assert_eq!(responder.receive().await.unwrap(), None);
    responder.send(b"still writable").await.unwrap();
    assert_eq!(
        initiator.receive().await.unwrap().unwrap(),
        b"still writable"
    );
}

#[tokio::test]
async fn transcript_mismatch_is_rejected_before_session_return() {
    let (initiator, responder) = connected_pair(("ssh", "admin")).await;
    assert!(initiator.is_err());
    assert!(responder.is_err());
}

#[tokio::test]
async fn plaintext_has_a_hard_bound() {
    let (initiator, responder) = connected_pair(("ssh", "ssh")).await;
    let initiator = initiator.unwrap();
    let _responder = responder.unwrap();
    assert!(
        initiator
            .send(&vec![0; MAX_PEER_TCP_PLAINTEXT_BYTES + 1])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cancellation_interrupts_authentication_before_session_return() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (authentication, _) = authentication_pair(("ssh", "ssh"));
    let peer = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let stream = TcpStream::connect(address).await.unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let result = EncryptedPeerTcp::authenticate(
        stream,
        authentication,
        Duration::from_secs(1),
        cancellation,
    )
    .await;
    assert!(matches!(result, Err(PeerTcpError::Cancelled)));
    peer.abort();
}

#[tokio::test]
async fn silent_peer_hits_the_authentication_deadline() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (authentication, _) = authentication_pair(("ssh", "ssh"));
    let peer = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let stream = TcpStream::connect(address).await.unwrap();
    let result = EncryptedPeerTcp::authenticate(
        stream,
        authentication,
        Duration::from_millis(20),
        CancellationToken::new(),
    )
    .await;
    assert!(matches!(result, Err(PeerTcpError::AuthenticationTimedOut)));
    peer.abort();
}

struct QueueFactory(Mutex<VecDeque<PeerTcpAuthentication>>);

impl PeerTcpAuthenticationFactory for QueueFactory {
    fn create(&self) -> Result<PeerTcpAuthentication, PeerTcpError> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(PeerTcpError::AuthenticationFailed)
    }
}

fn free_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn stalled_early_socket_does_not_beat_later_authenticated_candidate() {
    let local = free_address();
    let stalled_addr = free_address();
    let valid_addr = free_address();
    let (first_local, _) = authentication_pair(("ssh", "ssh"));
    let (second_local, second_peer) = authentication_pair(("ssh", "ssh"));
    let factory = Arc::new(QueueFactory(Mutex::new(VecDeque::from([
        first_local,
        second_local,
    ]))));
    let attempt = Arc::new(TcpPathAttempt::new(
        local,
        vec![stalled_addr, valid_addr],
        Duration::from_secs(2),
        Duration::from_millis(300),
        factory,
    ));
    let connect_attempt = {
        let attempt = attempt.clone();
        tokio::spawn(async move { attempt.connect(CancellationToken::new()).await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;

    let stalled_socket = TcpSocket::new_v4().unwrap();
    stalled_socket.bind(stalled_addr).unwrap();
    let stalled = stalled_socket.connect(local).await.unwrap();

    let valid_socket = TcpSocket::new_v4().unwrap();
    valid_socket.bind(valid_addr).unwrap();
    let valid_stream = valid_socket.connect(local).await.unwrap();
    let peer = tokio::spawn(async move {
        EncryptedPeerTcp::authenticate(
            valid_stream,
            second_peer,
            Duration::from_secs(1),
            CancellationToken::new(),
        )
        .await
        .unwrap()
    });
    let selected = connect_attempt.await.unwrap().unwrap();
    assert_eq!(selected.kind(), PathKind::NativeTcp);
    drop(stalled);
    drop(selected);
    drop(peer.await.unwrap());
    tokio::task::yield_now().await;
    assert!(TcpListener::bind(local).await.is_ok());
}

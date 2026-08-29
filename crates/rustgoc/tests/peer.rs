use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use rustgo_crypto::{DeviceKeypair, EphemeralPeerKey, PeerRole, PeerSessionKeys, PeerTranscript};
use rustgo_path::{PathAttempt, PathError, PathKind, SelectedPath};
use rustgo_protocol::{BoundedString, ProtocolVersion};
use rustgo_rendezvous::{CandidateGeneration, SessionId};
use rustgoc::{PeerRelayChannel, PeerSessionRuntime, PeerSessionRuntimeOptions};
use tokio_util::sync::CancellationToken;

struct FailingDirect;

#[async_trait]
impl PathAttempt for FailingDirect {
    fn kind(&self) -> PathKind {
        PathKind::QuicV4
    }
    async fn connect(&self, _: CancellationToken) -> Result<SelectedPath, PathError> {
        Err(PathError::AttemptFailed(PathKind::QuicV4))
    }
}

fn key_pair() -> (PeerSessionKeys, PeerSessionKeys) {
    let initiator_identity = DeviceKeypair::from_secret_bytes([0x11; 32]);
    let responder_identity = DeviceKeypair::from_secret_bytes([0x22; 32]);
    let initiator_ephemeral = EphemeralPeerKey::generate();
    let responder_ephemeral = EphemeralPeerKey::generate();
    let transcript = PeerTranscript::new(
        SessionId::from([0x42; 32]),
        CandidateGeneration::INITIAL,
        initiator_identity.public_key(),
        responder_identity.public_key(),
        initiator_ephemeral.public_key(),
        responder_ephemeral.public_key(),
        BoundedString::try_from("ssh").unwrap(),
        ProtocolVersion::V0_2,
        [0x66; 32],
    );
    (
        PeerSessionKeys::derive(PeerRole::Initiator, initiator_ephemeral, &transcript).unwrap(),
        PeerSessionKeys::derive(PeerRole::Responder, responder_ephemeral, &transcript).unwrap(),
    )
}

fn expiry() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 30
}

#[test]
fn relay_boundary_carries_ciphertext_and_preserves_stream_and_datagram_semantics() {
    let (mut initiator, mut responder) = key_pair();
    let outgoing = PeerRelayChannel::stream(&mut initiator, 7).unwrap();
    let incoming = PeerRelayChannel::stream(&mut responder, 7).unwrap();
    let frame = outgoing.seal(b"secret application bytes", false).unwrap();
    assert_ne!(frame.ciphertext(), b"secret application bytes");
    assert_eq!(incoming.open(&frame).unwrap(), b"secret application bytes");

    let (mut initiator, mut responder) = key_pair();
    let outgoing = PeerRelayChannel::datagram(&mut initiator, 8).unwrap();
    let incoming = PeerRelayChannel::datagram(&mut responder, 8).unwrap();
    for payload in [b"one".as_slice(), b"two-two".as_slice()] {
        let frame = outgoing.seal(payload, false).unwrap();
        assert_eq!(incoming.open(&frame).unwrap(), payload);
    }
}

#[tokio::test]
async fn repeated_direct_failure_falls_back_and_releases_every_session() {
    let runtime = PeerSessionRuntime::new(
        PeerSessionRuntimeOptions {
            relay_grace: Duration::from_millis(1),
            direct_timeout: Duration::from_millis(20),
            attempt_timeout: Duration::from_millis(10),
            recheck_interval: Duration::from_secs(60),
            ..PeerSessionRuntimeOptions::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    for marker in 1..=25u8 {
        let (mut initiator, _) = key_pair();
        let relay = Arc::new(PeerRelayChannel::stream(&mut initiator, u64::from(marker)).unwrap());
        let handle = runtime
            .connect(
                SessionId::from([marker; 32]),
                expiry(),
                vec![Arc::new(FailingDirect)],
                Some(relay),
            )
            .await
            .unwrap();
        assert_eq!(handle.selected_path().kind(), PathKind::Relay);
        handle.close().await;
        assert_eq!(runtime.active_sessions(), 0);
    }
    runtime.shutdown().await;
}

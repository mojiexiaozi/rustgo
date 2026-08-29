use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use rustgo_crypto::{
    DeviceKeypair, EphemeralPeerKey, PeerRole, PeerSessionKeys, PeerTranscript, sign_peer_envelope,
};
use rustgo_path::{PathAttempt, PathError, PathKind, SelectedPath};
use rustgo_protocol::{BoundedBytes, BoundedString, PeerIdentityBinding, ProtocolVersion};
use rustgo_rendezvous::{
    CandidateGeneration, RendezvousEnvelope, RendezvousPayload, RendezvousRequest, SessionId,
};
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
fn tls_authoritative_binding_rejects_duplicate_mismatch_expiry_and_key_substitution() {
    let runtime = PeerSessionRuntime::new(
        PeerSessionRuntimeOptions::default(),
        CancellationToken::new(),
    )
    .unwrap();
    let peer = DeviceKeypair::from_secret_bytes([0x91; 32]);
    let substituted = DeviceKeypair::from_secret_bytes([0x92; 32]);
    let expires = expiry();
    let encoded_peer_key = peer.public_key().to_string();
    let binding = PeerIdentityBinding {
        session_id: [0x90; 32],
        peer: BoundedString::try_from("provider").unwrap(),
        public_key: BoundedString::try_from(encoded_peer_key.as_str()).unwrap(),
        protocol: None,
        peer_is_provider: true,
        expires_unix_secs: expires,
    };
    runtime
        .register_peer_binding(binding.clone(), "provider", true)
        .unwrap();
    assert!(
        runtime
            .register_peer_binding(binding, "provider", true)
            .is_err()
    );

    let mut envelope = RendezvousEnvelope {
        version: ProtocolVersion::V0_2,
        session_id: SessionId::from([0x90; 32]),
        sender: BoundedString::try_from("provider").unwrap(),
        target: BoundedString::try_from("consumer").unwrap(),
        step: 2,
        generation: CandidateGeneration::INITIAL,
        expires_unix_secs: expires,
        payload: RendezvousPayload::Request(RendezvousRequest {
            export: BoundedString::try_from("ssh").unwrap(),
        }),
        signature: BoundedBytes::try_from(Vec::new()).unwrap(),
    };
    envelope.signature = sign_peer_envelope(&peer, &envelope).unwrap();
    runtime.verify_authoritative_envelope(&envelope).unwrap();
    envelope.signature = sign_peer_envelope(&substituted, &envelope).unwrap();
    assert!(runtime.verify_authoritative_envelope(&envelope).is_err());
    envelope.sender = BoundedString::try_from("spoofed").unwrap();
    assert!(runtime.verify_authoritative_envelope(&envelope).is_err());
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

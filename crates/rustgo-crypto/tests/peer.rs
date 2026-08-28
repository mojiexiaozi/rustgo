use proptest::prelude::*;
use rustgo_crypto::{
    DeviceKeypair, EphemeralPeerKey, PeerCryptoError, PeerRole, PeerSessionKeys, PeerTranscript,
    sign_peer_envelope, verify_peer_envelope,
};
use rustgo_protocol::{
    BoundedBytes, BoundedString, BoundedVec, ProtocolVersion, SocketAddress, TunnelProtocol,
};
use rustgo_rendezvous::{
    Candidate, CandidateGeneration, CandidateSet, CandidateTransport, ConnectivityResult,
    PeerRelayFlags, PeerRelayFrame, ProviderDecision, RelayRequest, RendezvousClose,
    RendezvousEnvelope, RendezvousError, RendezvousPayload, RendezvousRequest, SessionId,
};

const INITIATOR_IDENTITY_SECRET: [u8; 32] = [0x11; 32];
const RESPONDER_IDENTITY_SECRET: [u8; 32] = [0x22; 32];
const SUBSTITUTE_IDENTITY_SECRET: [u8; 32] = [0x33; 32];
const INITIATOR_EPHEMERAL_SECRET: [u8; 32] = [0x44; 32];
const RESPONDER_EPHEMERAL_SECRET: [u8; 32] = [0x55; 32];

type CandidateMutation = Box<dyn Fn(&mut Candidate)>;

struct PeerFixture {
    initiator_identity: DeviceKeypair,
    responder_identity: DeviceKeypair,
    initiator_ephemeral: EphemeralPeerKey,
    responder_ephemeral: EphemeralPeerKey,
}

impl PeerFixture {
    fn new() -> Self {
        Self {
            initiator_identity: DeviceKeypair::from_secret_bytes(INITIATOR_IDENTITY_SECRET),
            responder_identity: DeviceKeypair::from_secret_bytes(RESPONDER_IDENTITY_SECRET),
            initiator_ephemeral: EphemeralPeerKey::from_secret_bytes(INITIATOR_EPHEMERAL_SECRET),
            responder_ephemeral: EphemeralPeerKey::from_secret_bytes(RESPONDER_EPHEMERAL_SECRET),
        }
    }

    fn transcript(&self, export: &str) -> PeerTranscript {
        PeerTranscript::new(
            session_id(0x42),
            CandidateGeneration::new(3).unwrap(),
            self.initiator_identity.public_key(),
            self.responder_identity.public_key(),
            self.initiator_ephemeral.public_key(),
            self.responder_ephemeral.public_key(),
            BoundedString::try_from(export).unwrap(),
            ProtocolVersion::V0_2,
            [0x66; 32],
        )
    }

    fn keys(&self, export: &str) -> (PeerSessionKeys, PeerSessionKeys) {
        let transcript = self.transcript(export);
        let initiator =
            PeerSessionKeys::derive(PeerRole::Initiator, &self.initiator_ephemeral, &transcript)
                .unwrap();
        let responder =
            PeerSessionKeys::derive(PeerRole::Responder, &self.responder_ephemeral, &transcript)
                .unwrap();
        (initiator, responder)
    }
}

fn session_id(byte: u8) -> SessionId {
    SessionId::from([byte; 32])
}

fn request_envelope() -> RendezvousEnvelope {
    RendezvousEnvelope {
        version: ProtocolVersion::V0_2,
        session_id: session_id(0x42),
        sender: BoundedString::try_from("laptop").unwrap(),
        target: BoundedString::try_from("office-pc").unwrap(),
        step: 7,
        generation: CandidateGeneration::new(3).unwrap(),
        expires_unix_secs: 2_000,
        payload: RendezvousPayload::Request(RendezvousRequest {
            export: BoundedString::try_from("ssh").unwrap(),
        }),
        signature: BoundedBytes::try_from(Vec::new()).unwrap(),
    }
}

fn candidate() -> Candidate {
    Candidate {
        transport: CandidateTransport::QuicUdp,
        address: SocketAddress::V4 {
            octets: [192, 0, 2, 9],
            port: 7443,
        },
        priority: 100,
        foundation: BoundedString::try_from("observed-udp").unwrap(),
        generation: CandidateGeneration::new(3).unwrap(),
        expires_unix_secs: 2_000,
        observation_source: BoundedString::try_from("rustgos:7443/udp").unwrap(),
    }
}

fn signed(mut envelope: RendezvousEnvelope, signer: &DeviceKeypair) -> RendezvousEnvelope {
    envelope.signature = sign_peer_envelope(signer, &envelope).unwrap();
    envelope
}

#[test]
fn both_role_orderings_derive_matching_directional_keys() {
    let fixture = PeerFixture::new();
    let (initiator, responder) = fixture.keys("ssh");

    let initiator_tag = initiator.handshake_tag();
    responder.verify_handshake_tag(&initiator_tag).unwrap();
    let responder_tag = responder.handshake_tag();
    initiator.verify_handshake_tag(&responder_tag).unwrap();

    let mut initiator_sealer = initiator
        .stream_sealer(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    let mut responder_opener = responder
        .stream_opener(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    let frame = initiator_sealer.seal(7, b"initiator payload").unwrap();
    assert_eq!(responder_opener.open(&frame).unwrap(), b"initiator payload");

    let mut responder_sealer = responder
        .stream_sealer(10, PeerRelayFlags::RELIABLE)
        .unwrap();
    let mut initiator_opener = initiator
        .stream_opener(10, PeerRelayFlags::RELIABLE)
        .unwrap();
    let frame = responder_sealer.seal(12, b"responder payload").unwrap();
    assert_eq!(initiator_opener.open(&frame).unwrap(), b"responder payload");
}

#[test]
fn local_ephemeral_key_must_match_its_claimed_role() {
    let fixture = PeerFixture::new();
    let transcript = fixture.transcript("ssh");

    assert!(matches!(
        PeerSessionKeys::derive(
            PeerRole::Responder,
            &fixture.initiator_ephemeral,
            &transcript,
        ),
        Err(PeerCryptoError::LocalEphemeralKeyMismatch)
    ));
}

#[test]
fn export_name_is_bound_into_session_keys() {
    let fixture = PeerFixture::new();
    let (ssh, _) = fixture.keys("ssh");
    let (admin, _) = fixture.keys("admin");

    assert_ne!(ssh.handshake_tag(), admin.handshake_tag());
}

#[test]
fn session_peer_generation_and_rendezvous_hash_are_bound_into_keys() {
    let fixture = PeerFixture::new();
    let base = fixture.transcript("ssh");
    let substitute = DeviceKeypair::from_secret_bytes(SUBSTITUTE_IDENTITY_SECRET);
    let variants = [
        PeerTranscript::new(
            session_id(0x43),
            CandidateGeneration::new(3).unwrap(),
            fixture.initiator_identity.public_key(),
            fixture.responder_identity.public_key(),
            fixture.initiator_ephemeral.public_key(),
            fixture.responder_ephemeral.public_key(),
            BoundedString::try_from("ssh").unwrap(),
            ProtocolVersion::V0_2,
            [0x66; 32],
        ),
        PeerTranscript::new(
            session_id(0x42),
            CandidateGeneration::new(4).unwrap(),
            fixture.initiator_identity.public_key(),
            fixture.responder_identity.public_key(),
            fixture.initiator_ephemeral.public_key(),
            fixture.responder_ephemeral.public_key(),
            BoundedString::try_from("ssh").unwrap(),
            ProtocolVersion::V0_2,
            [0x66; 32],
        ),
        PeerTranscript::new(
            session_id(0x42),
            CandidateGeneration::new(3).unwrap(),
            fixture.initiator_identity.public_key(),
            substitute.public_key(),
            fixture.initiator_ephemeral.public_key(),
            fixture.responder_ephemeral.public_key(),
            BoundedString::try_from("ssh").unwrap(),
            ProtocolVersion::V0_2,
            [0x66; 32],
        ),
        PeerTranscript::new(
            session_id(0x42),
            CandidateGeneration::new(3).unwrap(),
            fixture.initiator_identity.public_key(),
            fixture.responder_identity.public_key(),
            fixture.initiator_ephemeral.public_key(),
            fixture.responder_ephemeral.public_key(),
            BoundedString::try_from("ssh").unwrap(),
            ProtocolVersion::V0_2,
            [0x67; 32],
        ),
    ];
    let base_keys =
        PeerSessionKeys::derive(PeerRole::Initiator, &fixture.initiator_ephemeral, &base).unwrap();

    for changed in &variants {
        let changed_keys =
            PeerSessionKeys::derive(PeerRole::Initiator, &fixture.initiator_ephemeral, changed)
                .unwrap();
        assert_ne!(base_keys.handshake_tag(), changed_keys.handshake_tag());
    }
}

#[test]
fn envelope_signature_binds_metadata_export_and_expected_peer_identity() {
    let fixture = PeerFixture::new();
    let original = signed(request_envelope(), &fixture.initiator_identity);
    verify_peer_envelope(&fixture.initiator_identity.public_key(), &original).unwrap();

    let mut variants = Vec::new();
    let mut changed = original.clone();
    changed.version = ProtocolVersion::V0_1;
    variants.push(changed);
    let mut changed = original.clone();
    changed.session_id = session_id(0x43);
    variants.push(changed);
    let mut changed = original.clone();
    changed.sender = BoundedString::try_from("attacker").unwrap();
    variants.push(changed);
    let mut changed = original.clone();
    changed.target = BoundedString::try_from("other-peer").unwrap();
    variants.push(changed);
    let mut changed = original.clone();
    changed.step += 1;
    variants.push(changed);
    let mut changed = original.clone();
    changed.generation = CandidateGeneration::new(4).unwrap();
    variants.push(changed);
    let mut changed = original.clone();
    changed.expires_unix_secs += 1;
    variants.push(changed);
    let mut changed = original.clone();
    changed.payload = RendezvousPayload::Request(RendezvousRequest {
        export: BoundedString::try_from("admin").unwrap(),
    });
    variants.push(changed);

    for changed in variants {
        assert_eq!(
            verify_peer_envelope(&fixture.initiator_identity.public_key(), &changed),
            Err(PeerCryptoError::SignatureVerificationFailed)
        );
    }
    assert_eq!(
        verify_peer_envelope(&fixture.responder_identity.public_key(), &original),
        Err(PeerCryptoError::SignatureVerificationFailed)
    );
}

#[test]
fn envelope_signature_binds_every_candidate_field() {
    let fixture = PeerFixture::new();
    let mut unsigned = request_envelope();
    unsigned.payload = RendezvousPayload::CandidateSet(CandidateSet {
        ephemeral_public_key: BoundedBytes::try_from(vec![0x44; 32]).unwrap(),
        candidates: BoundedVec::try_from(vec![candidate()]).unwrap(),
    });
    let original = signed(unsigned, &fixture.initiator_identity);

    let mutations: Vec<CandidateMutation> = vec![
        Box::new(|value| value.transport = CandidateTransport::NativeTcp),
        Box::new(|value| {
            value.address = SocketAddress::V4 {
                octets: [192, 0, 2, 10],
                port: 7443,
            }
        }),
        Box::new(|value| value.priority += 1),
        Box::new(|value| value.foundation = BoundedString::try_from("lan").unwrap()),
        Box::new(|value| value.generation = CandidateGeneration::new(4).unwrap()),
        Box::new(|value| value.expires_unix_secs += 1),
        Box::new(|value| {
            value.observation_source = BoundedString::try_from("rustgos:7444/udp").unwrap()
        }),
    ];

    for mutate in mutations {
        let mut changed = original.clone();
        let RendezvousPayload::CandidateSet(set) = &mut changed.payload else {
            unreachable!()
        };
        let mut candidate = set.candidates.as_slice()[0].clone();
        mutate(&mut candidate);
        set.candidates = BoundedVec::try_from(vec![candidate]).unwrap();
        assert_eq!(
            verify_peer_envelope(&fixture.initiator_identity.public_key(), &changed),
            Err(PeerCryptoError::SignatureVerificationFailed)
        );
    }

    let mut changed = original.clone();
    let RendezvousPayload::CandidateSet(set) = &mut changed.payload else {
        unreachable!()
    };
    set.ephemeral_public_key = BoundedBytes::try_from(vec![0x45; 32]).unwrap();
    assert_eq!(
        verify_peer_envelope(&fixture.initiator_identity.public_key(), &changed),
        Err(PeerCryptoError::SignatureVerificationFailed)
    );
}

#[test]
fn envelope_signature_binds_all_payload_variants() {
    let fixture = PeerFixture::new();
    let payload_pairs = [
        (
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::TCP)),
            RendezvousPayload::ProviderDecision(ProviderDecision::accepted(TunnelProtocol::UDP)),
        ),
        (
            RendezvousPayload::ConnectivityResult(ConnectivityResult {
                connected: true,
                transport: Some(CandidateTransport::QuicUdp),
                detail: None,
            }),
            RendezvousPayload::ConnectivityResult(ConnectivityResult {
                connected: false,
                transport: Some(CandidateTransport::QuicUdp),
                detail: None,
            }),
        ),
        (
            RendezvousPayload::RelayRequest(RelayRequest { datagram: false }),
            RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
        ),
        (
            RendezvousPayload::Close(RendezvousClose { detail: None }),
            RendezvousPayload::Close(RendezvousClose {
                detail: Some(BoundedString::try_from("closed").unwrap()),
            }),
        ),
        (
            RendezvousPayload::Error(RendezvousError {
                code: 7,
                detail: BoundedString::try_from("unavailable").unwrap(),
            }),
            RendezvousPayload::Error(RendezvousError {
                code: 8,
                detail: BoundedString::try_from("unavailable").unwrap(),
            }),
        ),
    ];

    for (original_payload, changed_payload) in payload_pairs {
        let mut envelope = request_envelope();
        envelope.payload = original_payload;
        let original = signed(envelope, &fixture.initiator_identity);
        verify_peer_envelope(&fixture.initiator_identity.public_key(), &original).unwrap();
        let mut changed = original.clone();
        changed.payload = changed_payload;
        assert_eq!(
            verify_peer_envelope(&fixture.initiator_identity.public_key(), &changed),
            Err(PeerCryptoError::SignatureVerificationFailed)
        );
    }
}

#[test]
fn handshake_stream_datagram_and_directions_use_separate_keys() {
    let fixture = PeerFixture::new();
    let (initiator, responder) = fixture.keys("ssh");
    assert_ne!(initiator.handshake_tag(), responder.handshake_tag());

    let mut stream = initiator
        .stream_sealer(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    let mut datagram = initiator.datagram_sealer(9).unwrap();
    let stream_frame = stream.seal(7, b"same payload").unwrap();
    let datagram_frame = datagram.seal(7, b"same payload").unwrap();
    assert_ne!(stream_frame.ciphertext(), datagram_frame.ciphertext());

    let mut reverse = responder
        .stream_sealer(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    let reverse_frame = reverse.seal(7, b"same payload").unwrap();
    assert_ne!(stream_frame.ciphertext(), reverse_frame.ciphertext());
}

#[test]
fn stream_channels_do_not_reuse_the_same_key_and_nonce_pair() {
    let fixture = PeerFixture::new();
    let (initiator, _) = fixture.keys("ssh");
    let mut channel_9 = initiator
        .stream_sealer(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    let mut channel_10 = initiator
        .stream_sealer(10, PeerRelayFlags::RELIABLE)
        .unwrap();
    let frame_9 = channel_9.seal(7, b"same payload").unwrap();
    let frame_10 = channel_10.seal(7, b"same payload").unwrap();

    assert_ne!(
        &frame_9.ciphertext()[..b"same payload".len()],
        &frame_10.ciphertext()[..b"same payload".len()]
    );
}

#[test]
fn opener_rejects_replayed_sequence_and_ordered_gaps() {
    let fixture = PeerFixture::new();
    let (initiator, responder) = fixture.keys("ssh");
    let mut sealer = initiator
        .stream_sealer(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    let mut opener = responder
        .stream_opener(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    let frame_7 = sealer.seal(7, b"payload").unwrap();
    let frame_8 = sealer.seal(8, b"next").unwrap();

    assert_eq!(opener.open(&frame_7).unwrap(), b"payload");
    assert_eq!(opener.open(&frame_7), Err(PeerCryptoError::Replay));
    let skipped = PeerRelayFrame::new(
        frame_8.session_id,
        frame_8.channel_id,
        9,
        frame_8.flags,
        frame_8.ciphertext().to_vec(),
    )
    .unwrap();
    assert_eq!(
        opener.open(&skipped),
        Err(PeerCryptoError::UnexpectedSequence)
    );
    assert_eq!(opener.open(&frame_8).unwrap(), b"next");
}

#[test]
fn sealer_rejects_nonce_reuse_and_sequence_exhaustion() {
    let fixture = PeerFixture::new();
    let (initiator, _) = fixture.keys("ssh");
    let mut stream = initiator
        .stream_sealer(9, PeerRelayFlags::RELIABLE)
        .unwrap();
    stream.seal(7, b"payload").unwrap();
    assert_eq!(stream.seal(7, b"again"), Err(PeerCryptoError::Replay));
    assert_eq!(
        stream.seal(9, b"gap"),
        Err(PeerCryptoError::UnexpectedSequence)
    );

    let mut exhausted = initiator.datagram_sealer(10).unwrap();
    exhausted.seal(u64::MAX, b"last").unwrap();
    assert_eq!(
        exhausted.seal(u64::MAX, b"reuse"),
        Err(PeerCryptoError::Replay)
    );
    assert_eq!(
        exhausted.seal(0, b"wrapped"),
        Err(PeerCryptoError::SequenceExhausted)
    );
}

#[test]
fn datagram_opener_accepts_reordering_but_rejects_duplicate_and_too_old_frames() {
    let fixture = PeerFixture::new();
    let (initiator, responder) = fixture.keys("ssh");
    let mut sealer = initiator.datagram_sealer(9).unwrap();
    let frame_0 = sealer.seal(0, b"zero").unwrap();
    let frame_1 = sealer.seal(1, b"one").unwrap();
    let frame_2 = sealer.seal(2, b"two").unwrap();
    let frame_64 = sealer.seal(64, b"sixty-four").unwrap();
    let mut opener = responder.datagram_opener(9).unwrap();

    assert_eq!(opener.open(&frame_2).unwrap(), b"two");
    assert_eq!(opener.open(&frame_0).unwrap(), b"zero");
    assert_eq!(opener.open(&frame_1).unwrap(), b"one");
    assert_eq!(opener.open(&frame_1), Err(PeerCryptoError::Replay));
    assert_eq!(opener.open(&frame_64).unwrap(), b"sixty-four");
    assert_eq!(opener.open(&frame_0), Err(PeerCryptoError::Replay));
}

#[test]
fn bit_flipped_ciphertext_is_rejected_without_consuming_the_sequence() {
    let fixture = PeerFixture::new();
    let (initiator, responder) = fixture.keys("ssh");
    let mut sealer = initiator.datagram_sealer(9).unwrap();
    let frame = sealer.seal(7, b"payload").unwrap();
    let mut changed = frame.ciphertext().to_vec();
    changed[0] ^= 1;
    let changed =
        PeerRelayFrame::new(session_id(0x42), 9, 7, PeerRelayFlags::DATAGRAM, changed).unwrap();
    let mut opener = responder.datagram_opener(9).unwrap();

    assert_eq!(
        opener.open(&changed),
        Err(PeerCryptoError::FrameAuthenticationFailed)
    );
    assert_eq!(opener.open(&frame).unwrap(), b"payload");
}

#[test]
fn frame_header_and_canonical_context_are_authenticated() {
    let fixture = PeerFixture::new();
    let (initiator, responder) = fixture.keys("ssh");
    let mut sealer = initiator.datagram_sealer(9).unwrap();
    let frame = sealer.seal(7, b"payload").unwrap();
    let altered_channel = PeerRelayFrame::new(
        session_id(0x42),
        10,
        7,
        PeerRelayFlags::DATAGRAM,
        frame.ciphertext().to_vec(),
    )
    .unwrap();
    let altered_session = PeerRelayFrame::new(
        session_id(0x43),
        9,
        7,
        PeerRelayFlags::DATAGRAM,
        frame.ciphertext().to_vec(),
    )
    .unwrap();
    let mut opener = responder.datagram_opener(9).unwrap();

    assert_eq!(
        opener.open(&altered_channel),
        Err(PeerCryptoError::FrameContextMismatch)
    );
    assert_eq!(
        opener.open(&altered_session),
        Err(PeerCryptoError::FrameContextMismatch)
    );

    let (_, wrong_responder) = fixture.keys("admin");
    let mut wrong_context = wrong_responder.datagram_opener(9).unwrap();
    assert_eq!(
        wrong_context.open(&frame),
        Err(PeerCryptoError::FrameAuthenticationFailed)
    );
}

#[test]
fn secret_debug_and_errors_do_not_expose_key_or_payload_bytes() {
    let fixture = PeerFixture::new();
    let (keys, _) = fixture.keys("ssh");
    let ephemeral_debug = format!("{:?}", fixture.initiator_ephemeral);
    let keys_debug = format!("{keys:?}");
    let error = format!("{:?}", PeerCryptoError::FrameAuthenticationFailed);

    assert_eq!(ephemeral_debug, "EphemeralPeerKey([REDACTED])");
    assert_eq!(keys_debug, "PeerSessionKeys([REDACTED])");
    assert!(!ephemeral_debug.contains("44444444"));
    assert!(!keys_debug.contains("payload"));
    assert_eq!(error, "FrameAuthenticationFailed");
}

proptest! {
    #[test]
    fn arbitrary_single_bit_ciphertext_corruption_is_rejected(
        payload in prop::collection::vec(any::<u8>(), 1..512),
        byte_offset in any::<usize>(),
        bit in 0_u8..8,
    ) {
        let fixture = PeerFixture::new();
        let (initiator, responder) = fixture.keys("ssh");
        let mut sealer = initiator.datagram_sealer(9).unwrap();
        let frame = sealer.seal(7, &payload).unwrap();
        let mut ciphertext = frame.ciphertext().to_vec();
        let index = byte_offset % ciphertext.len();
        ciphertext[index] ^= 1 << bit;
        let corrupted = PeerRelayFrame::new(
            session_id(0x42),
            9,
            7,
            PeerRelayFlags::DATAGRAM,
            ciphertext,
        ).unwrap();
        let mut opener = responder.datagram_opener(9).unwrap();

        prop_assert_eq!(
            opener.open(&corrupted),
            Err(PeerCryptoError::FrameAuthenticationFailed),
        );
        prop_assert_eq!(opener.open(&frame).unwrap(), payload);
    }
}

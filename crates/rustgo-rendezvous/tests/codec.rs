use rustgo_protocol::{
    BoundedBytes, BoundedString, BoundedVec, FrameCodec, Message, MessageId, ProtocolVersion,
    SocketAddress, TunnelProtocol,
};
use rustgo_rendezvous::{
    Candidate, CandidateGeneration, CandidateSet, CandidateTransport, ConnectivityResult,
    MAX_CANDIDATES, MAX_DEVICE_NAME_BYTES, MAX_PEER_RELAY_CIPHERTEXT_BYTES, PeerRelayFlags,
    PeerRelayFrame, ProviderDecision, RelayRequest, RendezvousClose, RendezvousEnvelope,
    RendezvousError, RendezvousPayload, RendezvousRequest, SessionId, WireError,
};
use serde::Serialize;

fn session_id() -> SessionId {
    SessionId::from([0x42; 32])
}

fn candidate() -> Candidate {
    Candidate {
        transport: CandidateTransport::QuicUdp,
        address: SocketAddress::V4 {
            octets: [192, 0, 2, 7],
            port: 7443,
        },
        priority: 100,
        foundation: BoundedString::try_from("observed-udp").unwrap(),
        generation: CandidateGeneration::new(1).unwrap(),
        expires_unix_secs: 2_000,
        observation_source: BoundedString::try_from("rustgos:7443/udp").unwrap(),
    }
}

fn request_envelope() -> RendezvousEnvelope {
    RendezvousEnvelope {
        version: ProtocolVersion::V0_2,
        session_id: session_id(),
        sender: BoundedString::try_from("laptop").unwrap(),
        target: BoundedString::try_from("office-pc").unwrap(),
        step: 1,
        generation: CandidateGeneration::new(1).unwrap(),
        expires_unix_secs: 2_000,
        payload: RendezvousPayload::Request(RendezvousRequest {
            export: BoundedString::try_from("ssh").unwrap(),
            protocol: TunnelProtocol::TCP,
        }),
        signature: BoundedBytes::try_from(vec![0x5a; 64]).unwrap(),
    }
}

#[test]
fn candidate_collection_accepts_thirty_two_entries() {
    let candidates = vec![candidate(); MAX_CANDIDATES];
    assert!(BoundedVec::<_, MAX_CANDIDATES>::try_from(candidates).is_ok());
}

#[test]
fn candidate_collection_rejects_the_thirty_third_entry() {
    let candidates = vec![candidate(); MAX_CANDIDATES + 1];
    assert!(BoundedVec::<_, MAX_CANDIDATES>::try_from(candidates).is_err());
}

#[test]
fn device_names_are_bounded_to_128_utf8_bytes() {
    assert!(BoundedString::<MAX_DEVICE_NAME_BYTES>::try_from("a".repeat(128).as_str()).is_ok());
    assert!(BoundedString::<MAX_DEVICE_NAME_BYTES>::try_from("a".repeat(129).as_str()).is_err());
}

#[test]
fn candidate_set_round_trips_through_the_real_frame_codec() {
    let mut envelope = request_envelope();
    envelope.payload = RendezvousPayload::CandidateSet(CandidateSet {
        ephemeral_public_key: BoundedBytes::try_from(vec![0x24; 32]).unwrap(),
        candidates: BoundedVec::try_from(vec![candidate()]).unwrap(),
    });
    envelope.step = 3;

    let codec = FrameCodec::new(70_000);
    let message = envelope.to_protocol_message().unwrap();
    let encoded = codec.encode(ProtocolVersion::V0_2, 0, &message).unwrap();
    let decoded = codec.decode_exact(&encoded).unwrap();

    assert_eq!(decoded.version, ProtocolVersion::new(1, 1));
    assert_eq!(decoded.message.id().as_u16(), 17);
    assert_eq!(
        RendezvousEnvelope::from_protocol_message(decoded.message).unwrap(),
        envelope
    );
}

#[test]
fn every_rendezvous_payload_uses_its_stable_outer_id_and_round_trips() {
    let payloads = [
        RendezvousPayload::Request(RendezvousRequest {
            export: BoundedString::try_from("ssh").unwrap(),
            protocol: TunnelProtocol::TCP,
        }),
        RendezvousPayload::ProviderDecision(ProviderDecision {
            accepted: true,
            detail: None,
        }),
        RendezvousPayload::CandidateSet(CandidateSet {
            ephemeral_public_key: BoundedBytes::try_from(vec![3; 32]).unwrap(),
            candidates: BoundedVec::try_from(vec![candidate()]).unwrap(),
        }),
        RendezvousPayload::ConnectivityResult(ConnectivityResult {
            connected: true,
            transport: Some(CandidateTransport::NativeTcp),
            detail: None,
        }),
        RendezvousPayload::RelayRequest(RelayRequest { datagram: true }),
        RendezvousPayload::Close(RendezvousClose { detail: None }),
        RendezvousPayload::Error(RendezvousError {
            code: 7,
            detail: BoundedString::try_from("peer unavailable").unwrap(),
        }),
    ];
    let codec = FrameCodec::new(70_000);

    for (offset, payload) in payloads.into_iter().enumerate() {
        let mut envelope = request_envelope();
        envelope.payload = payload;
        let expected_id = 15 + u16::try_from(offset).unwrap();
        let bytes = codec
            .encode(
                ProtocolVersion::V0_2,
                0,
                &envelope.to_protocol_message().unwrap(),
            )
            .unwrap();
        let frame = codec.decode_exact(&bytes).unwrap();

        assert_eq!(frame.message.id().as_u16(), expected_id);
        assert_eq!(
            RendezvousEnvelope::from_protocol_message(frame.message).unwrap(),
            envelope
        );
    }
}

#[test]
fn inner_payload_must_match_the_outer_message_id() {
    let envelope = request_envelope();
    let Message::RendezvousRequest(opaque) = envelope.to_protocol_message().unwrap() else {
        panic!("request must map to request message ID");
    };

    assert_eq!(
        RendezvousEnvelope::from_protocol_message(Message::RendezvousClose(opaque)),
        Err(WireError::MessageIdMismatch {
            expected: MessageId::RENDEZVOUS_REQUEST,
            actual: MessageId::RENDEZVOUS_CLOSE,
        })
    );
}

#[test]
fn v01_and_v02_message_ids_are_stable() {
    let expected = [
        (MessageId::CLIENT_HELLO, 1),
        (MessageId::SERVER_CHALLENGE, 2),
        (MessageId::CLIENT_AUTHENTICATE, 3),
        (MessageId::AUTH_RESULT, 4),
        (MessageId::REGISTER_TUNNELS, 5),
        (MessageId::TUNNEL_RESULTS, 6),
        (MessageId::OPEN_TCP_STREAM, 7),
        (MessageId::TCP_STREAM_READY, 8),
        (MessageId::UDP_DATAGRAM, 9),
        (MessageId::HEARTBEAT, 10),
        (MessageId::ERROR, 11),
        (MessageId::OPEN_UDP_CHANNEL, 12),
        (MessageId::DATA_CHANNEL_BIND, 13),
        (MessageId::UDP_SESSION_RETIRED, 14),
        (MessageId::RENDEZVOUS_REQUEST, 15),
        (MessageId::RENDEZVOUS_PROVIDER_DECISION, 16),
        (MessageId::RENDEZVOUS_CANDIDATE_SET, 17),
        (MessageId::RENDEZVOUS_CONNECTIVITY_RESULT, 18),
        (MessageId::RENDEZVOUS_RELAY_REQUEST, 19),
        (MessageId::RENDEZVOUS_CLOSE, 20),
        (MessageId::RENDEZVOUS_ERROR, 21),
        (MessageId::PEER_RELAY_FRAME, 22),
    ];

    for (id, numeric) in expected {
        assert_eq!(id.as_u16(), numeric);
        assert_eq!(MessageId::try_from(numeric), Ok(id));
    }
}

#[test]
fn peer_relay_frame_round_trips_as_opaque_ciphertext() {
    let relay = PeerRelayFrame::new(
        session_id(),
        9,
        17,
        PeerRelayFlags::DATAGRAM,
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap();
    let codec = FrameCodec::new(70_000);
    let encoded = codec
        .encode(
            ProtocolVersion::V0_2,
            0,
            &relay.to_protocol_message().unwrap(),
        )
        .unwrap();
    let decoded = codec.decode_exact(&encoded).unwrap();

    assert_eq!(decoded.message.id(), MessageId::PEER_RELAY_FRAME);
    assert_eq!(
        PeerRelayFrame::from_protocol_message(decoded.message).unwrap(),
        relay
    );
    assert_eq!(relay.ciphertext_len(), 4);
    assert_eq!(relay.ciphertext(), &[0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn peer_relay_ciphertext_has_a_hard_ceiling() {
    let maximum = PeerRelayFrame::new(
        session_id(),
        1,
        u64::MAX,
        PeerRelayFlags::RELIABLE,
        vec![0; MAX_PEER_RELAY_CIPHERTEXT_BYTES],
    )
    .unwrap();
    assert!(maximum.to_protocol_message().is_ok());
    assert!(
        PeerRelayFrame::new(
            session_id(),
            1,
            0,
            PeerRelayFlags::RELIABLE,
            vec![0; MAX_PEER_RELAY_CIPHERTEXT_BYTES + 1],
        )
        .is_err()
    );
}

#[test]
fn peer_relay_rejects_zero_flow_ids_and_unknown_flags() {
    assert!(PeerRelayFrame::new(session_id(), 0, 0, PeerRelayFlags::RELIABLE, vec![1],).is_err());
    assert!(PeerRelayFlags::try_from(0x80).is_err());
}

#[test]
fn peer_relay_decode_rejects_a_mismatched_explicit_ciphertext_length() {
    #[derive(Serialize)]
    struct InvalidRelayWire {
        session_id: SessionId,
        channel_id: u64,
        sequence: u64,
        flags: PeerRelayFlags,
        ciphertext_len: u32,
        ciphertext: BoundedBytes<MAX_PEER_RELAY_CIPHERTEXT_BYTES>,
    }

    let invalid = postcard::to_allocvec(&InvalidRelayWire {
        session_id: session_id(),
        channel_id: 1,
        sequence: 2,
        flags: PeerRelayFlags::RELIABLE,
        ciphertext_len: 5,
        ciphertext: BoundedBytes::try_from(vec![1, 2, 3, 4]).unwrap(),
    })
    .unwrap();
    let message = Message::PeerRelayFrame(BoundedBytes::try_from(invalid).unwrap());

    assert_eq!(
        PeerRelayFrame::from_protocol_message(message),
        Err(WireError::Decode)
    );
}

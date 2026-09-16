use rustgo_protocol::*;

fn raw_frame(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = b"RSGO\0\x01\0\x04".to_vec();
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn managed_editing_wire_ids_decode() {
    let codec = FrameCodec::new(128 * 1024);
    for (id, payload) in [
        (36, postcard::to_allocvec(&(1u64, vec![b'a'])).unwrap()),
        (37, postcard::to_allocvec(&(2u64, None::<String>)).unwrap()),
    ] {
        let decoded = codec.decode_exact(&raw_frame(id, &payload)).unwrap();
        assert_eq!(decoded.message.id().as_u16(), id);
    }
}

#[test]
fn managed_editing_roundtrips_at_bounds() {
    let codec = FrameCodec::new(128 * 1024);
    for size in [0, MAX_MANAGED_CONFIGURATION_BYTES] {
        let message = Message::ManagedConfigUpdate(ManagedConfigUpdate {
            expected_revision: u64::MAX,
            configuration: vec![b'a'; size].try_into().unwrap(),
        });
        let encoded = codec.encode(ProtocolVersion::V0_5, 0, &message).unwrap();
        assert_eq!(codec.decode_exact(&encoded).unwrap().message, message);
        if size == MAX_MANAGED_CONFIGURATION_BYTES {
            assert_eq!(encoded.len() - 16, message.id().max_payload());
        }
    }
    for error in [None, Some(""), Some("x".repeat(1024).as_str())] {
        let message = Message::ManagedConfigUpdateResult(ManagedConfigUpdateResult {
            revision: u64::MAX,
            error: error.map(|value| value.try_into().unwrap()),
        });
        let encoded = codec.encode(ProtocolVersion::V0_5, 0, &message).unwrap();
        assert_eq!(codec.decode_exact(&encoded).unwrap().message, message);
        if error.is_some_and(|error| error.len() == 1024) {
            assert_eq!(encoded.len() - 16, message.id().max_payload());
        }
    }
}

#[test]
fn managed_editing_rejects_oversize_inner_fields_and_invalid_option() {
    let codec = FrameCodec::new(128 * 1024);
    for (id, payload) in [
        (
            36,
            postcard::to_allocvec(&(0u64, vec![0u8; 65537])).unwrap(),
        ),
        (
            37,
            postcard::to_allocvec(&(0u64, Some("x".repeat(1025)))).unwrap(),
        ),
        (37, vec![0, 2]),
    ] {
        assert!(matches!(
            codec.decode_exact(&raw_frame(id, &payload)),
            Err(FrameError::MalformedPayload { .. })
        ));
    }
}

#[test]
fn managed_editing_requires_version_authenticated_phase_and_direction() {
    use ControlMessageDirection::{ClientToServer as C, ServerToClient as S};
    let session_id = BoundedBytes::try_from(vec![1]).unwrap();
    let states = [
        ClientHandshakeState::AwaitingHello,
        ClientHandshakeState::AwaitingChallenge,
        ClientHandshakeState::AwaitingAuthenticate {
            session_id: session_id.clone(),
        },
        ClientHandshakeState::AwaitingAuthResult {
            session_id: session_id.clone(),
        },
        ClientHandshakeState::AwaitingTunnelRegistration {
            session_id: session_id.clone(),
        },
        ClientHandshakeState::Active { session_id },
        ClientHandshakeState::Rejected,
    ];
    let messages = [
        (
            Message::ManagedConfigUpdate(ManagedConfigUpdate {
                expected_revision: 1,
                configuration: vec![].try_into().unwrap(),
            }),
            C,
        ),
        (
            Message::ManagedConfigUpdateResult(ManagedConfigUpdateResult {
                revision: 2,
                error: None,
            }),
            S,
        ),
    ];
    assert_eq!(ProtocolVersion::SUPPORTED, ProtocolVersion::V0_6);
    assert_eq!(
        ProtocolVersion::V0_5.negotiate(ProtocolVersion::V0_4),
        Ok(ProtocolVersion::V0_4)
    );
    for (version, supported) in [
        (ProtocolVersion::V0_1, false),
        (ProtocolVersion::V0_2, false),
        (ProtocolVersion::V0_3, false),
        (ProtocolVersion::V0_4, false),
        (ProtocolVersion::V0_5, true),
        (ProtocolVersion::new(1, 5), true),
        (ProtocolVersion::new(2, 4), false),
    ] {
        assert_eq!(version.supports_managed_editing(), supported);
        for state in &states {
            for direction in [C, S] {
                for (message, expected_direction) in &messages {
                    let result = state.transition_control(version, direction, message);
                    if supported
                        && matches!(
                            state,
                            ClientHandshakeState::AwaitingTunnelRegistration { .. }
                        )
                        && direction == *expected_direction
                    {
                        assert_eq!(result, Ok(state.clone()));
                    } else {
                        assert_eq!(result, Err(StateError::invalid_state()));
                    }
                    assert!(state.transition(message).is_err());
                }
            }
        }
    }
}

#[test]
fn v04_managed_wire_payloads_remain_unchanged() {
    let codec = FrameCodec::new(128 * 1024);
    for (message, expected) in [
        (
            Message::ManagedConfigRequest(ManagedConfigRequest {
                configuration: vec![b'a'].try_into().unwrap(),
            }),
            vec![1, b'a'],
        ),
        (
            Message::ManagedConfigSnapshot(ManagedConfigSnapshot {
                revision: 1,
                configuration: Some(vec![b'a'].try_into().unwrap()),
            }),
            vec![1, 1, 1, b'a'],
        ),
        (
            Message::ManagedConfigReport(ManagedConfigReport {
                revision: 1,
                results: vec![b'a'].try_into().unwrap(),
            }),
            vec![1, 1, b'a'],
        ),
    ] {
        let encoded = codec.encode(ProtocolVersion::V0_4, 0, &message).unwrap();
        assert_eq!(&encoded[16..], &expected);
    }
}

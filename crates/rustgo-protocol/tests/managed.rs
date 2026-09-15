use rustgo_protocol::*;

#[test]
fn managed_messages_roundtrip_and_bound_payloads() {
    let codec = FrameCodec::new(128 * 1024);
    for size in [0, 65536] {
        let data = BoundedBytes::try_from(vec![b' '; size]).unwrap();
        for message in [
            Message::ManagedConfigRequest(ManagedConfigRequest {
                configuration: data.clone(),
            }),
            Message::ManagedConfigSnapshot(ManagedConfigSnapshot {
                revision: u64::MAX,
                configuration: Some(data.clone()),
            }),
            Message::ManagedConfigReport(ManagedConfigReport {
                revision: u64::MAX,
                results: data,
            }),
            Message::ManagedConfigSnapshot(ManagedConfigSnapshot {
                revision: 0,
                configuration: None,
            }),
        ] {
            let encoded = codec.encode(ProtocolVersion::V0_4, 0, &message).unwrap();
            assert_eq!(codec.decode_exact(&encoded).unwrap().message, message);
        }
    }
    assert!(BoundedBytes::<65536>::try_from(vec![0; 65537]).is_err());
    // A valid postcard byte vector above the JSON bound must fail on decode.
    let payload = postcard::to_allocvec(&vec![0u8; 65537]).unwrap();
    let mut frame = b"RSGO\0\x01\0\x03\0\x21\0\0".to_vec();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend(payload);
    assert!(codec.decode_exact(&frame).is_err());
}

#[test]
fn managed_messages_require_version_phase_and_direction() {
    use ControlMessageDirection::{ClientToServer as C, ServerToClient as S};
    let session_id = BoundedBytes::try_from(vec![1]).unwrap();
    let pre = ClientHandshakeState::AwaitingTunnelRegistration {
        session_id: session_id.clone(),
    };
    let active = ClientHandshakeState::Active { session_id };
    let request = Message::ManagedConfigRequest(ManagedConfigRequest {
        configuration: BoundedBytes::try_from(vec![]).unwrap(),
    });
    let snapshot = Message::ManagedConfigSnapshot(ManagedConfigSnapshot {
        revision: 1,
        configuration: None,
    });
    let report = Message::ManagedConfigReport(ManagedConfigReport {
        revision: 1,
        results: BoundedBytes::try_from(vec![]).unwrap(),
    });
    assert!(!ProtocolVersion::V0_3.supports_managed_configuration());
    assert!(ProtocolVersion::V0_4.supports_managed_configuration());
    assert_eq!(
        ProtocolVersion::SUPPORTED.negotiate(ProtocolVersion::V0_3),
        Ok(ProtocolVersion::V0_3)
    );
    for version in [
        ProtocolVersion::V0_1,
        ProtocolVersion::V0_2,
        ProtocolVersion::V0_3,
        ProtocolVersion::V0_4,
    ] {
        for (index, state) in [
            ClientHandshakeState::new(),
            pre.clone(),
            active.clone(),
            ClientHandshakeState::Rejected,
        ]
        .iter()
        .enumerate()
        {
            for direction in [C, S] {
                for (message, phase, allowed_direction) in
                    [(&request, 1, C), (&snapshot, 1, S), (&report, 2, C)]
                {
                    assert_eq!(
                        state
                            .transition_control(version, direction, message)
                            .is_ok(),
                        version == ProtocolVersion::V0_4
                            && index == phase
                            && direction == allowed_direction
                    );
                    assert!(state.transition(message).is_err());
                }
            }
        }
    }
}

#[test]
fn managed_inner_bounds_and_option_tags_are_checked_on_decode() {
    let codec = FrameCodec::new(128 * 1024);
    for (id, payload) in [
        (
            34u16,
            postcard::to_allocvec(&(0u64, Some(vec![0u8; 65537]))).unwrap(),
        ),
        (
            35u16,
            postcard::to_allocvec(&(0u64, vec![0u8; 65537])).unwrap(),
        ),
        (34u16, vec![0, 2]), // invalid Option discriminant
    ] {
        let mut frame = b"RSGO\0\x01\0\x03".to_vec();
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend(payload);
        assert!(matches!(
            codec.decode_exact(&frame),
            Err(FrameError::MalformedPayload { .. })
        ));
    }
}

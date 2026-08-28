use bytes::BytesMut;
use proptest::prelude::*;
use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, BoundedVec, ClientAuthenticate, ClientHello,
    DataChannelBind, DataChannelKind, ErrorMessage, FrameCodec, FrameError, HEADER_LEN, Heartbeat,
    MAGIC, MAX_BINDING_TOKEN_BYTES, MAX_OBSERVATION_GRANT_BYTES, MAX_UDP_PAYLOAD_BYTES, Message,
    MessageId, ObservationGrantRequest, OpenTcpStream, OpenUdpChannel, ProtocolErrorCode,
    ProtocolVersion, RegisterTunnels, ServerChallenge, SocketAddress, TcpStreamReady,
    TunnelProtocol, TunnelRegistration, TunnelResult, TunnelResults, UDP_METADATA_LEN, UdpDatagram,
    UdpSessionRetired,
};

const VERSION: ProtocolVersion = ProtocolVersion::new(1, 7);

fn text<const MAX: usize>(value: &str) -> BoundedString<MAX> {
    BoundedString::try_from(value).expect("fixture is within its bound")
}

fn bytes<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(value).expect("fixture is within its bound")
}

fn messages() -> Vec<Message> {
    let tunnel = TunnelRegistration {
        tunnel_id: 41,
        name: text("ssh"),
        protocol: TunnelProtocol::TCP,
        remote_port: 2222,
    };
    vec![
        Message::ClientHello(ClientHello {
            client_name: text("home-pc"),
            fingerprint: bytes(&[0x11; 32]),
            heartbeat_interval_secs: 20,
        }),
        Message::ServerChallenge(ServerChallenge {
            challenge: bytes(&[0x22; 32]),
            session_id: bytes(&[0x33; 16]),
        }),
        Message::ClientAuthenticate(ClientAuthenticate {
            public_key: bytes(&[0x44; 32]),
            signature: bytes(&[0x55; 64]),
        }),
        Message::AuthResult(AuthResult {
            accepted: true,
            error: None,
        }),
        Message::RegisterTunnels(RegisterTunnels {
            tunnels: BoundedVec::try_from(vec![tunnel.clone()]).expect("bounded fixture"),
        }),
        Message::TunnelResults(TunnelResults {
            results: BoundedVec::try_from(vec![TunnelResult {
                tunnel_id: tunnel.tunnel_id,
                accepted: false,
                error: Some(ProtocolErrorCode::TUNNEL_REJECTED),
            }])
            .expect("bounded fixture"),
        }),
        Message::OpenTcpStream(OpenTcpStream {
            tunnel_id: 41,
            connection_id: 9001,
            peer: SocketAddress::V4 {
                octets: [203, 0, 113, 8],
                port: 53_120,
            },
            binding_token: bytes(&[0x66; MAX_BINDING_TOKEN_BYTES]),
        }),
        Message::TcpStreamReady(TcpStreamReady {
            connection_id: 9001,
            accepted: true,
            error: None,
        }),
        Message::UdpDatagram(UdpDatagram {
            tunnel_id: 42,
            session_id: 73,
            source: SocketAddress::V6 {
                octets: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10],
                port: 27_015,
            },
            payload: bytes(&[0, 1, 2, 0xff]),
        }),
        Message::Heartbeat(Heartbeat { sequence: 17 }),
        Message::Error(ErrorMessage {
            code: ProtocolErrorCode::INVALID_STATE,
            detail: text("out-of-order message"),
        }),
        Message::OpenUdpChannel(OpenUdpChannel {
            tunnel_id: 42,
            channel_id: 9002,
            binding_token: bytes(&[0x77; MAX_BINDING_TOKEN_BYTES]),
            max_sessions: 1024,
            idle_timeout_millis: 60_000,
            max_payload_bytes: 65_507,
            queue_capacity: 1024,
        }),
        Message::UdpSessionRetired(UdpSessionRetired {
            tunnel_id: 42,
            session_id: 73,
        }),
        Message::DataChannelBind(DataChannelBind {
            client_name: text("home-pc"),
            session_id: bytes(&[0x88; 32]),
            kind: DataChannelKind::TCP,
            tunnel_id: 41,
            target_id: 9001,
            binding_token: bytes(&[0x99; MAX_BINDING_TOKEN_BYTES]),
        }),
        Message::ObservationGrantRequest(ObservationGrantRequest {}),
        Message::ObservationGrant(bytes::<MAX_OBSERVATION_GRANT_BYTES>(&[0xaa; 72])),
    ]
}

#[test]
fn every_message_family_round_trips() {
    let codec = FrameCodec::new(4096);

    for message in messages() {
        let encoded = codec.encode(VERSION, 0, &message).unwrap();
        let decoded = codec.decode_exact(&encoded).unwrap();
        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.message, message);
    }
}

#[test]
fn header_uses_fixed_magic_and_network_byte_order() {
    let codec = FrameCodec::new(4096);
    let encoded = codec
        .encode(VERSION, 0, &Message::Heartbeat(Heartbeat { sequence: 17 }))
        .unwrap();

    assert_eq!(HEADER_LEN, 16);
    assert_eq!(&encoded[0..4], &MAGIC);
    assert_eq!(&encoded[4..6], &[0, 1]);
    assert_eq!(&encoded[6..8], &[0, 7]);
    assert_eq!(&encoded[8..10], &[0, 10]);
    assert_eq!(&encoded[10..12], &[0, 0]);
    assert_eq!(
        u32::from_be_bytes(encoded[12..16].try_into().unwrap()) as usize,
        encoded.len() - HEADER_LEN
    );
}

#[test]
fn message_ids_are_explicit_and_stable() {
    assert_eq!(MessageId::CLIENT_HELLO.as_u16(), 1);
    assert_eq!(MessageId::SERVER_CHALLENGE.as_u16(), 2);
    assert_eq!(MessageId::CLIENT_AUTHENTICATE.as_u16(), 3);
    assert_eq!(MessageId::AUTH_RESULT.as_u16(), 4);
    assert_eq!(MessageId::REGISTER_TUNNELS.as_u16(), 5);
    assert_eq!(MessageId::TUNNEL_RESULTS.as_u16(), 6);
    assert_eq!(MessageId::OPEN_TCP_STREAM.as_u16(), 7);
    assert_eq!(MessageId::TCP_STREAM_READY.as_u16(), 8);
    assert_eq!(MessageId::UDP_DATAGRAM.as_u16(), 9);
    assert_eq!(MessageId::HEARTBEAT.as_u16(), 10);
    assert_eq!(MessageId::ERROR.as_u16(), 11);
    assert_eq!(MessageId::OPEN_UDP_CHANNEL.as_u16(), 12);
    assert_eq!(MessageId::DATA_CHANNEL_BIND.as_u16(), 13);
    assert_eq!(MessageId::UDP_SESSION_RETIRED.as_u16(), 14);
    assert_eq!(MessageId::RENDEZVOUS_REQUEST.as_u16(), 15);
    assert_eq!(MessageId::RENDEZVOUS_PROVIDER_DECISION.as_u16(), 16);
    assert_eq!(MessageId::RENDEZVOUS_CANDIDATE_SET.as_u16(), 17);
    assert_eq!(MessageId::RENDEZVOUS_CONNECTIVITY_RESULT.as_u16(), 18);
    assert_eq!(MessageId::RENDEZVOUS_RELAY_REQUEST.as_u16(), 19);
    assert_eq!(MessageId::RENDEZVOUS_CLOSE.as_u16(), 20);
    assert_eq!(MessageId::RENDEZVOUS_ERROR.as_u16(), 21);
    assert_eq!(MessageId::PEER_RELAY_FRAME.as_u16(), 22);
    assert_eq!(MessageId::OBSERVATION_GRANT_REQUEST.as_u16(), 23);
    assert_eq!(MessageId::OBSERVATION_GRANT.as_u16(), 24);
}

#[test]
fn v02_is_supported_without_changing_the_major_version() {
    assert_eq!(ProtocolVersion::V0_1, ProtocolVersion::new(1, 0));
    assert_eq!(ProtocolVersion::V0_2, ProtocolVersion::new(1, 1));
    assert_eq!(ProtocolVersion::SUPPORTED, ProtocolVersion::V0_2);
}

#[test]
fn udp_channel_limits_and_retirement_round_trip_as_bounded_explicit_messages() {
    let codec = FrameCodec::new(4096);
    let open = Message::OpenUdpChannel(OpenUdpChannel {
        tunnel_id: 7,
        channel_id: 9,
        binding_token: bytes(&[0xA5; MAX_BINDING_TOKEN_BYTES]),
        max_sessions: 1,
        idle_timeout_millis: 150,
        max_payload_bytes: 16,
        queue_capacity: 1,
    });
    let retired = Message::UdpSessionRetired(UdpSessionRetired {
        tunnel_id: 7,
        session_id: 11,
    });

    for message in [open, retired] {
        let encoded = codec.encode(VERSION, 0, &message).unwrap();
        assert_eq!(codec.decode_exact(&encoded).unwrap().message, message);
    }
}

#[test]
fn udp_negotiation_and_retirement_reject_invalid_numeric_metadata_on_decode() {
    let codec = FrameCodec::new(4096);
    let valid_open = OpenUdpChannel {
        tunnel_id: 7,
        channel_id: 9,
        binding_token: bytes(&[0xA5; MAX_BINDING_TOKEN_BYTES]),
        max_sessions: 1,
        idle_timeout_millis: 150,
        max_payload_bytes: 16,
        queue_capacity: 1,
    };
    let invalid_retirement = Message::UdpSessionRetired(UdpSessionRetired {
        tunnel_id: 7,
        session_id: 0,
    });

    let invalid_messages = [
        Message::OpenUdpChannel(OpenUdpChannel {
            tunnel_id: 0,
            ..valid_open.clone()
        }),
        Message::OpenUdpChannel(OpenUdpChannel {
            channel_id: 0,
            ..valid_open.clone()
        }),
        Message::OpenUdpChannel(OpenUdpChannel {
            max_sessions: 0,
            ..valid_open
        }),
        invalid_retirement,
    ];
    for message in invalid_messages {
        let message_id = message.id();
        let encoded = codec.encode(VERSION, 0, &message).unwrap();
        assert_eq!(
            codec.decode_exact(&encoded),
            Err(FrameError::MalformedPayload {
                message: message_id
            })
        );
    }
}

#[test]
fn udp_datagrams_reject_zero_tunnel_and_session_ids_on_encode() {
    let codec = FrameCodec::new(4096);
    for (tunnel_id, session_id) in [(0, 1), (1, 0)] {
        let message = Message::UdpDatagram(UdpDatagram {
            tunnel_id,
            session_id,
            source: SocketAddress::V4 {
                octets: [127, 0, 0, 1],
                port: 53,
            },
            payload: bytes(&[1]),
        });
        assert_eq!(
            codec.encode(VERSION, 0, &message),
            Err(FrameError::MalformedPayload {
                message: MessageId::UDP_DATAGRAM
            })
        );
    }
}

#[test]
fn tls_data_channel_has_an_explicit_first_frame_message_id() {
    assert_eq!(MessageId::try_from(13).map(MessageId::as_u16), Ok(13));
}

#[test]
fn data_channel_bind_first_frame_decodes_from_its_stable_wire_shape() {
    let payload = [1, b'a', 1, 2, 1, 1, 1, 1, 3];
    let mut encoded = Vec::from(MAGIC);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&13_u16.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&payload);

    let decoded = FrameCodec::new(4096).decode_exact(&encoded).unwrap();
    assert_eq!(
        decoded.message,
        Message::DataChannelBind(DataChannelBind {
            client_name: text("a"),
            session_id: bytes(&[2]),
            kind: DataChannelKind::TCP,
            tunnel_id: 1,
            target_id: 1,
            binding_token: bytes(&[3]),
        })
    );
}

#[test]
fn oversized_declared_length_is_rejected_from_header_alone() {
    let codec = FrameCodec::new(128);
    let mut header = [0_u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&1_u16.to_be_bytes());
    header[6..8].copy_from_slice(&0_u16.to_be_bytes());
    header[8..10].copy_from_slice(&MessageId::HEARTBEAT.as_u16().to_be_bytes());
    header[12..16].copy_from_slice(&10_000_u32.to_be_bytes());

    assert_eq!(
        codec.decode_exact(&header),
        Err(FrameError::PayloadTooLarge {
            declared: 10_000,
            max: 128,
        })
    );
}

#[test]
fn per_message_limit_is_checked_before_waiting_for_payload() {
    let codec = FrameCodec::new(4096);
    let mut header = [0_u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&1_u16.to_be_bytes());
    header[8..10].copy_from_slice(&MessageId::HEARTBEAT.as_u16().to_be_bytes());
    header[12..16].copy_from_slice(&1024_u32.to_be_bytes());

    assert!(matches!(
        codec.decode_exact(&header),
        Err(FrameError::MessagePayloadTooLarge {
            message: MessageId::HEARTBEAT,
            declared: 1024,
            ..
        })
    ));
}

#[test]
fn truncated_unknown_and_malformed_frames_are_typed_errors() {
    let codec = FrameCodec::new(4096);
    assert_eq!(
        codec.decode_exact(&MAGIC),
        Err(FrameError::Truncated {
            needed: HEADER_LEN,
            available: MAGIC.len(),
        })
    );

    let mut unknown = [0_u8; HEADER_LEN];
    unknown[0..4].copy_from_slice(&MAGIC);
    unknown[4..6].copy_from_slice(&1_u16.to_be_bytes());
    unknown[8..10].copy_from_slice(&999_u16.to_be_bytes());
    assert_eq!(
        codec.decode_exact(&unknown),
        Err(FrameError::UnknownMessage(999))
    );

    let mut malformed = BytesMut::from(
        codec
            .encode(VERSION, 0, &Message::Heartbeat(Heartbeat { sequence: 1 }))
            .unwrap()
            .as_ref(),
    );
    malformed.truncate(malformed.len() - 1);
    assert!(matches!(
        codec.decode_exact(&malformed),
        Err(FrameError::Truncated { .. })
    ));
}

#[test]
fn invalid_magic_is_rejected() {
    let codec = FrameCodec::new(4096);
    let mut frame = codec
        .encode(VERSION, 0, &Message::Heartbeat(Heartbeat { sequence: 1 }))
        .unwrap()
        .to_vec();
    frame[0] ^= 0xff;
    assert_eq!(codec.decode_exact(&frame), Err(FrameError::InvalidMagic));
}

#[test]
fn encoder_rejects_unsupported_flags() {
    let codec = FrameCodec::new(4096);
    assert_eq!(
        codec.encode(VERSION, 1, &Message::Heartbeat(Heartbeat { sequence: 1 }),),
        Err(FrameError::UnsupportedFlags(1))
    );
}

#[test]
fn decoder_rejects_unsupported_flags_from_header_alone() {
    let codec = FrameCodec::new(4096);
    let mut header = [0_u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&1_u16.to_be_bytes());
    header[8..10].copy_from_slice(&MessageId::HEARTBEAT.as_u16().to_be_bytes());
    header[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
    header[12..16].copy_from_slice(&8_u32.to_be_bytes());

    assert_eq!(
        codec.decode_exact(&header),
        Err(FrameError::UnsupportedFlags(0x8000))
    );
}

#[test]
fn postcard_payload_with_internal_trailing_byte_is_rejected() {
    let codec = FrameCodec::new(4096);
    let mut frame = codec
        .encode(VERSION, 0, &Message::Heartbeat(Heartbeat { sequence: 1 }))
        .unwrap()
        .to_vec();
    let payload_len = u32::from_be_bytes(frame[12..16].try_into().unwrap());
    frame[12..16].copy_from_slice(&(payload_len + 1).to_be_bytes());
    frame.push(0);

    assert_eq!(
        codec.decode_exact(&frame),
        Err(FrameError::MalformedPayload {
            message: MessageId::HEARTBEAT,
        })
    );
}

#[test]
fn streaming_decoder_does_not_consume_a_complete_malformed_frame() {
    let codec = FrameCodec::new(4096);
    let mut input = BytesMut::from(
        codec
            .encode(VERSION, 0, &Message::Heartbeat(Heartbeat { sequence: 1 }))
            .unwrap()
            .as_ref(),
    );
    let original_len = input.len();
    *input.last_mut().unwrap() = 0x80;

    assert_eq!(
        codec.decode(&mut input),
        Err(FrameError::MalformedPayload {
            message: MessageId::HEARTBEAT,
        })
    );
    assert_eq!(input.len(), original_len);
}

#[test]
fn bounded_values_reject_oversized_construction() {
    assert!(BoundedBytes::<4>::try_from(&[0_u8; 5][..]).is_err());
    assert!(BoundedString::<4>::try_from("12345").is_err());
    assert!(BoundedVec::<u8, 4>::try_from(vec![0; 5]).is_err());
}

#[test]
fn data_channel_binding_tokens_are_bounded_wire_values() {
    assert!(
        BoundedBytes::<{ MAX_BINDING_TOKEN_BYTES }>::try_from(vec![0; MAX_BINDING_TOKEN_BYTES + 1])
            .is_err()
    );
}

proptest! {
    #[test]
    fn arbitrary_input_never_panics_or_requests_an_oversized_payload(
        input in proptest::collection::vec(any::<u8>(), 0..8192)
    ) {
        const MAX: usize = 256;
        let codec = FrameCodec::new(MAX);
        let result = std::panic::catch_unwind(|| codec.decode_exact(&input));
        prop_assert!(result.is_ok());
        if let Ok(Err(FrameError::Truncated { needed, available })) = result {
            prop_assert!(needed.saturating_sub(available) <= MAX);
        }
    }
}

#[test]
fn udp_payload_remains_binary() {
    let codec = FrameCodec::new(4096);
    let message = Message::UdpDatagram(UdpDatagram {
        tunnel_id: 1,
        session_id: 2,
        source: SocketAddress::V4 {
            octets: [127, 0, 0, 1],
            port: 53,
        },
        payload: bytes(&[0, 0xff, b'R', b'S', b'G', b'O']),
    });
    let encoded = codec.encode(VERSION, 0, &message).unwrap();
    assert_eq!(codec.decode_exact(&encoded).unwrap().message, message);
}

#[test]
fn udp_uses_fixed_big_endian_metadata_followed_by_raw_payload() {
    let codec = FrameCodec::new(70_000);
    let raw = [0, 0xff, b'R', b'S', b'G', b'O'];
    let message = Message::UdpDatagram(UdpDatagram {
        tunnel_id: 0x0102_0304,
        session_id: 0x0102_0304_0506_0708,
        source: SocketAddress::V4 {
            octets: [192, 0, 2, 10],
            port: 0x1234,
        },
        payload: bytes(&raw),
    });

    let encoded = codec.encode(VERSION, 0, &message).unwrap();
    let payload = &encoded[HEADER_LEN..];
    assert_eq!(UDP_METADATA_LEN, 31);
    assert_eq!(&payload[0..4], &[1, 2, 3, 4]);
    assert_eq!(&payload[4..12], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(payload[12], 4);
    assert_eq!(&payload[13..17], &[192, 0, 2, 10]);
    assert_eq!(&payload[17..29], &[0; 12]);
    assert_eq!(&payload[29..31], &[0x12, 0x34]);
    assert_eq!(&payload[UDP_METADATA_LEN..], &raw);
    assert_eq!(codec.decode_exact(&encoded).unwrap().message, message);
}

#[test]
fn udp_streaming_decode_waits_for_the_raw_payload_without_consuming() {
    let codec = FrameCodec::new(70_000);
    let message = Message::UdpDatagram(UdpDatagram {
        tunnel_id: 1,
        session_id: 2,
        source: SocketAddress::V6 {
            octets: [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 53,
        },
        payload: bytes(&[7, 8, 9]),
    });
    let encoded = codec.encode(VERSION, 0, &message).unwrap();
    let mut input = BytesMut::from(&encoded[..encoded.len() - 1]);

    assert_eq!(codec.decode(&mut input), Ok(None));
    assert_eq!(input.len(), encoded.len() - 1);
    input.extend_from_slice(&encoded[encoded.len() - 1..]);
    assert_eq!(codec.decode(&mut input).unwrap().unwrap().message, message);
    assert!(input.is_empty());
}

#[test]
fn udp_oversize_is_rejected_from_declared_length_before_payload_copy() {
    let codec = FrameCodec::new(70_000);
    let declared = UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES + 1;
    let mut header = [0_u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&1_u16.to_be_bytes());
    header[8..10].copy_from_slice(&MessageId::UDP_DATAGRAM.as_u16().to_be_bytes());
    header[12..16].copy_from_slice(&(declared as u32).to_be_bytes());

    assert_eq!(
        codec.decode_exact(&header),
        Err(FrameError::MessagePayloadTooLarge {
            message: MessageId::UDP_DATAGRAM,
            declared,
            max: UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES,
        })
    );
}

#[test]
fn udp_truncated_fixed_metadata_is_rejected() {
    let codec = FrameCodec::new(70_000);
    let declared = UDP_METADATA_LEN - 1;
    let mut frame = vec![0_u8; HEADER_LEN + declared];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4..6].copy_from_slice(&1_u16.to_be_bytes());
    frame[8..10].copy_from_slice(&MessageId::UDP_DATAGRAM.as_u16().to_be_bytes());
    frame[12..16].copy_from_slice(&(declared as u32).to_be_bytes());

    assert_eq!(
        codec.decode_exact(&frame),
        Err(FrameError::MalformedPayload {
            message: MessageId::UDP_DATAGRAM,
        })
    );
}

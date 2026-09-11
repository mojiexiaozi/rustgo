#![forbid(unsafe_code)]

use rustgo_protocol::{
    BoundedBytes, BoundedString, ENROLLMENT_PROTOCOL_VERSION, EnrollmentErrorCode,
    EnrollmentKeyMaterial, EnrollmentPurpose, EnrollmentRequest, EnrollmentResultMessage,
    FrameCodec, MAX_ENROLLMENT_KEY_BYTES, MAX_ENROLLMENT_REQUEST_ID_BYTES, MAX_PUBLIC_KEY_BYTES,
    Message, ProtocolVersion,
};

#[test]
fn enrollment_key_codec_round_trips_bounded_material() {
    let material = EnrollmentKeyMaterial::new(
        EnrollmentPurpose::Enroll,
        "Tunnel.Example.com:7443",
        [0x11; 32],
        [0x22; 32],
    )
    .unwrap();

    let encoded = material.encode();
    let decoded = EnrollmentKeyMaterial::decode(&encoded).unwrap();

    assert_eq!(decoded.server_addr(), "tunnel.example.com:7443");
    assert_eq!(decoded.certificate_fingerprint(), &[0x11; 32]);
    assert_eq!(decoded.purpose(), EnrollmentPurpose::Enroll);
    assert_eq!(decoded.token(), &[0x22; 32]);
}

#[test]
fn enrollment_messages_are_versioned_bounded_and_frame_round_trip() {
    let request = EnrollmentRequest {
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        enrollment_key: BoundedString::<MAX_ENROLLMENT_KEY_BYTES>::try_from("secret").unwrap(),
        public_key: BoundedBytes::<MAX_PUBLIC_KEY_BYTES>::try_from(b"public".as_slice()).unwrap(),
        request_id: BoundedString::<MAX_ENROLLMENT_REQUEST_ID_BYTES>::try_from("request-1")
            .unwrap(),
    };
    let message = Message::EnrollmentRequest(request.clone());
    let codec = FrameCodec::new(2048);
    let encoded = codec
        .encode(ProtocolVersion::SUPPORTED, 0, &message)
        .unwrap();
    assert_eq!(codec.decode_exact(&encoded).unwrap().message, message);
    assert!(!format!("{request:?}").contains("secret"));

    let result = Message::EnrollmentResult(EnrollmentResultMessage {
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        accepted: false,
        client_id: None,
        revision: None,
        error: Some(EnrollmentErrorCode::InvalidKey),
    });
    let encoded = codec
        .encode(ProtocolVersion::SUPPORTED, 0, &result)
        .unwrap();
    assert_eq!(codec.decode_exact(&encoded).unwrap().message, result);
    assert!(BoundedString::<MAX_ENROLLMENT_KEY_BYTES>::try_from("x".repeat(513).as_str()).is_err());
}

#[test]
fn enrollment_key_codec_rejects_mutation_and_unbounded_input() {
    let material = EnrollmentKeyMaterial::new(
        EnrollmentPurpose::ReEnroll,
        "server.example:7443",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let encoded = material.encode();
    let mut mutated = encoded.into_bytes();
    let last = mutated.len() - 1;
    mutated[last] = if mutated[last] == b'0' { b'1' } else { b'0' };

    assert!(EnrollmentKeyMaterial::decode(std::str::from_utf8(&mutated).unwrap()).is_err());
    assert!(EnrollmentKeyMaterial::decode(&"x".repeat(513)).is_err());
    assert!(EnrollmentKeyMaterial::decode("rustgo-enroll-v2.YQ.00000000").is_err());
}

#[test]
fn enrollment_key_codec_rejects_invalid_address_and_redacts_secrets() {
    assert!(
        EnrollmentKeyMaterial::new(EnrollmentPurpose::Enroll, "missing-port", [7; 32], [8; 32],)
            .is_err()
    );

    let material = EnrollmentKeyMaterial::new(
        EnrollmentPurpose::Enroll,
        "server.example:7443",
        [0xaa; 32],
        [0xbb; 32],
    )
    .unwrap();
    let debug = format!("{material:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("bbbbbbbb"));
}

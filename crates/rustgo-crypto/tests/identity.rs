use std::str::FromStr;

use rustgo_crypto::{
    AuthTranscript, DeviceKeypair, DevicePublicKey, Fingerprint, sign_auth, verify_auth,
};

const RFC_8032_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn transcript() -> AuthTranscript {
    AuthTranscript::new(
        vec![0x10, 0x20, 0x30],
        vec![0xa0, 0xb0],
        0x0102,
        "home-pc".to_owned(),
    )
}

#[test]
fn canonical_transcript_uses_domain_and_fixed_width_big_endian_lengths() {
    let expected = [
        b"rustgo-auth-v1".as_slice(),
        &[0, 0, 0, 3],
        &[0x10, 0x20, 0x30],
        &[0, 0, 0, 2],
        &[0xa0, 0xb0],
        &[0x01, 0x02],
        &[0, 0, 0, 7],
        b"home-pc".as_slice(),
    ]
    .concat();

    assert_eq!(transcript().as_bytes(), expected);
}

#[test]
fn signature_binds_every_authentication_field() {
    let keypair = DeviceKeypair::from_secret_bytes(RFC_8032_SECRET);
    let original = transcript();
    let signature = sign_auth(&keypair, &original);

    assert!(verify_auth(&keypair.public_key(), &original, &signature).is_ok());

    let altered = [
        AuthTranscript::new(
            vec![0x11, 0x20, 0x30],
            vec![0xa0, 0xb0],
            0x0102,
            "home-pc".into(),
        ),
        AuthTranscript::new(
            vec![0x10, 0x20, 0x30],
            vec![0xa0, 0xb1],
            0x0102,
            "home-pc".into(),
        ),
        AuthTranscript::new(
            vec![0x10, 0x20, 0x30],
            vec![0xa0, 0xb0],
            0x0103,
            "home-pc".into(),
        ),
        AuthTranscript::new(
            vec![0x10, 0x20, 0x30],
            vec![0xa0, 0xb0],
            0x0102,
            "other".into(),
        ),
    ];

    for changed in &altered {
        assert!(verify_auth(&keypair.public_key(), changed, &signature).is_err());
    }
}

#[test]
fn malformed_and_invalid_signatures_share_a_non_secret_error() {
    let keypair = DeviceKeypair::from_secret_bytes(RFC_8032_SECRET);
    let transcript = transcript();
    let signature = sign_auth(&keypair, &transcript);
    let malformed = verify_auth(&keypair.public_key(), &transcript, &[0x5a; 12]).unwrap_err();

    let mut invalid = signature;
    invalid[0] ^= 1;
    let invalid = verify_auth(&keypair.public_key(), &transcript, &invalid).unwrap_err();

    assert_eq!(malformed, invalid);
    assert_eq!(invalid.to_string(), "authentication verification failed");
}

#[test]
fn public_key_and_fingerprint_have_stable_display_encodings() {
    let keypair = DeviceKeypair::from_secret_bytes(RFC_8032_SECRET);
    let public_key = keypair.public_key();

    assert_eq!(
        public_key.to_string(),
        "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    );
    assert_eq!(
        public_key.fingerprint().to_string(),
        "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
    );
    assert_eq!(
        DevicePublicKey::from_str(&public_key.to_string()).unwrap(),
        public_key
    );
    assert_eq!(Fingerprint::from(&public_key), public_key.fingerprint());
}

#[test]
fn private_key_debug_output_is_redacted() {
    let keypair = DeviceKeypair::from_secret_bytes(RFC_8032_SECRET);
    let debug = format!("{keypair:?}");

    assert_eq!(debug, "DeviceKeypair([REDACTED])");
    assert!(!debug.contains("9d61b19d"));
}

use rustgo_protocol::{EnrollmentPurpose, ProtocolVersion, RegistrationIntent};

#[test]
fn profile_intent_roundtrips_unicode_uid_and_signature() {
    for uid in [None, Some("a123_uid-42")] {
        let intent =
            RegistrationIntent::for_profile("小明 🦀. laptop", uid, EnrollmentPurpose::ReEnroll)
                .unwrap();
        let wire = format!("{}:{}", intent.encode(), "a5".repeat(64));
        assert!(wire.len() <= 512);
        let decoded = RegistrationIntent::decode(&wire).unwrap();
        assert!(decoded.profile);
        assert_eq!(decoded.client_name, intent.client_name);
        assert_eq!(decoded.uid.as_deref(), uid);
        assert_eq!(decoded.purpose, EnrollmentPurpose::ReEnroll);
        assert_eq!(decoded.signature, Some([0xa5; 64]));
    }
}

#[test]
fn invalid_profile_values_are_rejected() {
    for name in ["", "  ", "a\nb", &"é".repeat(65)] {
        assert!(RegistrationIntent::for_profile(name, None, EnrollmentPurpose::Enroll).is_err());
    }
    for uid in ["", "bad id", "用户", &"a".repeat(65)] {
        assert!(
            RegistrationIntent::for_profile("label", Some(uid), EnrollmentPurpose::Enroll).is_err()
        );
    }
    for wire in [
        "rustgo-approval-v2.enroll._w.",
        "rustgo-approval-v2.enroll.%%.",
        "rustgo-approval-v2.enroll.YQ.bad uid",
        "rustgo-approval-v2.enroll.YQ",
    ] {
        assert!(RegistrationIntent::decode(wire).is_err());
    }
}

#[test]
fn legacy_intent_and_protocol_negotiation_remain_compatible() {
    let old = RegistrationIntent::new("old.node", EnrollmentPurpose::Enroll).unwrap();
    assert_eq!(old.encode(), "rustgo-approval-v1.enroll.old.node");
    assert!(!RegistrationIntent::decode(&old.encode()).unwrap().profile);
    assert_eq!(
        ProtocolVersion::SUPPORTED.negotiate(ProtocolVersion::V0_5),
        Ok(ProtocolVersion::V0_5)
    );
    assert!(!ProtocolVersion::V0_5.supports_client_profile());
    assert!(ProtocolVersion::V0_6.supports_client_profile());
}

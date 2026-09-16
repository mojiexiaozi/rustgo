use rustgo_crypto::DeviceKeypair;
use rustgo_protocol::EnrollmentPurpose;
use rustgos::enrollment::{DynamicClientStore, EnrollmentStoreError, EnrollmentStoreLimits};
use std::time::{Duration, SystemTime};

#[test]
fn deleted_client_can_request_restoration_but_remains_deleted_until_approved() {
    let dir = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(
        dir.path().join("db"),
        EnrollmentStoreLimits {
            max_active_clients: 4,
            max_tokens: 4,
        },
    )
    .unwrap();
    let key = DeviceKeypair::from_secret_bytes([41; 32]).public_key();
    let now = SystemTime::now();
    let _ = store.request_approval("restore", EnrollmentPurpose::Enroll, &key, "initial", now);
    store.review_approval("initial", true).unwrap();
    let old = store.client_by_display_id("restore").unwrap().unwrap();
    store
        .delete_client(old.internal_id(), old.revision())
        .unwrap();
    assert_eq!(
        store.request_approval(
            "restore",
            EnrollmentPurpose::ReEnroll,
            &key,
            "restore-request",
            now
        ),
        Err(EnrollmentStoreError::ReplacementApprovalPending)
    );
    assert!(store.list_clients().unwrap().is_empty());
    assert_eq!(store.pending_approvals().unwrap().len(), 1);
    store.review_approval("restore-request", true).unwrap();
    assert!(
        store
            .client_by_display_id("restore")
            .unwrap()
            .unwrap()
            .enabled()
    );
}

#[test]
fn approval_creates_client_and_replacement_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(
        dir.path().join("db"),
        EnrollmentStoreLimits {
            max_active_clients: 4,
            max_tokens: 4,
        },
    )
    .unwrap();
    let first = DeviceKeypair::from_secret_bytes([1; 32]).public_key();
    let second = DeviceKeypair::from_secret_bytes([2; 32]).public_key();
    let now = SystemTime::now();
    assert_eq!(
        store.request_approval("node", EnrollmentPurpose::Enroll, &first, "first", now),
        Err(EnrollmentStoreError::ApprovalPending)
    );
    assert!(store.list_clients().unwrap().is_empty());
    assert_eq!(store.pending_approvals().unwrap().len(), 1);
    let approved = store.review_approval("first", true).unwrap().unwrap();
    assert_eq!(approved.display_id(), "node");
    assert!(store.review_approval("first", true).unwrap().is_none());
    assert_eq!(
        store
            .request_approval("node", EnrollmentPurpose::Enroll, &first, "first", now)
            .unwrap()
            .revision(),
        1
    );
    for _ in 0..2 {
        let error = store
            .request_approval("node", EnrollmentPurpose::Enroll, &second, "replace", now)
            .unwrap_err();
        assert_eq!(format!("{error:?}"), "ReplacementApprovalPending");
    }
    assert_eq!(
        store
            .client_by_display_id("node")
            .unwrap()
            .unwrap()
            .revision(),
        1
    );
    assert_eq!(
        store
            .review_approval("replace", true)
            .unwrap()
            .unwrap()
            .revision(),
        2
    );
    assert_eq!(
        store.review_approval("first", true),
        Err(EnrollmentStoreError::RevisionConflict)
    );
    assert_eq!(
        store.request_approval("node", EnrollmentPurpose::ReEnroll, &first, "replace", now),
        Err(EnrollmentStoreError::InvalidRequestId)
    );
}

#[test]
fn rejection_never_binds_and_expired_request_can_resume_with_same_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(
        dir.path().join("db"),
        EnrollmentStoreLimits {
            max_active_clients: 4,
            max_tokens: 4,
        },
    )
    .unwrap();
    let key = DeviceKeypair::from_secret_bytes([3; 32]).public_key();
    let now = SystemTime::now();
    let _ = store.request_approval("node", EnrollmentPurpose::Enroll, &key, "reject", now);
    store.review_approval("reject", false).unwrap();
    assert_eq!(
        store.request_approval("node", EnrollmentPurpose::Enroll, &key, "reject", now),
        Err(EnrollmentStoreError::ApprovalRejected)
    );
    let _ = store.request_approval("node", EnrollmentPurpose::Enroll, &key, "expire", now);
    assert_eq!(
        store.request_approval(
            "node",
            EnrollmentPurpose::Enroll,
            &key,
            "expire",
            now + Duration::from_secs(86401)
        ),
        Err(EnrollmentStoreError::ApprovalPending)
    );
    assert!(store.list_clients().unwrap().is_empty());
    assert_eq!(store.pending_approvals().unwrap()[0].request_id, "expire");
    store.review_approval("expire", true).unwrap();
}

#[test]
fn approval_preserves_static_identities_and_detects_concurrent_change() {
    let dir = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(
        dir.path().join("db"),
        EnrollmentStoreLimits {
            max_active_clients: 4,
            max_tokens: 4,
        },
    )
    .unwrap();
    let key = DeviceKeypair::from_secret_bytes([7; 32]).public_key();
    store
        .validate_static_collisions(&[rustgo_config::AuthorizedClient {
            name: "static".into(),
            public_key: key.to_string(),
            enabled: true,
        }])
        .unwrap();
    assert_eq!(
        store.request_approval(
            "static",
            EnrollmentPurpose::ReEnroll,
            &key,
            "static-request",
            SystemTime::now()
        ),
        Err(EnrollmentStoreError::StaticIdentityConflict)
    );
    let other = DeviceKeypair::from_secret_bytes([8; 32]).public_key();
    let _ = store.request_approval(
        "node",
        EnrollmentPurpose::Enroll,
        &other,
        "first",
        SystemTime::now(),
    );
    store.review_approval("first", true).unwrap();
    let _ = store.request_approval(
        "node",
        EnrollmentPurpose::ReEnroll,
        &other,
        "second",
        SystemTime::now(),
    );
    let client = store.client_by_display_id("node").unwrap().unwrap();
    store
        .delete_client(client.internal_id(), client.revision())
        .unwrap();
    assert_eq!(
        store.review_approval("second", true),
        Err(EnrollmentStoreError::RevisionConflict)
    );
}

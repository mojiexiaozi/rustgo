use rustgo_crypto::DeviceKeypair;
use rustgo_protocol::EnrollmentPurpose;
use rustgos::enrollment::{DynamicClientStore, EnrollmentStoreError, EnrollmentStoreLimits};
use std::time::SystemTime;

#[test]
fn duplicate_labels_have_distinct_uids_and_retries_bind_the_signed_profile() {
    let dir = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(
        dir.path().join("db"),
        EnrollmentStoreLimits {
            max_active_clients: 10,
            max_tokens: 10,
        },
    )
    .unwrap();
    let now = SystemTime::now();
    let a = DeviceKeypair::from_secret_bytes([71; 32]).public_key();
    let b = DeviceKeypair::from_secret_bytes([72; 32]).public_key();
    for (key, req) in [(&a, "first"), (&b, "second")] {
        assert_eq!(
            store.request_profile_approval(
                "用户 Alice",
                None,
                EnrollmentPurpose::Enroll,
                key,
                req,
                now
            ),
            Err(EnrollmentStoreError::ApprovalPending)
        );
        store.review_approval(req, true).unwrap();
    }
    let first = store.client_by_public_key(&a).unwrap().unwrap();
    let second = store.client_by_public_key(&b).unwrap().unwrap();
    assert_ne!(first.internal_id(), second.internal_id());
    assert_eq!(first.internal_id(), first.display_id());
    assert_eq!(first.display_name(), "用户 Alice");
    assert_eq!(
        store
            .request_profile_approval(
                "用户 Alice",
                None,
                EnrollmentPurpose::Enroll,
                &a,
                "first",
                now
            )
            .unwrap()
            .display_id(),
        first.display_id()
    );
    assert_eq!(
        store.request_profile_approval(
            "changed",
            None,
            EnrollmentPurpose::Enroll,
            &a,
            "first",
            now
        ),
        Err(EnrollmentStoreError::InvalidRequestId)
    );
    assert_eq!(
        store.request_profile_approval(
            "用户 Alice",
            Some(first.internal_id()),
            EnrollmentPurpose::Enroll,
            &a,
            "first",
            now
        ),
        Err(EnrollmentStoreError::InvalidRequestId)
    );
    store
        .update_profile(first.internal_id(), "新名字", Some("192.168.1.2"))
        .unwrap();
    let updated = store.client(first.internal_id()).unwrap().unwrap();
    assert_eq!(updated.revision(), first.revision());
    assert_eq!(updated.display_id(), first.display_id());
    assert_eq!(updated.local_ip(), Some("192.168.1.2"));
    assert!(
        store
            .update_profile(first.internal_id(), "bad\nname", None)
            .is_err()
    );
    assert!(
        store
            .update_profile(first.internal_id(), "ok", Some("hostname"))
            .is_err()
    );
    assert!(
        store
            .update_profile(first.internal_id(), &"a".repeat(129), None)
            .is_err()
    );
    store
        .delete_client(first.internal_id(), first.revision())
        .unwrap();
    assert_eq!(
        store.request_profile_approval(
            "用户 Alice",
            None,
            EnrollmentPurpose::Enroll,
            &a,
            "first",
            now
        ),
        Err(EnrollmentStoreError::RevisionConflict)
    );
    assert_eq!(
        store.request_profile_approval(
            "restored",
            Some(first.internal_id()),
            EnrollmentPurpose::ReEnroll,
            &a,
            "restore",
            now
        ),
        Err(EnrollmentStoreError::ReplacementApprovalPending)
    );
    store.review_approval("restore", true).unwrap();
    let restored = store.client_by_public_key(&a).unwrap().unwrap();
    assert_eq!(restored.internal_id(), first.internal_id());
    assert_eq!(restored.display_name(), "restored");
}

#[test]
fn profile_registration_matches_existing_key_without_changing_legacy_routing_alias() {
    let dir = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(
        dir.path().join("db"),
        EnrollmentStoreLimits {
            max_active_clients: 10,
            max_tokens: 10,
        },
    )
    .unwrap();
    let now = SystemTime::now();
    let key = DeviceKeypair::from_secret_bytes([73; 32]).public_key();
    let _ = store.request_approval(
        "legacy-node",
        EnrollmentPurpose::Enroll,
        &key,
        "legacy",
        now,
    );
    store.review_approval("legacy", true).unwrap();
    let original = store.client_by_public_key(&key).unwrap().unwrap();
    assert_eq!(original.display_name(), "legacy-node");
    assert_eq!(
        store.request_profile_approval(
            "新显示名",
            None,
            EnrollmentPurpose::ReEnroll,
            &key,
            "profile",
            now
        ),
        Err(EnrollmentStoreError::ReplacementApprovalPending)
    );
    let pending = store.pending_approvals().unwrap();
    assert_eq!(pending[0].display_name, "新显示名");
    assert_eq!(pending[0].uid.as_deref(), Some(original.internal_id()));
    assert_eq!(
        store
            .review_approval("profile", true)
            .unwrap()
            .unwrap()
            .display_id(),
        "legacy-node"
    );
    let updated = store.client_by_public_key(&key).unwrap().unwrap();
    assert_eq!(updated.internal_id(), original.internal_id());
    assert_eq!(updated.display_id(), original.display_id());
    assert_eq!(updated.display_name(), "新显示名");
    assert_eq!(
        store.request_profile_approval(
            "新显示名",
            None,
            EnrollmentPurpose::Enroll,
            &key,
            "profile",
            now
        ),
        Err(EnrollmentStoreError::InvalidRequestId)
    );
    assert_eq!(
        store.request_approval(
            "legacy-node",
            EnrollmentPurpose::ReEnroll,
            &key,
            "profile",
            now
        ),
        Err(EnrollmentStoreError::InvalidRequestId)
    );
}

#[test]
fn schema_four_migration_defaults_metadata_and_persists_updates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let limits = EnrollmentStoreLimits {
        max_active_clients: 10,
        max_tokens: 10,
    };
    let store = DynamicClientStore::open(&path, limits).unwrap();
    let original = store.create_client("legacy").unwrap();
    drop(store);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("ALTER TABLE dynamic_clients DROP COLUMN display_name; ALTER TABLE dynamic_clients DROP COLUMN local_ip; ALTER TABLE registration_requests DROP COLUMN profile_name; ALTER TABLE registration_requests DROP COLUMN requested_uid; PRAGMA user_version=4;").unwrap();
    drop(db);
    let store = DynamicClientStore::open(&path, limits).unwrap();
    let migrated = store.client(original.internal_id()).unwrap().unwrap();
    assert_eq!(migrated.display_name(), "legacy");
    assert_eq!(migrated.local_ip(), None);
    assert_eq!(migrated.internal_id(), original.internal_id());
    store
        .update_profile(original.internal_id(), "新的名字", Some("2001:db8::1"))
        .unwrap();
    drop(store);
    let store = DynamicClientStore::open(&path, limits).unwrap();
    let updated = store.client(original.internal_id()).unwrap().unwrap();
    assert_eq!(updated.display_name(), "新的名字");
    assert_eq!(updated.local_ip(), Some("2001:db8::1"));
    assert_eq!(updated.revision(), original.revision());
}

#![forbid(unsafe_code)]

use std::{
    sync::{Arc, Barrier},
    time::{Duration, SystemTime},
};

use rustgo_config::AuthorizedClient;
use rustgo_crypto::DeviceKeypair;
use rustgo_protocol::{EnrollmentKeyMaterial, EnrollmentPurpose};
use rustgos::enrollment::{DynamicClientStore, EnrollmentStoreError, EnrollmentStoreLimits};

fn limits(max_active_clients: usize) -> EnrollmentStoreLimits {
    EnrollmentStoreLimits {
        max_active_clients,
        max_tokens: 8,
    }
}

#[test]
fn static_identity_collisions_are_rejected_by_name_and_public_key() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("authority.db"), limits(4)).unwrap();
    let dynamic = store.create_client("Dynamic.One").unwrap();
    assert_eq!(
        store.validate_static_collisions(&[AuthorizedClient {
            name: "dynamic.one".to_owned(),
            public_key: DeviceKeypair::from_secret_bytes([9; 32])
                .public_key()
                .to_string(),
            enabled: true,
        }]),
        Err(EnrollmentStoreError::StaticIdentityConflict)
    );

    let key = DeviceKeypair::from_secret_bytes([10; 32]);
    let issued = store
        .issue_token(
            dynamic.internal_id(),
            EnrollmentPurpose::Enroll,
            "server.example:7443",
            [1; 32],
            Duration::from_secs(60),
            1,
        )
        .unwrap();
    let issued = issued.into_encoded();
    store
        .consume_token(
            &issued,
            &key.public_key(),
            "static-collision",
            SystemTime::now(),
        )
        .unwrap();
    assert_eq!(
        store.validate_static_collisions(&[AuthorizedClient {
            name: "Static.One".to_owned(),
            public_key: key.public_key().to_string(),
            enabled: true,
        }]),
        Err(EnrollmentStoreError::StaticIdentityConflict)
    );
}

#[test]
fn client_creation_bootstraps_and_persists() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("enrollment.sqlite3");
    let store = DynamicClientStore::open(&path, limits(2)).unwrap();
    let client = store.create_client("  Node.One  ").unwrap();
    assert_eq!(client.display_id(), "Node.One");
    assert!(client.enabled());
    assert_eq!(client.revision(), 1);
    assert!(!client.is_bound());
    let internal_id = client.internal_id().to_owned();
    drop(store);

    let reopened = DynamicClientStore::open(&path, limits(2)).unwrap();
    let loaded = reopened.client(&internal_id).unwrap().unwrap();
    assert_eq!(loaded.display_id(), "Node.One");
}

#[test]
fn audit_health_and_bounded_tombstone_purge_are_operational() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("authority.db"), limits(4)).unwrap();
    store.health_check().unwrap();
    let client = store.create_client("Deleted.Node").unwrap();
    store.delete_client(client.internal_id(), 1).unwrap();
    assert_eq!(store.audit_count().unwrap(), 2);
    assert_eq!(
        store.purge_tombstones(SystemTime::now() + Duration::from_secs(1), 1),
        Ok(1)
    );
    assert_eq!(store.audit_count().unwrap(), 3);
    assert_eq!(
        store.purge_tombstones(SystemTime::now(), 0),
        Err(EnrollmentStoreError::InvalidPurgeLimit)
    );
}

#[test]
fn ids_are_validated_and_case_insensitively_unique() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db");
    let store = DynamicClientStore::open(&path, limits(4)).unwrap();
    store.create_client("Node_1.example").unwrap();
    assert_eq!(
        store.create_client("node_1.EXAMPLE").unwrap_err(),
        EnrollmentStoreError::DuplicateDisplayId
    );
    let too_long = "x".repeat(65);
    for invalid in ["", " ", "bad id", "slash/id", "é", too_long.as_str()] {
        assert_eq!(
            store.create_client(invalid).unwrap_err(),
            EnrollmentStoreError::InvalidDisplayId
        );
    }
}

#[test]
fn active_client_capacity_is_transactional() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("db"), limits(1)).unwrap();
    store.create_client("first").unwrap();
    assert_eq!(
        store.create_client("second").unwrap_err(),
        EnrollmentStoreError::ClientCapacity
    );
}

#[test]
fn issued_key_decodes_and_plaintext_is_not_persisted() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db");
    let store = DynamicClientStore::open(&path, limits(2)).unwrap();
    let client = store.create_client("node").unwrap();
    let issued = store
        .issue_token(
            client.internal_id(),
            EnrollmentPurpose::Enroll,
            "SERVER.example:7443",
            [0x55; 32],
            Duration::from_secs(300),
            1,
        )
        .unwrap();
    assert!(format!("{issued:?}").contains("[REDACTED]"));
    let encoded = issued.into_encoded();
    let decoded = EnrollmentKeyMaterial::decode(&encoded).unwrap();
    assert_eq!(decoded.server_addr(), "server.example:7443");
    let token = *decoded.token();
    drop(store);
    let database = std::fs::read(path).unwrap();
    assert!(
        !database
            .windows(encoded.len())
            .any(|bytes| bytes == encoded.as_bytes())
    );
    assert!(!database.windows(token.len()).any(|bytes| bytes == token));
}

#[test]
fn issuing_checks_revision_and_replaces_same_purpose_token() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(
        directory.path().join("db"),
        EnrollmentStoreLimits {
            max_active_clients: 2,
            max_tokens: 1,
        },
    )
    .unwrap();
    let client = store.create_client("node").unwrap();
    assert_eq!(
        store
            .issue_token(
                client.internal_id(),
                EnrollmentPurpose::Enroll,
                "server:7443",
                [1; 32],
                Duration::from_secs(60),
                2,
            )
            .unwrap_err(),
        EnrollmentStoreError::RevisionConflict
    );
    store
        .issue_token(
            client.internal_id(),
            EnrollmentPurpose::Enroll,
            "server:7443",
            [1; 32],
            Duration::from_secs(60),
            1,
        )
        .unwrap();
    store
        .issue_token(
            client.internal_id(),
            EnrollmentPurpose::Enroll,
            "server:7443",
            [1; 32],
            Duration::from_secs(60),
            1,
        )
        .unwrap();
}

fn issue(
    store: &DynamicClientStore,
    client: &str,
    purpose: EnrollmentPurpose,
    revision: u64,
) -> String {
    store
        .issue_token(
            client,
            purpose,
            "server:7443",
            [9; 32],
            Duration::from_secs(60),
            revision,
        )
        .unwrap()
        .into_encoded()
}

#[test]
fn consumption_binds_atomically_and_exact_replay_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db");
    let store = DynamicClientStore::open(&path, limits(4)).unwrap();
    let client = store.create_client("node").unwrap();
    let encoded = issue(&store, client.internal_id(), EnrollmentPurpose::Enroll, 1);
    let key = DeviceKeypair::from_secret_bytes([1; 32]).public_key();
    let result = store
        .consume_token(&encoded, &key, "request-1", SystemTime::now())
        .unwrap();
    assert_eq!(result.display_id(), "node");
    assert_eq!(result.revision(), 2);
    assert_eq!(
        store
            .consume_token(&encoded, &key, "request-1", SystemTime::now())
            .unwrap(),
        result
    );
    assert_eq!(
        store
            .consume_token(&encoded, &key, "different", SystemTime::now())
            .unwrap_err(),
        EnrollmentStoreError::TokenAlreadyUsed
    );
    assert!(
        store
            .client(client.internal_id())
            .unwrap()
            .unwrap()
            .is_bound()
    );
    let internal_id = client.internal_id().to_owned();
    drop(store);
    let reopened = DynamicClientStore::open(path, limits(4)).unwrap();
    assert_eq!(
        reopened
            .consume_token(&encoded, &key, "request-1", SystemTime::now())
            .unwrap(),
        result
    );
    assert!(reopened.client(&internal_id).unwrap().unwrap().is_bound());
}

#[test]
fn bound_client_requires_reenrollment_and_advances_revision() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("db"), limits(3)).unwrap();
    let client = store.create_client("node").unwrap();
    let first_key = DeviceKeypair::from_secret_bytes([10; 32]).public_key();
    store
        .consume_token(
            &issue(&store, client.internal_id(), EnrollmentPurpose::Enroll, 1),
            &first_key,
            "initial",
            SystemTime::now(),
        )
        .unwrap();
    let second_key = DeviceKeypair::from_secret_bytes([11; 32]).public_key();
    assert_eq!(
        store
            .issue_token(
                client.internal_id(),
                EnrollmentPurpose::Enroll,
                "server:7443",
                [9; 32],
                Duration::from_secs(60),
                2,
            )
            .unwrap_err(),
        EnrollmentStoreError::PurposeMismatch
    );
    let replacement = issue(&store, client.internal_id(), EnrollmentPurpose::ReEnroll, 2);
    let result = store
        .consume_token(&replacement, &second_key, "replace", SystemTime::now())
        .unwrap();
    assert_eq!(result.revision(), 3);
}

#[test]
fn consumption_rejects_invalid_expired_or_wrong_state_without_consuming() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("db"), limits(5)).unwrap();
    let client = store.create_client("node").unwrap();
    let encoded = issue(&store, client.internal_id(), EnrollmentPurpose::Enroll, 1);
    let key = DeviceKeypair::from_secret_bytes([2; 32]).public_key();
    let future = SystemTime::now() + Duration::from_secs(120);
    assert_eq!(
        store
            .consume_token(&encoded, &key, "expired", future)
            .unwrap_err(),
        EnrollmentStoreError::TokenExpired
    );
    assert_eq!(
        store
            .consume_token("bad", &key, "bad", SystemTime::now())
            .unwrap_err(),
        EnrollmentStoreError::InvalidToken
    );
    store
        .consume_token(&encoded, &key, "valid", SystemTime::now())
        .unwrap();

    let other = store.create_client("other").unwrap();
    assert_eq!(
        store
            .issue_token(
                other.internal_id(),
                EnrollmentPurpose::ReEnroll,
                "server:7443",
                [9; 32],
                Duration::from_secs(60),
                1,
            )
            .unwrap_err(),
        EnrollmentStoreError::PurposeMismatch
    );
}

#[test]
fn consumption_enforces_public_key_uniqueness_and_disabled_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("db"), limits(5)).unwrap();
    let first = store.create_client("first").unwrap();
    let second = store.create_client("second").unwrap();
    let key = DeviceKeypair::from_secret_bytes([3; 32]).public_key();
    store
        .consume_token(
            &issue(&store, first.internal_id(), EnrollmentPurpose::Enroll, 1),
            &key,
            "one",
            SystemTime::now(),
        )
        .unwrap();
    let second_token = issue(&store, second.internal_id(), EnrollmentPurpose::Enroll, 1);
    assert_eq!(
        store
            .consume_token(&second_token, &key, "two", SystemTime::now())
            .unwrap_err(),
        EnrollmentStoreError::PublicKeyConflict
    );
    store
        .set_client_enabled(second.internal_id(), false, 1)
        .unwrap();
    let other_key = DeviceKeypair::from_secret_bytes([4; 32]).public_key();
    assert_eq!(
        store
            .consume_token(&second_token, &other_key, "three", SystemTime::now())
            .unwrap_err(),
        EnrollmentStoreError::ClientDisabled
    );
}

#[test]
fn concurrent_consumers_have_one_winner() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(DynamicClientStore::open(directory.path().join("db"), limits(3)).unwrap());
    let client = store.create_client("node").unwrap();
    let encoded = Arc::new(issue(
        &store,
        client.internal_id(),
        EnrollmentPurpose::Enroll,
        1,
    ));
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (5_u8..7)
        .map(|secret| {
            let store = Arc::clone(&store);
            let encoded = Arc::clone(&encoded);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let key = DeviceKeypair::from_secret_bytes([secret; 32]).public_key();
                barrier.wait();
                store.consume_token(
                    &encoded,
                    &key,
                    &format!("request-{secret}"),
                    SystemTime::now(),
                )
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(EnrollmentStoreError::TokenAlreadyUsed)))
            .count(),
        1
    );
}

#[test]
fn lifecycle_mutations_use_revision_cas_and_hide_tombstones() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("db"), limits(3)).unwrap();
    let first = store.create_client("First").unwrap();
    let second = store.create_client("Second").unwrap();
    let renamed = store
        .rename_client(first.internal_id(), "Renamed", 1)
        .unwrap();
    assert_eq!(renamed.display_id(), "Renamed");
    assert_eq!(renamed.revision(), 2);
    assert_eq!(
        store
            .rename_client(first.internal_id(), "stale", 1)
            .unwrap_err(),
        EnrollmentStoreError::RevisionConflict
    );
    assert_eq!(
        store
            .rename_client(second.internal_id(), "RENAMED", 1)
            .unwrap_err(),
        EnrollmentStoreError::DuplicateDisplayId
    );

    let disabled = store
        .set_client_enabled(first.internal_id(), false, 2)
        .unwrap();
    assert!(!disabled.enabled());
    assert_eq!(disabled.revision(), 3);
    let enabled = store
        .set_client_enabled(first.internal_id(), true, 3)
        .unwrap();
    assert!(enabled.enabled());
    let deleted = store.delete_client(first.internal_id(), 4).unwrap();
    assert!(deleted.is_deleted());
    assert_eq!(store.list_clients().unwrap().len(), 1);
    assert_eq!(
        store
            .rename_client(first.internal_id(), "gone", 5)
            .unwrap_err(),
        EnrollmentStoreError::ClientNotFound
    );
}

#[test]
fn disabling_revokes_tokens_and_enabling_obeys_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("db"), limits(1)).unwrap();
    let first = store.create_client("first").unwrap();
    let token = issue(&store, first.internal_id(), EnrollmentPurpose::Enroll, 1);
    store
        .set_client_enabled(first.internal_id(), false, 1)
        .unwrap();
    let second = store.create_client("second").unwrap();
    assert_eq!(
        store
            .set_client_enabled(first.internal_id(), true, 2)
            .unwrap_err(),
        EnrollmentStoreError::ClientCapacity
    );
    let key = DeviceKeypair::from_secret_bytes([21; 32]).public_key();
    assert_eq!(
        store
            .consume_token(&token, &key, "revoked", SystemTime::now())
            .unwrap_err(),
        EnrollmentStoreError::ClientDisabled
    );
    store.delete_client(second.internal_id(), 1).unwrap();
    assert!(
        store
            .set_client_enabled(first.internal_id(), true, 2)
            .unwrap()
            .enabled()
    );
}

#[test]
fn schema_v1_migrates_transactionally() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch(
        "PRAGMA user_version = 1;
         CREATE TABLE dynamic_clients (internal_id TEXT PRIMARY KEY, display_id TEXT NOT NULL,
           normalized_id TEXT NOT NULL UNIQUE, public_key TEXT UNIQUE, enabled INTEGER NOT NULL,
           revision INTEGER NOT NULL);
         CREATE TABLE enrollment_tokens (selector BLOB PRIMARY KEY, token_hash BLOB NOT NULL,
           salt BLOB NOT NULL, purpose INTEGER NOT NULL, target_id TEXT NOT NULL,
           issued_revision INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER,
           request_id TEXT, result_public_key TEXT, result_revision INTEGER, revoked INTEGER NOT NULL DEFAULT 0);
         INSERT INTO dynamic_clients VALUES ('legacy-id', 'Legacy', 'legacy', NULL, 1, 7);"
    ).unwrap();
    drop(connection);
    let store = DynamicClientStore::open(path, limits(3)).unwrap();
    let client = store.client("legacy-id").unwrap().unwrap();
    assert_eq!(client.revision(), 7);
    assert!(!client.is_deleted());
}

#[test]
fn client_creation_and_first_token_are_one_transaction() {
    let directory = tempfile::tempdir().unwrap();
    let blocked = DynamicClientStore::open(
        directory.path().join("blocked"),
        EnrollmentStoreLimits {
            max_active_clients: 2,
            max_tokens: 0,
        },
    )
    .unwrap();
    assert_eq!(
        blocked
            .create_client_with_token("orphan", "server:7443", [1; 32], Duration::from_secs(60),)
            .unwrap_err(),
        EnrollmentStoreError::TokenCapacity
    );
    assert!(blocked.list_clients().unwrap().is_empty());

    let store = DynamicClientStore::open(directory.path().join("ok"), limits(2)).unwrap();
    let (client, issued) = store
        .create_client_with_token("atomic", "server:7443", [2; 32], Duration::from_secs(60))
        .unwrap();
    assert_eq!(client.display_id(), "atomic");
    assert_eq!(
        EnrollmentKeyMaterial::decode(&issued.into_encoded())
            .unwrap()
            .purpose(),
        EnrollmentPurpose::Enroll
    );
    assert_eq!(store.list_clients().unwrap().len(), 1);
}

#[test]
fn display_id_lookup_and_token_purpose_follow_binding_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = DynamicClientStore::open(directory.path().join("db"), limits(4)).unwrap();
    let client = store.create_client("Node.One").unwrap();
    assert_eq!(
        store.client_by_display_id("node.one").unwrap().unwrap(),
        client
    );
    assert_eq!(
        store
            .issue_token(
                client.internal_id(),
                EnrollmentPurpose::ReEnroll,
                "server:7443",
                [1; 32],
                Duration::from_secs(60),
                1,
            )
            .unwrap_err(),
        EnrollmentStoreError::PurposeMismatch
    );
    let key = DeviceKeypair::from_secret_bytes([31; 32]).public_key();
    store
        .consume_token(
            &issue(&store, client.internal_id(), EnrollmentPurpose::Enroll, 1),
            &key,
            "bind",
            SystemTime::now(),
        )
        .unwrap();
    assert_eq!(
        store
            .issue_token(
                client.internal_id(),
                EnrollmentPurpose::Enroll,
                "server:7443",
                [1; 32],
                Duration::from_secs(60),
                2,
            )
            .unwrap_err(),
        EnrollmentStoreError::PurposeMismatch
    );
    assert!(
        store
            .issue_token(
                client.internal_id(),
                EnrollmentPurpose::ReEnroll,
                "server:7443",
                [1; 32],
                Duration::from_secs(60),
                2,
            )
            .is_ok()
    );
}

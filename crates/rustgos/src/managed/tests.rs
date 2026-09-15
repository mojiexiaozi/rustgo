use super::*;
use serde_json::json;

fn config(nonempty: bool) -> ManagedConfiguration {
    serde_json::from_value(json!({
        "tunnels": if nonempty { json!([{"name":"http","protocol":"tcp","local_addr":"127.0.0.1:8080","remote_port":18080}]) } else { json!([]) },
        "exports": [], "forwards": [], "p2p_enabled": false
    })).unwrap()
}

#[test]
fn empty_snapshot_survives_reopen_and_does_not_reimport() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed.db");
    let store = ManagedStore::open(&path).unwrap();
    let initial = store.sync("static:key", "node", &config(true)).unwrap();
    assert_eq!(initial.revision, 1);
    let deleted = store.replace("node", 1, &config(false)).unwrap();
    assert_eq!(deleted.revision, 2);
    drop(store);
    let store = ManagedStore::open(&path).unwrap();
    let result = store.sync("static:key", "node", &config(true)).unwrap();
    assert!(result.configuration.tunnels.is_empty());
    assert_eq!(result.revision, 2);
}

#[test]
fn authenticated_rename_and_name_reuse_do_not_inherit_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&dir.path().join("managed.db")).unwrap();
    store.sync("dynamic:first", "old", &config(true)).unwrap();
    store.replace("old", 1, &config(false)).unwrap();
    assert_eq!(
        store
            .sync("dynamic:first", "new", &config(true))
            .unwrap()
            .revision,
        2
    );
    assert!(store.get("old").unwrap().is_none());
    let replacement = store.sync("dynamic:second", "new", &config(true)).unwrap();
    assert_eq!(replacement.revision, 1);
    assert_eq!(replacement.configuration.tunnels.len(), 1);
    assert!(
        store
            .sync("dynamic:first", "elsewhere", &config(true))
            .unwrap()
            .configuration
            .tunnels
            .is_empty()
    );
    assert_eq!(store.get("new").unwrap().unwrap().revision, 1);
}

#[test]
fn concurrent_compare_and_swap_has_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed.db");
    let first = ManagedStore::open(&path).unwrap();
    let second = ManagedStore::open(&path).unwrap();
    first.sync("key", "node", &config(true)).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    let thread = std::thread::spawn(move || {
        other.wait();
        second.replace("node", 1, &config(false))
    });
    barrier.wait();
    let local = first.replace("node", 1, &config(false));
    let remote = thread.join().unwrap();
    assert_eq!(usize::from(local.is_ok()) + usize::from(remote.is_ok()), 1);
    assert!(
        matches!(local, Err(ManagedError::Conflict))
            || matches!(remote, Err(ManagedError::Conflict))
    );
}

#[test]
fn reports_are_bounded_validated_and_stale_reports_cannot_clear_pending() {
    let dir = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&dir.path().join("managed.db")).unwrap();
    store.sync("key", "node", &config(true)).unwrap();
    let ready = json!([{"kind":"tunnel","name":"http","state":"ready","error":null}]);
    store.report("key", 1, ready.clone()).unwrap();
    assert_eq!(
        store.get("node").unwrap().unwrap().applied_revision,
        Some(1)
    );
    store.replace("node", 1, &config(false)).unwrap();
    assert!(matches!(
        store.report("key", 1, ready.clone()),
        Err(ManagedError::Conflict)
    ));
    assert!(
        store
            .get("node")
            .unwrap()
            .unwrap()
            .applied_revision
            .is_none()
    );
    assert!(matches!(
        store.report("key", 2, ready),
        Err(ManagedError::Invalid(_))
    ));
    store.report("key", 2, json!([])).unwrap();
    assert_eq!(
        store.get("node").unwrap().unwrap().applied_revision,
        Some(2)
    );
    assert!(matches!(
        store.report("missing", 2, json!([])),
        Err(ManagedError::NotFound)
    ));
    assert!(matches!(
        store.report("key", 2, json!("x".repeat(65537))),
        Err(ManagedError::Invalid(_))
    ));
}

#[test]
fn invalid_import_and_replace_leave_saved_state_intact() {
    let dir = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&dir.path().join("managed.db")).unwrap();
    let mut invalid = config(true);
    invalid.tunnels[0].remote_port = 70000;
    assert!(matches!(
        store.sync("key", "node", &invalid),
        Err(ManagedError::Invalid(_))
    ));
    assert!(store.get("node").unwrap().is_none());
    store.sync("key", "node", &config(true)).unwrap();
    assert!(matches!(
        store.replace("node", 1, &invalid),
        Err(ManagedError::Invalid(_))
    ));
    assert_eq!(store.get("node").unwrap().unwrap().revision, 1);
    assert!(matches!(
        store.replace("missing", 1, &config(false)),
        Err(ManagedError::NotFound)
    ));
}

#[test]
fn malformed_or_incomplete_reports_never_acknowledge_revision() {
    let dir = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&dir.path().join("managed.db")).unwrap();
    store.sync("key", "node", &config(true)).unwrap();
    for bad in [
        json!([]),
        json!({}),
        json!([{"kind":"tunnel","name":"http","state":"unknown"}]),
        json!([{"kind":"export","name":"http","state":"ready"}]),
        json!([{"kind":"tunnel","name":"http","state":"failed","error":"x".repeat(2049)}]),
        json!([{"kind":"tunnel","name":"http","state":"ready"},{"kind":"tunnel","name":"http","state":"ready"}]),
    ] {
        assert!(matches!(
            store.report("key", 1, bad),
            Err(ManagedError::Invalid(_))
        ));
        assert!(
            store
                .get("node")
                .unwrap()
                .unwrap()
                .applied_revision
                .is_none()
        );
    }
}

#[test]
fn identity_scoped_replace_cannot_modify_another_identity_with_same_revision() {
    let dir = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&dir.path().join("managed.db")).unwrap();
    store.sync("first", "node", &config(true)).unwrap();
    store.sync("second", "node", &config(false)).unwrap();
    let updated = store
        .replace_for_identity("first", "renamed", 1, &config(false))
        .unwrap();
    assert_eq!(updated.identity, "first");
    assert_eq!(updated.name, "renamed");
    assert_eq!(store.get("node").unwrap().unwrap().identity, "second");
    assert_eq!(
        store.get_for_identity("second").unwrap().unwrap().revision,
        1
    );
    assert!(matches!(
        store.replace_for_identity("missing", "node", 1, &config(true)),
        Err(ManagedError::NotFound)
    ));
}

#[test]
fn reconnect_clears_previous_generation_readiness_without_changing_desired_revision() {
    let dir = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&dir.path().join("managed.db")).unwrap();
    store.sync("key", "node", &config(true)).unwrap();
    store
        .report(
            "key",
            1,
            json!([{"kind":"tunnel","name":"http","state":"ready","error":null}]),
        )
        .unwrap();
    let next = store.sync("key", "node", &config(false)).unwrap();
    assert_eq!(next.revision, 1);
    assert_eq!(next.configuration.tunnels.len(), 1);
    assert!(next.applied_revision.is_none());
    assert_eq!(next.results, json!([]));
}

#[cfg(unix)]
#[test]
fn database_is_private_on_creation_and_reopen() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed.db");
    drop(ManagedStore::open(&path).unwrap());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(ManagedStore::open(&path).unwrap());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#![forbid(unsafe_code)]

//! Path-status store unit tests.

use rustgoc::{PathKindStatus, PathStatus, PathStatusStore};
use std::sync::Arc;

#[test]
fn path_status_store_basic_operations() {
    let store = Arc::new(PathStatusStore::new());

    // Record a relay status
    store.record(
        "export1".to_string(),
        PathStatus {
            kind: PathKindStatus::Relay,
            updated_unix_millis: 1000,
        },
    );

    // Verify it exists
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot.contains_key("export1"));

    let status = snapshot.get("export1").unwrap();
    assert!(matches!(status.kind, PathKindStatus::Relay));
    assert_eq!(status.updated_unix_millis, 1000);

    // Update to direct
    store.record(
        "export1".to_string(),
        PathStatus {
            kind: PathKindStatus::Direct {
                address: "192.168.1.1:1234".to_string(),
            },
            updated_unix_millis: 2000,
        },
    );

    // Verify update
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 1);
    let status = snapshot.get("export1").unwrap();
    if let PathKindStatus::Direct { address } = &status.kind {
        assert_eq!(address, "192.168.1.1:1234");
    } else {
        panic!("Expected Direct status");
    }
    assert_eq!(status.updated_unix_millis, 2000);

    // Remove entry
    store.remove("export1");
    let snapshot = store.snapshot();
    assert!(snapshot.is_empty());
}

#[test]
fn path_status_store_multiple_exports() {
    let store = Arc::new(PathStatusStore::new());

    // Add multiple exports
    store.record(
        "export1".to_string(),
        PathStatus {
            kind: PathKindStatus::Relay,
            updated_unix_millis: 1000,
        },
    );

    store.record(
        "export2".to_string(),
        PathStatus {
            kind: PathKindStatus::Direct {
                address: "10.0.0.1:5000".to_string(),
            },
            updated_unix_millis: 1500,
        },
    );

    store.record(
        "export3".to_string(),
        PathStatus {
            kind: PathKindStatus::Relay,
            updated_unix_millis: 2000,
        },
    );

    // Verify all exist
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 3);
    assert!(snapshot.contains_key("export1"));
    assert!(snapshot.contains_key("export2"));
    assert!(snapshot.contains_key("export3"));

    // Remove one
    store.remove("export2");
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 2);
    assert!(!snapshot.contains_key("export2"));

    // Verify others still exist
    assert!(snapshot.contains_key("export1"));
    assert!(snapshot.contains_key("export3"));
}

#[test]
fn path_status_store_overwrite() {
    let store = Arc::new(PathStatusStore::new());

    // Record initial relay
    store.record(
        "export1".to_string(),
        PathStatus {
            kind: PathKindStatus::Relay,
            updated_unix_millis: 1000,
        },
    );

    // Overwrite with direct
    store.record(
        "export1".to_string(),
        PathStatus {
            kind: PathKindStatus::Direct {
                address: "1.2.3.4:8080".to_string(),
            },
            updated_unix_millis: 2000,
        },
    );

    // Overwrite again with relay
    store.record(
        "export1".to_string(),
        PathStatus {
            kind: PathKindStatus::Relay,
            updated_unix_millis: 3000,
        },
    );

    // Verify final state
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 1);
    let status = snapshot.get("export1").unwrap();
    assert!(matches!(status.kind, PathKindStatus::Relay));
    assert_eq!(status.updated_unix_millis, 3000);
}

#[test]
fn path_status_store_remove_nonexistent() {
    let store = Arc::new(PathStatusStore::new());

    // Remove non-existent entry (should not panic)
    store.remove("nonexistent");

    // Add one entry
    store.record(
        "export1".to_string(),
        PathStatus {
            kind: PathKindStatus::Relay,
            updated_unix_millis: 1000,
        },
    );

    // Remove different entry
    store.remove("export2");

    // Verify original entry still exists
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot.contains_key("export1"));
}

#[test]
fn path_status_store_concurrent_access() {
    use std::thread;

    let store = Arc::new(PathStatusStore::new());
    let mut handles = vec![];

    // Spawn multiple threads recording to different exports
    for i in 0..10 {
        let store = store.clone();
        let handle = thread::spawn(move || {
            store.record(
                format!("export{}", i),
                PathStatus {
                    kind: PathKindStatus::Relay,
                    updated_unix_millis: (i * 1000) as u64,
                },
            );
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all entries exist
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 10);
    for i in 0..10 {
        assert!(snapshot.contains_key(&format!("export{}", i)));
    }
}

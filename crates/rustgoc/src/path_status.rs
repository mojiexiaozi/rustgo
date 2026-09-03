#![forbid(unsafe_code)]

//! Public P2P path-status observation store.
//!
//! The GUI client needs to display which exports are using direct paths versus
//! relay fallback, and when each path selection was last updated. This module
//! provides a read-only store that the orchestration layer records into at
//! existing ownership boundaries (promotion, fallback, teardown).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The kind of path currently selected for an export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKindStatus {
    /// Using a direct QUIC or native-TCP connection.
    Direct { address: String },
    /// Using the encrypted server relay.
    Relay,
}

/// Path status snapshot for one export at a point in time.
#[derive(Debug, Clone)]
pub struct PathStatus {
    pub kind: PathKindStatus,
    /// Unix timestamp in milliseconds when this status was recorded.
    pub updated_unix_millis: u64,
}

/// Thread-safe store of current path selections keyed by export name.
///
/// Supports cheap version-based change detection: poll `version()` each frame
/// and call `snapshot()` only when the version changed.
#[derive(Debug, Clone)]
pub struct PathStatusStore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    entries: Mutex<BTreeMap<String, PathStatus>>,
    version: AtomicU64,
}

impl PathStatusStore {
    /// Create an empty store with version 0.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                entries: Mutex::new(BTreeMap::new()),
                version: AtomicU64::new(0),
            }),
        }
    }

    /// Return the current version counter.
    ///
    /// Increments on every `record()` or `remove()` call. Use this to detect
    /// changes without cloning the full map.
    pub fn version(&self) -> u64 {
        self.inner.version.load(Ordering::Acquire)
    }

    /// Clone the current map of export names to path statuses.
    pub fn snapshot(&self) -> BTreeMap<String, PathStatus> {
        self.inner.entries.lock().unwrap().clone()
    }

    /// Record a path selection for the given export.
    ///
    /// Increments the version counter. This is a synchronous bookkeeping
    /// operation and cannot alter path selection outcomes.
    #[doc(hidden)]
    pub fn record(&self, export_name: String, status: PathStatus) {
        let mut entries = self.inner.entries.lock().unwrap();
        entries.insert(export_name, status);
        self.inner.version.fetch_add(1, Ordering::Release);
    }

    /// Remove the entry for the given export.
    ///
    /// Called when a session finishes. Increments the version counter.
    #[doc(hidden)]
    pub fn remove(&self, export_name: &str) {
        let mut entries = self.inner.entries.lock().unwrap();
        if entries.remove(export_name).is_some() {
            self.inner.version.fetch_add(1, Ordering::Release);
        }
    }
}

impl Default for PathStatusStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_store() {
        let store = PathStatusStore::new();
        assert_eq!(store.version(), 0);
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn test_record_increments_version() {
        let store = PathStatusStore::new();
        assert_eq!(store.version(), 0);

        store.record(
            "export1".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 1000,
            },
        );
        assert_eq!(store.version(), 1);

        store.record(
            "export2".to_string(),
            PathStatus {
                kind: PathKindStatus::Direct {
                    address: "10.0.0.2:7000".to_string(),
                },
                updated_unix_millis: 2000,
            },
        );
        assert_eq!(store.version(), 2);
    }

    #[test]
    fn test_snapshot_ordering() {
        let store = PathStatusStore::new();
        store.record(
            "zebra".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 3000,
            },
        );
        store.record(
            "alpha".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 1000,
            },
        );
        store.record(
            "beta".to_string(),
            PathStatus {
                kind: PathKindStatus::Direct {
                    address: "192.168.1.5:7001".to_string(),
                },
                updated_unix_millis: 2000,
            },
        );

        let snap = store.snapshot();
        let keys: Vec<_> = snap.keys().collect();
        assert_eq!(keys, vec!["alpha", "beta", "zebra"]);
    }

    #[test]
    fn test_remove_increments_version_only_if_present() {
        let store = PathStatusStore::new();
        store.record(
            "export1".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 1000,
            },
        );
        assert_eq!(store.version(), 1);

        store.remove("export1");
        assert_eq!(store.version(), 2);
        assert!(store.snapshot().is_empty());

        // Removing nonexistent entry does not increment version
        store.remove("export1");
        assert_eq!(store.version(), 2);
    }

    #[test]
    fn test_update_existing_entry() {
        let store = PathStatusStore::new();
        store.record(
            "export1".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 1000,
            },
        );
        assert_eq!(store.version(), 1);

        store.record(
            "export1".to_string(),
            PathStatus {
                kind: PathKindStatus::Direct {
                    address: "10.0.0.3:7002".to_string(),
                },
                updated_unix_millis: 2000,
            },
        );
        assert_eq!(store.version(), 2);

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        let status = snap.get("export1").unwrap();
        assert!(matches!(&status.kind, PathKindStatus::Direct { address } if address == "10.0.0.3:7002"));
        assert_eq!(status.updated_unix_millis, 2000);
    }

    #[test]
    fn test_version_bumps_on_every_record() {
        let store = PathStatusStore::new();
        for i in 0..10 {
            store.record(
                format!("export{}", i),
                PathStatus {
                    kind: PathKindStatus::Relay,
                    updated_unix_millis: i * 1000,
                },
            );
        }
        assert_eq!(store.version(), 10);
        assert_eq!(store.snapshot().len(), 10);
    }
}

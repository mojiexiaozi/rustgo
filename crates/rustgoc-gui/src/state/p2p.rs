#![forbid(unsafe_code)]
#![allow(dead_code)]

use rustgoc::{PathKindStatus, PathStatus};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct P2PPathRow {
    pub export_name: String,
    pub kind: PathRowKind,
    pub age_millis: u64,
}

#[derive(Clone, Debug)]
pub enum PathRowKind {
    Direct { address: String },
    Relay,
}

pub struct P2PViewModel {
    store: rustgoc::PathStatusStore,
    last_version: u64,
    cached_snapshot: BTreeMap<String, PathStatus>,
}

impl P2PViewModel {
    pub fn new(store: rustgoc::PathStatusStore) -> Self {
        Self {
            store,
            last_version: 0,
            cached_snapshot: BTreeMap::new(),
        }
    }

    pub fn update(&mut self) -> bool {
        let current_version = self.store.version();
        if current_version != self.last_version {
            self.cached_snapshot = self.store.snapshot();
            self.last_version = current_version;
            true
        } else {
            false
        }
    }

    pub fn rows(&self, now_millis: u64) -> Vec<P2PPathRow> {
        self.cached_snapshot
            .iter()
            .map(|(name, status)| {
                let age_millis = now_millis.saturating_sub(status.updated_unix_millis);
                let kind = match &status.kind {
                    PathKindStatus::Direct { address } => PathRowKind::Direct {
                        address: address.clone(),
                    },
                    PathKindStatus::Relay => PathRowKind::Relay,
                };
                P2PPathRow {
                    export_name: name.clone(),
                    kind,
                    age_millis,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_based_update_detection() {
        let store = rustgoc::PathStatusStore::new();
        let mut vm = P2PViewModel::new(store.clone());

        assert!(!vm.update());
        assert_eq!(vm.rows(1000).len(), 0);

        store.record(
            "export1".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 500,
            },
        );

        assert!(vm.update());
        assert_eq!(vm.rows(1000).len(), 1);

        assert!(!vm.update());
    }

    #[test]
    fn test_row_projection() {
        let store = rustgoc::PathStatusStore::new();
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
                    address: "10.0.0.5:7000".to_string(),
                },
                updated_unix_millis: 2000,
            },
        );

        let mut vm = P2PViewModel::new(store);
        vm.update();
        let rows = vm.rows(3000);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].export_name, "export1");
        assert!(matches!(rows[0].kind, PathRowKind::Relay));
        assert_eq!(rows[0].age_millis, 2000);

        assert_eq!(rows[1].export_name, "export2");
        match &rows[1].kind {
            PathRowKind::Direct { address } => {
                assert_eq!(address, "10.0.0.5:7000");
            }
            _ => panic!("Expected Direct"),
        }
        assert_eq!(rows[1].age_millis, 1000);
    }

    #[test]
    fn test_age_saturating_sub() {
        let store = rustgoc::PathStatusStore::new();
        store.record(
            "export1".to_string(),
            PathStatus {
                kind: PathKindStatus::Relay,
                updated_unix_millis: 5000,
            },
        );

        let mut vm = P2PViewModel::new(store);
        vm.update();
        let rows = vm.rows(3000);

        assert_eq!(rows[0].age_millis, 0);
    }
}

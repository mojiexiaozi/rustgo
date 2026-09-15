#![forbid(unsafe_code)]
#![allow(dead_code)]

use rustgoc::RegisteredTunnel;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelRow {
    pub tunnel_id: u32,
    pub name: String,
    pub protocol: String,
    pub local_addr: String,
    pub remote_port: u16,
    pub accepted: bool,
    pub error: Option<String>,
}

impl TunnelRow {
    pub fn from_registered(tunnel: &RegisteredTunnel) -> Self {
        Self {
            tunnel_id: tunnel.tunnel_id(),
            name: tunnel.name().to_string(),
            protocol: format!("{:?}", tunnel.protocol()),
            local_addr: tunnel.local_addr().to_string(),
            remote_port: tunnel.remote_port(),
            accepted: tunnel.accepted(),
            error: tunnel.error_message(),
        }
    }

    pub fn diff(old: &[Self], new: &[Self]) -> Vec<TunnelRowDiff> {
        let mut diffs = Vec::new();

        for new_row in new {
            if let Some(old_row) = old.iter().find(|r| r.tunnel_id == new_row.tunnel_id) {
                if old_row != new_row {
                    diffs.push(TunnelRowDiff::Modified(new_row.clone()));
                }
            } else {
                diffs.push(TunnelRowDiff::Added(new_row.clone()));
            }
        }

        for old_row in old {
            if !new.iter().any(|r| r.tunnel_id == old_row.tunnel_id) {
                diffs.push(TunnelRowDiff::Removed(old_row.tunnel_id));
            }
        }

        diffs
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelRowDiff {
    Added(TunnelRow),
    Modified(TunnelRow),
    Removed(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_registered() {
        // This test can't use accepted_for_test which is private to rustgoc
        // In real usage, RegisteredTunnel comes from ClientApp
        // So we'll skip this unit test and rely on integration test
    }

    #[test]
    fn test_diff_empty() {
        let old: Vec<TunnelRow> = vec![];
        let new: Vec<TunnelRow> = vec![];
        let diffs = TunnelRow::diff(&old, &new);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_diff_added() {
        let old: Vec<TunnelRow> = vec![];
        let new = vec![TunnelRow {
            tunnel_id: 1,
            name: "test".to_string(),
            protocol: "Tcp".to_string(),
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port: 9001,
            accepted: true,
            error: None,
        }];

        let diffs = TunnelRow::diff(&old, &new);
        assert_eq!(diffs.len(), 1);
        match &diffs[0] {
            TunnelRowDiff::Added(row) => assert_eq!(row.tunnel_id, 1),
            _ => panic!("Expected Added"),
        }
    }

    #[test]
    fn test_diff_removed() {
        let old = vec![TunnelRow {
            tunnel_id: 1,
            name: "test".to_string(),
            protocol: "Tcp".to_string(),
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port: 9001,
            accepted: true,
            error: None,
        }];
        let new: Vec<TunnelRow> = vec![];

        let diffs = TunnelRow::diff(&old, &new);
        assert_eq!(diffs.len(), 1);
        match &diffs[0] {
            TunnelRowDiff::Removed(id) => assert_eq!(*id, 1),
            _ => panic!("Expected Removed"),
        }
    }

    #[test]
    fn test_diff_no_change() {
        let row = TunnelRow {
            tunnel_id: 1,
            name: "test".to_string(),
            protocol: "Tcp".to_string(),
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port: 9001,
            accepted: true,
            error: None,
        };
        let old = vec![row.clone()];
        let new = vec![row];

        let diffs = TunnelRow::diff(&old, &new);
        assert!(diffs.is_empty());
    }
}

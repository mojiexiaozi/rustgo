use rustgo_config::ManagedConfiguration;

/// Server snapshots never replace the editable, locally persisted config.
#[derive(Default)]
pub struct ManagedViewModel {
    server: String,
    revision: Option<u64>,
    snapshot: Option<ManagedConfiguration>,
}

impl ManagedViewModel {
    pub fn select_server(&mut self, server: &str) {
        if self.server != server {
            self.server = server.to_owned();
            self.revision = None;
            self.snapshot = None;
        }
    }

    pub fn observe(
        &mut self,
        active: bool,
        revision: Option<u64>,
        snapshot: Option<&ManagedConfiguration>,
    ) -> bool {
        if active && revision.is_none() && snapshot.is_some() {
            // A successful legacy/unmanaged session confirms ownership changed.
            self.revision = None;
            return self.snapshot.take().is_some();
        }
        let (Some(revision), Some(snapshot)) = (revision, snapshot) else {
            // A fresh ClientApp or disconnected status must not unlock editing.
            return false;
        };
        if self.revision == Some(revision) && self.snapshot.as_ref() == Some(snapshot) {
            return false;
        }
        self.revision = Some(revision);
        self.snapshot = Some(snapshot.clone());
        true
    }

    pub fn revision(&self) -> Option<u64> {
        self.revision
    }
    pub fn snapshot(&self) -> Option<&ManagedConfiguration> {
        self.snapshot.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_unmanaged_session_unlocks_same_server_but_disconnect_does_not() {
        let mut model = ManagedViewModel::default();
        model.select_server("one:8443");
        let snapshot = ManagedConfiguration {
            p2p_enabled: false,
            tunnels: vec![],
            exports: vec![],
            forwards: vec![],
        };
        assert!(model.observe(true, Some(7), Some(&snapshot)));
        assert!(!model.observe(false, None, None));
        assert!(model.snapshot().is_some());
        assert!(!model.observe(false, None, Some(&snapshot)));
        assert!(model.snapshot().is_some());
        assert!(model.observe(true, None, Some(&snapshot)));
        assert!(model.snapshot().is_none());
        assert_eq!(model.revision(), None);
    }

    #[test]
    fn managed_snapshot_survives_reconnect_but_not_server_change() {
        let mut model = ManagedViewModel::default();
        model.select_server("one:8443");
        let snapshot = rustgo_config::ManagedConfiguration {
            p2p_enabled: false,
            tunnels: vec![],
            exports: vec![],
            forwards: vec![],
        };
        assert!(model.observe(true, Some(7), Some(&snapshot)));
        assert!(!model.observe(true, Some(7), Some(&snapshot)));
        assert!(!model.observe(false, None, None));
        model.select_server("one:8443");
        assert_eq!(model.snapshot(), Some(&snapshot));
        let mut changed = snapshot.clone();

        assert!(model.observe(true, Some(8), Some(&changed)));
        changed.tunnels.push(rustgo_config::TunnelConfig {
            name: "ssh".into(),
            protocol: rustgo_config::TunnelProtocol::Tcp,
            local_addr: "127.0.0.1:22".into(),
            remote_port: 10022,
        });
        assert!(model.observe(true, Some(8), Some(&changed)));
        assert_eq!(model.snapshot(), Some(&changed));
        model.select_server("two:8443");
        assert!(model.snapshot().is_none());
    }
}

use std::{collections::HashMap, sync::Arc};

use rustgo_config::{AuthorizedClient, ManagedConfiguration};
use rustgo_crypto::DevicePublicKey;

use crate::{
    enrollment::DynamicClientStore,
    managed::{ManagedError, ManagedSnapshot, ManagedStore},
    registry::ClientRegistry,
};

/// Shares authenticated identity resolution between the control channel and dashboard.
#[derive(Clone)]
pub struct TunnelManagement {
    pub(crate) store: Arc<ManagedStore>,
    pub(crate) registry: ClientRegistry,
    static_identities: Arc<HashMap<String, (String, bool)>>,
    dynamic: Option<Arc<DynamicClientStore>>,
    max_tunnels: usize,
}

impl TunnelManagement {
    pub(crate) fn update_authenticated(
        &self,
        authenticated: &crate::AuthenticatedClient,
        expected_revision: u64,
        configuration: &ManagedConfiguration,
    ) -> Result<ManagedSnapshot, ManagedError> {
        self.validate(authenticated.name(), configuration)?;
        if !configuration.p2p_enabled
            && (!configuration.exports.is_empty() || !configuration.forwards.is_empty())
        {
            return Err(ManagedError::Invalid(
                "请先在客户端启用 P2P，或删除 P2P 项目".into(),
            ));
        }
        let identity = self.authenticated_identity(authenticated)?;
        self.store.replace_for_identity(
            &identity,
            authenticated.name(),
            expected_revision,
            configuration,
        )
    }

    pub(crate) fn sync_authenticated(
        &self,
        authenticated: &crate::AuthenticatedClient,
        configuration: &ManagedConfiguration,
    ) -> Result<ManagedSnapshot, ManagedError> {
        self.validate(authenticated.name(), configuration)?;
        let identity = self.authenticated_identity(authenticated)?;
        let snapshot = self
            .store
            .sync(&identity, authenticated.name(), configuration)?;
        if !configuration.p2p_enabled
            && (!snapshot.configuration.exports.is_empty()
                || !snapshot.configuration.forwards.is_empty())
        {
            let results: Vec<_> = snapshot.configuration.tunnels.iter().map(|item| ("tunnel",item.name.as_str()))
                .chain(snapshot.configuration.exports.iter().map(|item| ("export",item.name.as_str())))
                .chain(snapshot.configuration.forwards.iter().map(|item| ("forward",item.name.as_str())))
                .map(|(kind,name)| serde_json::json!({"kind":kind,"name":name,"state":"failed","error":"配置无法应用：请在客户端启用 P2P 或删除服务器上的 P2P 项目"})).collect();
            self.store
                .report(&identity, snapshot.revision, serde_json::json!(results))?;
        }
        Ok(snapshot)
    }

    pub(crate) fn authenticated_identity(
        &self,
        authenticated: &crate::AuthenticatedClient,
    ) -> Result<String, ManagedError> {
        let name = authenticated.name();
        if let Some((identity, enabled)) = self.static_identities.get(name) {
            if *enabled && identity == &format!("static:{}", authenticated.fingerprint()) {
                return Ok(identity.clone());
            }
            return Err(ManagedError::NotFound);
        }
        let client = self
            .dynamic
            .as_ref()
            .ok_or(ManagedError::NotFound)?
            .client_by_display_id(name)
            .map_err(|error| ManagedError::Storage(error.to_string()))?
            .ok_or(ManagedError::NotFound)?;
        let key: DevicePublicKey = client
            .public_key()
            .ok_or(ManagedError::NotFound)?
            .parse()
            .map_err(|_| ManagedError::NotFound)?;
        if !client.enabled()
            || client.is_deleted()
            || key.fingerprint().to_string() != authenticated.fingerprint()
        {
            return Err(ManagedError::NotFound);
        }
        Ok(format!("dynamic:{}", client.internal_id()))
    }

    pub(crate) fn new(
        store: Arc<ManagedStore>,
        registry: ClientRegistry,
        clients: &[AuthorizedClient],
        dynamic: Option<Arc<DynamicClientStore>>,
        max_tunnels: usize,
    ) -> Result<Self, ManagedError> {
        let mut identities = HashMap::new();
        for client in clients {
            let key: DevicePublicKey = client
                .public_key
                .parse()
                .map_err(|_| ManagedError::Invalid("invalid client public key".into()))?;
            identities.insert(
                client.name.clone(),
                (format!("static:{}", key.fingerprint()), client.enabled),
            );
        }
        Ok(Self {
            store,
            registry,
            static_identities: Arc::new(identities),
            dynamic,
            max_tunnels,
        })
    }

    pub(crate) fn identity(&self, name: &str) -> Result<String, ManagedError> {
        if let Some((identity, enabled)) = self.static_identities.get(name) {
            return if *enabled {
                Ok(identity.clone())
            } else {
                Err(ManagedError::NotFound)
            };
        }
        let client = self
            .dynamic
            .as_ref()
            .ok_or(ManagedError::NotFound)?
            .client_by_display_id(name)
            .map_err(|error| ManagedError::Storage(error.to_string()))?
            .ok_or(ManagedError::NotFound)?;
        if !client.enabled() || client.is_deleted() || !client.is_bound() {
            return Err(ManagedError::NotFound);
        }
        Ok(format!("dynamic:{}", client.internal_id()))
    }

    pub(crate) fn validate(
        &self,
        name: &str,
        configuration: &ManagedConfiguration,
    ) -> Result<(), ManagedError> {
        configuration
            .validate()
            .map_err(|error| ManagedError::Invalid(error.to_string()))?;
        if configuration
            .forwards
            .iter()
            .any(|forward| forward.peer.eq_ignore_ascii_case(name))
        {
            return Err(ManagedError::Invalid("转发目标不能是客户端自身".into()));
        }
        if configuration.tunnels.len() > self.max_tunnels {
            return Err(ManagedError::Invalid("too many server tunnels".into()));
        }
        Ok(())
    }

    pub(crate) fn snapshot(&self, name: &str) -> Result<Option<ManagedSnapshot>, ManagedError> {
        let Some(mut snapshot) = self.store.get_for_identity(&self.identity(name)?)? else {
            return Ok(None);
        };
        for forward in &snapshot.configuration.forwards {
            let target = match self.identity(&forward.peer) {
                Ok(identity) => self.store.get_for_identity(&identity)?,
                Err(ManagedError::NotFound) => None,
                Err(error) => return Err(error),
            };
            let issue = if let Some(target) = &target {
                match target
                    .configuration
                    .exports
                    .iter()
                    .find(|export| export.name == forward.export)
                {
                    None => Some(("failed", "目标导出不存在")),
                    Some(export) if !export.allows_peer(name) => {
                        Some(("failed", "目标导出不允许此客户端访问"))
                    }
                    Some(_)
                        if self
                            .registry
                            .active_control_session(&forward.peer)
                            .is_none() =>
                    {
                        Some(("pending", "目标客户端离线"))
                    }
                    Some(_) if target.applied_revision != Some(target.revision) => {
                        Some(("pending", "目标配置等待应用"))
                    }
                    _ => None,
                }
            } else if self
                .registry
                .active_control_session(&forward.peer)
                .is_none()
            {
                Some(("pending", "目标客户端不可用"))
            } else {
                None
            };
            if let Some((state, error)) = issue
                && let Some(results) = snapshot.results.as_array_mut()
            {
                let projected = serde_json::json!({"kind":"forward","name":forward.name,"state":state,"error":error});
                if let Some(result) = results
                    .iter_mut()
                    .find(|result| result["kind"] == "forward" && result["name"] == forward.name)
                {
                    if result["state"] != "failed" {
                        *result = projected;
                    }
                } else {
                    results.push(projected);
                }
            }
        }
        Ok(Some(snapshot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleting_provider_export_marks_consumer_target_unavailable_without_deleting_forward() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(ManagedStore::open(&directory.path().join("managed.db")).unwrap());
        let clients: Vec<_> = [("provider", 1), ("consumer", 2)]
            .into_iter()
            .map(|(name, seed)| AuthorizedClient {
                name: name.into(),
                public_key: rustgo_crypto::DeviceKeypair::from_secret_bytes([seed; 32])
                    .public_key()
                    .to_string(),
                enabled: true,
            })
            .collect();
        let registry = ClientRegistry::new(
            4,
            16,
            "127.0.0.1".parse().unwrap(),
            32,
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let management =
            TunnelManagement::new(store.clone(), registry, &clients, None, 16).unwrap();
        let mut provider = ManagedConfiguration {
            tunnels: vec![],
            exports: vec![rustgo_config::ExportConfig {
                name: "ssh".into(),
                protocol: rustgo_config::TunnelProtocol::Tcp,
                local_addr: "127.0.0.1:22".into(),
                allowed_peers: vec!["consumer".into()],
            }],
            forwards: vec![],
            p2p_enabled: true,
        };
        store
            .sync(
                &management.identity("provider").unwrap(),
                "provider",
                &provider,
            )
            .unwrap();
        let mut disabled = provider.clone();
        disabled.p2p_enabled = false;
        let authenticated = crate::AuthenticatedClient::verified(
            "provider".into(),
            rustgo_crypto::DeviceKeypair::from_secret_bytes([1; 32])
                .public_key()
                .fingerprint()
                .to_string(),
            vec![1; 32],
        );
        management
            .sync_authenticated(&authenticated, &disabled)
            .unwrap();
        let failed = store.get("provider").unwrap().unwrap();
        assert_eq!(failed.configuration.exports.len(), 1);
        assert_eq!(failed.results[0]["state"], "failed");
        assert!(
            failed.results[0]["error"]
                .as_str()
                .unwrap()
                .contains("启用 P2P")
        );
        let consumer = ManagedConfiguration {
            tunnels: vec![],
            exports: vec![],
            forwards: vec![rustgo_config::ForwardConfig {
                name: "use-ssh".into(),
                peer: "provider".into(),
                export: "ssh".into(),
                listen_addr: "127.0.0.1:10022".into(),
            }],
            p2p_enabled: true,
        };
        let identity = management.identity("consumer").unwrap();
        store.sync(&identity, "consumer", &consumer).unwrap();
        store.report(&identity,1,serde_json::json!([{"kind":"forward","name":"use-ssh","state":"ready","error":null}])).unwrap();
        provider.exports.clear();
        store
            .replace("provider", failed.revision, &provider)
            .unwrap();
        let projected = management.snapshot("consumer").unwrap().unwrap();
        assert_eq!(projected.configuration.forwards.len(), 1);
        assert_eq!(projected.results[0]["state"], "failed");
        assert_eq!(projected.results[0]["error"], "目标导出不存在");
        assert_eq!(
            store.get("consumer").unwrap().unwrap().results[0]["state"],
            "ready"
        );
    }
}

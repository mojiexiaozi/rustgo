use crate::{ClientConfig, ExportConfig, ForwardConfig, TunnelConfig, ValidationError};
use serde::{Deserialize, Serialize};

/// Server-owned collections and the client's advertised local P2P capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedConfiguration {
    pub tunnels: Vec<TunnelConfig>,
    pub exports: Vec<ExportConfig>,
    pub forwards: Vec<ForwardConfig>,
    pub p2p_enabled: bool,
}

impl ManagedConfiguration {
    pub fn from_client(client: &ClientConfig) -> Self {
        Self {
            tunnels: client.tunnels.clone(),
            exports: client.exports.clone(),
            forwards: client.forwards.clone(),
            p2p_enabled: client.p2p.as_ref().is_some_and(|p| p.enabled),
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        crate::validate::validate_managed_collections(
            &self.tunnels,
            &self.exports,
            &self.forwards,
            None,
        )
    }

    /// Apply atomically while preserving all locally owned identity and P2P policy.
    pub fn apply_to(&self, client: &mut ClientConfig) -> Result<(), ValidationError> {
        self.validate()?;
        if (!self.exports.is_empty() || !self.forwards.is_empty())
            && !client.p2p.as_ref().is_some_and(|p| p.enabled)
        {
            return Err(ValidationError::new(
                "managed exports and forwards require locally enabled P2P",
            ));
        }
        let mut candidate = client.clone();
        candidate.tunnels.clone_from(&self.tunnels);
        candidate.exports.clone_from(&self.exports);
        candidate.forwards.clone_from(&self.forwards);
        candidate.validate()?;
        *client = candidate;
        Ok(())
    }
}

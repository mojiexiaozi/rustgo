use std::{net::IpAddr, path::PathBuf};

use serde::Deserialize;

use crate::ValidationError;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub limits: Limits,
    #[serde(default)]
    pub clients: Vec<AuthorizedClient>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub bind_addr: String,
    #[serde(default)]
    pub udp_bind_ip: Option<IpAddr>,
    #[serde(default)]
    pub p2p_observation_bind: Option<String>,
    #[serde(default)]
    pub p2p_observation_alternate_bind: Option<String>,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub heartbeat_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_clients: u32,
    pub max_tunnels_per_client: u32,
    pub max_tcp_connections_per_tunnel: u32,
    pub max_udp_sessions_per_tunnel: u32,
    pub max_udp_payload_bytes: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedClient {
    pub name: String,
    pub public_key: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client: ClientSection,
    pub p2p: Option<crate::P2pConfig>,
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,
    #[serde(default)]
    pub exports: Vec<crate::ExportConfig>,
    #[serde(default)]
    pub forwards: Vec<crate::ForwardConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    pub name: String,
    pub server_addr: String,
    pub server_name: String,
    pub certificate_authority_file: PathBuf,
    pub private_key_file: PathBuf,
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub name: String,
    pub protocol: TunnelProtocol,
    pub local_addr: String,
    pub remote_port: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Tcp,
    Udp,
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        crate::validate::validate_server(self)
    }
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        crate::validate::validate_client(self)
    }

    pub fn validation_warnings(&self) -> Vec<crate::ConfigWarning> {
        crate::validate::client_validation_warnings(self)
    }
}

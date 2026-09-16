use std::{fmt, net::IpAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::ValidationError;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub limits: Limits,
    #[serde(default)]
    pub clients: Vec<AuthorizedClient>,
    #[serde(default)]
    pub web: Option<WebConfig>,
    #[serde(default)]
    pub enrollment: Option<EnrollmentConfig>,
    #[serde(default)]
    pub managed_tunnels: Option<ManagedTunnelsConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedTunnelsConfig {
    pub database_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EnrollmentConfig {
    pub enabled: bool,
    pub database_path: PathBuf,
    pub public_addr: String,
    pub token_ttl_secs: u64,
    pub max_active_clients: u32,
    pub max_tokens: u32,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: PathBuf::from("./rustgo-enrollment.db"),
            public_addr: "127.0.0.1:7443".to_owned(),
            token_ttl_secs: 900,
            max_active_clients: 10_000,
            max_tokens: 20_000,
        }
    }
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
    pub telemetry: Option<TelemetryConfig>,
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
    #[serde(default)]
    pub profile: Option<ClientProfile>,
    #[serde(default)]
    pub identity_mode: Option<IdentityMode>,
    pub server_addr: String,
    pub server_name: String,
    pub certificate_authority_file: PathBuf,
    #[serde(default)]
    pub trust_mode: Option<TrustMode>,
    #[serde(default)]
    pub server_certificate_fingerprint: Option<String>,
    pub private_key_file: PathBuf,
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientProfile {
    pub display_name: String,
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub local_ip: Option<String>,
}

impl ClientSection {
    pub fn display_name(&self) -> &str {
        self.profile
            .as_ref()
            .map_or(&self.name, |profile| &profile.display_name)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrustMode {
    Pinned,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IdentityMode {
    Static,
    Dynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub name: String,
    pub protocol: TunnelProtocol,
    pub local_addr: String,
    pub remote_port: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub enabled: bool,
    pub bind: String,
    pub external_origin: Option<String>,
    pub admin_username: String,
    pub admin_password: String,
    pub cookie_secure: bool,
    pub history_days: u16,
    pub database_path: PathBuf,
    pub database_max_mib: u32,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:7450".to_owned(),
            external_origin: None,
            admin_username: "admin".to_owned(),
            admin_password: "replace-with-at-least-16-characters".to_owned(),
            cookie_secure: true,
            history_days: 7,
            database_path: PathBuf::from("./rustgo-metrics.db"),
            database_max_mib: 256,
        }
    }
}

impl fmt::Debug for WebConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebConfig")
            .field("enabled", &self.enabled)
            .field("bind", &self.bind)
            .field("external_origin", &self.external_origin)
            .field("admin_username", &self.admin_username)
            .field("admin_password", &"[REDACTED]")
            .field("cookie_secure", &self.cookie_secure)
            .field("history_days", &self.history_days)
            .field("database_path", &self.database_path)
            .field("database_max_mib", &self.database_max_mib)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub sample_interval_secs: u64,
    pub report_interval_secs: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_interval_secs: 10,
            report_interval_secs: 30,
        }
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        crate::validate::validate_server(self)
    }

    pub fn validation_warnings(&self) -> Vec<crate::ConfigWarning> {
        crate::validate::server_validation_warnings(self)
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

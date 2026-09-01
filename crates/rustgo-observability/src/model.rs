use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const MAX_AUTHENTICATED_CLIENT_NAME_BYTES: usize = 128;

/// Identity copied from a server-side authenticated control context.
///
/// Telemetry payloads deliberately do not carry this value. Callers create it
/// only after server authentication and pass it beside observations.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedClientIdentity {
    name: String,
    generation: u64,
}

impl AuthenticatedClientIdentity {
    pub fn from_server_authentication(
        name: impl Into<String>,
        generation: u64,
    ) -> Result<Self, AuthenticatedIdentityError> {
        let name = name.into();
        if name.is_empty() || name.len() > MAX_AUTHENTICATED_CLIENT_NAME_BYTES {
            return Err(AuthenticatedIdentityError::InvalidNameLength);
        }
        if generation == 0 {
            return Err(AuthenticatedIdentityError::ZeroGeneration);
        }
        Ok(Self { name, generation })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for AuthenticatedClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedClientIdentity")
            .field("name", &self.name)
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedIdentityError {
    InvalidNameLength,
    ZeroGeneration,
}

impl fmt::Display for AuthenticatedIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNameLength => write!(
                formatter,
                "authenticated client name must contain 1 to {MAX_AUTHENTICATED_CLIENT_NAME_BYTES} bytes"
            ),
            Self::ZeroGeneration => {
                formatter.write_str("authenticated client generation must be nonzero")
            }
        }
    }
}

impl std::error::Error for AuthenticatedIdentityError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMetrics {
    pub sampled_unix_millis: u64,
    pub cpu_basis_points: Option<u16>,
    pub process_cpu_basis_points: Option<u16>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub process_memory_bytes: Option<u64>,
    pub disk_used_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub disk_read_bytes_per_sec: Option<u64>,
    pub disk_write_bytes_per_sec: Option<u64>,
    pub network_rx_bytes_per_sec: Option<u64>,
    pub network_tx_bytes_per_sec: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficCounters {
    pub received_bytes: u64,
    pub sent_bytes: u64,
}

impl TrafficCounters {
    pub(crate) fn saturating_add(&mut self, delta: Self) {
        self.received_bytes = self.received_bytes.saturating_add(delta.received_bytes);
        self.sent_bytes = self.sent_bytes.saturating_add(delta.sent_bytes);
    }
}

/// A one-way, deterministic redaction of a full runtime session identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortSessionId(String);

impl ShortSessionId {
    const HEX_BYTES: usize = 16;

    pub fn from_bytes(full_session_id: &[u8]) -> Self {
        let digest = Sha256::digest(full_session_id);
        let mut shortened = String::with_capacity(Self::HEX_BYTES);
        for byte in &digest[..Self::HEX_BYTES / 2] {
            use fmt::Write as _;
            write!(&mut shortened, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(shortened)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShortSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for ShortSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ShortSessionId")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for ShortSessionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ShortSessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != Self::HEX_BYTES || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(D::Error::custom("invalid shortened session identifier"));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionKind {
    Tcp,
    Udp,
    P2p,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionPath {
    Relay,
    P2pDirect,
    P2pFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub id: ShortSessionId,
    pub client: String,
    pub peer: Option<String>,
    pub tunnel: Option<String>,
    pub export: Option<String>,
    pub kind: SessionKind,
    pub path: SessionPath,
    pub traffic: TrafficCounters,
    pub opened_unix_millis: u64,
    pub closed_unix_millis: Option<u64>,
    pub terminal_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub name: String,
    pub generation: u64,
    pub version: String,
    pub online: bool,
    pub authenticated_unix_millis: u64,
    pub disconnected_unix_millis: Option<u64>,
    pub last_heartbeat_unix_millis: Option<u64>,
    pub telemetry_received_unix_millis: Option<u64>,
    pub telemetry_sequence: Option<u64>,
    pub metrics: Option<HostMetrics>,
    pub traffic: TrafficCounters,
    pub tunnels: Vec<String>,
    pub exports: Vec<String>,
    pub forwards: Vec<String>,
    pub reconnects: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSnapshot {
    pub metrics: Option<HostMetrics>,
    pub traffic: TrafficCounters,
    pub online_clients: usize,
    pub active_tcp_sessions: usize,
    pub active_udp_sessions: usize,
    pub active_p2p_sessions: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverviewSnapshot {
    pub generated_unix_millis: u64,
    pub server: ServerSnapshot,
    pub clients: Vec<ClientSnapshot>,
    pub sessions: Vec<SessionSnapshot>,
    pub event_queue_depth: usize,
    pub dropped_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HistoryPoint {
    pub timestamp_unix_millis: u64,
    pub value: f64,
}

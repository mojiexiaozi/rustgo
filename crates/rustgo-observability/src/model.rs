use std::fmt;

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const MAX_AUTHENTICATED_CLIENT_NAME_BYTES: usize = 128;
pub const MAX_EVENT_LABEL_BYTES: usize = 128;
pub const MAX_INVENTORY_ITEMS: usize = 256;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedLabel(String);

impl BoundedLabel {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BoundedLabel")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for BoundedLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for BoundedLabel {
    type Error = LabelTooLong;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > MAX_EVENT_LABEL_BYTES {
            return Err(LabelTooLong {
                actual_bytes: value.len(),
            });
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for BoundedLabel {
    type Error = LabelTooLong;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl Serialize for BoundedLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BoundedLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelTooLong {
    actual_bytes: usize,
}

impl LabelTooLong {
    pub const fn actual_bytes(self) -> usize {
        self.actual_bytes
    }

    pub const fn maximum_bytes(self) -> usize {
        MAX_EVENT_LABEL_BYTES
    }
}

impl fmt::Display for LabelTooLong {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "label contains {} UTF-8 bytes; maximum is {MAX_EVENT_LABEL_BYTES}",
            self.actual_bytes
        )
    }
}

impl std::error::Error for LabelTooLong {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundedInventory(Vec<BoundedLabel>);

impl BoundedInventory {
    /// Retains the first 256 input entries, then sorts and deduplicates them.
    /// Any retained label over 128 UTF-8 bytes rejects the whole inventory.
    pub fn try_from_names<I, S>(names: I) -> Result<Self, LabelTooLong>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut names = names.into_iter();
        let mut bounded = Vec::with_capacity(names.size_hint().0.min(MAX_INVENTORY_ITEMS));
        for name in names.by_ref().take(MAX_INVENTORY_ITEMS) {
            bounded.push(BoundedLabel::try_from(name.as_ref())?);
        }
        bounded.sort_unstable();
        bounded.dedup();
        Ok(Self(bounded))
    }

    pub fn as_slice(&self) -> &[BoundedLabel] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for BoundedInventory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BoundedInventory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InventoryVisitor;

        impl<'de> Visitor<'de> for InventoryVisitor {
            type Value = BoundedInventory;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "at most {MAX_INVENTORY_ITEMS} bounded labels")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut labels =
                    Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_INVENTORY_ITEMS));
                while let Some(label) = sequence.next_element::<BoundedLabel>()? {
                    if labels.len() == MAX_INVENTORY_ITEMS {
                        return Err(A::Error::custom("inventory exceeds 256 entries"));
                    }
                    labels.push(label);
                }
                labels.sort_unstable();
                labels.dedup();
                Ok(BoundedInventory(labels))
            }
        }

        deserializer.deserialize_seq(InventoryVisitor)
    }
}

/// Identity copied from a server-side authenticated control context.
///
/// Telemetry payloads deliberately do not carry this value. Callers create it
/// only after server authentication and pass it beside observations.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedClientIdentity {
    name: BoundedLabel,
    generation: u64,
}

impl AuthenticatedClientIdentity {
    pub fn from_server_authentication(
        name: impl Into<String>,
        generation: u64,
    ) -> Result<Self, AuthenticatedIdentityError> {
        let name = name.into();
        if name.is_empty() {
            return Err(AuthenticatedIdentityError::InvalidNameLength);
        }
        let name = BoundedLabel::try_from(name)
            .map_err(|_| AuthenticatedIdentityError::InvalidNameLength)?;
        if generation == 0 {
            return Err(AuthenticatedIdentityError::ZeroGeneration);
        }
        Ok(Self { name, generation })
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub(crate) fn label(&self) -> &BoundedLabel {
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
            .field("name", &self.name.as_str())
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
    pub client: BoundedLabel,
    pub peer: Option<BoundedLabel>,
    pub tunnel: Option<BoundedLabel>,
    pub export: Option<BoundedLabel>,
    pub kind: SessionKind,
    pub path: SessionPath,
    pub traffic: TrafficCounters,
    pub opened_unix_millis: u64,
    pub closed_unix_millis: Option<u64>,
    pub terminal_reason: Option<BoundedLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub name: BoundedLabel,
    pub generation: u64,
    pub version: BoundedLabel,
    pub online: bool,
    pub authenticated_unix_millis: u64,
    pub disconnected_unix_millis: Option<u64>,
    pub last_heartbeat_unix_millis: Option<u64>,
    pub telemetry_received_unix_millis: Option<u64>,
    pub telemetry_sequence: Option<u64>,
    pub metrics: Option<HostMetrics>,
    pub traffic: TrafficCounters,
    pub tunnels: BoundedInventory,
    pub exports: BoundedInventory,
    pub forwards: BoundedInventory,
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

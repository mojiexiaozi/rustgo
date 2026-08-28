use serde::{Deserialize, Deserializer, de::Error as _};

use crate::TunnelProtocol;

const MAX_PORTS_PER_RANGE: u32 = 1024;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct P2pConfig {
    pub enabled: bool,
    pub prefer_direct: bool,
    pub direct_timeout_secs: u64,
    pub reconnect_timeout_secs: u64,
    pub allow_relay_fallback: bool,
    pub udp_port_range: PortRange,
    pub tcp_port_range: PortRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let Some((start, end)) = value.split_once('-') else {
            return Err(D::Error::custom("port range must use START-END format"));
        };
        let start = start
            .parse::<u16>()
            .map_err(|_| D::Error::custom("port range start must be a valid port"))?;
        let end = end
            .parse::<u16>()
            .map_err(|_| D::Error::custom("port range end must be a valid port"))?;
        if start == 0 || end == 0 {
            return Err(D::Error::custom(
                "port range ports must be between 1 and 65535",
            ));
        }
        if start > end {
            return Err(D::Error::custom("port range start must not exceed end"));
        }
        if u32::from(end) - u32::from(start) + 1 > MAX_PORTS_PER_RANGE {
            return Err(D::Error::custom(format!(
                "port range must contain at most {MAX_PORTS_PER_RANGE} ports"
            )));
        }
        Ok(Self { start, end })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    pub name: String,
    pub protocol: TunnelProtocol,
    pub local_addr: String,
    #[serde(default)]
    pub allowed_peers: Vec<String>,
}

impl ExportConfig {
    pub fn allows_peer(&self, peer: &str) -> bool {
        self.allowed_peers.is_empty() || self.allowed_peers.iter().any(|allowed| allowed == peer)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    pub name: String,
    pub peer: String,
    pub export: String,
    pub listen_addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    code: &'static str,
    message: String,
}

impl ConfigWarning {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

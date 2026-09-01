use std::{collections::HashSet, net::SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustgo_protocol::{MAX_CLIENT_NAME_BYTES, MAX_TUNNEL_NAME_BYTES, MAX_TUNNELS};
use thiserror::Error;
use url::{Host, Url};

use crate::{
    ClientConfig, ConfigWarning, MAX_ALLOWED_PEERS_PER_EXPORT, MAX_EXPORTS, MAX_FORWARDS,
    ServerConfig,
};

const MAX_LIMIT: u32 = 1_000_000;
const MAX_UDP_PAYLOAD_BYTES: u32 = 65_507;
pub const MAX_WEB_AUTHORITY_BYTES: usize = 128;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid configuration: {message}")]
pub struct ValidationError {
    message: String,
}

impl ValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebOrigin {
    scheme: &'static str,
    host: String,
    ipv6: bool,
    port: u16,
}

impl WebOrigin {
    pub fn from_config(web: &crate::WebConfig) -> Result<Self, ValidationError> {
        match web.external_origin.as_deref() {
            Some(origin) => {
                let parsed = Self::parse(origin)?;
                let expected_scheme = if web.cookie_secure { "https" } else { "http" };
                if parsed.scheme != expected_scheme {
                    return Err(ValidationError::new(format!(
                        "web.external_origin must use {expected_scheme} when web.cookie_secure is {}",
                        web.cookie_secure
                    )));
                }
                Ok(parsed)
            }
            None if web.cookie_secure => Err(ValidationError::new(
                "web.external_origin is required when web.cookie_secure is true",
            )),
            None => {
                let bind = web.bind.parse::<SocketAddr>().map_err(|_| {
                    ValidationError::new("web.bind must be an IP address with a port")
                })?;
                let origin = Self {
                    scheme: "http",
                    host: bind.ip().to_string(),
                    ipv6: bind.is_ipv6(),
                    port: bind.port(),
                };
                origin.ensure_authority_limit()?;
                Ok(origin)
            }
        }
    }

    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(invalid_external_origin());
        }
        let (_, raw_authority) = value
            .split_once("://")
            .ok_or_else(invalid_external_origin)?;
        if raw_authority.is_empty()
            || raw_authority
                .bytes()
                .any(|byte| matches!(byte, b'/' | b'\\' | b'?' | b'#'))
        {
            return Err(invalid_external_origin());
        }

        let parsed = Url::parse(value).map_err(|_| invalid_external_origin())?;
        let scheme = match parsed.scheme() {
            "http" => "http",
            "https" => "https",
            _ => return Err(invalid_external_origin()),
        };
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(invalid_external_origin());
        }

        let (host, ipv6) = match parsed.host().ok_or_else(invalid_external_origin)? {
            Host::Domain(domain) => (validate_canonical_dns_name(domain)?, false),
            Host::Ipv4(address) => (address.to_string(), false),
            Host::Ipv6(address) => (address.to_string(), true),
        };
        let port = parsed
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or_else(invalid_external_origin)?;
        let origin = Self {
            scheme,
            host,
            ipv6,
            port,
        };
        origin.ensure_authority_limit()?;
        Ok(origin)
    }

    pub const fn scheme(&self) -> &'static str {
        self.scheme
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn authority(&self) -> String {
        let host = if self.ipv6 {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default_port(self.scheme) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn as_str(&self) -> String {
        format!("{}://{}", self.scheme, self.authority())
    }

    pub fn matches_authority(&self, value: &str) -> bool {
        if value.is_empty()
            || value.len() > MAX_WEB_AUTHORITY_BYTES
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return false;
        }
        Self::parse(&format!("{}://{value}", self.scheme)).is_ok_and(|origin| origin == *self)
    }

    fn ensure_authority_limit(&self) -> Result<(), ValidationError> {
        if self.authority().len() > MAX_WEB_AUTHORITY_BYTES {
            return Err(invalid_external_origin());
        }
        Ok(())
    }
}

fn validate_canonical_dns_name(host: &str) -> Result<String, ValidationError> {
    if host.is_empty() || host.ends_with('.') {
        return Err(invalid_external_origin());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(invalid_external_origin());
        }
    }
    Ok(host.to_owned())
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

fn invalid_external_origin() -> ValidationError {
    ValidationError::new(format!(
        "web.external_origin must be an absolute HTTP(S) origin with a canonical authority of at most {MAX_WEB_AUTHORITY_BYTES} bytes and without userinfo, path, query, or fragment"
    ))
}

pub(crate) fn validate_server(config: &ServerConfig) -> Result<(), ValidationError> {
    validate_bind_address(&config.server.bind_addr)?;
    match (
        config.server.p2p_observation_bind.as_deref(),
        config.server.p2p_observation_alternate_bind.as_deref(),
    ) {
        (None, None) => {}
        (Some(primary), Some(alternate)) => {
            let primary = validate_server_socket_address("server.p2p_observation_bind", primary)?;
            let alternate =
                validate_server_socket_address("server.p2p_observation_alternate_bind", alternate)?;
            if primary.port() == alternate.port() {
                return Err(ValidationError::new(
                    "server observation bind addresses must use distinct ports",
                ));
            }
        }
        _ => {
            return Err(ValidationError::new(
                "server.p2p_observation_bind and server.p2p_observation_alternate_bind must be configured together",
            ));
        }
    }
    if config.server.udp_bind_ip.is_some_and(|ip| {
        ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast())
    }) {
        return Err(ValidationError::new(
            "server.udp_bind_ip must be a specific unicast or local interface address",
        ));
    }
    require_nonzero(
        "server.heartbeat_timeout_secs",
        config.server.heartbeat_timeout_secs,
    )?;
    validate_limits(&config.limits)?;
    if let Some(web) = &config.web
        && web.enabled
    {
        validate_web(web)?;
    }

    let mut names = HashSet::new();
    let mut public_keys = HashSet::new();
    for client in &config.clients {
        validate_client_name(&client.name)?;
        if !names.insert(&client.name) {
            return Err(ValidationError::new(format!(
                "duplicate client name `{}`",
                client.name
            )));
        }
        validate_public_key(&client.public_key)?;
        if !public_keys.insert(&client.public_key) {
            return Err(ValidationError::new("duplicate client public key"));
        }
    }
    Ok(())
}

pub(crate) fn validate_client(config: &ClientConfig) -> Result<(), ValidationError> {
    validate_client_name(&config.client.name)?;
    validate_host_address("client.server_addr", &config.client.server_addr)?;
    require_non_empty("client.server_name", &config.client.server_name)?;
    require_nonzero(
        "client.heartbeat_interval_secs",
        config.client.heartbeat_interval_secs,
    )?;
    if config.client.heartbeat_interval_secs > u64::from(u32::MAX) {
        return Err(ValidationError::new(format!(
            "client.heartbeat_interval_secs must be at most {}",
            u32::MAX
        )));
    }
    if config.tunnels.len() > MAX_TUNNELS {
        return Err(ValidationError::new(format!(
            "tunnels must contain at most {MAX_TUNNELS} entries"
        )));
    }

    let mut names = HashSet::new();
    let mut remote_ports = HashSet::new();
    for tunnel in &config.tunnels {
        validate_wire_string("tunnels.name", &tunnel.name, MAX_TUNNEL_NAME_BYTES)?;
        validate_host_address("tunnels.local_addr", &tunnel.local_addr)?;
        if !(1..=u16::MAX as u32).contains(&tunnel.remote_port) {
            return Err(ValidationError::new(format!(
                "tunnel `{}` has an invalid remote port",
                tunnel.name
            )));
        }
        if !names.insert(&tunnel.name) {
            return Err(ValidationError::new(format!(
                "duplicate tunnel name `{}`",
                tunnel.name
            )));
        }
        if !remote_ports.insert((tunnel.protocol, tunnel.remote_port)) {
            return Err(ValidationError::new(format!(
                "duplicate {:?} remote port {}",
                tunnel.protocol, tunnel.remote_port
            )));
        }
    }
    if let Some(p2p) = &config.p2p {
        require_nonzero("p2p.direct_timeout_secs", p2p.direct_timeout_secs)?;
        require_nonzero("p2p.reconnect_timeout_secs", p2p.reconnect_timeout_secs)?;
        match (
            &p2p.observation_primary_addr,
            &p2p.observation_alternate_addr,
        ) {
            (Some(primary), Some(alternate)) => {
                validate_host_address("p2p.observation_primary_addr", primary)?;
                validate_host_address("p2p.observation_alternate_addr", alternate)?;
                if primary == alternate {
                    return Err(ValidationError::new(
                        "P2P observation endpoints must be distinct",
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ValidationError::new(
                    "P2P observation primary and alternate endpoints must be configured together",
                ));
            }
        }
    }
    if let Some(telemetry) = &config.telemetry
        && telemetry.enabled
    {
        validate_telemetry(telemetry)?;
    }

    if config.exports.len() > MAX_EXPORTS {
        return Err(ValidationError::new(format!(
            "exports must contain at most {MAX_EXPORTS} entries"
        )));
    }
    if config.forwards.len() > MAX_FORWARDS {
        return Err(ValidationError::new(format!(
            "forwards must contain at most {MAX_FORWARDS} entries"
        )));
    }

    let mut export_names = HashSet::new();
    for export in &config.exports {
        validate_wire_string("exports.name", &export.name, MAX_TUNNEL_NAME_BYTES)?;
        validate_host_address("exports.local_addr", &export.local_addr)?;
        if !export_names.insert(&export.name) {
            return Err(ValidationError::new(format!(
                "duplicate export name `{}`",
                export.name
            )));
        }
        if export.allowed_peers.len() > MAX_ALLOWED_PEERS_PER_EXPORT {
            return Err(ValidationError::new(format!(
                "export `{}` allowed_peers must contain at most {MAX_ALLOWED_PEERS_PER_EXPORT} entries",
                export.name
            )));
        }
        for peer in &export.allowed_peers {
            validate_client_name(peer)?;
        }
    }

    let mut forward_names = HashSet::new();
    for forward in &config.forwards {
        validate_wire_string("forwards.name", &forward.name, MAX_TUNNEL_NAME_BYTES)?;
        validate_client_name(&forward.peer)?;
        validate_wire_string("forwards.export", &forward.export, MAX_TUNNEL_NAME_BYTES)?;
        validate_host_address("forwards.listen_addr", &forward.listen_addr)?;
        if forward.peer == config.client.name {
            return Err(ValidationError::new(format!(
                "forward `{}` must not target the local client",
                forward.name
            )));
        }
        if !forward_names.insert(&forward.name) {
            return Err(ValidationError::new(format!(
                "duplicate forward name `{}`",
                forward.name
            )));
        }
    }
    Ok(())
}

pub(crate) fn server_validation_warnings(config: &ServerConfig) -> Vec<ConfigWarning> {
    let mut warnings = Vec::new();
    if cfg!(windows) && config.web.as_ref().is_some_and(|web| web.enabled) {
        warnings.push(ConfigWarning::new(
            "WEB_CONFIG_ACL_REVIEW_REQUIRED",
            "enabled web configuration requires a manual ACL review on Windows",
        ));
    }
    warnings
}

pub(crate) fn client_validation_warnings(config: &ClientConfig) -> Vec<ConfigWarning> {
    let mut warnings = Vec::new();
    for export in &config.exports {
        if export.allowed_peers.is_empty() {
            warnings.push(ConfigWarning::new(
                "P2P_EXPORT_ALLOW_ALL",
                format!("export `{}` permits every authenticated peer", export.name),
            ));
        }
    }
    for forward in &config.forwards {
        if !is_loopback_listen_address(&forward.listen_addr) {
            warnings.push(ConfigWarning::new(
                "P2P_FORWARD_NON_LOOPBACK_LISTEN",
                format!(
                    "forward `{}` listens on a non-loopback address `{}`",
                    forward.name, forward.listen_addr
                ),
            ));
        }
    }
    warnings
}

fn validate_limits(limits: &crate::Limits) -> Result<(), ValidationError> {
    for (name, value) in [
        ("limits.max_clients", limits.max_clients),
        (
            "limits.max_tunnels_per_client",
            limits.max_tunnels_per_client,
        ),
        (
            "limits.max_tcp_connections_per_tunnel",
            limits.max_tcp_connections_per_tunnel,
        ),
        (
            "limits.max_udp_sessions_per_tunnel",
            limits.max_udp_sessions_per_tunnel,
        ),
    ] {
        if value == 0 || value > MAX_LIMIT {
            return Err(ValidationError::new(format!(
                "{name} must be between 1 and {MAX_LIMIT}"
            )));
        }
    }
    if !(1..=MAX_UDP_PAYLOAD_BYTES).contains(&limits.max_udp_payload_bytes) {
        return Err(ValidationError::new(format!(
            "limits.max_udp_payload_bytes must be between 1 and {MAX_UDP_PAYLOAD_BYTES}"
        )));
    }
    Ok(())
}

fn validate_web(web: &crate::WebConfig) -> Result<(), ValidationError> {
    let bind = web
        .bind
        .parse::<SocketAddr>()
        .map_err(|_| ValidationError::new("web.bind must be an IP address with a port"))?;
    if !bind.ip().is_loopback() {
        return Err(ValidationError::new(
            "web.bind must use a loopback IP address",
        ));
    }
    if bind.port() == 0 {
        return Err(ValidationError::new(
            "web.bind must use a port between 1 and 65535",
        ));
    }
    if bind.port() == 7443 {
        return Err(ValidationError::new(
            "web.bind must not use Rustgo relay port 7443",
        ));
    }
    WebOrigin::from_config(web)?;
    validate_byte_string("web.admin_username", &web.admin_username, 1, 64)?;
    validate_byte_string("web.admin_password", &web.admin_password, 16, 256)?;
    if !(1..=90).contains(&web.history_days) {
        return Err(ValidationError::new(
            "web.history_days must be between 1 and 90",
        ));
    }
    if !(16..=4096).contains(&web.database_max_mib) {
        return Err(ValidationError::new(
            "web.database_max_mib must be between 16 and 4096",
        ));
    }
    // A loopback-only listener may deliberately support direct local HTTP.
    // Reverse-proxied HTTPS deployments must set cookie_secure = true.
    let _ = web.cookie_secure;
    Ok(())
}

fn validate_telemetry(telemetry: &crate::TelemetryConfig) -> Result<(), ValidationError> {
    for (field, value) in [
        (
            "telemetry.sample_interval_secs",
            telemetry.sample_interval_secs,
        ),
        (
            "telemetry.report_interval_secs",
            telemetry.report_interval_secs,
        ),
    ] {
        if !(1..=3600).contains(&value) {
            return Err(ValidationError::new(format!(
                "{field} must be between 1 and 3600"
            )));
        }
    }
    if telemetry.report_interval_secs < telemetry.sample_interval_secs {
        return Err(ValidationError::new(
            "telemetry.report_interval_secs must be at least telemetry.sample_interval_secs",
        ));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(format!("{field} must not be empty")));
    }
    Ok(())
}

pub fn validate_client_name(value: &str) -> Result<(), ValidationError> {
    validate_wire_string("client name", value, MAX_CLIENT_NAME_BYTES)
}

fn validate_wire_string(
    field: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ValidationError> {
    require_non_empty(field, value)?;
    if value.len() > maximum_bytes {
        return Err(ValidationError::new(format!(
            "{field} must be at most {maximum_bytes} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_byte_string(
    field: &str,
    value: &str,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<(), ValidationError> {
    if !(minimum_bytes..=maximum_bytes).contains(&value.len()) {
        return Err(ValidationError::new(format!(
            "{field} must be between {minimum_bytes} and {maximum_bytes} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn require_nonzero(field: &str, value: u64) -> Result<(), ValidationError> {
    if value == 0 {
        return Err(ValidationError::new(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(())
}

fn validate_bind_address(value: &str) -> Result<(), ValidationError> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| ValidationError::new("server.bind_addr must be an IP address with a port"))?;
    if address.port() == 0 {
        return Err(ValidationError::new(
            "server.bind_addr must use a port between 1 and 65535",
        ));
    }
    Ok(())
}

fn validate_server_socket_address(field: &str, value: &str) -> Result<SocketAddr, ValidationError> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| ValidationError::new(format!("{field} must be an IP address with a port")))?;
    if address.port() == 0 {
        return Err(ValidationError::new(format!(
            "{field} must use a port between 1 and 65535"
        )));
    }
    Ok(address)
}

fn validate_host_address(field: &str, value: &str) -> Result<(), ValidationError> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(ValidationError::new(format!(
            "{field} must include a host and port"
        )));
    };
    if host.is_empty() || (host.contains(':') && !(host.starts_with('[') && host.ends_with(']'))) {
        return Err(ValidationError::new(format!(
            "{field} must contain a valid host"
        )));
    }
    let port = port
        .parse::<u32>()
        .map_err(|_| ValidationError::new(format!("{field} has an invalid port")))?;
    if !(1..=u16::MAX as u32).contains(&port) {
        return Err(ValidationError::new(format!("{field} has an invalid port")));
    }
    Ok(())
}

fn is_loopback_listen_address(value: &str) -> bool {
    value
        .parse::<SocketAddr>()
        .is_ok_and(|address| address.ip().is_loopback())
        || value.starts_with("localhost:")
}

fn validate_public_key(value: &str) -> Result<(), ValidationError> {
    let Some(encoded) = value.strip_prefix("ed25519:") else {
        return Err(ValidationError::new(
            "client public key must use ed25519: format",
        ));
    };
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| ValidationError::new("client public key is not valid base64"))?;
    if decoded.len() != 32 {
        return Err(ValidationError::new(
            "client public key must contain exactly 32 bytes",
        ));
    }
    Ok(())
}

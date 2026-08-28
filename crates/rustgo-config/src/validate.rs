use std::{collections::HashSet, net::SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustgo_protocol::{MAX_CLIENT_NAME_BYTES, MAX_TUNNEL_NAME_BYTES, MAX_TUNNELS};
use thiserror::Error;

use crate::{ClientConfig, ServerConfig};

const MAX_LIMIT: u32 = 1_000_000;
const MAX_UDP_PAYLOAD_BYTES: u32 = 65_507;

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

pub(crate) fn validate_server(config: &ServerConfig) -> Result<(), ValidationError> {
    validate_bind_address(&config.server.bind_addr)?;
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

    let mut names = HashSet::new();
    let mut public_keys = HashSet::new();
    for client in &config.clients {
        validate_wire_string("clients.name", &client.name, MAX_CLIENT_NAME_BYTES)?;
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
    validate_wire_string("client.name", &config.client.name, MAX_CLIENT_NAME_BYTES)?;
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
    Ok(())
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

fn require_non_empty(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(format!("{field} must not be empty")));
    }
    Ok(())
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

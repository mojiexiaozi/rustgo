use crate::{MappingEvidence, Observation, analyze_mappings};

pub const MAX_PREDICTED_PORTS: usize = 16;

/// A requested prediction width; it is clamped to [`MAX_PREDICTED_PORTS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredictionPolicy {
    pub requested_window: usize,
}

pub fn predicted_ports(observations: &[Observation], policy: PredictionPolicy) -> Vec<u16> {
    let MappingEvidence::Sequential { delta } = analyze_mappings(observations) else {
        return Vec::new();
    };
    let Some(last) = observations.last() else {
        return Vec::new();
    };
    let last_port = match &last.mapped_address {
        rustgo_protocol::SocketAddress::V4 { port, .. }
        | rustgo_protocol::SocketAddress::V6 { port, .. } => *port,
    };
    let mut ports = Vec::with_capacity(policy.requested_window.min(MAX_PREDICTED_PORTS));
    for offset in 1..=policy.requested_window.min(MAX_PREDICTED_PORTS) {
        let predicted =
            i32::from(last_port) + i32::from(delta) * i32::try_from(offset).unwrap_or(i32::MAX);
        let Ok(port) = u16::try_from(predicted) else {
            break;
        };
        if port == 0 {
            break;
        }
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports
}

use rustgo_protocol::SocketAddress;

use crate::candidate::is_usable_address;

/// A server-observed mapping for one UDP probe destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub destination: SocketAddress,
    pub mapped_address: SocketAddress,
}

impl Observation {
    pub fn new(destination: SocketAddress, mapped_address: SocketAddress) -> Self {
        Self {
            destination,
            mapped_address,
        }
    }
}

/// Bounded observations about mappings, intentionally not a definitive NAT classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingEvidence {
    Stable,
    DestinationPortDependent,
    Sequential { delta: i16 },
    Uncertain,
}

pub fn analyze_mappings(observations: &[Observation]) -> MappingEvidence {
    if observations.len() < 2
        || observations.iter().any(|observation| {
            !is_usable_address(&observation.destination)
                || !is_usable_address(&observation.mapped_address)
        })
        || !all_share_destination_host(observations)
        || !all_share_mapped_host(observations)
    {
        return MappingEvidence::Uncertain;
    }

    if observations
        .iter()
        .all(|observation| observation.mapped_address == observations[0].mapped_address)
    {
        return MappingEvidence::Stable;
    }

    if destination_port_dependent(observations) {
        return MappingEvidence::DestinationPortDependent;
    }

    sequential_delta(observations)
        .map(|delta| MappingEvidence::Sequential { delta })
        .unwrap_or(MappingEvidence::Uncertain)
}

fn all_share_destination_host(observations: &[Observation]) -> bool {
    observations
        .iter()
        .all(|observation| same_host(&observation.destination, &observations[0].destination))
}

fn destination_port_dependent(observations: &[Observation]) -> bool {
    let mut mappings: Vec<(u16, &SocketAddress)> = Vec::new();
    for observation in observations {
        let destination_port = port(&observation.destination);
        if let Some((_, mapped_address)) = mappings
            .iter()
            .find(|(known_port, _)| *known_port == destination_port)
        {
            if *mapped_address != &observation.mapped_address {
                return false;
            }
        } else {
            mappings.push((destination_port, &observation.mapped_address));
        }
    }
    mappings.len() >= 2 && mappings.windows(2).any(|pair| pair[0].1 != pair[1].1)
}

fn sequential_delta(observations: &[Observation]) -> Option<i16> {
    if observations.len() < 3 || !all_share_mapped_host(observations) {
        return None;
    }
    let delta = signed_port_delta(
        port(&observations[0].mapped_address),
        port(&observations[1].mapped_address),
    )?;
    if delta == 0
        || observations.windows(2).any(|pair| {
            signed_port_delta(port(&pair[0].mapped_address), port(&pair[1].mapped_address))
                != Some(delta)
        })
    {
        return None;
    }
    Some(delta)
}

fn all_share_mapped_host(observations: &[Observation]) -> bool {
    observations
        .iter()
        .all(|observation| same_host(&observation.mapped_address, &observations[0].mapped_address))
}

fn signed_port_delta(previous: u16, next: u16) -> Option<i16> {
    i16::try_from(i32::from(next) - i32::from(previous)).ok()
}

fn port(address: &SocketAddress) -> u16 {
    match address {
        SocketAddress::V4 { port, .. } | SocketAddress::V6 { port, .. } => *port,
    }
}

fn same_host(left: &SocketAddress, right: &SocketAddress) -> bool {
    match (left, right) {
        (SocketAddress::V4 { octets: left, .. }, SocketAddress::V4 { octets: right, .. }) => {
            left == right
        }
        (SocketAddress::V6 { octets: left, .. }, SocketAddress::V6 { octets: right, .. }) => {
            left == right
        }
        _ => false,
    }
}

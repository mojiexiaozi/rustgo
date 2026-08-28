use std::net::{Ipv4Addr, Ipv6Addr};

use rustgo_config::PortRange;
use rustgo_protocol::{BoundedString, SocketAddress};
use rustgo_rendezvous::{
    Candidate, CandidateGeneration, CandidateTransport, MAX_CANDIDATES, MAX_FOUNDATION_BYTES,
    MAX_OBSERVATION_SOURCE_BYTES,
};

const IPV6_PRIORITY: u32 = 600;
const LAN_PRIORITY: u32 = 500;
const OBSERVED_UDP_PRIORITY: u32 = 400;
const PREDICTED_UDP_PRIORITY: u32 = 300;
const NATIVE_TCP_PRIORITY: u32 = 200;
const RELAY_PRIORITY: u32 = 100;

/// A socket-free candidate discovered by a later runtime-owned collector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateInput {
    UsableIpv6(SocketAddress),
    Lan(SocketAddress),
    ObservedUdp(SocketAddress),
    PredictedUdp(SocketAddress),
    NativeTcp(SocketAddress),
    Relay(SocketAddress),
}

impl CandidateInput {
    fn metadata(&self) -> (CandidateTransport, u32, &'static str, &'static str) {
        match self {
            Self::UsableIpv6(_) => (CandidateTransport::QuicUdp, IPV6_PRIORITY, "ipv6", "local"),
            Self::Lan(_) => (CandidateTransport::QuicUdp, LAN_PRIORITY, "lan", "local"),
            Self::ObservedUdp(_) => (
                CandidateTransport::QuicUdp,
                OBSERVED_UDP_PRIORITY,
                "observed-udp",
                "server-observed",
            ),
            Self::PredictedUdp(_) => (
                CandidateTransport::QuicUdp,
                PREDICTED_UDP_PRIORITY,
                "predicted-udp",
                "prediction",
            ),
            Self::NativeTcp(_) => (
                CandidateTransport::NativeTcp,
                NATIVE_TCP_PRIORITY,
                "native-tcp",
                "local",
            ),
            Self::Relay(_) => (CandidateTransport::Relay, RELAY_PRIORITY, "relay", "relay"),
        }
    }

    fn address(&self) -> &SocketAddress {
        match self {
            Self::UsableIpv6(address)
            | Self::Lan(address)
            | Self::ObservedUdp(address)
            | Self::PredictedUdp(address)
            | Self::NativeTcp(address)
            | Self::Relay(address) => address,
        }
    }
}

/// Applies configured binding ranges, address safety checks, ordering, deduplication, and the
/// rendezvous wire candidate bound to runtime-discovered candidates.
#[derive(Debug, Clone)]
pub struct CandidateGatherer {
    generation: CandidateGeneration,
    expires_unix_secs: u64,
    udp_port_range: PortRange,
    tcp_port_range: PortRange,
}

impl CandidateGatherer {
    pub fn new(
        generation: CandidateGeneration,
        expires_unix_secs: u64,
        udp_port_range: PortRange,
        tcp_port_range: PortRange,
    ) -> Self {
        Self {
            generation,
            expires_unix_secs,
            udp_port_range,
            tcp_port_range,
        }
    }

    pub fn gather<I>(&self, inputs: I) -> Vec<Candidate>
    where
        I: IntoIterator<Item = CandidateInput>,
    {
        let mut candidates: Vec<_> = inputs
            .into_iter()
            .filter_map(|input| self.to_candidate(input))
            .collect();
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
        let mut seen = Vec::new();
        candidates.retain(|candidate| {
            let duplicate = seen.iter().any(|(transport, address)| {
                *transport == candidate.transport && *address == candidate.address
            });
            if !duplicate {
                seen.push((candidate.transport, candidate.address.clone()));
            }
            !duplicate
        });
        candidates.truncate(MAX_CANDIDATES);
        candidates
    }

    fn to_candidate(&self, input: CandidateInput) -> Option<Candidate> {
        let address = input.address();
        if !is_usable_address(address) || !self.is_allowed_input(&input) {
            return None;
        }
        let (transport, priority, foundation, observation_source) = input.metadata();
        let foundation = BoundedString::<MAX_FOUNDATION_BYTES>::try_from(foundation).ok()?;
        let observation_source =
            BoundedString::<MAX_OBSERVATION_SOURCE_BYTES>::try_from(observation_source).ok()?;
        Some(Candidate {
            transport,
            address: address.clone(),
            priority,
            foundation,
            generation: self.generation,
            expires_unix_secs: self.expires_unix_secs,
            observation_source,
        })
    }

    fn is_allowed_input(&self, input: &CandidateInput) -> bool {
        match input {
            CandidateInput::UsableIpv6(address) => {
                matches!(address, SocketAddress::V6 { port, .. } if range_contains(&self.udp_port_range, *port))
            }
            CandidateInput::Lan(SocketAddress::V4 { octets, port }) => {
                Ipv4Addr::from(*octets).is_private() && range_contains(&self.udp_port_range, *port)
            }
            CandidateInput::Lan(SocketAddress::V6 { .. }) => false,
            CandidateInput::NativeTcp(address) => {
                range_contains(&self.tcp_port_range, address_port(address))
            }
            CandidateInput::ObservedUdp(_)
            | CandidateInput::PredictedUdp(_)
            | CandidateInput::Relay(_) => true,
        }
    }
}

fn address_port(address: &SocketAddress) -> u16 {
    match address {
        SocketAddress::V4 { port, .. } | SocketAddress::V6 { port, .. } => *port,
    }
}

fn range_contains(range: &PortRange, port: u16) -> bool {
    range.start <= port && port <= range.end
}

pub(crate) fn is_usable_address(address: &SocketAddress) -> bool {
    match address {
        SocketAddress::V4 { octets, port } => {
            let address = Ipv4Addr::from(*octets);
            *port != 0
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_loopback()
                && !address.is_link_local()
        }
        SocketAddress::V6 { octets, port } => {
            let address = Ipv6Addr::from(*octets);
            *port != 0
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_loopback()
                && !address.is_unicast_link_local()
        }
    }
}

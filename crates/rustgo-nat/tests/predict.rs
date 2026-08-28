use proptest::prelude::*;
use rustgo_config::PortRange;
use rustgo_nat::{
    CandidateGatherer, CandidateInput, MappingEvidence, Observation, PredictionPolicy,
    analyze_mappings, predicted_ports,
};
use rustgo_protocol::SocketAddress;
use rustgo_rendezvous::CandidateGeneration;
use std::collections::HashSet;

fn address(octets: [u8; 4], port: u16) -> SocketAddress {
    SocketAddress::V4 { octets, port }
}

fn observation(destination_port: u16, mapped_port: u16) -> Observation {
    Observation::new(
        address([198, 51, 100, 10], destination_port),
        address([203, 0, 113, 7], mapped_port),
    )
}

fn socket_address_strategy() -> BoxedStrategy<SocketAddress> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>())
            .prop_map(|(octets, port)| SocketAddress::V4 { octets, port }),
        (any::<[u8; 16]>(), any::<u16>())
            .prop_map(|(octets, port)| SocketAddress::V6 { octets, port }),
        any::<u16>().prop_map(|port| SocketAddress::V4 {
            octets: [0, 0, 0, 0],
            port,
        }),
        (224u8..=239, any::<[u8; 3]>(), any::<u16>()).prop_map(|(first, tail, port)| {
            SocketAddress::V4 {
                octets: [first, tail[0], tail[1], tail[2]],
                port,
            }
        }),
        any::<u16>().prop_map(|port| SocketAddress::V4 {
            octets: [255, 255, 255, 255],
            port,
        }),
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u16>()).prop_map(
            |(second, third, fourth, port)| SocketAddress::V4 {
                octets: [127, second, third, fourth],
                port,
            },
        ),
        (any::<u8>(), any::<u8>(), any::<u16>()).prop_map(|(third, fourth, port)| {
            SocketAddress::V4 {
                octets: [169, 254, third, fourth],
                port,
            }
        }),
        any::<u16>().prop_map(|port| SocketAddress::V6 {
            octets: [0; 16],
            port,
        }),
        (any::<u8>(), any::<[u8; 14]>(), any::<u16>()).prop_map(|(second, tail, port)| {
            SocketAddress::V6 {
                octets: [
                    0xff, second, tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6],
                    tail[7], tail[8], tail[9], tail[10], tail[11], tail[12], tail[13],
                ],
                port,
            }
        }),
        any::<u16>().prop_map(|port| SocketAddress::V6 {
            octets: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port,
        }),
        (0u8..=63, any::<[u8; 14]>(), any::<u16>()).prop_map(|(scope, tail, port)| {
            SocketAddress::V6 {
                octets: [
                    0xfe,
                    0x80 | scope,
                    tail[0],
                    tail[1],
                    tail[2],
                    tail[3],
                    tail[4],
                    tail[5],
                    tail[6],
                    tail[7],
                    tail[8],
                    tail[9],
                    tail[10],
                    tail[11],
                    tail[12],
                    tail[13],
                ],
                port,
            }
        }),
        usable_ipv6_strategy(),
    ]
    .boxed()
}

fn usable_ipv6_strategy() -> BoxedStrategy<SocketAddress> {
    (any::<[u8; 14]>(), 7400u16..=7499)
        .prop_map(|(tail, port)| SocketAddress::V6 {
            octets: [
                0x20, 0x01, tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
                tail[8], tail[9], tail[10], tail[11], tail[12], tail[13],
            ],
            port,
        })
        .boxed()
}

fn candidate_input_strategy() -> BoxedStrategy<CandidateInput> {
    prop_oneof![
        usable_ipv6_strategy().prop_map(CandidateInput::UsableIpv6),
        socket_address_strategy().prop_map(CandidateInput::Lan),
        socket_address_strategy().prop_map(CandidateInput::ObservedUdp),
        socket_address_strategy().prop_map(CandidateInput::PredictedUdp),
        socket_address_strategy().prop_map(CandidateInput::NativeTcp),
        socket_address_strategy().prop_map(CandidateInput::Relay),
    ]
    .boxed()
}

#[test]
fn predicted_ports_reject_wraparound_and_zero() {
    let observations = [
        observation(7443, 65533),
        observation(7443, 65534),
        observation(7443, 65535),
    ];

    assert!(
        predicted_ports(
            &observations,
            PredictionPolicy {
                requested_window: 16
            }
        )
        .is_empty()
    );
}

proptest! {
    #[test]
    fn arbitrary_observations_have_bounded_unique_nonzero_predictions_and_no_cross_host_port_evidence(
        addresses in proptest::collection::vec((socket_address_strategy(), socket_address_strategy()), 0..80),
        requested_window in any::<usize>(),
    ) {
        let observations: Vec<_> = addresses.into_iter()
            .map(|(destination, mapped_address)| Observation::new(destination, mapped_address))
            .collect();
        let predicted = predicted_ports(&observations, PredictionPolicy { requested_window });
        let unique: HashSet<_> = predicted.iter().copied().collect();
        let mapped_hosts_differ = observations.windows(2).any(|pair| {
            !same_host(&pair[0].mapped_address, &pair[1].mapped_address)
        });

        prop_assert!(predicted.len() <= 16);
        prop_assert!(predicted.iter().all(|port| *port != 0));
        prop_assert_eq!(predicted.len(), unique.len());
        if mapped_hosts_differ {
            prop_assert_ne!(analyze_mappings(&observations), MappingEvidence::DestinationPortDependent);
        }
    }

    #[test]
    fn arbitrary_inputs_never_emit_rejected_or_duplicate_candidates(
        inputs in proptest::collection::vec(candidate_input_strategy(), 0..128),
    ) {
        let gatherer = CandidateGatherer::new(
            CandidateGeneration::INITIAL,
            10_000,
            PortRange { start: 7400, end: 7499 },
            PortRange { start: 7400, end: 7499 },
        );
        let candidates = gatherer.gather(inputs);
        let all_usable = candidates.iter().all(is_independently_usable);
        let all_unique = candidates.iter().enumerate().all(|(index, candidate)| {
            candidates[..index].iter().all(|earlier| {
                earlier.transport != candidate.transport || earlier.address != candidate.address
            })
        });

        prop_assert!(candidates.len() <= 32);
        prop_assert!(all_unique);
        prop_assert!(all_usable);
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

fn is_independently_usable(candidate: &rustgo_rendezvous::Candidate) -> bool {
    match &candidate.address {
        SocketAddress::V4 { octets, port } => {
            *port != 0
                && octets != &[0, 0, 0, 0]
                && octets != &[255, 255, 255, 255]
                && !(224..=239).contains(&octets[0])
                && octets[0] != 127
                && !(octets[0] == 169 && octets[1] == 254)
        }
        SocketAddress::V6 { octets, port } => {
            *port != 0
                && octets != &[0; 16]
                && octets != &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                && octets[0] != 0xff
                && !(octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        }
    }
}

use proptest::prelude::*;
use rustgo_config::PortRange;
use rustgo_nat::{
    CandidateGatherer, CandidateInput, Observation, PredictionPolicy, predicted_ports,
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
    fn arbitrary_observations_have_bounded_unique_nonzero_predictions(
        pairs in proptest::collection::vec((any::<u16>(), any::<u16>()), 0..80),
        requested_window in any::<usize>(),
    ) {
        let observations: Vec<_> = pairs.into_iter()
            .map(|(destination_port, mapped_port)| observation(destination_port, mapped_port))
            .collect();
        let predicted = predicted_ports(&observations, PredictionPolicy { requested_window });
        let unique: HashSet<_> = predicted.iter().copied().collect();

        prop_assert!(predicted.len() <= 16);
        prop_assert!(predicted.iter().all(|port| *port != 0));
        prop_assert_eq!(predicted.len(), unique.len());
    }

    #[test]
    fn arbitrary_inputs_never_emit_unusable_or_duplicate_candidates(
        inputs in proptest::collection::vec((any::<[u8; 4]>(), any::<u16>(), 0u8..6), 0..128),
    ) {
        let gatherer = CandidateGatherer::new(
            CandidateGeneration::INITIAL,
            10_000,
            PortRange { start: 7400, end: 7499 },
            PortRange { start: 7400, end: 7499 },
        );
        let candidates = gatherer.gather(inputs.into_iter().map(|(octets, port, kind)| {
            let address = address(octets, port);
            match kind {
                0 => CandidateInput::UsableIpv6(SocketAddress::V6 { octets: [0; 16], port }),
                1 => CandidateInput::Lan(address),
                2 => CandidateInput::ObservedUdp(address),
                3 => CandidateInput::PredictedUdp(address),
                4 => CandidateInput::NativeTcp(address),
                _ => CandidateInput::Relay(address),
            }
        }));
        let all_usable = candidates.iter().all(is_usable_candidate);
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

fn is_usable_candidate(candidate: &rustgo_rendezvous::Candidate) -> bool {
    match &candidate.address {
        SocketAddress::V4 { octets, port } => {
            *port != 0 && octets != &[0, 0, 0, 0] && !(224..=239).contains(&octets[0])
        }
        SocketAddress::V6 { octets, port } => *port != 0 && octets != &[0; 16] && octets[0] != 0xff,
    }
}

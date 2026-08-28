use rustgo_config::PortRange;
use rustgo_nat::{
    CandidateGatherer, CandidateInput, MappingEvidence, Observation, PredictionPolicy,
    analyze_mappings, predicted_ports,
};
use rustgo_protocol::SocketAddress;
use rustgo_rendezvous::{CandidateGeneration, CandidateTransport};

fn v4(octets: [u8; 4], port: u16) -> SocketAddress {
    SocketAddress::V4 { octets, port }
}

fn v6(octets: [u8; 16], port: u16) -> SocketAddress {
    SocketAddress::V6 { octets, port }
}

fn observation(destination_port: u16, mapped_port: u16) -> Observation {
    Observation::new(
        v4([198, 51, 100, 10], destination_port),
        v4([203, 0, 113, 7], mapped_port),
    )
}

fn gatherer() -> CandidateGatherer {
    CandidateGatherer::new(
        CandidateGeneration::INITIAL,
        10_000,
        PortRange {
            start: 7400,
            end: 7499,
        },
        PortRange {
            start: 7400,
            end: 7499,
        },
    )
}

#[test]
fn stable_mappings_are_evidence_not_a_nat_classification() {
    let observations = [observation(7443, 40000), observation(7444, 40000)];

    assert_eq!(analyze_mappings(&observations), MappingEvidence::Stable);
}

#[test]
fn destination_port_dependent_mappings_are_labeled_as_evidence() {
    let observations = [
        observation(7443, 40000),
        observation(7443, 40000),
        observation(7444, 40100),
        observation(7444, 40100),
    ];

    assert_eq!(
        analyze_mappings(&observations),
        MappingEvidence::DestinationPortDependent
    );
}

#[test]
fn sequential_mappings_report_their_delta() {
    let observations = [
        observation(7443, 40000),
        observation(7443, 40002),
        observation(7443, 40004),
    ];

    assert_eq!(
        analyze_mappings(&observations),
        MappingEvidence::Sequential { delta: 2 }
    );
}

#[test]
fn sequential_mappings_remain_sequential_across_probe_ports() {
    let observations = [
        observation(7443, 40000),
        observation(7444, 40002),
        observation(7443, 40004),
    ];

    assert_eq!(
        analyze_mappings(&observations),
        MappingEvidence::Sequential { delta: 2 }
    );
}

#[test]
fn random_mappings_remain_uncertain() {
    let observations = [
        observation(7443, 40000),
        observation(7443, 40117),
        observation(7443, 40053),
    ];

    assert_eq!(analyze_mappings(&observations), MappingEvidence::Uncertain);
}

#[test]
fn gatherer_orders_deduplicates_and_filters_unusable_candidates() {
    let candidates = gatherer().gather([
        CandidateInput::Relay(v4([203, 0, 113, 10], 443)),
        CandidateInput::NativeTcp(v4([192, 168, 1, 10], 7401)),
        CandidateInput::PredictedUdp(v4([203, 0, 113, 7], 40002)),
        CandidateInput::ObservedUdp(v4([203, 0, 113, 7], 40000)),
        CandidateInput::Lan(v4([192, 168, 1, 10], 7400)),
        CandidateInput::UsableIpv6(v6(
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            7400,
        )),
        CandidateInput::ObservedUdp(v4([203, 0, 113, 7], 40000)),
        CandidateInput::ObservedUdp(v4([0, 0, 0, 0], 40000)),
        CandidateInput::ObservedUdp(v4([224, 0, 0, 1], 40000)),
        CandidateInput::ObservedUdp(v4([203, 0, 113, 7], 0)),
    ]);

    assert_eq!(candidates.len(), 6);
    assert_eq!(candidates[0].transport, CandidateTransport::QuicUdp);
    assert_eq!(
        candidates[0].address,
        v6(
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            7400
        )
    );
    assert_eq!(candidates[4].transport, CandidateTransport::NativeTcp);
    assert_eq!(candidates[5].transport, CandidateTransport::Relay);
    assert!(
        candidates
            .windows(2)
            .all(|pair| pair[0].priority > pair[1].priority)
    );
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.address != v4([203, 0, 113, 7], 0))
    );
}

#[test]
fn gatherer_never_emits_more_than_the_wire_limit() {
    let candidates = gatherer().gather(
        (1..=255).map(|octet| CandidateInput::ObservedUdp(v4([203, 0, 113, octet], 40000))),
    );

    assert!(candidates.len() <= 32);
}

#[test]
fn gatherer_rejects_unspecified_and_multicast_ipv6_candidates() {
    let candidates = gatherer().gather([
        CandidateInput::ObservedUdp(v6([0; 16], 7400)),
        CandidateInput::ObservedUdp(v6(
            [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            7400,
        )),
    ]);

    assert!(candidates.is_empty());
}

#[test]
fn gatherer_deduplicates_a_udp_endpoint_across_nonadjacent_sources() {
    let endpoint = v6(
        [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        7400,
    );
    let candidates = gatherer().gather([
        CandidateInput::UsableIpv6(endpoint.clone()),
        CandidateInput::Lan(v4([192, 168, 1, 10], 7400)),
        CandidateInput::ObservedUdp(endpoint),
    ]);

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].priority, 600);
}

#[test]
fn prediction_never_exceeds_hard_window() {
    let observations = [
        observation(7443, 40000),
        observation(7443, 40001),
        observation(7443, 40002),
    ];
    let policy = PredictionPolicy {
        requested_window: 10_000,
    };

    assert!(predicted_ports(&observations, policy).len() <= 16);
}

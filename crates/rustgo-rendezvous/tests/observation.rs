#![forbid(unsafe_code)]

use rustgo_protocol::SocketAddress;
use rustgo_rendezvous::{
    ObservationEndpoint, ObservationGrant, ObservationNonce, ObservationProbe, ObservationReply,
    ObservationToken,
};

#[test]
fn observation_packets_round_trip_with_fixed_bounded_fields() {
    let primary = ObservationToken::from([0x11; 32]);
    let alternate = ObservationToken::from([0x22; 32]);
    let nonce = ObservationNonce::from([0x33; 16]);
    let grant = ObservationGrant::new(primary.clone(), alternate.clone(), 42);
    assert_eq!(grant.primary_token(), &primary);
    assert_eq!(grant.alternate_token(), &alternate);
    assert_eq!(grant.expires_unix_secs(), 42);

    let probe = ObservationProbe::new(primary, nonce);
    let encoded = probe.encode().unwrap();
    assert!(encoded.len() <= ObservationProbe::MAX_WIRE_BYTES);
    assert_eq!(ObservationProbe::decode(&encoded).unwrap(), probe);

    let reply = ObservationReply::new(
        nonce,
        SocketAddress::V4 {
            octets: [127, 0, 0, 1],
            port: 40_000,
        },
        ObservationEndpoint::Primary,
    );
    let encoded = reply.encode().unwrap();
    assert!(encoded.len() <= ObservationReply::MAX_WIRE_BYTES);
    assert_eq!(ObservationReply::decode(&encoded).unwrap(), reply);
}

#[test]
fn observation_packet_decoders_reject_trailing_and_oversized_input() {
    let probe = ObservationProbe::new(
        ObservationToken::from([0x44; 32]),
        ObservationNonce::from([0x55; 16]),
    );
    let mut trailing = probe.encode().unwrap();
    trailing.push(0);
    assert!(ObservationProbe::decode(&trailing).is_err());
    assert!(ObservationProbe::decode(&[0_u8; ObservationProbe::MAX_WIRE_BYTES + 1]).is_err());
}

#[test]
fn ipv6_high_port_reply_fits_the_declared_wire_bound() {
    let reply = ObservationReply::new(
        ObservationNonce::from([0x66; 16]),
        SocketAddress::V6 {
            octets: [0xAB; 16],
            port: u16::MAX,
        },
        ObservationEndpoint::Alternate,
    );

    let encoded = reply.encode().unwrap();
    assert_eq!(encoded.len(), 37);
    assert!(encoded.len() <= ObservationReply::MAX_WIRE_BYTES);
    assert_eq!(ObservationReply::decode(&encoded).unwrap(), reply);
}

use rustgo_config::*;
fn client() -> ClientConfig {
    toml::from_str(
        r#"
[client]
name = "local"
server_addr = "localhost:7443"
server_name = "localhost"
certificate_authority_file = "ca"
private_key_file = "key"
heartbeat_interval_secs = 10
[p2p]
enabled = true
prefer_direct = false
direct_timeout_secs = 3
reconnect_timeout_secs = 4
allow_relay_fallback = false
udp_port_range = "10000-10001"
tcp_port_range = "10002-10003"
[[tunnels]]
name = "ssh"
protocol = "tcp"
local_addr = "localhost:22"
remote_port = 2222
[[exports]]
name = "service"
protocol = "udp"
local_addr = "localhost:53"
allowed_peers = ["peer"]
[[forwards]]
name = "remote"
peer = "peer"
export = "service"
listen_addr = "localhost:8080"
"#,
    )
    .unwrap()
}
#[test]
fn snapshots_roundtrip_and_empty_apply_preserves_local_policy() {
    let mut client = client();
    let original = client.clone();
    let snapshot = ManagedConfiguration::from_client(&client);
    snapshot.validate().unwrap();
    assert_eq!(
        serde_json::from_slice::<ManagedConfiguration>(&serde_json::to_vec(&snapshot).unwrap())
            .unwrap(),
        snapshot
    );
    let empty = ManagedConfiguration {
        tunnels: vec![],
        exports: vec![],
        forwards: vec![],
        p2p_enabled: false,
    };
    empty.apply_to(&mut client).unwrap();
    assert!(client.tunnels.is_empty() && client.exports.is_empty() && client.forwards.is_empty());
    assert_eq!(client.p2p, original.p2p);
    assert_eq!(client.client, original.client);
}
#[test]
fn invalid_snapshots_are_rejected_without_mutating_client() {
    let baseline = ManagedConfiguration::from_client(&client());
    let mut invalid = Vec::new();
    let mut s = baseline.clone();
    s.tunnels[0].remote_port = 0;
    invalid.push(s);
    let mut s = baseline.clone();
    s.tunnels[0].local_addr = "invalid".into();
    invalid.push(s);
    let mut s = baseline.clone();
    s.tunnels.push(s.tunnels[0].clone());
    invalid.push(s);
    let mut s = baseline.clone();
    s.exports[0].allowed_peers.push(" ".into());
    invalid.push(s);
    let mut s = baseline.clone();
    s.exports[0].allowed_peers = vec!["peer".into(); 257];
    invalid.push(s);
    let mut s = baseline.clone();
    s.forwards[0].export.clear();
    invalid.push(s);
    for snapshot in invalid {
        assert!(snapshot.validate().is_err());
        let mut target = client();
        let before = target.clone();
        assert!(snapshot.apply_to(&mut target).is_err());
        assert_eq!(target, before);
    }
    for p2p in [None, {
        let mut p = client().p2p.unwrap();
        p.enabled = false;
        Some(p)
    }] {
        let mut target = client();
        target.p2p = p2p;
        let before = target.clone();
        assert!(baseline.apply_to(&mut target).is_err());
        assert_eq!(target, before);
    }
    let mut self_forward = baseline;
    self_forward.forwards[0].peer = "local".into();
    assert!(self_forward.apply_to(&mut client()).is_err());
}

#[test]
fn disabled_capability_does_not_discard_existing_structurally_valid_collections() {
    let mut snapshot = ManagedConfiguration::from_client(&client());
    snapshot.p2p_enabled = false;
    assert!(snapshot.validate().is_ok());
    let mut target = client();
    target.p2p.as_mut().unwrap().enabled = false;
    assert!(snapshot.apply_to(&mut target).is_err());
}

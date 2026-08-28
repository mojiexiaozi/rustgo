#![forbid(unsafe_code)]

use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use rustgo_config::{
    ClientConfig, ServerConfig, TunnelProtocol, check_client_references, load_client,
    load_client_with_lookup, load_server,
};

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustgo-config-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path.join(name);
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn valid_server() -> String {
    r#"
[server]
bind_addr = "0.0.0.0:7000"
certificate_file = "certs/server.crt"
private_key_file = "certs/server.key"
heartbeat_timeout_secs = 60

[limits]
max_clients = 128
max_tunnels_per_client = 64
max_tcp_connections_per_tunnel = 256
max_udp_sessions_per_tunnel = 1024
max_udp_payload_bytes = 65507

[[clients]]
name = "home-pc"
public_key = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
enabled = true
"#
    .to_owned()
}

fn valid_client() -> String {
    r#"
[client]
name = "home-pc"
server_addr = "tunnel.example.com:7000"
server_name = "tunnel.example.com"
certificate_authority_file = "certs/ca.crt"
private_key_file = "keys/device.key"
heartbeat_interval_secs = 20

[[tunnels]]
name = "ssh"
protocol = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 2222
"#
    .to_owned()
}

fn load_server_text(
    dir: &TempDir,
    contents: &str,
) -> Result<ServerConfig, rustgo_config::ConfigError> {
    load_server(&dir.write("server.toml", contents))
}

fn load_client_text(
    dir: &TempDir,
    contents: &str,
) -> Result<ClientConfig, rustgo_config::ConfigError> {
    load_client(&dir.write("client.toml", contents))
}

#[test]
fn server_rejects_unknown_fields() {
    let dir = TempDir::new();
    let config = valid_server().replace(
        "heartbeat_timeout_secs = 60",
        "heartbeat_timeout_secs = 60\nunexpected = true",
    );

    assert!(load_server_text(&dir, &config).is_err());
}

#[test]
fn server_accepts_only_a_unicast_udp_bind_ip() {
    let dir = TempDir::new();
    let explicit = valid_server().replace(
        "bind_addr = \"0.0.0.0:7000\"",
        "bind_addr = \"0.0.0.0:7000\"\nudp_bind_ip = \"192.0.2.10\"",
    );
    let loaded = load_server_text(&dir, &explicit).unwrap();
    assert_eq!(
        loaded.server.udp_bind_ip,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );

    for unspecified in ["0.0.0.0", "::"] {
        let invalid = valid_server().replace(
            "bind_addr = \"0.0.0.0:7000\"",
            &format!("bind_addr = \"0.0.0.0:7000\"\nudp_bind_ip = \"{unspecified}\""),
        );
        let error = load_server_text(&dir, &invalid).unwrap_err();
        assert!(error.to_string().contains("udp_bind_ip"), "{error}");
    }
}

#[test]
fn client_rejects_unknown_fields() {
    let dir = TempDir::new();
    let config = valid_client().replace(
        "remote_port = 2222",
        "remote_port = 2222\nunexpected = true",
    );

    assert!(load_client_text(&dir, &config).is_err());
}

#[test]
fn environment_variable_expands_before_parsing() {
    let dir = TempDir::new();
    let config = valid_client().replace("tunnel.example.com", "${RUSTGO_TEST_SERVER_NAME}");

    let loaded = load_client_with_lookup(&dir.write("client.toml", &config), |name| {
        (name == "RUSTGO_TEST_SERVER_NAME").then(|| "expanded.example.test".to_owned())
    })
    .unwrap();

    assert_eq!(loaded.client.server_addr, "expanded.example.test:7000");
    assert_eq!(loaded.client.server_name, "expanded.example.test");
}

#[test]
fn missing_environment_variable_is_an_error() {
    let dir = TempDir::new();
    let config = valid_client().replace("tunnel.example.com", "${RUSTGO_TEST_MISSING}");

    let error = load_client_with_lookup(&dir.write("client.toml", &config), |_| None).unwrap_err();

    assert!(error.to_string().contains("RUSTGO_TEST_MISSING"));
}

#[test]
fn relative_file_paths_resolve_from_config_directory() {
    let dir = TempDir::new();
    let config_path = dir.write("server.toml", &valid_server());
    let loaded = load_server(&config_path).unwrap();

    assert_eq!(
        loaded.server.certificate_file,
        dir.path.join("certs/server.crt")
    );
    assert_eq!(
        loaded.server.private_key_file,
        dir.path.join("certs/server.key")
    );

    let client_path = dir.write("client.toml", &valid_client());
    let client = load_client(&client_path).unwrap();
    assert_eq!(
        client.client.certificate_authority_file,
        dir.path.join("certs/ca.crt")
    );
    assert_eq!(
        client.client.private_key_file,
        dir.path.join("keys/device.key")
    );
}

#[test]
fn client_reference_check_requires_the_explicit_ca_and_private_key() {
    let dir = TempDir::new();
    let config_path = dir.write("client.toml", &valid_client());
    let config = load_client(&config_path).unwrap();

    let missing_ca = check_client_references(&config_path, &config).unwrap_err();
    assert!(missing_ca.to_string().contains("certificate authority"));

    fs::create_dir_all(dir.path.join("certs")).unwrap();
    fs::write(dir.path.join("certs/ca.crt"), "test CA").unwrap();
    let missing_key = check_client_references(&config_path, &config).unwrap_err();
    assert!(missing_key.to_string().contains("private key"));
}

#[test]
fn duplicate_client_names_are_rejected() {
    let dir = TempDir::new();
    let config = format!(
        "{}\n\n[[clients]]\nname = \"home-pc\"\npublic_key = \"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\nenabled = true\n",
        valid_server()
    );

    assert!(load_server_text(&dir, &config).is_err());
}

#[test]
fn duplicate_tunnel_names_are_rejected() {
    let dir = TempDir::new();
    let config = format!(
        "{}\n\n[[tunnels]]\nname = \"ssh\"\nprotocol = \"udp\"\nlocal_addr = \"127.0.0.1:53\"\nremote_port = 5353\n",
        valid_client()
    );

    assert!(load_client_text(&dir, &config).is_err());
}

#[test]
fn duplicate_protocol_and_remote_port_are_rejected() {
    let dir = TempDir::new();
    let config = format!(
        "{}\n\n[[tunnels]]\nname = \"web\"\nprotocol = \"tcp\"\nlocal_addr = \"127.0.0.1:8080\"\nremote_port = 2222\n",
        valid_client()
    );

    assert!(load_client_text(&dir, &config).is_err());
}

#[test]
fn invalid_ports_and_zero_timeouts_are_rejected() {
    let dir = TempDir::new();
    let invalid_server =
        valid_server().replace("heartbeat_timeout_secs = 60", "heartbeat_timeout_secs = 0");
    let invalid_client = valid_client()
        .replace("remote_port = 2222", "remote_port = 0")
        .replace(
            "heartbeat_interval_secs = 20",
            "heartbeat_interval_secs = 0",
        );

    assert!(load_server_text(&dir, &invalid_server).is_err());
    assert!(load_client_text(&dir, &invalid_client).is_err());
}

#[test]
fn client_heartbeat_interval_must_fit_the_bounded_wire_field() {
    let dir = TempDir::new();
    let invalid = valid_client().replace(
        "heartbeat_interval_secs = 20",
        "heartbeat_interval_secs = 4294967296",
    );

    assert!(load_client_text(&dir, &invalid).is_err());
}

#[test]
fn client_and_tunnel_name_limits_count_utf8_bytes() {
    let dir = TempDir::new();
    let too_long = "界".repeat(43);
    assert_eq!(too_long.chars().count(), 43);
    assert_eq!(too_long.len(), 129);
    let invalid_client =
        valid_client().replace("name = \"home-pc\"", &format!("name = \"{too_long}\""));
    let invalid_tunnel =
        valid_client().replace("name = \"ssh\"", &format!("name = \"{too_long}\""));

    assert!(load_client_text(&dir, &invalid_client).is_err());
    assert!(load_client_text(&dir, &invalid_tunnel).is_err());
}

#[test]
fn client_rejects_more_tunnels_than_the_wire_can_encode() {
    let dir = TempDir::new();
    let mut invalid = valid_client();
    for index in 0..64 {
        invalid.push_str(&format!(
            "\n[[tunnels]]\nname = \"extra-{index}\"\nprotocol = \"tcp\"\nlocal_addr = \"127.0.0.1:22\"\nremote_port = {}\n",
            10_000 + index
        ));
    }

    assert!(load_client_text(&dir, &invalid).is_err());
}

#[test]
fn invalid_ports_in_server_and_local_addresses_are_rejected() {
    let dir = TempDir::new();
    let invalid_server = valid_server().replace("0.0.0.0:7000", "0.0.0.0:0");
    let invalid_client = valid_client()
        .replace("tunnel.example.com:7000", "tunnel.example.com:70000")
        .replace("127.0.0.1:22", "127.0.0.1:0");

    assert!(load_server_text(&dir, &invalid_server).is_err());
    assert!(load_client_text(&dir, &invalid_client).is_err());
}

#[test]
fn limits_outside_supported_ranges_are_rejected() {
    let dir = TempDir::new();
    let config = valid_server()
        .replace("max_clients = 128", "max_clients = 0")
        .replace(
            "max_udp_payload_bytes = 65507",
            "max_udp_payload_bytes = 65508",
        );

    assert!(load_server_text(&dir, &config).is_err());
}

#[test]
fn protocol_deserializes_to_public_enum() {
    let dir = TempDir::new();
    let loaded = load_client_text(&dir, &valid_client()).unwrap();

    assert_eq!(loaded.tunnels[0].protocol, TunnelProtocol::Tcp);
}

#[allow(dead_code)]
fn assert_path(path: &Path) {
    assert!(path.is_absolute());
}

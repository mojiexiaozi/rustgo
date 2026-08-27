#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use rustgo_config::{
    ClientConfig, ServerConfig, TunnelProtocol, load_client, load_client_with_lookup, load_server,
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

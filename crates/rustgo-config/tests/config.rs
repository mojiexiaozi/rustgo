#![forbid(unsafe_code)]

use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use rustgo_config::{
    ClientConfig, ServerConfig, TelemetryConfig, TunnelProtocol, WebConfig,
    check_client_references, check_server_references, load_client, load_client_with_lookup,
    load_server,
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

fn load_client_fixture(contents: &str) -> ClientConfig {
    let dir = TempDir::new();
    load_client_text(&dir, contents).unwrap()
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
fn server_observation_binds_are_optional_but_must_be_configured_as_a_pair() {
    let dir = TempDir::new();
    let relay_only = load_server_text(&dir, &valid_server()).unwrap();
    assert_eq!(relay_only.server.p2p_observation_bind, None);
    assert_eq!(relay_only.server.p2p_observation_alternate_bind, None);

    let paired = valid_server().replace(
        "bind_addr = \"0.0.0.0:7000\"",
        "bind_addr = \"0.0.0.0:7000\"\np2p_observation_bind = \"0.0.0.0:7443\"\np2p_observation_alternate_bind = \"0.0.0.0:7444\"",
    );
    let loaded = load_server_text(&dir, &paired).unwrap();
    assert_eq!(
        loaded.server.p2p_observation_bind.as_deref(),
        Some("0.0.0.0:7443")
    );
    assert_eq!(
        loaded.server.p2p_observation_alternate_bind.as_deref(),
        Some("0.0.0.0:7444")
    );

    for lone_field in [
        "p2p_observation_bind = \"0.0.0.0:7443\"",
        "p2p_observation_alternate_bind = \"0.0.0.0:7444\"",
    ] {
        let invalid = valid_server().replace(
            "bind_addr = \"0.0.0.0:7000\"",
            &format!("bind_addr = \"0.0.0.0:7000\"\n{lone_field}"),
        );
        let error = load_server_text(&dir, &invalid).unwrap_err();
        assert!(error.to_string().contains("configured together"), "{error}");
    }
}

#[test]
fn server_observation_binds_require_distinct_nonzero_socket_addresses() {
    let dir = TempDir::new();
    for (primary, alternate) in [
        ("127.0.0.1:0", "127.0.0.1:7444"),
        ("127.0.0.1:7443", "not-an-address"),
        ("127.0.0.1:7443", "127.0.0.1:7443"),
        ("127.0.0.1:7443", "127.0.0.2:7443"),
    ] {
        let invalid = valid_server().replace(
            "bind_addr = \"0.0.0.0:7000\"",
            &format!(
                "bind_addr = \"0.0.0.0:7000\"\np2p_observation_bind = \"{primary}\"\np2p_observation_alternate_bind = \"{alternate}\""
            ),
        );
        assert!(load_server_text(&dir, &invalid).is_err());
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
fn observability_sections_are_absent_without_changing_v02_configuration() {
    let dir = TempDir::new();

    let server = load_server_text(&dir, &valid_server()).unwrap();
    let client = load_client_text(&dir, &valid_client()).unwrap();

    assert_eq!(server.web, None);
    assert_eq!(client.telemetry, None);
}

#[test]
fn observability_section_defaults_match_the_documented_reference_values() {
    assert_eq!(
        WebConfig::default(),
        WebConfig {
            enabled: false,
            bind: "127.0.0.1:7450".to_owned(),
            admin_username: "admin".to_owned(),
            admin_password: "replace-with-at-least-16-characters".to_owned(),
            cookie_secure: true,
            history_days: 7,
            database_path: PathBuf::from("./rustgo-metrics.db"),
            database_max_mib: 256,
        }
    );
    assert_eq!(
        TelemetryConfig::default(),
        TelemetryConfig {
            enabled: true,
            sample_interval_secs: 10,
            report_interval_secs: 30,
        }
    );
}

#[test]
fn enabled_web_configuration_resolves_its_database_relative_to_the_toml_file() {
    let dir = TempDir::new();
    let config = format!(
        "{}\n[web]\nenabled = true\nadmin_password = \"a-password-that-is-at-least-sixteen-bytes\"\ndatabase_path = \"history/metrics.db\"\n",
        valid_server()
    );

    let loaded = load_server_text(&dir, &config).unwrap();
    let web = loaded.web.unwrap();

    assert_eq!(web.bind, "127.0.0.1:7450");
    assert_eq!(web.database_path, dir.path.join("history/metrics.db"));
}

#[test]
fn enabled_web_configuration_rejects_non_loopback_and_weak_credentials() {
    let dir = TempDir::new();
    let valid_web = "\n[web]\nenabled = true\nbind = \"127.0.0.1:7450\"\nadmin_username = \"admin\"\nadmin_password = \"a-password-that-is-at-least-sixteen-bytes\"\ncookie_secure = false\nhistory_days = 90\ndatabase_path = \"metrics.db\"\ndatabase_max_mib = 4096\n";

    for invalid in [
        valid_web.replace("127.0.0.1:7450", "0.0.0.0:7450"),
        valid_web.replace("admin_username = \"admin\"", "admin_username = \"\""),
        valid_web.replace(
            "admin_password = \"a-password-that-is-at-least-sixteen-bytes\"",
            "admin_password = \"too-short\"",
        ),
        valid_web.replace("history_days = 90", "history_days = 91"),
    ] {
        assert!(load_server_text(&dir, &format!("{}{}", valid_server(), invalid)).is_err());
    }
}

#[test]
fn enabled_telemetry_requires_valid_ordered_intervals() {
    let dir = TempDir::new();
    let valid =
        "\n[telemetry]\nenabled = true\nsample_interval_secs = 10\nreport_interval_secs = 30\n";
    assert!(load_client_text(&dir, &format!("{}{}", valid_client(), valid)).is_ok());

    for invalid in [
        valid.replace("sample_interval_secs = 10", "sample_interval_secs = 0"),
        valid.replace("report_interval_secs = 30", "report_interval_secs = 3601"),
        valid.replace("report_interval_secs = 30", "report_interval_secs = 9"),
    ] {
        assert!(load_client_text(&dir, &format!("{}{}", valid_client(), invalid)).is_err());
    }
}

#[cfg(unix)]
#[test]
fn enabled_web_configuration_rejects_group_or_world_readable_toml() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new();
    fs::create_dir_all(dir.path.join("certs")).unwrap();
    fs::write(dir.path.join("certs/server.crt"), "certificate").unwrap();
    fs::write(dir.path.join("certs/server.key"), "private key").unwrap();
    let config_path = dir.write(
        "server.toml",
        &format!(
            "{}\n[web]\nenabled = true\nadmin_password = \"a-password-that-is-at-least-sixteen-bytes\"\n",
            valid_server()
        ),
    );
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o640)).unwrap();
    let config = load_server(&config_path).unwrap();

    let error = check_server_references(&config_path, &config).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("must not grant group or other permissions")
    );
}

#[cfg(windows)]
#[test]
fn enabled_web_configuration_reports_a_structured_windows_acl_warning() {
    let dir = TempDir::new();
    fs::create_dir_all(dir.path.join("certs")).unwrap();
    fs::write(dir.path.join("certs/server.crt"), "certificate").unwrap();
    fs::write(dir.path.join("certs/server.key"), "private key").unwrap();
    let config_path = dir.write(
        "server.toml",
        &format!(
            "{}\n[web]\nenabled = true\nadmin_password = \"a-password-that-is-at-least-sixteen-bytes\"\n",
            valid_server()
        ),
    );
    let config = load_server(&config_path).unwrap();

    let check = check_server_references(&config_path, &config).unwrap();

    assert_eq!(check.warnings().len(), 1);
    assert_eq!(check.warnings()[0].code(), "WEB_CONFIG_ACL_REVIEW_REQUIRED");
    assert!(check.warnings()[0].message().contains("manual ACL review"));
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

#[test]
fn p2p_missing_allowed_peers_means_allow_all() {
    let config = load_client_fixture(
        r#"
        [client]
        name = "home-pc"
        server_addr = "127.0.0.1:7443"
        server_name = "localhost"
        certificate_authority_file = "ca.crt"
        private_key_file = "device.key"
        heartbeat_interval_secs = 20

        [[exports]]
        name = "ssh"
        protocol = "tcp"
        local_addr = "127.0.0.1:22"
    "#,
    );

    assert!(config.exports[0].allows_peer("laptop"));
    assert!(
        config
            .validation_warnings()
            .iter()
            .any(|warning| warning.code() == "P2P_EXPORT_ALLOW_ALL")
    );
}

#[test]
fn p2p_empty_allowed_peers_means_allow_all() {
    let config = load_client_fixture(
        r#"
        [client]
        name = "home-pc"
        server_addr = "127.0.0.1:7443"
        server_name = "localhost"
        certificate_authority_file = "ca.crt"
        private_key_file = "device.key"
        heartbeat_interval_secs = 20

        [[exports]]
        name = "ssh"
        protocol = "tcp"
        local_addr = "127.0.0.1:22"
        allowed_peers = []
    "#,
    );

    assert!(config.exports[0].allows_peer("laptop"));
    assert!(
        config
            .validation_warnings()
            .iter()
            .any(|warning| warning.code() == "P2P_EXPORT_ALLOW_ALL")
    );
}

#[test]
fn p2p_named_allowed_peers_deny_an_absent_peer() {
    let config = load_client_fixture(
        r#"
        [client]
        name = "home-pc"
        server_addr = "127.0.0.1:7443"
        server_name = "localhost"
        certificate_authority_file = "ca.crt"
        private_key_file = "device.key"
        heartbeat_interval_secs = 20

        [[exports]]
        name = "ssh"
        protocol = "tcp"
        local_addr = "127.0.0.1:22"
        allowed_peers = ["laptop"]
    "#,
    );

    assert!(config.exports[0].allows_peer("laptop"));
    assert!(!config.exports[0].allows_peer("tablet"));
}

#[test]
fn p2p_rejects_unknown_fields() {
    let dir = TempDir::new();
    let config = format!(
        "{}\n\n[p2p]\nenabled = true\nprefer_direct = true\ndirect_timeout_secs = 8\nreconnect_timeout_secs = 3\nallow_relay_fallback = true\nudp_port_range = \"7400-7499\"\ntcp_port_range = \"7400-7499\"\nunexpected = true\n",
        valid_client()
    );

    assert!(load_client_text(&dir, &config).is_err());
}

#[test]
fn p2p_rejects_invalid_reversed_and_oversized_port_ranges() {
    let dir = TempDir::new();
    let p2p = "\n[p2p]\nenabled = true\nprefer_direct = true\ndirect_timeout_secs = 8\nreconnect_timeout_secs = 3\nallow_relay_fallback = true\nudp_port_range = \"7400-7499\"\ntcp_port_range = \"7400-7499\"\n";

    for invalid in ["0-7499", "7499-7400", "7400-8424"] {
        let config = format!(
            "{}{}",
            valid_client(),
            p2p.replace(
                "udp_port_range = \"7400-7499\"",
                &format!("udp_port_range = \"{invalid}\""),
            )
        );
        assert!(load_client_text(&dir, &config).is_err(), "{invalid}");
    }
}

#[test]
fn p2p_rejects_duplicate_export_and_forward_names() {
    let dir = TempDir::new();
    let duplicate_export = format!(
        "{}\n\n[[exports]]\nname = \"ssh\"\nprotocol = \"tcp\"\nlocal_addr = \"127.0.0.1:22\"\n\n[[exports]]\nname = \"ssh\"\nprotocol = \"udp\"\nlocal_addr = \"127.0.0.1:53\"\n",
        valid_client()
    );
    let duplicate_forward = format!(
        "{}\n\n[[forwards]]\nname = \"office-ssh\"\npeer = \"office-pc\"\nexport = \"ssh\"\nlisten_addr = \"127.0.0.1:2222\"\n\n[[forwards]]\nname = \"office-ssh\"\npeer = \"laptop\"\nexport = \"ssh\"\nlisten_addr = \"127.0.0.1:2223\"\n",
        valid_client()
    );

    assert!(load_client_text(&dir, &duplicate_export).is_err());
    assert!(load_client_text(&dir, &duplicate_forward).is_err());
}

#[test]
fn p2p_rejects_a_forward_to_the_local_client() {
    let dir = TempDir::new();
    let config = format!(
        "{}\n\n[[forwards]]\nname = \"self-ssh\"\npeer = \"home-pc\"\nexport = \"ssh\"\nlisten_addr = \"127.0.0.1:2222\"\n",
        valid_client()
    );

    assert!(load_client_text(&dir, &config).is_err());
}

#[test]
fn p2p_warns_when_a_forward_listens_on_wildcard_address() {
    let config = load_client_fixture(
        r#"
        [client]
        name = "home-pc"
        server_addr = "127.0.0.1:7443"
        server_name = "localhost"
        certificate_authority_file = "ca.crt"
        private_key_file = "device.key"
        heartbeat_interval_secs = 20

        [[forwards]]
        name = "office-ssh"
        peer = "office-pc"
        export = "ssh"
        listen_addr = "0.0.0.0:2222"
    "#,
    );

    assert!(
        config
            .validation_warnings()
            .iter()
            .any(|warning| warning.code() == "P2P_FORWARD_NON_LOOPBACK_LISTEN")
    );
}

#[test]
fn p2p_collection_bounds_reject_accidental_resource_explosions() {
    let dir = TempDir::new();
    let mut too_many_exports = valid_client();
    for index in 0..=rustgo_config::MAX_EXPORTS {
        too_many_exports.push_str(&format!(
            "\n[[exports]]\nname = \"export-{index}\"\nprotocol = \"tcp\"\nlocal_addr = \"127.0.0.1:22\"\n"
        ));
    }
    let export_error = load_client_text(&dir, &too_many_exports)
        .unwrap_err()
        .to_string();
    assert!(export_error.contains("exports must contain at most 256 entries"));

    let mut too_many_forwards = valid_client();
    for index in 0..=rustgo_config::MAX_FORWARDS {
        too_many_forwards.push_str(&format!(
            "\n[[forwards]]\nname = \"forward-{index}\"\npeer = \"peer-{index}\"\nexport = \"ssh\"\nlisten_addr = \"127.0.0.1:{}\"\n",
            20_000 + index
        ));
    }
    let forward_error = load_client_text(&dir, &too_many_forwards)
        .unwrap_err()
        .to_string();
    assert!(forward_error.contains("forwards must contain at most 256 entries"));

    let peers = (0..=rustgo_config::MAX_ALLOWED_PEERS_PER_EXPORT)
        .map(|index| format!("\"peer-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let too_many_peers = format!(
        "{}\n[[exports]]\nname = \"ssh-peer-list\"\nprotocol = \"tcp\"\nlocal_addr = \"127.0.0.1:22\"\nallowed_peers = [{peers}]\n",
        valid_client()
    );
    let peer_error = load_client_text(&dir, &too_many_peers)
        .unwrap_err()
        .to_string();
    assert!(peer_error.contains("allowed_peers must contain at most 256 entries"));

    let allow_all = format!(
        "{}\n[[exports]]\nname = \"allow-all\"\nprotocol = \"tcp\"\nlocal_addr = \"127.0.0.1:22\"\nallowed_peers = []\n",
        valid_client()
    );
    assert!(
        load_client_text(&dir, &allow_all)
            .unwrap()
            .exports
            .last()
            .unwrap()
            .allows_peer("any-authenticated-peer")
    );
}

#[allow(dead_code)]
fn assert_path(path: &Path) {
    assert!(path.is_absolute());
}

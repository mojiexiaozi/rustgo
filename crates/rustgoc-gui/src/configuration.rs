#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rustgo_config::{ClientConfig, IdentityMode, TrustMode, TunnelProtocol};
use toml::{Table, Value};

pub fn config_path_for_executable(executable: &Path) -> Result<PathBuf> {
    let directory = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("无法确定程序所在目录")?;
    Ok(directory.join("client.toml"))
}

pub fn load_or_create(path: &Path) -> Result<ClientConfig> {
    if !path.exists() {
        let default = default_config();
        save_validated(path, &default)?;
    }
    let mut config = rustgo_config::load_client(path)
        .with_context(|| format!("读取配置失败: {}", path.display()))?;
    enforce_fixed_credentials(&mut config);
    Ok(config)
}

pub fn save_validated(path: &Path, config: &ClientConfig) -> Result<()> {
    let mut config = config.clone();
    enforce_fixed_credentials(&mut config);
    config.validate().context("配置验证失败")?;
    let contents = toml::to_string_pretty(&to_toml(&config)).context("序列化配置失败")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建配置目录失败: {}", parent.display()))?;
    }
    let temporary = path.with_extension("toml.tmp");
    fs::write(&temporary, contents.as_bytes())
        .with_context(|| format!("写入临时配置失败: {}", temporary.display()))?;
    atomicwrites::replace_atomic(&temporary, path)
        .with_context(|| format!("替换配置失败: {}", path.display()))?;
    Ok(())
}

fn default_config() -> ClientConfig {
    ClientConfig {
        client: rustgo_config::ClientSection {
            name: "gui-client".into(),
            identity_mode: Some(IdentityMode::Dynamic),
            server_addr: "8.133.176.172:8443".into(),
            server_name: "8.133.176.172".into(),
            certificate_authority_file: "server-cert.pem".into(),
            trust_mode: None,
            server_certificate_fingerprint: None,
            private_key_file: "device.key".into(),
            heartbeat_interval_secs: 30,
        },
        p2p: None,
        telemetry: Some(rustgo_config::TelemetryConfig::default()),
        tunnels: Vec::new(),
        exports: Vec::new(),
        forwards: Vec::new(),
    }
}

fn enforce_fixed_credentials(config: &mut ClientConfig) {
    config.client.certificate_authority_file = "server-cert.pem".into();
    config.client.private_key_file = "device.key".into();
    if let Some(host) = server_host(&config.client.server_addr) {
        config.client.server_name = host;
    }
}

fn server_host(address: &str) -> Option<String> {
    if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
        return Some(socket.ip().to_string());
    }
    address
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']).to_owned())
        .filter(|host| !host.is_empty())
}

fn to_toml(config: &ClientConfig) -> Value {
    let mut root = Table::new();
    let mut client = Table::new();
    insert_string(&mut client, "name", &config.client.name);
    if let Some(mode) = config.client.identity_mode {
        insert_string(
            &mut client,
            "identity_mode",
            match mode {
                IdentityMode::Static => "static",
                IdentityMode::Dynamic => "dynamic",
            },
        );
    }
    insert_string(&mut client, "server_addr", &config.client.server_addr);
    insert_string(&mut client, "server_name", &config.client.server_name);
    insert_string(
        &mut client,
        "certificate_authority_file",
        &config.client.certificate_authority_file.to_string_lossy(),
    );
    if let Some(mode) = config.client.trust_mode {
        insert_string(
            &mut client,
            "trust_mode",
            match mode {
                TrustMode::Pinned => "pinned",
            },
        );
    }
    if let Some(fingerprint) = &config.client.server_certificate_fingerprint {
        insert_string(&mut client, "server_certificate_fingerprint", fingerprint);
    }
    insert_string(
        &mut client,
        "private_key_file",
        &config.client.private_key_file.to_string_lossy(),
    );
    client.insert(
        "heartbeat_interval_secs".into(),
        Value::Integer(config.client.heartbeat_interval_secs as i64),
    );
    root.insert("client".into(), Value::Table(client));

    if let Some(p2p) = &config.p2p {
        let mut table = Table::new();
        table.insert("enabled".into(), Value::Boolean(p2p.enabled));
        table.insert("prefer_direct".into(), Value::Boolean(p2p.prefer_direct));
        table.insert(
            "direct_timeout_secs".into(),
            Value::Integer(p2p.direct_timeout_secs as i64),
        );
        table.insert(
            "reconnect_timeout_secs".into(),
            Value::Integer(p2p.reconnect_timeout_secs as i64),
        );
        table.insert(
            "allow_relay_fallback".into(),
            Value::Boolean(p2p.allow_relay_fallback),
        );
        insert_string(
            &mut table,
            "udp_port_range",
            &format!("{}-{}", p2p.udp_port_range.start, p2p.udp_port_range.end),
        );
        insert_string(
            &mut table,
            "tcp_port_range",
            &format!("{}-{}", p2p.tcp_port_range.start, p2p.tcp_port_range.end),
        );
        if let Some(value) = &p2p.observation_primary_addr {
            insert_string(&mut table, "observation_primary_addr", value);
        }
        if let Some(value) = &p2p.observation_alternate_addr {
            insert_string(&mut table, "observation_alternate_addr", value);
        }
        root.insert("p2p".into(), Value::Table(table));
    }
    if let Some(telemetry) = &config.telemetry {
        let mut table = Table::new();
        table.insert("enabled".into(), Value::Boolean(telemetry.enabled));
        table.insert(
            "sample_interval_secs".into(),
            Value::Integer(telemetry.sample_interval_secs as i64),
        );
        table.insert(
            "report_interval_secs".into(),
            Value::Integer(telemetry.report_interval_secs as i64),
        );
        root.insert("telemetry".into(), Value::Table(table));
    }

    root.insert(
        "tunnels".into(),
        Value::Array(
            config
                .tunnels
                .iter()
                .map(|item| {
                    let mut table = Table::new();
                    insert_string(&mut table, "name", &item.name);
                    insert_string(&mut table, "protocol", protocol_name(item.protocol));
                    insert_string(&mut table, "local_addr", &item.local_addr);
                    table.insert(
                        "remote_port".into(),
                        Value::Integer(item.remote_port as i64),
                    );
                    Value::Table(table)
                })
                .collect(),
        ),
    );
    root.insert(
        "exports".into(),
        Value::Array(
            config
                .exports
                .iter()
                .map(|item| {
                    let mut table = Table::new();
                    insert_string(&mut table, "name", &item.name);
                    insert_string(&mut table, "protocol", protocol_name(item.protocol));
                    insert_string(&mut table, "local_addr", &item.local_addr);
                    table.insert(
                        "allowed_peers".into(),
                        Value::Array(
                            item.allowed_peers
                                .iter()
                                .cloned()
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                    Value::Table(table)
                })
                .collect(),
        ),
    );
    root.insert(
        "forwards".into(),
        Value::Array(
            config
                .forwards
                .iter()
                .map(|item| {
                    let mut table = Table::new();
                    insert_string(&mut table, "name", &item.name);
                    insert_string(&mut table, "peer", &item.peer);
                    insert_string(&mut table, "export", &item.export);
                    insert_string(&mut table, "listen_addr", &item.listen_addr);
                    Value::Table(table)
                })
                .collect(),
        ),
    );
    Value::Table(root)
}

fn insert_string(table: &mut Table, key: &str, value: &str) {
    table.insert(key.into(), Value::String(value.into()));
}

fn protocol_name(protocol: TunnelProtocol) -> &'static str {
    match protocol {
        TunnelProtocol::Tcp => "tcp",
        TunnelProtocol::Udp => "udp",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{config_path_for_executable, load_or_create, save_validated};

    #[test]
    fn config_path_is_beside_executable() {
        let path =
            config_path_for_executable(Path::new("C:/apps/rustgo/rustgoc-gui.exe")).expect("path");
        assert_eq!(path, Path::new("C:/apps/rustgo/client.toml"));
    }

    #[test]
    fn missing_config_is_created_and_loadable() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("client.toml");
        let config = load_or_create(&path).expect("default config");
        assert_eq!(config.client.server_addr, "8.133.176.172:8443");
        assert!(path.is_file());
        assert!(config.tunnels.is_empty());
        assert!(config.exports.is_empty());
        assert!(config.forwards.is_empty());
    }

    #[test]
    fn existing_config_is_not_rewritten() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("client.toml");
        fs::write(&path, valid_config("saved.example:8443")).unwrap();
        let before = fs::read(&path).unwrap();
        let loaded = load_or_create(&path).expect("existing config");
        assert_eq!(loaded.client.server_addr, "saved.example:8443");
        assert_eq!(loaded.client.server_name, "saved.example");
        assert_eq!(loaded.client.private_key_file, Path::new("device.key"));
        assert_eq!(
            loaded.client.certificate_authority_file,
            Path::new("server-cert.pem")
        );
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn invalid_save_preserves_existing_file() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("client.toml");
        fs::write(&path, valid_config("saved.example:8443")).unwrap();
        let before = fs::read(&path).unwrap();
        let mut config = rustgo_config::load_client(&path).unwrap();
        config.client.server_addr.clear();
        assert!(save_validated(&path, &config).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }

    fn valid_config(server_addr: &str) -> String {
        format!(
            "[client]\nname = \"gui-client\"\nidentity_mode = \"dynamic\"\nserver_addr = \"{server_addr}\"\nserver_name = \"server.example\"\ncertificate_authority_file = \"server-cert.pem\"\nprivate_key_file = \"device.key\"\nheartbeat_interval_secs = 30\n"
        )
    }

    use std::path::Path;
}

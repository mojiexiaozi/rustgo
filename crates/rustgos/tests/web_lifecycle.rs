#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_crypto::DeviceKeypair;
use tempfile::TempDir;

const SERVER_NAME: &str = "localhost";
const ADMIN_USERNAME: &str = "dashboard-user-never-log";
const ADMIN_PASSWORD: &str = "dashboard-password-never-log-0123456789";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

type AnyError = Box<dyn Error + Send + Sync>;

struct TestMaterial {
    directory: TempDir,
    public_key: String,
}

impl TestMaterial {
    fn generate() -> Result<Self, AnyError> {
        let directory = tempfile::tempdir()?;
        let (ca_pem, issuer) = certificate_authority()?;
        let (leaf_pem, private_key) = server_certificate(&issuer)?;
        fs::write(
            directory.path().join("server.crt"),
            format!("{leaf_pem}{ca_pem}"),
        )?;
        fs::write(directory.path().join("server.key"), private_key)?;
        let public_key = DeviceKeypair::from_secret_bytes([0x5a; 32])
            .public_key()
            .to_string();
        Ok(Self {
            directory,
            public_key,
        })
    }

    fn write_config(
        &self,
        name: &str,
        relay_address: SocketAddr,
        web: Option<WebFixture<'_>>,
    ) -> Result<PathBuf, AnyError> {
        let path = self.directory.path().join(name);
        let web = web.map_or_else(String::new, |web| {
            format!(
                r#"
[web]
enabled = {}
bind = "{}"
admin_username = "{}"
admin_password = "{}"
cookie_secure = false
history_days = 7
database_path = "{}"
database_max_mib = 16
"#,
                web.enabled, web.address, ADMIN_USERNAME, ADMIN_PASSWORD, web.database_path
            )
        });
        fs::write(
            &path,
            format!(
                r#"
[server]
bind_addr = "{relay_address}"
certificate_file = "server.crt"
private_key_file = "server.key"
heartbeat_timeout_secs = 10

[limits]
max_clients = 8
max_tunnels_per_client = 8
max_tcp_connections_per_tunnel = 8
max_udp_sessions_per_tunnel = 8
max_udp_payload_bytes = 65507

[[clients]]
name = "lifecycle-client"
public_key = "{}"
enabled = true
{web}
"#,
                self.public_key
            ),
        )?;
        restrict_to_owner(&path)?;
        Ok(path)
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }
}

#[derive(Clone, Copy)]
struct WebFixture<'a> {
    enabled: bool,
    address: SocketAddr,
    database_path: &'a str,
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn wait_with_output(mut self) -> Result<Output, AnyError> {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if self
                .child
                .as_mut()
                .expect("child is retained until wait")
                .try_wait()?
                .is_some()
            {
                return Ok(self
                    .child
                    .take()
                    .expect("completed child remains owned")
                    .wait_with_output()?);
            }
            if Instant::now() >= deadline {
                return Err("rustgos process did not terminate within the lifecycle bound".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn check_and_disabled_mode_create_neither_web_listener_nor_history_store() -> Result<(), AnyError> {
    let checked = TestMaterial::generate()?;
    let checked_relay = TcpListener::bind("127.0.0.1:0")?;
    let checked_web = TcpListener::bind("127.0.0.1:0")?;
    let checked_database = "checked-history.db";
    let checked_config = checked.write_config(
        "checked.toml",
        checked_relay.local_addr()?,
        Some(WebFixture {
            enabled: true,
            address: checked_web.local_addr()?,
            database_path: checked_database,
        }),
    )?;
    let checked_output = run_check(&checked_config)?.wait_with_output()?;
    assert!(
        checked_output.status.success(),
        "{}",
        diagnostics(&checked_output)
    );
    assert!(history_artifacts(checked.path(), checked_database)?.is_empty());
    assert!(checked_relay.local_addr().is_ok());
    assert!(checked_web.local_addr().is_ok());

    let disabled = TestMaterial::generate()?;
    let relay = reserve_address()?;
    let web = reserve_address()?;
    let database = "disabled-history.db";
    let config = disabled.write_config(
        "disabled.toml",
        relay,
        Some(WebFixture {
            enabled: false,
            address: web,
            database_path: database,
        }),
    )?;
    let child = spawn_run(&config, 800, &[])?;
    wait_for_tcp(relay)?;
    let reserved_while_running = TcpListener::bind(web)?;
    let output = child.wait_with_output()?;
    drop(reserved_while_running);

    assert!(output.status.success(), "{}", diagnostics(&output));
    assert!(history_artifacts(disabled.path(), database)?.is_empty());
    let logs = diagnostics(&output);
    assert!(logs.contains("web_enabled=false"), "{logs}");
    assert!(!logs.contains("Web dashboard listener ready"), "{logs}");
    Ok(())
}

#[test]
fn enabled_mode_starts_both_listeners_persists_history_and_cancels_cleanly() -> Result<(), AnyError>
{
    let material = TestMaterial::generate()?;
    let relay = reserve_address()?;
    let web = reserve_address()?;
    let database = "enabled-history.db";
    let config = material.write_config(
        "enabled.toml",
        relay,
        Some(WebFixture {
            enabled: true,
            address: web,
            database_path: database,
        }),
    )?;
    let child = spawn_run(&config, 1_200, &[])?;

    wait_for_health(web)?;
    wait_for_tcp(relay)?;
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "{}", diagnostics(&output));
    assert!(!history_artifacts(material.path(), database)?.is_empty());

    let logs = diagnostics(&output);
    assert!(logs.contains("web_enabled=true"), "{logs}");
    assert!(logs.contains("Web dashboard listener ready"), "{logs}");
    for secret in [
        ADMIN_USERNAME,
        ADMIN_PASSWORD,
        "admin_username",
        "admin_password",
        "cookie_secure",
        "database_path",
        "rustgo_session",
    ] {
        assert!(!logs.contains(secret), "log disclosed `{secret}`: {logs}");
    }
    Ok(())
}

#[test]
fn occupied_web_port_fails_startup_and_releases_the_relay_listener() -> Result<(), AnyError> {
    let material = TestMaterial::generate()?;
    let relay = reserve_address()?;
    let web_reservation = TcpListener::bind("127.0.0.1:0")?;
    let web = web_reservation.local_addr()?;
    let database = "conflict-history.db";
    let config = material.write_config(
        "conflict.toml",
        relay,
        Some(WebFixture {
            enabled: true,
            address: web,
            database_path: database,
        }),
    )?;

    let output = spawn_run(&config, 800, &[])?.wait_with_output()?;
    assert!(!output.status.success(), "{}", diagnostics(&output));
    assert!(history_artifacts(material.path(), database)?.is_empty());
    let rebound_relay = TcpListener::bind(relay)?;
    drop(rebound_relay);
    drop(web_reservation);

    let logs = diagnostics(&output);
    assert!(logs.contains("Web dashboard setup failed"), "{logs}");
    assert!(!logs.contains(ADMIN_USERNAME), "{logs}");
    assert!(!logs.contains(ADMIN_PASSWORD), "{logs}");
    Ok(())
}

#[test]
fn sqlite_failure_keeps_relay_live_while_web_exit_restarts_on_the_same_port() -> Result<(), AnyError>
{
    let material = TestMaterial::generate()?;
    let relay = reserve_address()?;
    let web = reserve_address()?;
    let config = material.write_config(
        "degraded.toml",
        relay,
        Some(WebFixture {
            enabled: true,
            address: web,
            database_path: "missing-parent/history.db",
        }),
    )?;
    let child = spawn_run(
        &config,
        1_800,
        &[("RUSTGO_TEST_WEB_EXIT_AFTER_ACCEPTS", "1")],
    )?;

    wait_for_tcp(relay)?;
    trigger_web_accept(web)?;
    wait_for_health(web)?;
    wait_for_tcp(relay)?;
    let output = child.wait_with_output()?;

    assert!(output.status.success(), "{}", diagnostics(&output));
    assert!(!material.path().join("missing-parent").exists());
    let logs = diagnostics(&output);
    assert!(
        logs.contains("SQLite history is unavailable; live observability remains active"),
        "{logs}"
    );
    assert!(logs.contains("Web server restarted"), "{logs}");
    assert!(logs.contains("web_enabled=true"), "{logs}");
    Ok(())
}

fn certificate_authority() -> Result<(String, Issuer<'static, KeyPair>), AnyError> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Rustgo lifecycle test CA");
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    let certificate = parameters.self_signed(&key)?;
    Ok((certificate.pem(), Issuer::new(parameters, key)))
}

fn server_certificate(issuer: &Issuer<'static, KeyPair>) -> Result<(String, String), AnyError> {
    let mut parameters = CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, SERVER_NAME);
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let certificate = parameters.signed_by(&key, issuer)?;
    Ok((certificate.pem(), key.serialize_pem()))
}

fn reserve_address() -> Result<SocketAddr, AnyError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

fn spawn_run(
    config: &Path,
    shutdown_after_millis: u64,
    environment: &[(&str, &str)],
) -> Result<ChildGuard, AnyError> {
    let mut command = rustgos_command(config);
    command.env("RUSTGO_INTERNAL_TESTING", "1").env(
        "RUSTGO_TEST_SHUTDOWN_AFTER_MS",
        shutdown_after_millis.to_string(),
    );
    for (name, value) in environment {
        command.env(name, value);
    }
    Ok(ChildGuard {
        child: Some(command.spawn()?),
    })
}

fn run_check(config: &Path) -> Result<ChildGuard, AnyError> {
    let mut command = rustgos_command(config);
    command.arg("check");
    Ok(ChildGuard {
        child: Some(command.spawn()?),
    })
}

fn rustgos_command(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustgos"));
    command
        .current_dir(config.parent().expect("test config has a directory"))
        .args(["-c", config.to_str().expect("temporary path is UTF-8")])
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn wait_for_tcp(address: SocketAddr) -> Result<(), AnyError> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("listener {address} did not become reachable").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn trigger_web_accept(address: SocketAddr) -> Result<(), AnyError> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(mut stream) => {
                let _ = stream.write_all(
                    format!(
                        "GET /healthz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                );
                return Ok(());
            }
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait_for_health(address: SocketAddr) -> Result<(), AnyError> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if health_is_ready(address) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("Web health endpoint {address} did not become ready").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn health_is_ready(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    if stream
        .write_all(
            format!("GET /healthz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok()
        && response.starts_with("HTTP/1.1 200")
        && response.ends_with("ok\n")
}

fn history_artifacts(directory: &Path, database: &str) -> Result<Vec<PathBuf>, AnyError> {
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(database) {
            artifacts.push(entry.path());
        }
    }
    Ok(artifacts)
}

fn diagnostics(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<(), AnyError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<(), AnyError> {
    Ok(())
}

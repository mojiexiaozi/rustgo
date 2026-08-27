use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use assert_cmd::Command;

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustgoc-cli-test-{}-{sequence}",
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

fn valid_config() -> &'static str {
    r#"
[client]
name = "home-pc"
server_addr = "127.0.0.1:7000"
server_name = "localhost"
certificate_authority_file = "ca.pem"
private_key_file = "device.key"
heartbeat_interval_secs = 20

[[tunnels]]
name = "ssh"
protocol = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 2222
"#
}

fn command() -> Command {
    Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap()
}

#[test]
fn default_run_reports_missing_conventional_config_and_override_flag() {
    let dir = TempDir::new();
    let output = command().current_dir(&dir.path).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("client.toml"));
    assert!(stderr.contains("-c"));
}

#[test]
fn check_validates_locally_without_contacting_the_configured_server() {
    let dir = TempDir::new();
    let config = dir.write("valid.toml", valid_config());
    dir.write("ca.pem", "test CA");
    dir.write("device.key", "test private key");
    let _reserved_port = TcpListener::bind("127.0.0.1:7000").unwrap();

    command()
        .current_dir(&dir.path)
        .args(["check", "-c", config.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn explicit_config_does_not_consult_conventional_filename() {
    let dir = TempDir::new();
    let config = dir.write("custom.toml", valid_config());
    dir.write("ca.pem", "test CA");
    dir.write("device.key", "test private key");
    dir.write("client.toml", "not valid toml = [");

    command()
        .current_dir(&dir.path)
        .args(["check", "-c", config.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn default_run_enters_client_runtime_and_rejects_invalid_identity_material() {
    let dir = TempDir::new();
    let config = dir.write("run.toml", valid_config());
    dir.write("ca.pem", "not a certificate");
    dir.write("device.key", "not a Rustgo private key");

    command()
        .current_dir(&dir.path)
        .args(["-c", config.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn wire_overflow_is_rejected_by_check_and_run_before_opening_a_socket() {
    let dir = TempDir::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut contents = valid_config().replace("127.0.0.1:7000", &address.to_string());
    for index in 0..64 {
        contents.push_str(&format!(
            "\n[[tunnels]]\nname = \"extra-{index}\"\nprotocol = \"tcp\"\nlocal_addr = \"127.0.0.1:22\"\nremote_port = {}\n",
            10_000 + index
        ));
    }
    let config = dir.write("overflow.toml", &contents);
    dir.write("ca.pem", "not needed when configuration is invalid");
    dir.write("device.key", "not needed when configuration is invalid");

    let check = command()
        .current_dir(&dir.path)
        .args(["check", "-c", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("invalid configuration"));

    let run = command()
        .current_dir(&dir.path)
        .args(["-c", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("invalid configuration"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

use std::{fs, io::Write as _, net::TcpListener, path::Path};

use assert_cmd::Command;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustgo_crypto::generate_key_file;
use tempfile::TempDir;

struct TestMaterial {
    directory: TempDir,
}

impl TestMaterial {
    fn generate() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("ca.pem"),
            certificate_authority().unwrap(),
        )
        .unwrap();
        generate_key_file(&directory.path().join("keys")).unwrap();
        Self { directory }
    }

    fn write_config(&self, name: &str) -> std::path::PathBuf {
        let path = self.directory.path().join(name);
        fs::write(&path, valid_config()).unwrap();
        path
    }
}

fn certificate_authority() -> Result<String, rcgen::Error> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Rustgo client CLI check test CA");
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    Ok(parameters.self_signed(&key)?.pem())
}

fn valid_config() -> &'static str {
    r#"
[client]
name = "home-pc"
server_addr = "127.0.0.1:7000"
server_name = "localhost"
certificate_authority_file = "ca.pem"
private_key_file = "keys/device.key"
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

fn check(config: &Path, current_dir: &Path) -> assert_cmd::assert::Assert {
    command()
        .current_dir(current_dir)
        .args(["check", "-c", config.to_str().unwrap()])
        .assert()
}

#[test]
fn default_run_reports_missing_conventional_config_and_override_flag() {
    let directory = tempfile::tempdir().unwrap();
    let output = command().current_dir(directory.path()).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("client.toml"));
    assert!(stderr.contains("-c"));
}

#[test]
fn check_parses_real_credentials_without_contacting_the_configured_server() {
    let material = TestMaterial::generate();
    let config = material.write_config("valid.toml");
    let _reserved_port = TcpListener::bind("127.0.0.1:7000").unwrap();

    check(&config, material.directory.path()).success();
}

#[test]
fn explicit_config_does_not_consult_conventional_filename() {
    let material = TestMaterial::generate();
    let config = material.write_config("custom.toml");
    fs::write(
        material.directory.path().join("client.toml"),
        "not valid toml = [",
    )
    .unwrap();

    check(&config, material.directory.path()).success();
}

#[test]
fn check_rejects_malformed_ca_certificate_chain() {
    let material = TestMaterial::generate();
    let config = material.write_config("client.toml");
    fs::OpenOptions::new()
        .append(true)
        .open(material.directory.path().join("ca.pem"))
        .unwrap()
        .write_all(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
        .unwrap();

    check(&config, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("invalid TLS certificate"));
}

#[test]
fn check_rejects_malformed_device_private_key() {
    let material = TestMaterial::generate();
    let config = material.write_config("client.toml");
    fs::write(
        material.directory.path().join("keys/device.key"),
        "not a Rustgo device key",
    )
    .unwrap();

    check(&config, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("invalid Rustgo private key"));
}

#[test]
fn wire_overflow_is_rejected_by_check_and_run_before_opening_a_socket() {
    let material = TestMaterial::generate();
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
    let config = material.directory.path().join("overflow.toml");
    fs::write(&config, contents).unwrap();

    let check_output = command()
        .current_dir(material.directory.path())
        .args(["check", "-c", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!check_output.status.success());
    assert!(String::from_utf8_lossy(&check_output.stderr).contains("invalid configuration"));

    let run = command()
        .current_dir(material.directory.path())
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

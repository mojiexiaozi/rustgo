use std::{fs, io::Write as _, net::TcpListener, path::Path};

use assert_cmd::Command;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_crypto::generate_key_file;
use tempfile::TempDir;

const SERVER_NAME: &str = "localhost";
const WEAK_PUBLIC_KEY: &str = "ed25519:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

struct TestMaterial {
    directory: TempDir,
    public_key: String,
    mismatched_private_key: String,
}

impl TestMaterial {
    fn generate() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let (ca_pem, issuer) = certificate_authority().unwrap();
        let (leaf_pem, private_key) = server_certificate(&issuer).unwrap();
        let (_, mismatched_private_key) = server_certificate(&issuer).unwrap();
        fs::write(
            directory.path().join("server.crt"),
            format!("{leaf_pem}{ca_pem}"),
        )
        .unwrap();
        fs::write(directory.path().join("server.key"), private_key).unwrap();
        let public_key = generate_key_file(&directory.path().join("device"))
            .unwrap()
            .to_string();
        Self {
            directory,
            public_key,
            mismatched_private_key,
        }
    }

    fn write_config(&self, name: &str, public_key: &str) -> std::path::PathBuf {
        let path = self.directory.path().join(name);
        fs::write(&path, valid_config(public_key)).unwrap();
        path
    }
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn certificate_authority() -> Result<(String, Issuer<'static, KeyPair>), rcgen::Error> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Rustgo CLI check test CA");
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    let certificate = parameters.self_signed(&key)?;
    Ok((certificate.pem(), Issuer::new(parameters, key)))
}

fn server_certificate(issuer: &Issuer<'static, KeyPair>) -> Result<(String, String), rcgen::Error> {
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

fn valid_config(public_key: &str) -> String {
    format!(
        r#"
[server]
bind_addr = "127.0.0.1:7000"
certificate_file = "server.crt"
private_key_file = "server.key"
heartbeat_timeout_secs = 60

[limits]
max_clients = 128
max_tunnels_per_client = 64
max_tcp_connections_per_tunnel = 256
max_udp_sessions_per_tunnel = 1024
max_udp_payload_bytes = 65507

[[clients]]
name = "home-pc"
public_key = "{public_key}"
enabled = true
"#
    )
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
    assert!(stderr.contains("server.toml"));
    assert!(stderr.contains("-c"));
}

#[test]
fn check_parses_real_credentials_without_binding_the_configured_port() {
    let material = TestMaterial::generate();
    let config = material.write_config("valid.toml", &material.public_key);
    let _reserved_port = TcpListener::bind("127.0.0.1:7000").unwrap();

    check(&config, material.directory.path()).success();
}

#[test]
fn check_accepts_enabled_web_defaults_when_its_toml_is_private() {
    let material = TestMaterial::generate();
    let path = material.directory.path().join("web.toml");
    fs::write(
        &path,
        format!(
            "{}\n[web]\nenabled = true\nexternal_origin = \"https://dashboard.example\"\nadmin_password = \"a-password-that-is-at-least-sixteen-bytes\"\n",
            valid_config(&material.public_key)
        ),
    )
    .unwrap();
    #[cfg(unix)]
    restrict_to_owner(&path);

    check(&path, material.directory.path()).success();
}

#[test]
fn check_rejects_non_loopback_web_bind_before_starting_a_listener() {
    let material = TestMaterial::generate();
    let path = material.directory.path().join("web.toml");
    fs::write(
        &path,
        format!(
            "{}\n[web]\nenabled = true\nbind = \"0.0.0.0:7450\"\nadmin_password = \"a-password-that-is-at-least-sixteen-bytes\"\n",
            valid_config(&material.public_key)
        ),
    )
    .unwrap();

    check(&path, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("loopback"));
}

#[cfg(windows)]
#[test]
fn check_warns_that_enabled_web_configuration_needs_manual_acl_review() {
    let material = TestMaterial::generate();
    let path = material.directory.path().join("web.toml");
    fs::write(
        &path,
        format!(
            "{}\n[web]\nenabled = true\nexternal_origin = \"https://dashboard.example\"\nadmin_password = \"a-password-that-is-at-least-sixteen-bytes\"\n",
            valid_config(&material.public_key)
        ),
    )
    .unwrap();

    check(&path, material.directory.path())
        .success()
        .stderr(predicates::str::contains("WEB_CONFIG_ACL_REVIEW_REQUIRED"))
        .stderr(predicates::str::contains("manual ACL review"));
}

#[test]
fn explicit_config_does_not_consult_conventional_filename() {
    let material = TestMaterial::generate();
    let config = material.write_config("custom.toml", &material.public_key);
    fs::write(
        material.directory.path().join("server.toml"),
        "not valid toml = [",
    )
    .unwrap();

    check(&config, material.directory.path()).success();
}

#[test]
fn check_rejects_malformed_certificate_in_chain() {
    let material = TestMaterial::generate();
    let config = material.write_config("server.toml", &material.public_key);
    fs::OpenOptions::new()
        .append(true)
        .open(material.directory.path().join("server.crt"))
        .unwrap()
        .write_all(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
        .unwrap();

    check(&config, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("invalid TLS certificate"));
}

#[test]
fn check_rejects_malformed_or_mismatched_tls_private_key() {
    let material = TestMaterial::generate();
    let config = material.write_config("server.toml", &material.public_key);
    let key_path = material.directory.path().join("server.key");
    fs::write(&key_path, "not a private key").unwrap();
    check(&config, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("invalid TLS private key"));

    fs::write(&key_path, &material.mismatched_private_key).unwrap();
    check(&config, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("not a valid identity"));
}

#[test]
fn check_rejects_malformed_and_weak_authorized_public_keys() {
    let material = TestMaterial::generate();
    let malformed = material.write_config("malformed.toml", "ed25519:not-base64");
    check(&malformed, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("invalid configuration"));

    let weak = material.directory.path().join("weak.toml");
    fs::write(
        &weak,
        format!(
            "{}\n[[clients]]\nname = \"second-device\"\npublic_key = \"{WEAK_PUBLIC_KEY}\"\nenabled = true\n",
            valid_config(&material.public_key)
        ),
    )
    .unwrap();
    check(&weak, material.directory.path())
        .failure()
        .stderr(predicates::str::contains("authentication setup"));
}

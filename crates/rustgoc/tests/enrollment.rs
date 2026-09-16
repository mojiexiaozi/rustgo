#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustgo_config::{
    ClientConfig, ClientSection, EnrollmentConfig, IdentityMode, Limits, ServerConfig,
    ServerSection, TrustMode,
};
use rustgoc::{
    EnrollmentKey, EnrollmentPurpose, EnrollmentState, PendingEnrollment,
    classify_enrollment_state, enroll, recover_pending_enrollment,
};

#[test]
fn approval_reuses_existing_key_and_request_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let key_dir = directory.path().join("keys");
    rustgo_crypto::generate_key_file(&key_dir).unwrap();
    let private = key_dir.join("device.key");
    let original = std::fs::read(&private).unwrap();
    let config_path = directory.path().join("client.toml");
    let encoded = encoded_key(1, "server.example:7443", [3; 32], [4; 32]);
    let key = EnrollmentKey::parse(&encoded).unwrap();
    let pending = PendingEnrollment::create_reusing(&config_path, &private, &key).unwrap();
    let request_id = pending.request_id().to_owned();
    let public = pending.public_key().to_owned();
    drop(pending);
    let reloaded = PendingEnrollment::load(&config_path).unwrap();
    assert_eq!(reloaded.request_id(), request_id);
    assert_eq!(reloaded.public_key(), public);
    reloaded.promote().unwrap();
    assert_eq!(std::fs::read(private).unwrap(), original);
}

#[test]
fn corrupt_default_identity_requests_approval_instead_of_stopping() {
    let directory = tempfile::tempdir().unwrap();
    let private = directory.path().join("device.key");
    std::fs::write(&private, "damaged").unwrap();
    let config = client_config(private, None);
    assert_eq!(
        rustgoc::classify_enrollment_state(&config, &directory.path().join("client.toml")).unwrap(),
        EnrollmentState::ReRegistrationRequired
    );
}

#[tokio::test]
async fn invalid_existing_enrollment_certificate_is_a_local_error_not_pending_approval() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("client.toml");
    let mut config = client_config(
        directory.path().join("device.key"),
        Some(IdentityMode::Dynamic),
    );
    config.client.trust_mode = None;
    config.client.certificate_authority_file = directory.path().join("missing-ca.pem");
    std::fs::write(
        &config.client.certificate_authority_file,
        "invalid certificate",
    )
    .unwrap();
    let error =
        rustgoc::request_registration(&mut config, &config_path, EnrollmentPurpose::ReEnroll)
            .await
            .unwrap_err();
    assert!(error.to_string().contains("本地证书配置不可用"), "{error}");
    assert!(
        !config_path
            .with_extension("enrollment-pending.toml")
            .exists()
    );
    assert!(!config.client.private_key_file.exists());
}

#[test]
fn pending_recovers_after_key_move_before_metadata_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("client.toml");
    let private = dir.path().join("device.key");
    let key =
        EnrollmentKey::parse(&encoded_key(1, "server.example:7443", [3; 32], [4; 32])).unwrap();
    PendingEnrollment::create_reusing(&config_path, &private, &key).unwrap();
    let metadata: toml::Value = toml::from_str(
        &std::fs::read_to_string(config_path.with_extension("enrollment-pending.toml")).unwrap(),
    )
    .unwrap();
    std::fs::rename(
        metadata["candidate_private_key"].as_str().unwrap(),
        &private,
    )
    .unwrap();
    PendingEnrollment::load(&config_path)
        .unwrap()
        .promote()
        .unwrap();
    assert!(private.exists());
    assert!(
        !config_path
            .with_extension("enrollment-pending.toml")
            .exists()
    );
}
use rustgos::{
    ServerApp,
    enrollment::{DynamicClientStore, EnrollmentStoreLimits},
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn encoded_key(purpose: u8, address: &str, fingerprint: [u8; 32], token: [u8; 32]) -> String {
    let mut payload = Vec::new();
    payload.push(purpose);
    payload.extend_from_slice(&(address.len() as u16).to_be_bytes());
    payload.extend_from_slice(address.as_bytes());
    payload.extend_from_slice(&fingerprint);
    payload.extend_from_slice(&token);
    let digest = Sha256::digest(&payload);
    format!(
        "rustgo-enroll-v1.{}.{:02x}{:02x}{:02x}{:02x}",
        URL_SAFE_NO_PAD.encode(payload),
        digest[0],
        digest[1],
        digest[2],
        digest[3]
    )
}

fn files_below(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(files_below(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[test]
fn enrollment_key_parses_bounded_metadata() {
    let raw = encoded_key(1, "Tunnel.Example.com:7443", [0x11; 32], [0x22; 32]);
    let key = EnrollmentKey::parse(&raw).unwrap();

    assert_eq!(key.server_addr(), "tunnel.example.com:7443");
    assert_eq!(key.certificate_fingerprint(), &[0x11; 32]);
    assert_eq!(key.purpose(), EnrollmentPurpose::Enroll);
    assert_eq!(key.token(), &[0x22; 32]);
}

#[test]
fn enrollment_key_rejects_malformed_inputs_without_disclosing_them() {
    let secret = "super-secret-token-material";
    for raw in [
        "",
        secret,
        "rustgo-enroll-v2.YQ.00000000",
        "rustgo-enroll-v1.***.00000000",
        &"x".repeat(513),
    ] {
        let error = EnrollmentKey::parse(raw).unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }
}

#[test]
fn enrollment_key_rejects_wrong_checksum_purpose_address_and_trailing_data() {
    let valid = encoded_key(1, "server.example:7443", [3; 32], [4; 32]);
    let wrong_checksum = format!("{}00000000", &valid[..valid.len() - 8]);
    assert!(EnrollmentKey::parse(&wrong_checksum).is_err());

    assert!(
        EnrollmentKey::parse(&encoded_key(9, "server.example:7443", [3; 32], [4; 32])).is_err()
    );
    assert!(EnrollmentKey::parse(&encoded_key(1, "missing-port", [3; 32], [4; 32])).is_err());

    let mut trailing_payload = Vec::new();
    trailing_payload.push(1);
    trailing_payload.extend_from_slice(&19_u16.to_be_bytes());
    trailing_payload.extend_from_slice(b"server.example:7443");
    trailing_payload.extend_from_slice(&[3; 32]);
    trailing_payload.extend_from_slice(&[4; 32]);
    trailing_payload.push(5);
    let digest = Sha256::digest(&trailing_payload);
    let trailing = format!(
        "rustgo-enroll-v1.{}.{:02x}{:02x}{:02x}{:02x}",
        URL_SAFE_NO_PAD.encode(trailing_payload),
        digest[0],
        digest[1],
        digest[2],
        digest[3]
    );
    assert!(EnrollmentKey::parse(&trailing).is_err());
}

fn client_config(
    private_key_file: std::path::PathBuf,
    identity_mode: Option<IdentityMode>,
) -> ClientConfig {
    ClientConfig {
        client: ClientSection {
            profile: None,
            name: "device-one".to_owned(),
            identity_mode,
            server_addr: "server.example:7443".to_owned(),
            server_name: "server.example".to_owned(),
            certificate_authority_file: "ca.pem".into(),
            trust_mode: None,
            server_certificate_fingerprint: None,
            private_key_file,
            heartbeat_interval_secs: 20,
        },
        p2p: None,
        telemetry: None,
        tunnels: Vec::new(),
        exports: Vec::new(),
        forwards: Vec::new(),
    }
}

#[test]
fn startup_state_distinguishes_legacy_static_and_dynamic_missing_keys() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing.key");
    let config_path = directory.path().join("client.toml");

    assert_eq!(
        classify_enrollment_state(&client_config(missing.clone(), None), &config_path).unwrap(),
        EnrollmentState::RegistrationRequired
    );
    assert_eq!(
        classify_enrollment_state(
            &client_config(missing.clone(), Some(IdentityMode::Dynamic)),
            &config_path
        )
        .unwrap(),
        EnrollmentState::ReRegistrationRequired
    );
    assert!(
        classify_enrollment_state(
            &client_config(missing, Some(IdentityMode::Static)),
            &config_path
        )
        .is_err()
    );
}

#[test]
fn startup_state_accepts_a_loadable_legacy_key() {
    let directory = TempDir::new().unwrap();
    rustgo_crypto::generate_key_file(directory.path()).unwrap();
    let config = client_config(directory.path().join("device.key"), None);

    assert_eq!(
        classify_enrollment_state(&config, &directory.path().join("client.toml")).unwrap(),
        EnrollmentState::Ready
    );
}

#[test]
fn pending_enrollment_survives_reload_without_persisting_the_token() {
    let directory = TempDir::new().unwrap();
    let config_path = directory.path().join("client.toml");
    let final_key = directory.path().join("keys/device.key");
    let raw = encoded_key(1, "server.example:7443", [7; 32], [0x5a; 32]);
    let key = EnrollmentKey::parse(&raw).unwrap();

    let created = PendingEnrollment::create(&config_path, &final_key, &key).unwrap();
    let public_key = created.public_key().to_owned();
    let request_id = created.request_id().to_owned();
    drop(created);

    let loaded = PendingEnrollment::load(&config_path).unwrap();
    assert_eq!(loaded.public_key(), public_key);
    assert_eq!(loaded.request_id(), request_id);

    for path in files_below(directory.path()) {
        let contents = std::fs::read(path).unwrap();
        assert!(!String::from_utf8_lossy(&contents).contains(&raw));
    }
}

#[test]
fn pending_enrollment_promotes_once_and_malformed_metadata_fails_closed() {
    let directory = TempDir::new().unwrap();
    let config_path = directory.path().join("client.toml");
    let final_key = directory.path().join("keys/device.key");
    let raw = encoded_key(1, "server.example:7443", [8; 32], [9; 32]);
    let key = EnrollmentKey::parse(&raw).unwrap();

    let pending = PendingEnrollment::create(&config_path, &final_key, &key).unwrap();
    let public_key = pending.public_key().to_owned();
    pending.promote().unwrap();
    assert_eq!(
        rustgo_crypto::DeviceKeypair::load_private_file(&final_key)
            .unwrap()
            .public_key()
            .to_string(),
        public_key
    );
    assert!(PendingEnrollment::load(&config_path).is_err());

    std::fs::write(
        config_path.with_extension("enrollment-pending.toml"),
        "format_version = 1\n",
    )
    .unwrap();
    assert!(PendingEnrollment::load(&config_path).is_err());
}

#[test]
fn startup_state_restores_pending_before_examining_the_final_key() {
    for (purpose, mode, expected) in [
        (1, None, EnrollmentState::EnrollmentPending),
        (
            2,
            Some(IdentityMode::Dynamic),
            EnrollmentState::ReEnrollmentPending,
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let config_path = directory.path().join("client.toml");
        let final_key = directory.path().join("keys/device.key");
        let raw = encoded_key(purpose, "server.example:7443", [7; 32], [8; 32]);
        PendingEnrollment::create(
            &config_path,
            &final_key,
            &EnrollmentKey::parse(&raw).unwrap(),
        )
        .unwrap();

        assert_eq!(
            classify_enrollment_state(&client_config(final_key, mode), &config_path).unwrap(),
            expected
        );
    }
}

#[test]
fn reenrollment_pending_can_be_created_before_old_key_removal() {
    let directory = TempDir::new().unwrap();
    let config_path = directory.path().join("client.toml");
    let final_key = directory.path().join("keys/device.key");
    std::fs::create_dir_all(final_key.parent().unwrap()).unwrap();
    std::fs::write(&final_key, b"corrupt old key").unwrap();
    let raw = encoded_key(2, "server.example:7443", [7; 32], [8; 32]);

    let pending = PendingEnrollment::create(
        &config_path,
        &final_key,
        &EnrollmentKey::parse(&raw).unwrap(),
    )
    .unwrap();

    assert_eq!(pending.purpose(), EnrollmentPurpose::ReEnroll);
    assert!(final_key.exists());
}

#[tokio::test]
async fn client_runtime_enrolls_over_pinned_tls_and_promotes_configuration() {
    let directory = TempDir::new().unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let certificate_file = directory.path().join("server.pem");
    let server_key_file = directory.path().join("server.key");
    std::fs::write(&certificate_file, certificate.pem()).unwrap();
    std::fs::write(&server_key_file, key_pair.serialize_pem()).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address = format!("127.0.0.1:{port}");
    let database = directory.path().join("enrollment.db");
    let store = DynamicClientStore::open(
        &database,
        EnrollmentStoreLimits {
            max_active_clients: 4,
            max_tokens: 4,
        },
    )
    .unwrap();
    let dynamic = store.create_client("Runtime.Node").unwrap();
    let fingerprint =
        rustgo_transport::TlsServer::leaf_certificate_fingerprint(&certificate_file).unwrap();
    let encoded = store
        .issue_token(
            dynamic.internal_id(),
            EnrollmentPurpose::Enroll,
            &address,
            fingerprint,
            std::time::Duration::from_secs(60),
            1,
        )
        .unwrap()
        .into_encoded();
    drop(store);
    let server = ServerApp::bind(ServerConfig {
        managed_tunnels: None,
        server: ServerSection {
            bind_addr: address.clone(),
            udp_bind_ip: None,
            p2p_observation_bind: None,
            p2p_observation_alternate_bind: None,
            certificate_file: certificate_file.clone(),
            private_key_file: server_key_file,
            heartbeat_timeout_secs: 60,
        },
        limits: Limits {
            max_clients: 4,
            max_tunnels_per_client: 4,
            max_tcp_connections_per_tunnel: 4,
            max_udp_sessions_per_tunnel: 4,
            max_udp_payload_bytes: 65_507,
        },
        clients: Vec::new(),
        web: None,
        enrollment: Some(EnrollmentConfig {
            enabled: true,
            database_path: database,
            public_addr: address.clone(),
            token_ttl_secs: 60,
            max_active_clients: 4,
            max_tokens: 4,
        }),
    })
    .await
    .unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server_task = tokio::spawn(server.run_until(server_shutdown));

    let config_path = directory.path().join("client.toml");
    let final_key = directory.path().join("keys/device.key");
    std::fs::write(
        &config_path,
        format!(
            "[client]\nname = \"placeholder\"\nserver_addr = \"{address}\"\nserver_name = \"localhost\"\ncertificate_authority_file = \"server.pem\"\nprivate_key_file = \"{}\"\nheartbeat_interval_secs = 20\n",
            final_key.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    let mut config = client_config(final_key.clone(), None);
    config.client.server_addr = address;
    config.client.server_name = "localhost".to_owned();
    let result = enroll(&mut config, &config_path, &encoded).await.unwrap();
    assert_eq!(result.client_id, "Runtime.Node");
    assert_eq!(result.revision, 2);
    assert!(final_key.exists());
    assert_eq!(config.client.identity_mode, Some(IdentityMode::Dynamic));
    assert_eq!(config.client.trust_mode, Some(TrustMode::Pinned));
    let expected_fingerprint: String = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        config.client.server_certificate_fingerprint.as_deref(),
        Some(expected_fingerprint.as_str())
    );
    assert!(
        !config_path
            .with_extension("enrollment-pending.toml")
            .exists()
    );
    let authority = DynamicClientStore::open(
        directory.path().join("enrollment.db"),
        EnrollmentStoreLimits {
            max_active_clients: 4,
            max_tokens: 4,
        },
    )
    .unwrap();
    authority
        .rename_client(dynamic.internal_id(), "Renamed.Runtime.Node", 2)
        .unwrap();
    let recovery_client = authority.create_client("Recovery.Node").unwrap();
    let recovery_key = authority
        .issue_token(
            recovery_client.internal_id(),
            EnrollmentPurpose::Enroll,
            &config.client.server_addr,
            fingerprint,
            std::time::Duration::from_secs(60),
            1,
        )
        .unwrap()
        .into_encoded();
    let recovery_config_path = directory.path().join("recovery.toml");
    let recovery_final_key = directory.path().join("keys/recovery.key");
    std::fs::write(
        &recovery_config_path,
        format!(
            "[client]\nname = \"recovery-placeholder\"\nserver_addr = \"{}\"\nserver_name = \"localhost\"\ncertificate_authority_file = \"server.pem\"\nprivate_key_file = \"{}\"\nheartbeat_interval_secs = 20\n",
            config.client.server_addr,
            recovery_final_key.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    let mut recovery_config = client_config(recovery_final_key.clone(), None);
    recovery_config.client.server_addr = config.client.server_addr.clone();
    recovery_config.client.server_name = "localhost".to_owned();
    let pending = PendingEnrollment::create(
        &recovery_config_path,
        &recovery_final_key,
        &EnrollmentKey::parse(&recovery_key).unwrap(),
    )
    .unwrap();
    let pending_public = pending.public_key().parse().unwrap();
    authority
        .consume_token(
            &recovery_key,
            &pending_public,
            pending.request_id(),
            std::time::SystemTime::now(),
        )
        .unwrap();
    drop(pending);
    drop(authority);
    let session = rustgoc::ControlClient::from_config(config)
        .unwrap()
        .connect()
        .await
        .unwrap();
    drop(session);
    assert!(
        recover_pending_enrollment(&mut recovery_config, &recovery_config_path)
            .await
            .unwrap()
    );
    assert!(recovery_final_key.exists());
    shutdown.cancel();
    server_task.await.unwrap().unwrap();
}

use rustgoc::{EnrollmentError, EnrollmentErrorCode, EnrollmentPurpose, PendingEnrollment};
use rustgos::enrollment::{DynamicClientStore, EnrollmentStoreLimits};
use std::{fs, path::Path, time::Duration};

fn config_text(name: &str, address: &str, certificate: &Path) -> String {
    format!(
        "[client]\nname='{name}'\nserver_addr='{address}'\nserver_name='localhost'\ncertificate_authority_file='{}'\nprivate_key_file='device.key'\nheartbeat_interval_secs=20\n[telemetry]\nenabled=false\n",
        certificate.to_string_lossy().replace('\\', "/")
    )
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_reuses_keys_rotates_only_when_requested_and_cli_waits_without_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let pair = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&pair)
        .unwrap();
    let cert_path = dir.path().join("server.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(dir.path().join("server.key"), pair.serialize_pem()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    let server_path = dir.path().join("server.toml");
    fs::write(&server_path,format!("[server]\nbind_addr='{address}'\ncertificate_file='server.pem'\nprivate_key_file='server.key'\nheartbeat_timeout_secs=60\n[limits]\nmax_clients=8\nmax_tunnels_per_client=4\nmax_tcp_connections_per_tunnel=4\nmax_udp_sessions_per_tunnel=4\nmax_udp_payload_bytes=65507\n[enrollment]\nenabled=true\ndatabase_path='approval.db'\npublic_addr='{address}'\nmax_active_clients=8\nmax_tokens=8\n")).unwrap();
    let server = rustgos::ServerApp::bind(rustgo_config::load_server(&server_path).unwrap())
        .await
        .unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.run_until(shutdown.clone()));
    let store = DynamicClientStore::open(
        dir.path().join("approval.db"),
        EnrollmentStoreLimits {
            max_active_clients: 8,
            max_tokens: 8,
        },
    )
    .unwrap();
    let config_path = dir.path().join("client.toml");
    fs::write(
        &config_path,
        config_text("Reuse.Node", &address, &dir.path().join("absent.pem")),
    )
    .unwrap();
    rustgo_crypto::generate_key_file(dir.path()).unwrap();
    let private = dir.path().join("device.key");
    let original = fs::read(&private).unwrap();
    let mut config = rustgo_config::load_client(&config_path).unwrap();
    for _ in 0..2 {
        assert_eq!(
            rustgoc::request_registration(&mut config, &config_path, EnrollmentPurpose::Enroll)
                .await,
            Err(EnrollmentError::Rejected(
                EnrollmentErrorCode::PendingApproval
            ))
        );
    }
    config.client.profile = Some(rustgo_config::ClientProfile {
        display_name: "Changed while pending".into(),
        uid: None,
        local_ip: None,
    });
    assert!(matches!(
        rustgoc::request_registration(&mut config, &config_path, EnrollmentPurpose::Enroll).await,
        Err(EnrollmentError::Rejected(
            EnrollmentErrorCode::PendingApproval
        ))
    ));
    assert_eq!(
        store.pending_approvals().unwrap()[0].display_name,
        "Reuse.Node"
    );
    config.client.profile = None;
    assert!(store.list_clients().unwrap().is_empty());
    assert!(config.client.trust_mode.is_none());
    let requests = store.pending_approvals().unwrap();
    assert_eq!(requests.len(), 1);
    let pending = PendingEnrollment::load(&config_path).unwrap();
    assert_eq!(pending.request_id(), requests[0].request_id);
    // Retries must use the persisted pin, never fall back to first-contact TLS.
    let metadata_path = config_path.with_extension("enrollment-pending.toml");
    let original_metadata = fs::read_to_string(&metadata_path).unwrap();
    let mut metadata: toml::Value = toml::from_str(&original_metadata).unwrap();
    metadata["certificate_fingerprint"] = toml::Value::String("00".repeat(32));
    fs::write(&metadata_path, toml::to_string(&metadata).unwrap()).unwrap();
    assert!(matches!(
        rustgoc::request_registration(&mut config, &config_path, EnrollmentPurpose::Enroll).await,
        Err(EnrollmentError::NetworkDetail(_))
    ));
    fs::write(&metadata_path, original_metadata).unwrap();
    assert_eq!(fs::read(&private).unwrap(), original);
    store.review_approval(pending.request_id(), true).unwrap();
    rustgoc::request_registration(&mut config, &config_path, EnrollmentPurpose::Enroll)
        .await
        .unwrap();
    assert_eq!(fs::read(&private).unwrap(), original);
    let old_client = rustgoc::ControlClient::from_config(config.clone()).unwrap();
    let session = old_client.connect().await.unwrap();
    assert!(session.managed_revision().is_none());
    let effective = session.effective_config().unwrap();
    let profile = effective.client.profile.as_ref().unwrap();
    assert_eq!(profile.display_name, "Reuse.Node");
    assert_eq!(profile.uid.as_deref(), Some(config.client.name.as_str()));
    assert_eq!(profile.local_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(effective.client.name, config.client.name);
    drop(session);

    // Equal human labels never share an authenticated identity or approval.
    let duplicate_dir = dir.path().join("duplicate");
    fs::create_dir(&duplicate_dir).unwrap();
    let duplicate_path = duplicate_dir.join("client.toml");
    fs::write(
        &duplicate_path,
        config_text("Reuse.Node", &address, &cert_path),
    )
    .unwrap();
    let mut duplicate = rustgo_config::load_client(&duplicate_path).unwrap();
    assert!(matches!(
        rustgoc::request_registration(&mut duplicate, &duplicate_path, EnrollmentPurpose::Enroll)
            .await,
        Err(EnrollmentError::Rejected(
            EnrollmentErrorCode::PendingApproval
        ))
    ));
    // New-format metadata survives a crash before binding the v2 intent.
    let metadata_path = duplicate_path.with_extension("enrollment-pending.toml");
    let mut metadata: toml::Value =
        toml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();
    metadata.as_table_mut().unwrap().remove("approval_intent");
    fs::write(&metadata_path, toml::to_string(&metadata).unwrap()).unwrap();
    assert!(matches!(
        rustgoc::request_registration(&mut duplicate, &duplicate_path, EnrollmentPurpose::Enroll)
            .await,
        Err(EnrollmentError::Rejected(
            EnrollmentErrorCode::PendingApproval
        ))
    ));
    let duplicate_request = PendingEnrollment::load(&duplicate_path).unwrap();
    store
        .review_approval(duplicate_request.request_id(), true)
        .unwrap();
    rustgoc::request_registration(&mut duplicate, &duplicate_path, EnrollmentPurpose::Enroll)
        .await
        .unwrap();
    assert_ne!(duplicate.client.name, config.client.name);
    assert_eq!(
        duplicate.client.display_name(),
        config.client.display_name()
    );
    let session = rustgoc::ControlClient::from_config(duplicate.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    assert_eq!(
        session
            .effective_config()
            .unwrap()
            .client
            .profile
            .as_ref()
            .unwrap()
            .uid
            .as_deref(),
        Some(duplicate.client.name.as_str())
    );
    drop(session);
    assert_eq!(
        rustgoc::request_key_rotation(&mut config, &config_path).await,
        Err(EnrollmentError::Rejected(
            EnrollmentErrorCode::ReplacementApprovalPending
        ))
    );
    let pending = PendingEnrollment::load(&config_path).unwrap();
    assert_ne!(pending.public_key(), requests[0].public_key);
    assert_eq!(fs::read(&private).unwrap(), original);
    store.review_approval(pending.request_id(), true).unwrap();
    rustgoc::request_key_rotation(&mut config, &config_path)
        .await
        .unwrap();
    assert_ne!(fs::read(&private).unwrap(), original);
    assert!(matches!(
        old_client.connect().await,
        Err(rustgoc::ClientError::AuthenticationRejected)
    ));
    drop(
        rustgoc::ControlClient::from_config(config.clone())
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    // Upgrade a pending v1 request written before approval_intent was persisted.
    let legacy_dir = dir.path().join("legacy");
    fs::create_dir(&legacy_dir).unwrap();
    let legacy_path = legacy_dir.join("client.toml");
    fs::write(
        &legacy_path,
        config_text("Legacy.Pending", &address, &cert_path),
    )
    .unwrap();
    let mut legacy = rustgo_config::load_client(&legacy_path).unwrap();
    let v1 = rustgo_protocol::RegistrationIntent::new("Legacy.Pending", EnrollmentPurpose::Enroll)
        .unwrap();
    assert!(matches!(
        rustgoc::enroll(&mut legacy, &legacy_path, &v1.encode()).await,
        Err(EnrollmentError::Rejected(
            EnrollmentErrorCode::PendingApproval
        ))
    ));
    let legacy_metadata = legacy_path.with_extension("enrollment-pending.toml");
    let mut value: toml::Value =
        toml::from_str(&fs::read_to_string(&legacy_metadata).unwrap()).unwrap();
    value.as_table_mut().unwrap().remove("approval_intent");
    value
        .as_table_mut()
        .unwrap()
        .remove("approval_metadata_version");
    fs::write(&legacy_metadata, toml::to_string(&value).unwrap()).unwrap();
    assert!(matches!(
        rustgoc::request_registration(&mut legacy, &legacy_path, EnrollmentPurpose::Enroll).await,
        Err(EnrollmentError::Rejected(
            EnrollmentErrorCode::PendingApproval
        ))
    ));
    let pending = PendingEnrollment::load(&legacy_path).unwrap();
    store.review_approval(pending.request_id(), true).unwrap();
    rustgoc::request_registration(&mut legacy, &legacy_path, EnrollmentPurpose::Enroll)
        .await
        .unwrap();
    assert_eq!(legacy.client.name, "Legacy.Pending");

    let cli_dir = dir.path().join("cli");
    fs::create_dir(&cli_dir).unwrap();
    let cli_path = cli_dir.join(if cfg!(windows) {
        "rustgoc.exe"
    } else {
        "rustgoc"
    });
    let source = assert_cmd::cargo::cargo_bin("rustgoc");
    if fs::hard_link(&source, &cli_path).is_err() {
        fs::copy(source, &cli_path).unwrap();
    }
    fs::write(
        cli_dir.join("client.toml"),
        config_text("Auto.Node", &address, &cert_path),
    )
    .unwrap();
    let mut child = Child(
        std::process::Command::new(&cli_path)
            .current_dir(dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let request = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "CLI exited before approval"
            );
            if let Some(request) = store
                .pending_approvals()
                .unwrap()
                .into_iter()
                .find(|r| r.display_name == "Auto.Node")
            {
                break request;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(store.client_by_display_id("Auto.Node").unwrap().is_none());
    store.review_approval(&request.request_id, true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !cli_dir.join("device.key").exists()
            || cli_dir.join("client.enrollment-pending.toml").exists()
        {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "CLI exited while applying approval"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let saved = rustgo_config::load_client(&cli_dir.join("client.toml")).unwrap();
            if saved
                .client
                .profile
                .as_ref()
                .is_some_and(|p| p.uid.is_some() && p.local_ip.as_deref() == Some("127.0.0.1"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(child.0.try_wait().unwrap().is_none());
    drop(child);
    shutdown.cancel();
    task.await.unwrap().unwrap();
}

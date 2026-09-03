#![forbid(unsafe_code)]

use rustgoc::{ClientApp, ClientStatus};
use rustgo_config::{
    AuthorizedClient, ClientConfig, ClientSection, Limits, ServerConfig, ServerSection,
    TelemetryConfig, TunnelConfig, TunnelProtocol,
};
use rustgo_crypto::{DeviceKeypair, generate_key_file};
use rustgoc_gui::state::connection::{ConnectionState, ConnectionViewModel};
use rustgoc_gui::state::tunnels::TunnelRow;
use rustgos::ServerApp;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

const SERVER_NAME: &str = "gui-state.test";
type AnyError = Box<dyn Error + Send + Sync>;

struct TestPki {
    _directory: TempDir,
    ca_file: PathBuf,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl TestPki {
    fn generate() -> Result<Self, AnyError> {
        let directory = tempfile::tempdir()?;
        let ca_file = directory.path().join("ca.pem");
        let certificate_file = directory.path().join("server.pem");
        let private_key_file = directory.path().join("server.key");
        let (ca_pem, issuer) = certificate_authority()?;
        let (server_pem, server_key_pem) = server_certificate(&issuer)?;
        fs::write(&ca_file, ca_pem)?;
        fs::write(&certificate_file, server_pem)?;
        fs::write(&private_key_file, server_key_pem)?;
        Ok(Self {
            _directory: directory,
            ca_file,
            certificate_file,
            private_key_file,
        })
    }
}

fn certificate_authority() -> Result<(String, Issuer<'static, KeyPair>), AnyError> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GUI State Test CA");
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

struct ClientKeys {
    _directory: TempDir,
    keypair: DeviceKeypair,
}

fn generate_client_keys() -> Result<ClientKeys, AnyError> {
    let directory = tempfile::tempdir()?;
    generate_key_file(directory.path())?;
    let keypair = DeviceKeypair::load_private_file(&directory.path().join("device.key"))?;
    Ok(ClientKeys {
        _directory: directory,
        keypair,
    })
}

fn client_config(pki: &TestPki, keys: &ClientKeys, server_addr: String) -> ClientConfig {
    ClientConfig {
        client: ClientSection {
            name: "gui-test-client".to_owned(),
            server_addr,
            server_name: SERVER_NAME.to_owned(),
            certificate_authority_file: pki.ca_file.clone(),
            private_key_file: keys._directory.path().join("device.key"),
            heartbeat_interval_secs: 1,
        },
        p2p: None,
        tunnels: vec![
            TunnelConfig {
                name: "tcp-tunnel".to_owned(),
                protocol: TunnelProtocol::Tcp,
                local_addr: "127.0.0.1:8080".to_owned(),
                remote_port: 9001,
            },
            TunnelConfig {
                name: "udp-tunnel".to_owned(),
                protocol: TunnelProtocol::Udp,
                local_addr: "127.0.0.1:8081".to_owned(),
                remote_port: 9002,
            },
        ],
        exports: Vec::new(),
        forwards: Vec::new(),
        telemetry: Some(TelemetryConfig::default()),
    }
}

fn server_config(pki: &TestPki, key: &DeviceKeypair) -> ServerConfig {
    ServerConfig {
        server: ServerSection {
            bind_addr: "127.0.0.1:0".to_owned(),
            udp_bind_ip: None,
            p2p_observation_bind: None,
            p2p_observation_alternate_bind: None,
            certificate_file: pki.certificate_file.clone(),
            private_key_file: pki.private_key_file.clone(),
            heartbeat_timeout_secs: 5,
        },
        limits: Limits {
            max_clients: 2,
            max_tunnels_per_client: 4,
            max_tcp_connections_per_tunnel: 4,
            max_udp_sessions_per_tunnel: 4,
            max_udp_payload_bytes: 65_507,
        },
        clients: vec![AuthorizedClient {
            name: "gui-test-client".to_owned(),
            public_key: key.public_key().to_string(),
            enabled: true,
        }],
        web: None,
    }
}

async fn wait_for_status<F>(
    status: &mut watch::Receiver<ClientStatus>,
    predicate: F,
    timeout: Duration,
) -> Result<(), AnyError>
where
    F: Fn(&ClientStatus) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if predicate(&status.borrow_and_update()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for client status".into());
        }
        if status.changed().await.is_err() {
            return Err("client status channel closed".into());
        }
    }
}

#[tokio::test]
async fn test_gui_state_lifecycle() -> Result<(), AnyError> {
    let pki = TestPki::generate()?;
    let keys = generate_client_keys()?;

    let server_app = ServerApp::bind(server_config(&pki, &keys.keypair)).await?;
    let server_addr = server_app.local_addr()?.to_string();
    let server_shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server_app.run_until(server_shutdown.clone()));

    let config = client_config(&pki, &keys, server_addr);
    let app = ClientApp::from_config(config)?;

    let mut status_rx = app.subscribe();
    let mut vm = ConnectionViewModel::new(app.subscribe());

    vm.mark_connecting();
    assert_eq!(vm.current(), &ConnectionState::Connecting);

    let shutdown = CancellationToken::new();
    let app_task = tokio::spawn(app.run_until(shutdown.clone()));

    wait_for_status(
        &mut status_rx,
        |status| status.active().is_some(),
        Duration::from_secs(5),
    )
    .await?;

    let state = vm.update();
    match state {
        ConnectionState::Connected { generation } => {
            assert!(generation > 0);
        }
        _ => return Err(format!("Expected Connected state, got {:?}", state).into()),
    }

    if let Some(active) = status_rx.borrow().active() {
        let tunnels = active.registered_tunnels();
        assert_eq!(tunnels.len(), 2);

        let rows: Vec<TunnelRow> = tunnels.iter().map(TunnelRow::from_registered).collect();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.name == "tcp-tunnel"));
        assert!(rows.iter().any(|r| r.name == "udp-tunnel"));
    } else {
        return Err("Expected active status with tunnels".into());
    }

    shutdown.cancel();
    server_shutdown.cancel();

    let app_result = app_task.await?;
    if let Err(e) = app_result {
        return Err(format!("app task failed: {}", e).into());
    }

    server_task.await??;

    Ok(())
}

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_transport::{
    BindingError, ChannelBinding, ChannelBindingStore, ChannelKind, TlsClient, TlsError, TlsServer,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const SERVER_NAME: &str = "tunnel.example.test";

struct TestPki {
    _directory: TempDir,
    ca_file: PathBuf,
    unknown_ca_file: PathBuf,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl TestPki {
    fn generate() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let ca_file = directory.path().join("ca.pem");
        let unknown_ca_file = directory.path().join("unknown-ca.pem");
        let certificate_file = directory.path().join("server.pem");
        let private_key_file = directory.path().join("server.key");

        let (ca_pem, issuer) = certificate_authority("Rustgo test CA")?;
        let (server_pem, server_key_pem) = server_certificate(SERVER_NAME, &issuer)?;
        let (unknown_ca_pem, _) = certificate_authority("Unknown test CA")?;

        fs::write(&ca_file, ca_pem)?;
        fs::write(&unknown_ca_file, unknown_ca_pem)?;
        fs::write(&certificate_file, server_pem)?;
        fs::write(&private_key_file, server_key_pem)?;

        Ok(Self {
            _directory: directory,
            ca_file,
            unknown_ca_file,
            certificate_file,
            private_key_file,
        })
    }
}

fn certificate_authority(
    common_name: &str,
) -> Result<(String, Issuer<'static, KeyPair>), Box<dyn Error>> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    let certificate = parameters.self_signed(&key)?;
    Ok((certificate.pem(), Issuer::new(parameters, key)))
}

fn server_certificate(
    server_name: &str,
    issuer: &Issuer<'static, KeyPair>,
) -> Result<(String, String), Box<dyn Error>> {
    let mut parameters = CertificateParams::new(vec![server_name.to_owned()])?;
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, server_name);
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let certificate = parameters.signed_by(&key, issuer)?;
    Ok((certificate.pem(), key.serialize_pem()))
}

async fn server_once(
    server: TlsServer,
) -> tokio::task::JoinHandle<Result<ProtocolVersion, TlsError>> {
    tokio::spawn(async move {
        let (socket, _) = server.accept_tcp().await?;
        let stream = server.handshake(socket).await?;
        stream
            .get_ref()
            .1
            .protocol_version()
            .ok_or(TlsError::HandshakeFailed)
    })
}

async fn bind_test_server(pki: &TestPki) -> Result<TlsServer, TlsError> {
    TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await
}

#[tokio::test]
async fn valid_name_and_ca_negotiate_tls_1_3() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let server = bind_test_server(&pki).await?;
    let address = server.local_addr()?;
    let server_task = server_once(server).await;

    let client = TlsClient::from_ca_file(&pki.ca_file, SERVER_NAME)?;
    let stream = client.connect(address).await?;

    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(server_task.await??, ProtocolVersion::TLSv1_3);
    Ok(())
}

#[tokio::test]
async fn wrong_server_name_is_rejected() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let server = bind_test_server(&pki).await?;
    let address = server.local_addr()?;
    let server_task = server_once(server).await;

    let client = TlsClient::from_ca_file(&pki.ca_file, "wrong.example.test")?;
    assert!(client.connect(address).await.is_err());
    assert!(server_task.await?.is_err());
    Ok(())
}

#[tokio::test]
async fn unknown_certificate_authority_is_rejected() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let server = bind_test_server(&pki).await?;
    let address = server.local_addr()?;
    let server_task = server_once(server).await;

    let client = TlsClient::from_ca_file(&pki.unknown_ca_file, SERVER_NAME)?;
    assert!(client.connect(address).await.is_err());
    assert!(server_task.await?.is_err());
    Ok(())
}

#[tokio::test]
async fn tls_1_2_only_client_is_rejected() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let server = bind_test_server(&pki).await?;
    let address = server.local_addr()?;
    let server_task = server_once(server).await;

    let roots = root_store(&pki.ca_file)?;
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let socket = TcpStream::connect(address).await?;
    let name = ServerName::try_from(SERVER_NAME)?.to_owned();

    assert!(connector.connect(name, socket).await.is_err());
    assert!(server_task.await?.is_err());
    Ok(())
}

#[tokio::test]
async fn plaintext_input_is_rejected() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let server = bind_test_server(&pki).await?;
    let address = server.local_addr()?;
    let server_task = server_once(server).await;

    let mut socket = TcpStream::connect(address).await?;
    socket
        .write_all(b"plaintext is not a transport mode")
        .await?;
    socket.shutdown().await?;

    assert!(server_task.await?.is_err());
    Ok(())
}

#[tokio::test]
async fn malformed_tls_material_fails_before_socket_binding_without_leaking_key_contents()
-> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let address = occupied.local_addr()?;
    let malformed_certificate = pki._directory.path().join("malformed-cert.pem");
    let malformed_key = pki._directory.path().join("malformed-key.pem");
    const SECRET_SENTINEL: &str = "PRIVATE-KEY-MATERIAL-MUST-NOT-LEAK";
    fs::write(&malformed_certificate, "not a certificate")?;
    fs::write(&malformed_key, SECRET_SENTINEL)?;

    let certificate_error = TlsServer::bind(address, &malformed_certificate, &pki.private_key_file)
        .await
        .expect_err("certificate parsing must happen before binding");
    assert!(matches!(
        certificate_error,
        TlsError::InvalidCertificateFile { .. }
    ));

    let key_error = TlsServer::bind(address, &pki.certificate_file, &malformed_key)
        .await
        .expect_err("private-key parsing must happen before binding");
    assert!(matches!(key_error, TlsError::InvalidPrivateKeyFile { .. }));
    assert!(!key_error.to_string().contains(SECRET_SENTINEL));
    assert!(!format!("{key_error:?}").contains(SECRET_SENTINEL));
    Ok(())
}

fn root_store(path: &Path) -> Result<RootCertStore, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let certificates = rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    Ok(roots)
}

fn session_id(value: u8) -> Vec<u8> {
    vec![value; 32]
}

#[test]
fn issued_binding_token_is_bounded_random_and_single_use() -> Result<(), Box<dyn Error>> {
    let session = session_id(7);
    let kind = ChannelKind::Tcp {
        tunnel_id: 3,
        connection_id: 41,
    };
    let mut bindings =
        ChannelBindingStore::new("client-a", &session, 4, std::time::Duration::from_secs(30))?;

    let token = bindings.issue(kind)?;
    let other_token = bindings.issue(ChannelKind::Tcp {
        tunnel_id: 3,
        connection_id: 42,
    })?;
    assert_eq!(token.as_slice().len(), 32);
    assert!(token.as_slice().len() <= rustgo_protocol::MAX_BINDING_TOKEN_BYTES);
    assert_ne!(token.as_slice(), other_token.as_slice());

    assert_eq!(
        bindings.redeem("client-a", &session, kind, token.as_slice())?,
        ChannelBinding {
            client_id: "client-a".to_owned(),
            session_id: session.clone(),
            channel_kind: kind,
        }
    );
    assert_eq!(
        bindings.redeem("client-a", &session, kind, token.as_slice()),
        Err(BindingError::Rejected)
    );
    assert_eq!(
        bindings.redeem("client-a", &session, kind, &[0x55; 32]),
        Err(BindingError::Rejected)
    );
    Ok(())
}

#[test]
fn binding_token_rejects_wrong_identity_session_kind_and_target() -> Result<(), Box<dyn Error>> {
    let session = session_id(9);
    let tcp = ChannelKind::Tcp {
        tunnel_id: 5,
        connection_id: 99,
    };
    let udp = ChannelKind::Udp {
        tunnel_id: 5,
        channel_id: 99,
    };
    let mut bindings =
        ChannelBindingStore::new("client-a", &session, 8, std::time::Duration::from_secs(30))?;

    let wrong_client = bindings.issue(tcp)?;
    assert_eq!(
        bindings.redeem("client-b", &session, tcp, wrong_client.as_slice()),
        Err(BindingError::Rejected)
    );
    assert_eq!(
        bindings.redeem("client-a", &session, tcp, wrong_client.as_slice()),
        Err(BindingError::Rejected),
        "a known token is consumed even when its presentation is invalid"
    );

    let wrong_session = bindings.issue(tcp)?;
    assert_eq!(
        bindings.redeem("client-a", &session_id(10), tcp, wrong_session.as_slice()),
        Err(BindingError::Rejected)
    );

    let wrong_kind = bindings.issue(tcp)?;
    assert_eq!(
        bindings.redeem("client-a", &session, udp, wrong_kind.as_slice()),
        Err(BindingError::Rejected)
    );

    let wrong_target = bindings.issue(tcp)?;
    assert_eq!(
        bindings.redeem(
            "client-a",
            &session,
            ChannelKind::Tcp {
                tunnel_id: 5,
                connection_id: 100,
            },
            wrong_target.as_slice(),
        ),
        Err(BindingError::Rejected)
    );
    Ok(())
}

#[tokio::test]
async fn expired_tokens_fail_and_expired_entries_release_bounded_capacity()
-> Result<(), Box<dyn Error>> {
    let session = session_id(11);
    let kind = ChannelKind::Udp {
        tunnel_id: 8,
        channel_id: 13,
    };
    let mut bindings = ChannelBindingStore::new(
        "client-a",
        &session,
        1,
        std::time::Duration::from_millis(10),
    )?;
    let expired = bindings.issue(kind)?;
    assert_eq!(bindings.issue(kind), Err(BindingError::CapacityReached));

    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    assert_eq!(
        bindings.redeem("client-a", &session, kind, expired.as_slice()),
        Err(BindingError::Rejected)
    );
    assert!(bindings.issue(kind).is_ok());
    Ok(())
}

#[test]
fn binding_store_rejects_unbounded_or_empty_owner_values() {
    assert!(matches!(
        ChannelBindingStore::new("", &[1], 1, std::time::Duration::from_secs(1)),
        Err(BindingError::InvalidConfiguration)
    ));
    assert!(matches!(
        ChannelBindingStore::new("client-a", &[], 1, std::time::Duration::from_secs(1)),
        Err(BindingError::InvalidConfiguration)
    ));
    assert!(matches!(
        ChannelBindingStore::new(
            "client-a",
            &[1; rustgo_protocol::MAX_SESSION_ID_BYTES + 1],
            1,
            std::time::Duration::from_secs(1),
        ),
        Err(BindingError::InvalidConfiguration)
    ));
}

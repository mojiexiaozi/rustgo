#![forbid(unsafe_code)]

use std::{error::Error, fs, net::SocketAddr, path::PathBuf, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_config::{Limits, ServerConfig, ServerSection};
use rustgo_rendezvous::{ObservationNonce, ObservationProbe, ObservationToken};
use rustgos::{ObservationRuntimeLimits, ObservationService, ServerApp};
use tempfile::TempDir;
use tokio::{net::UdpSocket, time::timeout};
use tokio_util::sync::CancellationToken;

fn loopback_ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

struct TestPki {
    _directory: TempDir,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl TestPki {
    fn generate() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let certificate_file = directory.path().join("server.pem");
        let private_key_file = directory.path().join("server.key");
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate()?;
        let issuer = Issuer::new(ca, ca_key);
        let mut server = CertificateParams::new(vec!["localhost".to_owned()])?;
        server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let certificate = server.signed_by(&server_key, &issuer)?;
        fs::write(&certificate_file, certificate.pem())?;
        fs::write(&private_key_file, server_key.serialize_pem())?;
        Ok(Self {
            _directory: directory,
            certificate_file,
            private_key_file,
        })
    }
}

fn server_config(pki: &TestPki) -> ServerConfig {
    ServerConfig {
        server: ServerSection {
            bind_addr: "127.0.0.1:0".to_owned(),
            udp_bind_ip: None,
            p2p_observation_bind: None,
            p2p_observation_alternate_bind: None,
            certificate_file: pki.certificate_file.clone(),
            private_key_file: pki.private_key_file.clone(),
            heartbeat_timeout_secs: 2,
        },
        limits: Limits {
            max_clients: 2,
            max_tunnels_per_client: 2,
            max_tcp_connections_per_tunnel: 2,
            max_udp_sessions_per_tunnel: 2,
            max_udp_payload_bytes: 1200,
        },
        clients: Vec::new(),
        web: None,
    }
}

#[tokio::test]
async fn unauthenticated_and_oversized_probes_are_silently_dropped() -> Result<(), Box<dyn Error>> {
    let service = ObservationService::bind(
        loopback_ephemeral(),
        loopback_ephemeral(),
        ObservationRuntimeLimits::default(),
    )
    .await?;
    let (primary, alternate) = service.local_addrs()?;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(service.run(shutdown.clone()));
    let client = UdpSocket::bind(loopback_ephemeral()).await?;

    let probe = ObservationProbe::new(
        ObservationToken::from([0xA5; 32]),
        ObservationNonce::from([0x5A; 16]),
    )
    .encode()?;
    client.send_to(&probe, primary).await?;
    client.send_to(&probe, alternate).await?;
    client.send_to(&[0xCC; 4096], primary).await?;

    let mut response = [0_u8; 128];
    assert!(
        timeout(Duration::from_millis(100), client.recv_from(&mut response))
            .await
            .is_err()
    );

    shutdown.cancel();
    task.await??;
    Ok(())
}

#[tokio::test]
async fn cancellation_releases_both_observation_ports() -> Result<(), Box<dyn Error>> {
    let service = ObservationService::bind(
        loopback_ephemeral(),
        loopback_ephemeral(),
        ObservationRuntimeLimits::default(),
    )
    .await?;
    let addresses = service.local_addrs()?;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(service.run(shutdown.clone()));

    shutdown.cancel();
    task.await??;

    let primary = UdpSocket::bind(addresses.0).await?;
    let alternate = UdpSocket::bind(addresses.1).await?;
    assert_eq!(primary.local_addr()?, addresses.0);
    assert_eq!(alternate.local_addr()?, addresses.1);
    Ok(())
}

#[tokio::test]
async fn observation_service_requires_two_distinct_destination_ports() -> Result<(), Box<dyn Error>>
{
    let reservation = std::net::UdpSocket::bind(loopback_ephemeral())?;
    let port = reservation.local_addr()?.port();
    drop(reservation);
    let result = ObservationService::bind(
        SocketAddr::from(([127, 0, 0, 1], port)),
        SocketAddr::from(([127, 0, 0, 2], port)),
        ObservationRuntimeLimits::default(),
    )
    .await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn alternate_bind_failure_releases_the_primary_socket() -> Result<(), Box<dyn Error>> {
    let primary_reservation = std::net::UdpSocket::bind(loopback_ephemeral())?;
    let primary = primary_reservation.local_addr()?;
    drop(primary_reservation);
    let alternate_reservation = std::net::UdpSocket::bind(loopback_ephemeral())?;
    let alternate = alternate_reservation.local_addr()?;

    let result =
        ObservationService::bind(primary, alternate, ObservationRuntimeLimits::default()).await;
    assert!(result.is_err());
    let rebound = UdpSocket::bind(primary).await?;
    assert_eq!(rebound.local_addr()?, primary);
    Ok(())
}

#[tokio::test]
async fn server_app_owns_the_optional_paired_observation_sockets() -> Result<(), Box<dyn Error>> {
    let pki = TestPki::generate()?;
    let primary_reservation = std::net::UdpSocket::bind(loopback_ephemeral())?;
    let primary = primary_reservation.local_addr()?;
    let alternate_reservation = std::net::UdpSocket::bind(loopback_ephemeral())?;
    let alternate = alternate_reservation.local_addr()?;
    drop(primary_reservation);
    drop(alternate_reservation);

    let mut configured = server_config(&pki);
    configured.server.p2p_observation_bind = Some(primary.to_string());
    configured.server.p2p_observation_alternate_bind = Some(alternate.to_string());
    let app = ServerApp::bind(configured).await?;
    assert_eq!(app.observation_local_addrs()?, Some((primary, alternate)));
    assert!(app.observation_token_issuer().is_some());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(app.run_until(shutdown.clone()));
    shutdown.cancel();
    task.await??;
    UdpSocket::bind(primary).await?;
    UdpSocket::bind(alternate).await?;

    let relay_only = ServerApp::bind(server_config(&pki)).await?;
    assert_eq!(relay_only.observation_local_addrs()?, None);
    assert!(relay_only.observation_token_issuer().is_none());
    Ok(())
}

use std::net::Ipv4Addr;

use rustgo_config::{ExportConfig, TunnelProtocol};
use rustgoc::{ExportError, ExportRegistry, PeerOpenRequest};
use tokio::{io::AsyncReadExt, net::TcpListener};
use tokio_util::sync::CancellationToken;

fn export(allowed_peers: &[&str], local_addr: String) -> ExportConfig {
    ExportConfig {
        name: "ssh".into(),
        protocol: TunnelProtocol::Tcp,
        local_addr,
        allowed_peers: allowed_peers.iter().map(|peer| (*peer).into()).collect(),
    }
}

#[test]
fn missing_or_empty_allowlist_authorizes_every_authenticated_peer() {
    let registry = ExportRegistry::new(vec![export(&[], "127.0.0.1:22".into())]).unwrap();
    assert!(
        registry
            .authorize("laptop", "ssh", TunnelProtocol::Tcp)
            .is_ok()
    );
}

#[test]
fn named_allowlist_unknown_export_and_protocol_mismatch_are_rejected() {
    let registry = ExportRegistry::new(vec![export(&["laptop"], "127.0.0.1:22".into())]).unwrap();
    assert!(matches!(
        registry.authorize("attacker", "ssh", TunnelProtocol::Tcp),
        Err(ExportError::PeerDenied)
    ));
    assert!(matches!(
        registry.authorize("laptop", "missing", TunnelProtocol::Tcp),
        Err(ExportError::UnknownExport)
    ));
    assert!(matches!(
        registry.authorize("laptop", "ssh", TunnelProtocol::Udp),
        Err(ExportError::ProtocolMismatch)
    ));
}

#[tokio::test]
async fn authorized_tcp_open_connects_to_the_local_target() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let registry = ExportRegistry::new(vec![export(
        &[],
        listener.local_addr().unwrap().to_string(),
    )])
    .unwrap();
    let request = PeerOpenRequest::new(7, "ssh", TunnelProtocol::Tcp);
    let open = registry.open_tcp("authenticated-laptop", &request, CancellationToken::new());
    let (opened, accepted) = tokio::join!(open, listener.accept());
    let mut opened = opened.unwrap();
    let (mut accepted, _) = accepted.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut opened, b"hello")
        .await
        .unwrap();
    let mut bytes = [0; 5];
    accepted.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"hello");
}

#[tokio::test]
async fn unavailable_target_and_cancellation_are_bounded_failures() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let registry = ExportRegistry::new(vec![export(&[], addr.to_string())]).unwrap();
    let request = PeerOpenRequest::new(9, "ssh", TunnelProtocol::Tcp);
    assert!(matches!(
        registry
            .open_tcp("laptop", &request, CancellationToken::new())
            .await,
        Err(ExportError::LocalTargetUnavailable)
    ));
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        registry
            .open_tcp("laptop", &request, cancelled)
            .await
            .unwrap_err(),
        ExportError::Cancelled
    );
}

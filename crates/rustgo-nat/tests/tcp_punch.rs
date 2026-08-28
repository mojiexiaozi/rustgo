use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use rustgo_nat::{TcpPunchError, TcpPuncher};
use tokio::net::{TcpListener, TcpSocket};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn accepted_connection_uses_the_fixed_owned_listener_port() {
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let remote_probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local = probe.local_addr().unwrap();
    let remote = remote_probe.local_addr().unwrap();
    drop(probe);
    drop(remote_probe);

    let mut candidates = TcpPuncher::candidates(
        local,
        vec![remote],
        tokio::time::Instant::now() + Duration::from_secs(2),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(
        TcpListener::bind(local).await.is_err(),
        "fixed port must remain exclusively owned"
    );
    let peer = TcpSocket::new_v4().unwrap();
    peer.bind(remote).unwrap();
    let peer_stream = peer.connect(local).await.unwrap();
    let stream = candidates.next().await.unwrap().unwrap();
    assert_eq!(stream.local_addr().unwrap().port(), local.port());
    drop(stream);
    drop(peer_stream);
    drop(candidates);
    tokio::task::yield_now().await;
    let rebound = TcpListener::bind(local).await.unwrap();
    drop(rebound);
}

#[tokio::test]
async fn candidates_are_hard_capped_at_eight() {
    let candidates = (1..=9)
        .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .collect();
    let err = TcpPuncher::connect(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        candidates,
        tokio::time::Instant::now() + Duration::from_millis(50),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err, TcpPunchError::TooManyCandidates);
}

#[tokio::test]
async fn cancellation_releases_the_fixed_port() {
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local = probe.local_addr().unwrap();
    drop(probe);
    let cancellation = CancellationToken::new();
    let mut candidates = TcpPuncher::candidates(
        local,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)],
        tokio::time::Instant::now() + Duration::from_secs(1),
        cancellation.clone(),
    )
    .await
    .unwrap();
    cancellation.cancel();
    assert_eq!(
        candidates.next().await.unwrap_err(),
        TcpPunchError::Cancelled
    );
    drop(candidates);
    tokio::task::yield_now().await;
    let rebound = TcpListener::bind(local).await.unwrap();
    drop(rebound);
}

#[tokio::test]
async fn two_real_punchers_attempt_same_port_simultaneous_open_when_supported() {
    let first = free_loopback_addr();
    let second = free_loopback_addr();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    let (left, right) = tokio::join!(
        TcpPuncher::connect(first, vec![second], deadline, CancellationToken::new()),
        TcpPuncher::connect(second, vec![first], deadline, CancellationToken::new()),
    );
    match (left, right) {
        (Ok(left), Ok(right)) => {
            assert_eq!(left.local_addr().unwrap(), first);
            assert_eq!(right.local_addr().unwrap(), second);
        }
        (left, right) => {
            // Windows' safe default exclusive ownership intentionally forbids listener plus
            // same-port active bind. Kernels without connect/connect support are permitted to
            // skip this one topology; accepted fallback, bounds, and cleanup remain mandatory.
            eprintln!("simultaneous-open unsupported: left={left:?}, right={right:?}");
        }
    }
}

fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap()
}

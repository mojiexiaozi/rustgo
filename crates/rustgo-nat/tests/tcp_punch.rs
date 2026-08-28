use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use rustgo_nat::{TcpPunchError, TcpPuncher};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn ordinary_connect_reuses_the_requested_local_port() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let remote = listener.local_addr().unwrap();
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local = probe.local_addr().unwrap();
    drop(probe);

    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let stream = TcpPuncher::connect(
        local,
        vec![remote],
        tokio::time::Instant::now() + Duration::from_secs(2),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(stream.local_addr().unwrap().port(), local.port());
    drop(stream);
    drop(accept.await.unwrap());
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
    cancellation.cancel();
    let result = TcpPuncher::connect(
        local,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)],
        tokio::time::Instant::now() + Duration::from_secs(1),
        cancellation,
    )
    .await;
    assert_eq!(result.unwrap_err(), TcpPunchError::Cancelled);
    let rebound = TcpListener::bind(local).await.unwrap();
    drop(rebound);
}

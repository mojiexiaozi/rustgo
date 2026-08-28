use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

#[cfg(windows)]
use rustgo_nat::TcpPunchMode;
use rustgo_nat::{TcpPunchError, TcpPuncher};
#[cfg(windows)]
use socket2::{Domain, Protocol, Socket, Type};
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
    #[cfg(windows)]
    {
        let hostile = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        hostile.set_reuse_address(true).unwrap();
        assert!(
            hostile.bind(&local.into()).is_err(),
            "a competing Windows SO_REUSEADDR binder must not steal the fixed port"
        );
    }
    let peer = TcpSocket::new_v4().unwrap();
    peer.bind(remote).unwrap();
    let peer_stream = peer.connect(local).await.unwrap();
    let stream = candidates.next().await.unwrap().unwrap();
    assert_eq!(stream.local_addr().unwrap().port(), local.port());
    drop(stream);
    drop(peer_stream);
    candidates.close().await;
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
    candidates.close().await;
    let rebound = TcpListener::bind(local).await.unwrap();
    drop(rebound);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_two_real_punchers_complete_fixed_port_simultaneous_open() {
    let first = free_loopback_addr();
    let second = free_loopback_addr();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    let (left, right) = tokio::join!(
        TcpPuncher::connect(first, vec![second], deadline, CancellationToken::new()),
        TcpPuncher::connect(second, vec![first], deadline, CancellationToken::new()),
    );
    let left = left.expect("Linux fixed-port simultaneous-open capability regressed");
    let right = right.expect("Linux fixed-port simultaneous-open capability regressed");
    assert_eq!(left.local_addr().unwrap(), first);
    assert_eq!(right.local_addr().unwrap(), second);
}

#[cfg(windows)]
#[tokio::test]
async fn windows_exclusive_listener_reports_the_explicit_simultaneous_open_fallback() {
    let first = free_loopback_addr();
    let second = free_loopback_addr();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    let (left, right) = tokio::join!(
        TcpPuncher::connect(first, vec![second], deadline, CancellationToken::new()),
        TcpPuncher::connect(second, vec![first], deadline, CancellationToken::new()),
    );
    assert!(matches!(left, Err(TcpPunchError::Deadline)));
    assert!(matches!(right, Err(TcpPunchError::Deadline)));
    assert!(TcpListener::bind(first).await.is_ok());
    assert!(TcpListener::bind(second).await.is_ok());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let mut responder = TcpPuncher::candidates_with_mode(
        second,
        vec![first],
        deadline,
        CancellationToken::new(),
        TcpPunchMode::ListenerOnly,
    )
    .await
    .unwrap();
    let mut initiator = TcpPuncher::candidates_with_mode(
        first,
        vec![second],
        deadline,
        CancellationToken::new(),
        TcpPunchMode::OutboundOnly,
    )
    .await
    .unwrap();
    let (outbound, accepted) = tokio::join!(initiator.next(), responder.next());
    assert_eq!(outbound.unwrap().unwrap().local_addr().unwrap(), first);
    assert_eq!(accepted.unwrap().unwrap().local_addr().unwrap(), second);
    initiator.close().await;
    responder.close().await;
}

fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap()
}

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use rustgo_config::{ForwardConfig, TunnelProtocol};
use rustgoc::{
    BoxPeerStream, ForwardConnector, ForwardError, ForwardRuntime, ForwardRuntimeOptions,
    PeerDatagramSession,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Connector {
    protocols: HashMap<String, TunnelProtocol>,
    tcp_calls: Mutex<Vec<String>>,
    udp_sessions: AtomicUsize,
    hold_tcp: AtomicBool,
    tcp_peers: Mutex<Vec<tokio::io::DuplexStream>>,
    hang_protocol: AtomicBool,
}

struct TestDatagram {
    loopback: tokio::sync::mpsc::Sender<Vec<u8>>,
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl PeerDatagramSession for TestDatagram {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.loopback
                .send(payload.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        })
    }
    fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            self.inbound
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "closed"))
        })
    }
}

use std::future::Future;

impl ForwardConnector for Connector {
    fn protocol<'a>(
        &'a self,
        _peer: &'a str,
        export: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<TunnelProtocol>> + Send + 'a>> {
        Box::pin(async move {
            if self.hang_protocol.load(Ordering::SeqCst) {
                std::future::pending().await
            }
            self.protocols
                .get(export)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        })
    }
    fn open_tcp<'a>(
        &'a self,
        peer: &'a str,
        export: &'a str,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxPeerStream>> + Send + 'a>> {
        Box::pin(async move {
            self.tcp_calls
                .lock()
                .unwrap()
                .push(format!("{peer}/{export}"));
            if export == "broken" {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "broken"));
            }
            let (left, mut right) = tokio::io::duplex(4096);
            if self.hold_tcp.load(Ordering::SeqCst) {
                self.tcp_peers.lock().unwrap().push(right);
                return Ok(Box::new(left) as BoxPeerStream);
            }
            tokio::spawn(async move {
                let _ =
                    tokio::io::copy_bidirectional(&mut right, &mut tokio::io::duplex(1).0).await;
            });
            Ok(Box::new(left) as BoxPeerStream)
        })
    }
    fn open_udp<'a>(
        &'a self,
        _peer: &'a str,
        _export: &'a str,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn PeerDatagramSession>>> + Send + 'a>> {
        Box::pin(async move {
            self.udp_sessions.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            Ok(Box::new(TestDatagram {
                loopback: tx,
                inbound: rx,
            }) as Box<dyn PeerDatagramSession>)
        })
    }
}

fn forward(name: &str, export: &str) -> ForwardConfig {
    ForwardConfig {
        name: name.into(),
        peer: "provider".into(),
        export: export.into(),
        listen_addr: "127.0.0.1:0".into(),
    }
}

#[tokio::test]
async fn tcp_listener_opens_one_peer_stream_per_local_connection() {
    let connector = Arc::new(Connector {
        protocols: HashMap::from([("ssh".into(), TunnelProtocol::Tcp)]),
        ..Default::default()
    });
    let shutdown = CancellationToken::new();
    let runtime = ForwardRuntime::start(
        vec![forward("ssh-local", "ssh")],
        connector.clone(),
        shutdown.clone(),
    )
    .await
    .unwrap();
    let addr = runtime.local_addr("ssh-local").unwrap();
    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut second = TcpStream::connect(addr).await.unwrap();
    first.write_all(b"a").await.unwrap();
    second.write_all(b"b").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if connector.tcp_calls.lock().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shutdown.cancel();
    runtime.shutdown().await;
}

#[tokio::test]
async fn one_failed_forward_does_not_terminate_another() {
    let connector = Arc::new(Connector {
        protocols: HashMap::from([
            ("broken".into(), TunnelProtocol::Tcp),
            ("good".into(), TunnelProtocol::Tcp),
        ]),
        ..Default::default()
    });
    let shutdown = CancellationToken::new();
    let runtime = ForwardRuntime::start(
        vec![forward("bad", "broken"), forward("good", "good")],
        connector.clone(),
        shutdown.clone(),
    )
    .await
    .unwrap();
    let _bad = TcpStream::connect(runtime.local_addr("bad").unwrap())
        .await
        .unwrap();
    let _good = TcpStream::connect(runtime.local_addr("good").unwrap())
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert!(
        TcpStream::connect(runtime.local_addr("good").unwrap())
            .await
            .is_ok()
    );
    shutdown.cancel();
    runtime.shutdown().await;
}

#[tokio::test]
async fn cancellation_releases_listener() {
    let connector = Arc::new(Connector {
        protocols: HashMap::from([("ssh".into(), TunnelProtocol::Tcp)]),
        ..Default::default()
    });
    let shutdown = CancellationToken::new();
    let runtime = ForwardRuntime::start(vec![forward("ssh", "ssh")], connector, shutdown.clone())
        .await
        .unwrap();
    let addr = runtime.local_addr("ssh").unwrap();
    shutdown.cancel();
    runtime.shutdown().await;
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn udp_sources_get_isolated_sessions_and_keep_datagram_boundaries() {
    let connector = Arc::new(Connector {
        protocols: HashMap::from([("dns".into(), TunnelProtocol::Udp)]),
        ..Default::default()
    });
    let shutdown = CancellationToken::new();
    let runtime = ForwardRuntime::start(
        vec![forward("dns", "dns")],
        connector.clone(),
        shutdown.clone(),
    )
    .await
    .unwrap();
    let target = runtime.local_addr("dns").unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    first.send_to(b"one", target).await.unwrap();
    second.send_to(b"two-two", target).await.unwrap();
    let mut one = [0_u8; 16];
    let mut two = [0_u8; 16];
    let (one_received, two_received) =
        tokio::join!(first.recv_from(&mut one), second.recv_from(&mut two));
    assert_eq!(&one[..one_received.unwrap().0], b"one");
    assert_eq!(&two[..two_received.unwrap().0], b"two-two");
    assert_eq!(connector.udp_sessions.load(Ordering::SeqCst), 2);
    shutdown.cancel();
    runtime.shutdown().await;
}

fn options() -> ForwardRuntimeOptions {
    ForwardRuntimeOptions {
        protocol_timeout: std::time::Duration::from_millis(50),
        session_open_timeout: std::time::Duration::from_millis(50),
        udp_source_idle_timeout: std::time::Duration::from_millis(40),
        max_tcp_sessions: 1,
        max_udp_source_sessions: 1,
    }
}

#[tokio::test]
async fn idle_udp_source_reclaims_capacity_without_cross_source_delivery() {
    let connector = Arc::new(Connector {
        protocols: HashMap::from([("dns".into(), TunnelProtocol::Udp)]),
        ..Default::default()
    });
    let shutdown = CancellationToken::new();
    let runtime = ForwardRuntime::start_with_options(
        vec![forward("dns", "dns")],
        connector.clone(),
        shutdown.clone(),
        options(),
    )
    .await
    .unwrap();
    let target = runtime.local_addr("dns").unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    first.send_to(b"first", target).await.unwrap();
    let mut payload = [0_u8; 16];
    let received = first.recv_from(&mut payload).await.unwrap().0;
    assert_eq!(&payload[..received], b"first");
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    second.send_to(b"second", target).await.unwrap();
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        second.recv_from(&mut payload),
    )
    .await
    .unwrap()
    .unwrap()
    .0;
    assert_eq!(&payload[..received], b"second");
    assert_eq!(connector.udp_sessions.load(Ordering::SeqCst), 2);
    shutdown.cancel();
    runtime.shutdown().await;
}

#[tokio::test]
async fn tcp_session_cap_rejects_excess_and_recovers_after_release() {
    let connector = Arc::new(Connector {
        protocols: HashMap::from([("ssh".into(), TunnelProtocol::Tcp)]),
        ..Default::default()
    });
    connector.hold_tcp.store(true, Ordering::SeqCst);
    let shutdown = CancellationToken::new();
    let runtime = ForwardRuntime::start_with_options(
        vec![forward("ssh", "ssh")],
        connector.clone(),
        shutdown.clone(),
        options(),
    )
    .await
    .unwrap();
    let addr = runtime.local_addr("ssh").unwrap();
    let first = TcpStream::connect(addr).await.unwrap();
    wait_for_count(&connector.tcp_calls, 1).await;
    let mut excess = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), excess.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(connector.tcp_calls.lock().unwrap().len(), 1);

    drop(first);
    connector.tcp_peers.lock().unwrap().clear();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let _recovered = TcpStream::connect(addr).await.unwrap();
    wait_for_count(&connector.tcp_calls, 2).await;
    shutdown.cancel();
    runtime.shutdown().await;
}

async fn wait_for_count(calls: &Mutex<Vec<String>>, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if calls.lock().unwrap().len() == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn protocol_discovery_honors_timeout_and_generation_cancellation() {
    let connector = Arc::new(Connector {
        protocols: HashMap::from([("ssh".into(), TunnelProtocol::Tcp)]),
        ..Default::default()
    });
    connector.hang_protocol.store(true, Ordering::SeqCst);
    let result = ForwardRuntime::start_with_options(
        vec![forward("ssh", "ssh")],
        connector.clone(),
        CancellationToken::new(),
        options(),
    )
    .await;
    assert!(matches!(result, Err(ForwardError::ProtocolTimeout)));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let result = ForwardRuntime::start_with_options(
        vec![forward("ssh", "ssh")],
        connector,
        cancelled,
        options(),
    )
    .await;
    assert!(matches!(result, Err(ForwardError::Cancelled)));
}

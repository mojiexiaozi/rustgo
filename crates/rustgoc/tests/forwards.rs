use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use rustgo_config::{ForwardConfig, TunnelProtocol};
use rustgoc::{BoxPeerStream, ForwardConnector, ForwardRuntime, PeerDatagramSession};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Connector {
    protocols: HashMap<String, TunnelProtocol>,
    tcp_calls: Mutex<Vec<String>>,
    udp_sessions: AtomicUsize,
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

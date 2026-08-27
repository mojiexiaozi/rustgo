use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use rustgo_e2e::{ManagedChild, ProcessFixture, TestResult, UdpEchoServer, UdpTunnelSpec};

const READY_TIMEOUT: Duration = Duration::from_secs(8);
const DATAGRAM_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UDP_PAYLOAD: usize = 65_507;

fn launch(mut fixture: ProcessFixture) -> TestResult<(ProcessFixture, ManagedChild, ManagedChild)> {
    let server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    if let Err(error) = client.wait_for_line("event=registration_ready", READY_TIMEOUT) {
        return Err(format!("{error}\nserver output:\n{}", server.output()).into());
    }
    Ok((fixture, server, client))
}

fn public_socket() -> TestResult<UdpSocket> {
    public_socket_with_timeout(DATAGRAM_TIMEOUT)
}

fn public_socket_with_timeout(timeout: Duration) -> TestResult<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    Ok(socket)
}

fn expect_no_datagram(socket: &UdpSocket) -> TestResult {
    let mut byte = [0_u8; 1];
    match socket.recv_from(&mut byte) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(())
        }
        Ok((length, source)) => {
            Err(format!("unexpected UDP reply of {length} bytes from {source}").into())
        }
        Err(error) => Err(error.into()),
    }
}

struct ReorderingUdpServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ReorderingUdpServer {
    fn start() -> TestResult<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let mut replies = Vec::new();
            let mut buffer = [0_u8; 2048];
            while !thread_shutdown.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((length, peer)) => {
                        let payload = buffer[..length].to_vec();
                        let reply_socket = match socket.try_clone() {
                            Ok(socket) => socket,
                            Err(_) => break,
                        };
                        replies.push(thread::spawn(move || {
                            if payload.first() == Some(&1) {
                                thread::sleep(Duration::from_millis(150));
                            }
                            let _ = reply_socket.send_to(&payload, peer);
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            for reply in replies {
                let _ = reply.join();
            }
        });
        Ok(Self {
            address,
            shutdown,
            thread: Some(thread),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for ReorderingUdpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(wakeup) = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
            let _ = wakeup.send_to(&[], self.address);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct TaggedUdpServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

struct ConditionalOversizeUdpServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

struct PeriodicReplyUdpServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl PeriodicReplyUdpServer {
    fn start(reply_len: usize) -> TestResult<Self> {
        if reply_len < 2 {
            return Err("periodic UDP replies require two sequence bytes".into());
        }
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 64];
            let mut peer = None;
            let mut sequence = 0_u16;
            let mut next_reply = std::time::Instant::now();
            while !thread_shutdown.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((_, source)) => {
                        peer = Some(source);
                        next_reply = std::time::Instant::now();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
                if let Some(source) = peer
                    && std::time::Instant::now() >= next_reply
                {
                    sequence = sequence.saturating_add(1);
                    let mut response = vec![0x5A; reply_len];
                    response[..2].copy_from_slice(&sequence.to_be_bytes());
                    let _ = socket.send_to(&response, source);
                    next_reply = std::time::Instant::now() + Duration::from_millis(30);
                }
                thread::sleep(Duration::from_millis(1));
            }
        });
        Ok(Self {
            address,
            shutdown,
            thread: Some(thread),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for PeriodicReplyUdpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(wakeup) = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
            let _ = wakeup.send_to(&[], self.address);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl ConditionalOversizeUdpServer {
    fn start() -> TestResult<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 2048];
            while !thread_shutdown.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((length, peer)) => {
                        let response: &[u8] = if buffer[..length] == [0xEE] {
                            &[0xDD; 17]
                        } else {
                            &buffer[..length]
                        };
                        let _ = socket.send_to(response, peer);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            shutdown,
            thread: Some(thread),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for ConditionalOversizeUdpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(wakeup) = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
            let _ = wakeup.send_to(&[], self.address);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl TaggedUdpServer {
    fn start(tag: u8) -> TestResult<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 2048];
            while !thread_shutdown.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((length, peer)) => {
                        let mut response = Vec::with_capacity(length + 1);
                        response.push(tag);
                        response.extend_from_slice(&buffer[..length]);
                        let _ = socket.send_to(&response, peer);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            shutdown,
            thread: Some(thread),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for TaggedUdpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(wakeup) = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
            let _ = wakeup.send_to(&[], self.address);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn assert_datagram_echo(socket: &UdpSocket, public: SocketAddr, payload: &[u8]) -> TestResult {
    let sent = socket.send_to(payload, public)?;
    if sent != payload.len() {
        return Err(format!("sent {sent} of {} UDP bytes", payload.len()).into());
    }
    receive_datagram(socket, public, payload)
}

fn receive_datagram(socket: &UdpSocket, public: SocketAddr, payload: &[u8]) -> TestResult {
    let mut received = vec![0_u8; MAX_UDP_PAYLOAD + 1];
    let (length, source) = socket.recv_from(&mut received)?;
    if source != public {
        return Err(format!("reply came from {source}, expected {public}").into());
    }
    if &received[..length] != payload {
        return Err(format!(
            "relay changed a UDP datagram: sent {} bytes, received {length}",
            payload.len()
        )
        .into());
    }
    Ok(())
}

#[test]
fn udp_echo() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_udp(
        echo.address(),
        8,
        MAX_UDP_PAYLOAD as u32,
    )?)?;
    let public = fixture.public_address();
    let socket = public_socket()?;

    for payload in [
        Vec::new(),
        vec![0x01],
        (0..1_472).map(|index| (index % 251) as u8).collect(),
        (0..MAX_UDP_PAYLOAD)
            .map(|index| (index % 251) as u8)
            .collect(),
    ] {
        if let Err(error) = assert_datagram_echo(&socket, public, &payload) {
            return Err(format!(
                "{error}; payload_len={}; client output:\n{}\nserver output:\n{}",
                payload.len(),
                client.output(),
                server.output(),
            )
            .into());
        }
    }

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn multiple_sources_keep_reordered_replies_isolated() -> TestResult {
    let echo = ReorderingUdpServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_udp(
        echo.address(),
        8,
        MAX_UDP_PAYLOAD as u32,
    )?)?;
    let public = fixture.public_address();
    let slow = public_socket()?;
    let fast = public_socket()?;

    slow.send_to(&[1, 0xA1], public)?;
    thread::sleep(Duration::from_millis(10));
    fast.send_to(&[2, 0xB2], public)?;
    receive_datagram(&fast, public, &[2, 0xB2])?;
    receive_datagram(&slow, public, &[1, 0xA1])?;
    assert_eq!(
        client
            .output()
            .lines()
            .filter(|line| line.contains("event=udp_channel_ready"))
            .count(),
        1,
        "one persistent UDP data channel must serve both external flows"
    );

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn session_limit_drops_then_idle_sweep_reclaims_capacity() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let fixture = ProcessFixture::single_udp(echo.address(), 1, 1024)?
        .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_server_env("RUSTGO_TEST_UDP_IDLE_TIMEOUT_MS", "150")
        .with_server_env("RUSTGO_TEST_UDP_SWEEP_INTERVAL_MS", "25")
        .with_server_env("RUSTGO_TEST_UDP_SWEEP_BATCH", "1");
    let (fixture, mut server, mut client) = launch(fixture)?;
    let public = fixture.public_address();
    let first = public_socket_with_timeout(Duration::from_millis(400))?;
    let second = public_socket_with_timeout(Duration::from_millis(400))?;

    assert_datagram_echo(&first, public, b"occupy")?;
    second.send_to(b"rejected", public)?;
    expect_no_datagram(&second)?;
    server.wait_for_line("reason=\"session_limit\"", Duration::from_secs(3))?;
    server.wait_for_line("event=udp_idle_sweep", Duration::from_secs(3))?;
    assert_datagram_echo(&second, public, b"after idle")?;

    client.terminate()?;
    let cleanup = server.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(!cleanup.contains("drops_sessions=0"), "{cleanup}");
    server.terminate()?;
    Ok(())
}

#[test]
fn negotiated_limits_retire_idle_client_flow_before_capacity_reuse() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let fixture = ProcessFixture::single_udp(echo.address(), 1, 16)?
        .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_server_env("RUSTGO_TEST_UDP_QUEUE_CAPACITY", "1")
        .with_server_env("RUSTGO_TEST_UDP_IDLE_TIMEOUT_MS", "150")
        .with_server_env("RUSTGO_TEST_UDP_SWEEP_INTERVAL_MS", "25")
        .with_server_env("RUSTGO_TEST_UDP_SWEEP_BATCH", "1");
    let (fixture, mut server, mut client) = launch(fixture)?;
    let ready = client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    assert!(ready.contains("max_sessions=1"), "{ready}");
    assert!(ready.contains("idle_timeout_millis=150"), "{ready}");
    assert!(ready.contains("max_payload_bytes=16"), "{ready}");
    assert!(ready.contains("queue_capacity=1"), "{ready}");
    let public = fixture.public_address();
    let first = public_socket()?;
    let second = public_socket()?;

    assert_datagram_echo(&first, public, &[0xA1; 16])?;
    server.wait_for_line("event=udp_idle_sweep", Duration::from_secs(3))?;
    let retired = client.wait_for_line("event=udp_session_retired", Duration::from_secs(3))?;
    assert!(retired.contains("sessions=0"), "{retired}");
    assert_datagram_echo(&second, public, &[0xB2; 16])?;

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn bounded_queue_overflow_drops_without_killing_the_tunnel() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let fixture = ProcessFixture::single_udp(echo.address(), 8, 1024)?
        .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_server_env("RUSTGO_TEST_UDP_QUEUE_CAPACITY", "1")
        .with_server_env("RUSTGO_TEST_UDP_WRITE_DELAY_MS", "50");
    let (fixture, mut server, mut client) = launch(fixture)?;
    let public = fixture.public_address();
    let socket = public_socket_with_timeout(Duration::from_millis(300))?;

    for sequence in 0_u16..256 {
        let payload = sequence.to_be_bytes();
        socket.send_to(&payload, public)?;
    }
    server.wait_for_line("reason=\"data_queue_full\"", Duration::from_secs(5))?;
    thread::sleep(Duration::from_millis(500));
    while socket.recv_from(&mut [0_u8; 16]).is_ok() {}

    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    assert_datagram_echo(&socket, public, b"queue recovered")?;

    client.terminate()?;
    let cleanup = server.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(!cleanup.contains("drops_queue=0"), "{cleanup}");
    server.terminate()?;
    Ok(())
}

#[test]
fn configured_oversize_is_dropped_without_poisoning_the_channel() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let (fixture, mut server, mut client) =
        launch(ProcessFixture::single_udp(echo.address(), 8, 16)?)?;
    let public = fixture.public_address();
    let socket = public_socket_with_timeout(Duration::from_millis(400))?;

    socket.send_to(&[0xEE; 17], public)?;
    expect_no_datagram(&socket)?;
    server.wait_for_line("reason=\"oversize_public\"", Duration::from_secs(3))?;
    assert_datagram_echo(&socket, public, &[0xAA; 16])?;

    client.terminate()?;
    let cleanup = server.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(!cleanup.contains("drops_oversize=0"), "{cleanup}");
    server.terminate()?;
    Ok(())
}

#[test]
fn oversized_local_reply_is_dropped_without_poisoning_the_channel() -> TestResult {
    let service = ConditionalOversizeUdpServer::start()?;
    let (fixture, mut server, mut client) =
        launch(ProcessFixture::single_udp(service.address(), 8, 16)?)?;
    let public = fixture.public_address();
    let socket = public_socket_with_timeout(Duration::from_millis(400))?;

    socket.send_to(&[0xEE], public)?;
    expect_no_datagram(&socket)?;
    client.wait_for_line("reason=\"oversize_local_reply\"", Duration::from_secs(3))?;
    assert!(
        !server.output().contains("reason=\"oversize_data_frame\""),
        "configured oversize reply reached the server TLS reader:\n{}",
        server.output()
    );
    assert_datagram_echo(&socket, public, b"still live")?;

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn udp_tunnels_are_isolated() -> TestResult {
    let alpha = TaggedUdpServer::start(0xA1)?;
    let beta = TaggedUdpServer::start(0xB2)?;
    let fixture = ProcessFixture::udp_tunnels(
        vec![
            UdpTunnelSpec::available("alpha", alpha.address()),
            UdpTunnelSpec::available("beta", beta.address()),
        ],
        8,
        1024,
    )?;
    let (fixture, mut server, mut client) = launch(fixture)?;
    let socket = public_socket()?;
    let mut response = [0_u8; 32];

    socket.send_to(b"one", fixture.public_address_at(0))?;
    let (length, source) = socket.recv_from(&mut response)?;
    assert_eq!(source, fixture.public_address_at(0));
    assert_eq!(&response[..length], b"\xA1one");

    socket.send_to(b"two", fixture.public_address_at(1))?;
    let (length, source) = socket.recv_from(&mut response)?;
    assert_eq!(source, fixture.public_address_at(1));
    assert_eq!(&response[..length], b"\xB2two");

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn client_disconnect_cleans_state_and_fresh_client_restores_mapping() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let (mut fixture, mut server, mut client) =
        launch(ProcessFixture::single_udp(echo.address(), 8, 1024)?)?;
    let public = fixture.public_address();
    let socket = public_socket()?;
    assert_datagram_echo(&socket, public, b"before disconnect")?;

    client.terminate()?;
    let cleanup = server.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(cleanup.contains("sessions=0"), "{cleanup}");
    assert!(cleanup.contains("queue=0"), "{cleanup}");
    let mut restarted = fixture.start_client()?;
    restarted.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    assert_datagram_echo(&socket, public, b"after reconnect")?;

    restarted.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn server_restart_cleans_stale_generation_and_restores_mapping() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let (mut fixture, mut server, mut client) =
        launch(ProcessFixture::single_udp(echo.address(), 8, 1024)?)?;
    let public = fixture.public_address();
    let socket = public_socket()?;
    assert_datagram_echo(&socket, public, b"before restart")?;

    server.terminate()?;
    let cleanup = client.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(cleanup.contains("generation=1"), "{cleanup}");
    assert!(cleanup.contains("sessions=0"), "{cleanup}");
    assert!(cleanup.contains("queue=0"), "{cleanup}");
    assert!(cleanup.contains("local_queue=0"), "{cleanup}");
    let mut restarted = fixture.start_server()?;
    client.wait_for_line("event=udp_channel_ready", Duration::from_secs(12))?;
    assert_datagram_echo(&socket, public, b"after restart")?;

    client.terminate()?;
    restarted.terminate()?;
    Ok(())
}

#[test]
fn udp_data_channel_failure_reconnects_generation_and_restores_mapping() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let fixture = ProcessFixture::single_udp(echo.address(), 8, 1024)?
        .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_server_env("RUSTGO_TEST_UDP_DISCONNECT_AFTER_REPLIES", "1");
    let (fixture, mut server, mut client) = launch(fixture)?;
    let public = fixture.public_address();
    let socket = public_socket()?;

    assert_datagram_echo(&socket, public, b"generation one")?;
    server.wait_for_line("event=udp_test_data_disconnect", Duration::from_secs(3))?;
    let cleanup = client.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(cleanup.contains("generation=1"), "{cleanup}");
    client.wait_for_line("event=registration_ready", Duration::from_secs(12))?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    assert_datagram_echo(&socket, public, b"generation two")?;

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn continuous_public_flood_does_not_starve_tls_replies() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let (fixture, mut server, mut client) =
        launch(ProcessFixture::single_udp(echo.address(), 8, 256)?)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    let public = fixture.public_address();
    let flood = public_socket()?;
    let stop = Arc::new(AtomicBool::new(false));
    let flood_stop = stop.clone();
    let flood_thread = thread::spawn(move || {
        let payload = [0xF0; 64];
        while !flood_stop.load(Ordering::Acquire) {
            let _ = flood.send_to(&payload, public);
        }
    });

    let probe = public_socket_with_timeout(Duration::from_millis(50))?;
    let marker = b"reverse path stays live";
    let deadline = std::time::Instant::now() + Duration::from_millis(750);
    let mut response = [0_u8; 64];
    let mut received = false;
    while std::time::Instant::now() < deadline {
        probe.send_to(marker, public)?;
        match probe.recv_from(&mut response) {
            Ok((length, source)) if source == public && &response[..length] == marker => {
                received = true;
                break;
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    stop.store(true, Ordering::Release);
    let _ = flood_thread.join();
    if !received {
        return Err(format!(
            "TLS reply path starved during public UDP flood; client output:\n{}\nserver output:\n{}",
            client.output(),
            server.output(),
        )
        .into());
    }

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn valid_reverse_only_replies_keep_the_negotiated_client_lease_alive() -> TestResult {
    let service = PeriodicReplyUdpServer::start(2)?;
    let fixture = ProcessFixture::single_udp(service.address(), 1, 16)?
        .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_server_env("RUSTGO_TEST_UDP_IDLE_TIMEOUT_MS", "150")
        .with_server_env("RUSTGO_TEST_UDP_SWEEP_INTERVAL_MS", "25");
    let (fixture, mut server, mut client) = launch(fixture)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    let public = fixture.public_address();
    let socket = public_socket_with_timeout(Duration::from_millis(100))?;
    socket.send_to(b"start", public)?;

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut highest_sequence = 0_u16;
    let mut response = [0_u8; 16];
    while highest_sequence < 10 && std::time::Instant::now() < deadline {
        match socket.recv_from(&mut response) {
            Ok((length, source)) if source == public && length == 2 => {
                highest_sequence =
                    highest_sequence.max(u16::from_be_bytes([response[0], response[1]]));
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if highest_sequence < 10 {
        return Err(format!(
            "reverse-only UDP lease expired at sequence {highest_sequence}; client output:\n{}\nserver output:\n{}",
            client.output(),
            server.output(),
        )
        .into());
    }

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn oversized_reverse_replies_do_not_refresh_the_client_lease() -> TestResult {
    let service = PeriodicReplyUdpServer::start(17)?;
    let fixture = ProcessFixture::single_udp(service.address(), 1, 16)?
        .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_server_env("RUSTGO_TEST_UDP_IDLE_TIMEOUT_MS", "150")
        .with_server_env("RUSTGO_TEST_UDP_SWEEP_INTERVAL_MS", "1000");
    let (fixture, mut server, mut client) = launch(fixture)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    let socket = public_socket()?;
    socket.send_to(b"start", fixture.public_address())?;

    client.wait_for_line("reason=\"oversize_local_reply\"", Duration::from_secs(2))?;
    let expired = client.wait_for_line("event=udp_idle_sweep", Duration::from_millis(600))?;
    assert!(expired.contains("sessions=0"), "{expired}");

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

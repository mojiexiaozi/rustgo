use std::{
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use rustgo_e2e::{
    EchoServer, ManagedChild, ProcessFixture, TestResult, UdpEchoServer, UdpTunnelSpec,
};

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
                io::ErrorKind::TimedOut
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionReset
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

fn append_tcp_sentinel(
    fixture: &ProcessFixture,
    local_address: SocketAddr,
    existing_tunnel_count: usize,
) -> TestResult<(TcpListener, SocketAddr)> {
    let reservation = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    let public_address = reservation.local_addr()?;
    let server_path = fixture.server_config_path();
    let original_limit = format!("max_tunnels_per_client = {existing_tunnel_count}");
    let updated_limit = format!("max_tunnels_per_client = {}", existing_tunnel_count + 1);
    let server_toml = fs::read_to_string(server_path)?;
    if !server_toml.contains(&original_limit) {
        return Err("server fixture tunnel limit was not found".into());
    }
    fs::write(
        server_path,
        server_toml.replacen(&original_limit, &updated_limit, 1),
    )?;
    let mut client_toml = fs::read_to_string(fixture.client_config_path())?;
    client_toml.push_str(&format!(
        "\n[[tunnels]]\nname = \"tcp-sentinel\"\nprotocol = \"tcp\"\nlocal_addr = \"{local_address}\"\nremote_port = {}\n",
        public_address.port()
    ));
    fs::write(fixture.client_config_path(), client_toml)?;
    Ok((reservation, public_address))
}

fn connect_tcp_sentinel(address: SocketAddr) -> TestResult<TcpStream> {
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok(stream)
}

fn assert_tcp_sentinel_echo(stream: &mut TcpStream, payload: &[u8]) -> TestResult {
    stream.write_all(payload)?;
    let mut echoed = vec![0_u8; payload.len()];
    stream.read_exact(&mut echoed)?;
    if echoed != payload {
        return Err("TCP sentinel payload changed in transit".into());
    }
    Ok(())
}

fn lines_with_all(output: &str, required: &[&str]) -> usize {
    output
        .lines()
        .filter(|line| required.iter().all(|needle| line.contains(needle)))
        .count()
}

fn set_wildcard_control_bind(fixture: &ProcessFixture, udp_bind_ip: Option<IpAddr>) -> TestResult {
    let path = fixture.server_config_path();
    let current = format!("bind_addr = \"{}\"", fixture.control_address());
    let mut replacement = format!(
        "bind_addr = \"0.0.0.0:{}\"",
        fixture.control_address().port()
    );
    if let Some(ip) = udp_bind_ip {
        replacement.push_str(&format!("\nudp_bind_ip = \"{ip}\""));
    }
    let config = fs::read_to_string(path)?;
    if !config.contains(&current) {
        return Err("server control bind address was not found".into());
    }
    fs::write(path, config.replacen(&current, &replacement, 1))?;
    Ok(())
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

struct DelayedMarkedReplyUdpServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    received: Arc<AtomicUsize>,
    delayed_sent: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DelayedMarkedReplyUdpServer {
    fn start(delay: Duration) -> TestResult<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicUsize::new(0));
        let delayed_sent = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread_received = received.clone();
        let thread_delayed_sent = delayed_sent.clone();
        let thread = thread::spawn(move || {
            let mut replies = Vec::new();
            let mut buffer = [0_u8; 2048];
            while !thread_shutdown.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((length, peer)) => {
                        thread_received.fetch_add(1, Ordering::AcqRel);
                        let payload = buffer[..length].to_vec();
                        if payload.first() == Some(&0xD1) {
                            let reply_socket = match socket.try_clone() {
                                Ok(socket) => socket,
                                Err(_) => break,
                            };
                            let reply_sent = thread_delayed_sent.clone();
                            replies.push(thread::spawn(move || {
                                thread::sleep(delay);
                                let _ = reply_socket.send_to(&payload, peer);
                                reply_sent.store(true, Ordering::Release);
                            }));
                        } else {
                            let _ = socket.send_to(&payload, peer);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    // Sending the delayed reply to the now-closed generation-1
                    // socket surfaces as WSAECONNRESET on the next recv on Windows.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
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
            received,
            delayed_sent,
            thread: Some(thread),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn wait_for_received(&self, minimum: usize, timeout: Duration) -> TestResult {
        let deadline = std::time::Instant::now() + timeout;
        while self.received.load(Ordering::Acquire) < minimum {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "local UDP service received {} datagrams, expected at least {minimum}",
                    self.received.load(Ordering::Acquire)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    fn wait_for_delayed_reply(&self, timeout: Duration) -> TestResult {
        let deadline = std::time::Instant::now() + timeout;
        while !self.delayed_sent.load(Ordering::Acquire) {
            if std::time::Instant::now() >= deadline {
                return Err("local UDP service never sent its delayed reply".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}

impl Drop for DelayedMarkedReplyUdpServer {
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
fn wildcard_control_without_udp_bind_rejects_only_udp_and_keeps_tcp() -> TestResult {
    let udp_echo = UdpEchoServer::start()?;
    let tcp_echo = EchoServer::start()?;
    let public_reservation = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    let fixture = ProcessFixture::udp_tunnels(
        vec![UdpTunnelSpec::on_port(
            "echo",
            udp_echo.address(),
            public_reservation.local_addr()?.port(),
        )],
        8,
        1024,
    )?;
    let (tcp_reservation, tcp_public) = append_tcp_sentinel(&fixture, tcp_echo.address(), 1)?;
    set_wildcard_control_bind(&fixture, None)?;
    drop(tcp_reservation);
    let (fixture, mut server, mut client) = launch(fixture)?;

    let rejected = server.wait_for_line("event=tunnel_rejected", READY_TIMEOUT)?;
    assert!(rejected.contains("udp_bind_ip"), "{rejected}");
    let registration = server.wait_for_line("event=registration_ready", READY_TIMEOUT)?;
    assert!(registration.contains("listeners=1"), "{registration}");
    assert_tcp_sentinel_echo(
        &mut connect_tcp_sentinel(tcp_public)?,
        b"TCP survives wildcard UDP rejection",
    )?;
    assert_eq!(public_reservation.local_addr()?, fixture.public_address());
    assert!(
        client
            .wait_for_line("event=udp_channel_ready", Duration::from_millis(300))
            .is_err(),
        "rejected UDP tunnel unexpectedly opened a data channel"
    );

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn wildcard_control_with_explicit_udp_bind_relays_udp() -> TestResult {
    let echo = UdpEchoServer::start()?;
    let fixture = ProcessFixture::single_udp(echo.address(), 8, 1024)?;
    set_wildcard_control_bind(&fixture, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))?;
    let (fixture, mut server, mut client) = launch(fixture)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    let socket = public_socket()?;
    assert_datagram_echo(&socket, fixture.public_address(), b"explicit UDP bind")?;
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
fn retirement_queue_pressure_recovers_only_its_udp_tunnel() -> TestResult {
    let service = DelayedMarkedReplyUdpServer::start(Duration::from_millis(900))?;
    let sibling_service = UdpEchoServer::start()?;
    let tcp_service = EchoServer::start()?;
    let fixture = ProcessFixture::udp_tunnels(
        vec![
            UdpTunnelSpec::available("unstable", service.address()),
            UdpTunnelSpec::available("sibling", sibling_service.address()),
        ],
        3,
        64,
    )?
    .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
    .with_server_env("RUSTGO_TEST_UDP_QUEUE_CAPACITY", "1")
    .with_server_env("RUSTGO_TEST_UDP_IDLE_TIMEOUT_MS", "800")
    .with_server_env("RUSTGO_TEST_UDP_SWEEP_INTERVAL_MS", "20")
    .with_server_env("RUSTGO_TEST_UDP_WRITE_DELAY_MS", "500");
    let (tcp_reservation, tcp_public) = append_tcp_sentinel(&fixture, tcp_service.address(), 2)?;
    drop(tcp_reservation);
    let (fixture, mut server, mut client) = launch(fixture)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    let public = fixture.public_address_at(0);
    let sibling_public = fixture.public_address_at(1);
    let delayed = public_socket()?;
    let blocker = public_socket()?;
    let queued = public_socket()?;
    let sibling = public_socket()?;
    let mut tcp = connect_tcp_sentinel(tcp_public)?;
    assert_tcp_sentinel_echo(&mut tcp, b"tcp before retirement pressure")?;

    delayed.send_to(b"\xD1late", public)?;
    service.wait_for_received(1, Duration::from_secs(2))?;
    blocker.send_to(b"block-writer", public)?;
    thread::sleep(Duration::from_millis(30));
    queued.send_to(b"fill-queue", public)?;

    server.wait_for_line("reason=\"retirement_queue_full\"", Duration::from_secs(3))?;
    let server_cleanup = server.wait_for_line("event=udp_cleanup", Duration::from_secs(3))?;
    assert!(server_cleanup.contains("sessions=0"), "{server_cleanup}");
    assert!(server_cleanup.contains("queue=0"), "{server_cleanup}");
    let cleanup = client.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(cleanup.contains("generation=1"), "{cleanup}");
    assert!(cleanup.contains("sessions=0"), "{cleanup}");
    assert!(cleanup.contains("queue=0"), "{cleanup}");
    assert!(cleanup.contains("local_queue=0"), "{cleanup}");
    let recovered = client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    assert!(recovered.contains("tunnel_id=1"), "{recovered}");
    assert!(recovered.contains("generation=1"), "{recovered}");
    assert_eq!(
        client.output().matches("event=registration_ready").count(),
        1,
        "UDP tunnel recovery must not reconnect control:\n{}",
        client.output()
    );
    assert_eq!(
        lines_with_all(
            &client.output(),
            &["event=udp_channel_ready", "tunnel_id=2"]
        ),
        1,
        "sibling UDP channel must not restart:\n{}",
        client.output()
    );
    assert_tcp_sentinel_echo(&mut tcp, b"same tcp after retirement pressure")?;
    assert_datagram_echo(&sibling, sibling_public, b"sibling remains healthy")?;
    service.wait_for_delayed_reply(Duration::from_secs(2))?;
    if let Err(error) = assert_datagram_echo(&delayed, public, b"failed tunnel recovered") {
        return Err(format!(
            "restored UDP mapping did not echo: {error}\nclient output:\n{}\nserver output:\n{}",
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
fn token_capacity_rejects_the_unprepared_udp_tunnel_before_registration() -> TestResult {
    let alpha = UdpEchoServer::start()?;
    let beta = UdpEchoServer::start()?;
    let fixture = ProcessFixture::udp_tunnels(
        vec![
            UdpTunnelSpec::available("accepted", alpha.address()),
            UdpTunnelSpec::available("rejected", beta.address()),
        ],
        8,
        1024,
    )?
    .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
    .with_server_env("RUSTGO_TEST_MAX_PENDING_DATA_CHANNEL_TOKENS", "1");
    let (fixture, mut server, mut client) = launch(fixture)?;
    let registration = server.wait_for_line("event=registration_ready", READY_TIMEOUT)?;
    assert!(registration.contains("listeners=1"), "{registration}");
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    thread::sleep(Duration::from_millis(250));
    assert_eq!(
        client.output().matches("event=udp_channel_ready").count(),
        1,
        "only the fully prepared tunnel may be active:\n{}",
        client.output()
    );
    assert_eq!(
        server.output().matches("event=udp_channel_ready").count(),
        1,
        "only the fully prepared listener may own a data channel:\n{}",
        server.output()
    );

    let socket = public_socket_with_timeout(Duration::from_millis(500))?;
    assert_datagram_echo(&socket, fixture.public_address_at(0), b"accepted")?;
    socket.send_to(b"rejected", fixture.public_address_at(1))?;
    expect_no_datagram(&socket)?;

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
fn udp_data_channel_failure_recovers_only_its_tunnel() -> TestResult {
    let failing_echo = UdpEchoServer::start()?;
    let sibling_echo = UdpEchoServer::start()?;
    let tcp_echo = EchoServer::start()?;
    let fixture = ProcessFixture::udp_tunnels(
        vec![
            UdpTunnelSpec::available("unstable", failing_echo.address()),
            UdpTunnelSpec::available("sibling", sibling_echo.address()),
        ],
        8,
        1024,
    )?
    .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
    .with_server_env("RUSTGO_TEST_UDP_DISCONNECT_AFTER_REPLIES", "1");
    let (tcp_reservation, tcp_public) = append_tcp_sentinel(&fixture, tcp_echo.address(), 2)?;
    drop(tcp_reservation);
    let (fixture, mut server, mut client) = launch(fixture)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    let public = fixture.public_address_at(0);
    let sibling_public = fixture.public_address_at(1);
    let socket = public_socket()?;
    let sibling = public_socket()?;
    let mut tcp = connect_tcp_sentinel(tcp_public)?;
    assert_tcp_sentinel_echo(&mut tcp, b"tcp before UDP data failure")?;

    assert_datagram_echo(&socket, public, b"first UDP channel")?;
    server.wait_for_line("event=udp_test_data_disconnect", Duration::from_secs(3))?;
    let cleanup = client.wait_for_line("event=udp_cleanup", Duration::from_secs(5))?;
    assert!(cleanup.contains("generation=1"), "{cleanup}");
    let recovered = client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    assert!(recovered.contains("tunnel_id=1"), "{recovered}");
    assert!(recovered.contains("generation=1"), "{recovered}");
    assert_eq!(
        client.output().matches("event=registration_ready").count(),
        1,
        "UDP tunnel recovery must not reconnect control:\n{}",
        client.output()
    );
    assert_eq!(
        lines_with_all(
            &client.output(),
            &["event=udp_channel_ready", "tunnel_id=2"]
        ),
        1,
        "sibling UDP channel must remain on its first data channel:\n{}",
        client.output()
    );
    assert_tcp_sentinel_echo(&mut tcp, b"same tcp after UDP data failure")?;
    assert_datagram_echo(&sibling, sibling_public, b"sibling UDP remains healthy")?;
    assert_datagram_echo(&socket, public, b"failed UDP tunnel recovered")?;

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

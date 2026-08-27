#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use rustgo_e2e::{
    EchoServer, HalfCloseServer, ManagedChild, ProcessFixture, ReservedPort, TcpTunnelSpec,
    TestResult,
};

const READY_TIMEOUT: Duration = Duration::from_secs(8);
const BACKPRESSURE_HANDSHAKE: &[u8] = b"rustgo-backpressure-handshake";
const BACKPRESSURE_ACK: &[u8] = b"rustgo-local-target-ready";
const BACKPRESSURE_CHUNK: usize = 16 * 1024;
const BACKPRESSURE_MIN_PROGRESS: usize = BACKPRESSURE_CHUNK;
const BACKPRESSURE_MAX_BEFORE_SATURATION: usize = 512 * 1024 * 1024;
const BACKPRESSURE_AFTER_SATURATION: usize = 8 * 1024 * 1024;

enum TargetGateCommand {
    ConfirmClosed(mpsc::Sender<usize>),
    Open,
}

struct GatedEchoServer {
    address: std::net::SocketAddr,
    gate: mpsc::Sender<TargetGateCommand>,
    gated: mpsc::Receiver<()>,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<TestResult>>,
}

impl GatedEchoServer {
    fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (gate, gate_rx) = mpsc::channel();
        let (gated_tx, gated) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + READY_TIMEOUT;
            let mut stream = loop {
                if thread_shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err("gated local target was never connected".into());
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            stream.set_nonblocking(true)?;
            let mut handshake = vec![0_u8; BACKPRESSURE_HANDSHAKE.len()];
            read_exact_nonblocking(
                &mut stream,
                &mut handshake,
                &thread_shutdown,
                Instant::now() + READY_TIMEOUT,
            )?;
            if handshake != BACKPRESSURE_HANDSHAKE {
                return Err("gated local target received the wrong handshake".into());
            }
            write_all_nonblocking(
                &mut stream,
                BACKPRESSURE_ACK,
                &thread_shutdown,
                Instant::now() + READY_TIMEOUT,
            )?;
            gated_tx.send(())?;

            loop {
                if thread_shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                match gate_rx.recv_timeout(Duration::from_millis(10)) {
                    Ok(TargetGateCommand::ConfirmClosed(reply)) => {
                        let queued = peek_nonblocking(
                            &stream,
                            &thread_shutdown,
                            Instant::now() + READY_TIMEOUT,
                        )?;
                        let _ = reply.send(queued);
                    }
                    Ok(TargetGateCommand::Open) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                }
            }

            let mut buffer = [0_u8; BACKPRESSURE_CHUNK];
            let mut progress_deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if thread_shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                match stream.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(read) => {
                        if buffer[..read].iter().any(|byte| *byte != 0x5a) {
                            return Err("gated local target received changed payload bytes".into());
                        }
                        write_all_nonblocking(
                            &mut stream,
                            &buffer[..read],
                            &thread_shutdown,
                            Instant::now() + Duration::from_secs(30),
                        )?;
                        progress_deadline = Instant::now() + Duration::from_secs(30);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= progress_deadline {
                            return Err(
                                "gated local target made no progress after gate open".into()
                            );
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
            }
        });
        Ok(Self {
            address,
            gate,
            gated,
            shutdown,
            thread: Some(thread),
        })
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn wait_until_gated(&self) -> TestResult {
        self.gated.recv_timeout(READY_TIMEOUT)?;
        Ok(())
    }

    fn confirm_closed(&self) -> TestResult<usize> {
        let (reply, result) = mpsc::channel();
        self.gate.send(TargetGateCommand::ConfirmClosed(reply))?;
        Ok(result.recv_timeout(READY_TIMEOUT)?)
    }

    fn open(&self) -> TestResult {
        self.gate.send(TargetGateCommand::Open)?;
        Ok(())
    }

    fn finish(&mut self) -> TestResult {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| "gated local target thread panicked")?
    }
}

impl Drop for GatedEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.gate.send(TargetGateCommand::Open);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_exact_nonblocking(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    shutdown: &AtomicBool,
    deadline: Instant,
) -> TestResult {
    let mut offset = 0;
    while offset < buffer.len() {
        if shutdown.load(Ordering::Acquire) {
            return Err("gated local target stopped while reading".into());
        }
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => return Err("gated local target reached EOF while reading".into()),
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("gated local target read timed out".into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_all_nonblocking(
    stream: &mut TcpStream,
    buffer: &[u8],
    shutdown: &AtomicBool,
    deadline: Instant,
) -> TestResult {
    let mut offset = 0;
    while offset < buffer.len() {
        if shutdown.load(Ordering::Acquire) {
            return Err("gated local target stopped while writing".into());
        }
        match stream.write(&buffer[offset..]) {
            Ok(0) => return Err("gated local target wrote zero bytes".into()),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("gated local target write timed out".into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn peek_nonblocking(
    stream: &TcpStream,
    shutdown: &AtomicBool,
    deadline: Instant,
) -> TestResult<usize> {
    let mut byte = [0_u8; 1];
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err("gated local target stopped while peeking".into());
        }
        match stream.peek(&mut byte) {
            Ok(0) => return Err("gated local target reached EOF while peeking".into()),
            Ok(queued) => return Ok(queued),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("no payload reached the closed local read gate".into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

enum ProducerCommand {
    Probe,
    Drain { additional_bytes: usize },
}

enum ProducerEvent {
    Started,
    Progress(usize),
    Saturated(usize),
    BlockedWhileDraining { written: usize, target: usize },
    Complete(TestResult<usize>),
}

fn run_nonblocking_producer(
    mut stream: TcpStream,
    commands: mpsc::Receiver<ProducerCommand>,
    events: mpsc::Sender<ProducerEvent>,
) {
    let _ = events.send(ProducerEvent::Started);
    let result = (|| -> TestResult<usize> {
        let payload = [0x5a_u8; BACKPRESSURE_CHUNK];
        let mut written = 0_usize;
        let mut reported_progress = false;
        let mut reported_drain_block = false;
        let mut target = None;
        loop {
            if target.is_some_and(|target| written >= target) {
                stream.shutdown(Shutdown::Write)?;
                return Ok(written);
            }
            let remaining = target.map_or(payload.len(), |target| target - written);
            match stream.write(&payload[..remaining.min(payload.len())]) {
                Ok(0) => return Err("backpressure producer wrote zero bytes".into()),
                Ok(count) => {
                    written += count;
                    if !reported_progress && written >= BACKPRESSURE_MIN_PROGRESS {
                        events.send(ProducerEvent::Progress(written))?;
                        reported_progress = true;
                    }
                    if target.is_none() && written >= BACKPRESSURE_MAX_BEFORE_SATURATION {
                        return Err("producer never observed socket saturation".into());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if !reported_progress {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    if let Some(drain_target) = target {
                        if !reported_drain_block {
                            events.send(ProducerEvent::BlockedWhileDraining {
                                written,
                                target: drain_target,
                            })?;
                            reported_drain_block = true;
                        }
                        thread::sleep(Duration::from_millis(1));
                    } else {
                        events.send(ProducerEvent::Saturated(written))?;
                        match commands.recv_timeout(Duration::from_secs(30))? {
                            ProducerCommand::Probe => {}
                            ProducerCommand::Drain { additional_bytes } => {
                                target = Some(
                                    written
                                        .checked_add(additional_bytes)
                                        .ok_or("backpressure producer byte target overflowed")?,
                                );
                            }
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    })();
    let _ = events.send(ProducerEvent::Complete(result));
}

fn consume_nonblocking_echo(mut stream: TcpStream) -> TestResult<usize> {
    let mut buffer = [0_u8; BACKPRESSURE_CHUNK];
    let mut received = 0_usize;
    let mut progress_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(received),
            Ok(read) => {
                if buffer[..read].iter().any(|byte| *byte != 0x5a) {
                    return Err("backpressure consumer observed changed payload bytes".into());
                }
                received += read;
                progress_deadline = Instant::now() + Duration::from_secs(60);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= progress_deadline {
                    return Err("backpressure consumer made no progress".into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_producer_event(events: &mpsc::Receiver<ProducerEvent>) -> TestResult<ProducerEvent> {
    Ok(events.recv_timeout(READY_TIMEOUT)?)
}

fn launch(mut fixture: ProcessFixture) -> TestResult<(ProcessFixture, ManagedChild, ManagedChild)> {
    let server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    if let Err(error) = client.wait_for_line("event=registration_ready", READY_TIMEOUT) {
        return Err(format!("{error}\nserver output:\n{}", server.output()).into());
    }
    Ok((fixture, server, client))
}

fn connect(address: std::net::SocketAddr) -> TestResult<TcpStream> {
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}

fn assert_echo(address: std::net::SocketAddr, payload: &[u8]) -> TestResult {
    let mut stream = connect(address)?;
    stream.write_all(payload)?;
    let mut echoed = vec![0_u8; payload.len()];
    stream.read_exact(&mut echoed)?;
    if echoed != payload {
        return Err("relay changed the echoed payload".into());
    }
    Ok(())
}

fn assert_stream_closes(mut stream: TcpStream, timeout: Duration) -> TestResult {
    stream.set_read_timeout(Some(timeout))?;
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => Ok(()),
        Err(error)
            if !matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(())
        }
        Ok(_) => Err("closed relay unexpectedly delivered application bytes".into()),
        Err(error) => Err(format!("relay did not close before timeout: {error}").into()),
    }
}

#[test]
fn tcp_echo() -> TestResult {
    let echo = EchoServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_tcp(echo.address())?)?;

    let mut public = connect(fixture.public_address())?;
    let payload = b"rustgo real-process tcp relay";
    public.write_all(payload)?;
    let mut echoed = vec![0_u8; payload.len()];
    if let Err(error) = public.read_exact(&mut echoed) {
        return Err(format!(
            "relay read failed: {error}; client output:\n{}\nserver output:\n{}",
            client.output(),
            server.output(),
        )
        .into());
    }
    assert_eq!(echoed, payload);

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn concurrent_tcp_connections_are_isolated() -> TestResult {
    let echo = EchoServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_tcp(echo.address())?)?;
    let address = fixture.public_address();

    let workers = (0_u8..8)
        .map(|index| {
            thread::spawn(move || {
                let payload = vec![index; 32 * 1024 + usize::from(index)];
                assert_echo(address, &payload)
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        let result = worker
            .join()
            .map_err(|_| "concurrent relay worker panicked")?;
        if let Err(error) = result {
            return Err(format!(
                "concurrent relay failed: {error}; client output:\n{}\nserver output:\n{}",
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
fn per_tunnel_connection_limit_rejects_excess_and_recovers() -> TestResult {
    let echo = EchoServer::start()?;
    let fixture =
        ProcessFixture::tcp_tunnels(vec![TcpTunnelSpec::available("limited", echo.address())], 2)?;
    let (fixture, mut server, mut client) = launch(fixture)?;
    let address = fixture.public_address();

    let mut first = connect(address)?;
    let mut second = connect(address)?;
    first.write_all(b"one")?;
    second.write_all(b"two")?;
    let mut first_echo = [0_u8; 3];
    let mut second_echo = [0_u8; 3];
    first.read_exact(&mut first_echo)?;
    second.read_exact(&mut second_echo)?;
    assert_eq!(&first_echo, b"one");
    assert_eq!(&second_echo, b"two");

    let excess = connect(address)?;
    assert_stream_closes(excess, Duration::from_secs(2))?;
    drop(first);

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match assert_echo(address, b"replacement") {
            Ok(()) => break,
            Err(error) if Instant::now() < deadline => {
                drop(error);
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
    drop(second);

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn streams_sixteen_mib_without_a_whole_transfer_buffer() -> TestResult {
    const CHUNK: usize = 16 * 1024;
    const CHUNKS: usize = 1024;
    let echo = EchoServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_tcp(echo.address())?)?;
    let stream = connect(fixture.public_address())?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let mut writer = stream.try_clone()?;
    let (first_chunk_written, wait_for_first_chunk) = mpsc::channel();
    let (allow_remainder, remainder_gate) = mpsc::channel();
    let (producer_complete, producer_result) = mpsc::channel();
    let writer_task = thread::spawn(move || {
        let result = (|| -> TestResult {
            let first = vec![0_u8; CHUNK];
            writer.write_all(&first)?;
            first_chunk_written.send(())?;
            remainder_gate.recv()?;
            for index in 1..CHUNKS {
                let chunk = vec![(index % 251) as u8; CHUNK];
                writer.write_all(&chunk)?;
            }
            writer.shutdown(Shutdown::Write)?;
            Ok(())
        })();
        let _ = producer_complete.send(result);
    });
    let mut reader = stream;
    let mut chunk = vec![0_u8; CHUNK];
    wait_for_first_chunk.recv_timeout(Duration::from_secs(2))?;
    let early_read = reader.read_exact(&mut chunk);
    let producer_before_gate = producer_result.try_recv();
    allow_remainder.send(())?;
    early_read?;
    if chunk.iter().any(|byte| *byte != 0) {
        return Err("16 MiB stream changed the first chunk".into());
    }
    if !matches!(producer_before_gate, Err(mpsc::TryRecvError::Empty)) {
        return Err("16 MiB producer reached EOF before the early-progress gate opened".into());
    }
    for index in 1..CHUNKS {
        reader.read_exact(&mut chunk)?;
        if chunk.iter().any(|byte| *byte != (index % 251) as u8) {
            return Err(format!("16 MiB stream changed chunk {index}").into());
        }
    }
    producer_result.recv_timeout(Duration::from_secs(5))??;
    writer_task.join().map_err(|_| "16 MiB writer panicked")?;

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn slow_reader_applies_backpressure_without_losing_bytes() -> TestResult {
    let mut target = GatedEchoServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_tcp(target.address())?)?;
    let mut public = connect(fixture.public_address())?;
    public.write_all(BACKPRESSURE_HANDSHAKE)?;
    let mut acknowledgement = vec![0_u8; BACKPRESSURE_ACK.len()];
    public.read_exact(&mut acknowledgement)?;
    if acknowledgement != BACKPRESSURE_ACK {
        return Err("public-to-local relay handshake returned the wrong acknowledgement".into());
    }
    target.wait_until_gated()?;

    public.set_nonblocking(true)?;
    let writer = public.try_clone()?;
    let reader = public;
    let (commands, command_rx) = mpsc::channel();
    let (event_tx, events) = mpsc::channel();
    let producer = thread::spawn(move || run_nonblocking_producer(writer, command_rx, event_tx));
    let consumer = thread::spawn(move || consume_nonblocking_echo(reader));

    if !matches!(receive_producer_event(&events)?, ProducerEvent::Started) {
        return Err("backpressure producer did not report its start".into());
    }
    let progress = match receive_producer_event(&events)? {
        ProducerEvent::Progress(bytes) => bytes,
        ProducerEvent::Complete(result) => {
            result?;
            return Err("producer completed before reporting progress".into());
        }
        _ => return Err("producer did not report initial progress".into()),
    };
    if progress < BACKPRESSURE_MIN_PROGRESS {
        return Err("producer progress barrier was too early".into());
    }
    let first_saturation = match receive_producer_event(&events)? {
        ProducerEvent::Saturated(bytes) => bytes,
        ProducerEvent::Complete(result) => {
            result?;
            return Err("producer completed without observing socket saturation".into());
        }
        _ => return Err("producer emitted an unexpected event before saturation".into()),
    };
    if target.confirm_closed()? == 0 {
        return Err("no payload was queued at the closed local read gate".into());
    }

    commands.send(ProducerCommand::Probe)?;
    let second_saturation = match receive_producer_event(&events)? {
        ProducerEvent::Saturated(bytes) => bytes,
        ProducerEvent::Complete(result) => {
            result?;
            return Err(
                "producer recovered and completed while the local read gate was closed".into(),
            );
        }
        _ => return Err("producer did not hit the saturation barrier a second time".into()),
    };
    if second_saturation < first_saturation {
        return Err("producer saturation offset moved backwards".into());
    }
    if target.confirm_closed()? == 0 {
        return Err("local payload queue drained before its read gate opened".into());
    }

    commands.send(ProducerCommand::Drain {
        additional_bytes: BACKPRESSURE_AFTER_SATURATION,
    })?;
    let (blocked, target_bytes) = match receive_producer_event(&events)? {
        ProducerEvent::BlockedWhileDraining { written, target } => (written, target),
        ProducerEvent::Complete(result) => {
            result?;
            return Err("producer completed while the local read gate was closed".into());
        }
        _ => return Err("producer did not reblock with its completion target armed".into()),
    };
    if blocked >= target_bytes {
        return Err("producer reported blockage after reaching its completion target".into());
    }
    if target.confirm_closed()? == 0 {
        return Err("local payload queue drained before the read gate release".into());
    }

    target.open()?;
    let produced = match receive_producer_event(&events)? {
        ProducerEvent::Complete(result) => result?,
        _ => return Err("producer did not complete after the local read gate opened".into()),
    };
    let received = consumer
        .join()
        .map_err(|_| "backpressure consumer panicked")??;
    producer
        .join()
        .map_err(|_| "backpressure producer panicked")?;
    if received != produced {
        return Err(format!(
            "backpressure echo length changed: produced {produced}, received {received}"
        )
        .into());
    }
    target.finish()?;

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn public_half_close_reaches_local_service_and_preserves_reverse_response() -> TestResult {
    const RESPONSE: &[u8] = b"response after request EOF";
    let service = HalfCloseServer::start(RESPONSE)?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_tcp(service.address())?)?;

    let mut public = connect(fixture.public_address())?;
    public.write_all(b"request body")?;
    public.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    public.read_to_end(&mut response)?;
    assert_eq!(response, RESPONSE);

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn local_refusal_closes_only_that_connection() -> TestResult {
    let echo = EchoServer::start()?;
    let mut refused = ReservedPort::acquire()?;
    let fixture = ProcessFixture::tcp_tunnels(
        vec![
            TcpTunnelSpec::available("refused", refused.address()),
            TcpTunnelSpec::available("healthy", echo.address()),
        ],
        4,
    )?;
    let (fixture, mut server, mut client) = launch(fixture)?;
    refused.release();

    for attempt in 0..12 {
        let mut failed = connect(fixture.public_address_at(0))?;
        let _ = failed.write_all(b"cannot arrive");
        assert_stream_closes(failed, Duration::from_secs(3))
            .map_err(|error| format!("refused connection {attempt} did not close: {error}"))?;
    }
    assert_echo(fixture.public_address_at(1), b"healthy after refusal")?;

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn public_port_conflict_rejects_only_that_tunnel() -> TestResult {
    let echo = EchoServer::start()?;
    let conflict = ReservedPort::acquire()?;
    let fixture = ProcessFixture::tcp_tunnels(
        vec![
            TcpTunnelSpec::on_port("conflict", echo.address(), conflict.address().port()),
            TcpTunnelSpec::available("healthy", echo.address()),
        ],
        4,
    )?;
    let (fixture, mut server, mut client) = launch(fixture)?;

    assert!(TcpListener::bind(conflict.address()).is_err());
    assert_echo(fixture.public_address_at(1), b"healthy despite conflict")?;

    client.terminate()?;
    server.terminate()?;
    Ok(())
}

#[test]
fn control_disconnect_closes_listener_and_active_stream() -> TestResult {
    let echo = EchoServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_tcp(echo.address())?)?;
    let address = fixture.public_address();
    let mut active = connect(address)?;
    active.write_all(b"before disconnect")?;
    let mut echoed = [0_u8; 17];
    active.read_exact(&mut echoed)?;
    assert_eq!(&echoed, b"before disconnect");

    client.terminate()?;
    assert_stream_closes(active, Duration::from_secs(5))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err() {
            break;
        }
        if Instant::now() >= deadline {
            return Err("public listener survived its control owner".into());
        }
        thread::sleep(Duration::from_millis(25));
    }

    server.terminate()?;
    Ok(())
}

#[test]
fn server_restart_restores_the_fixed_port_mapping() -> TestResult {
    let echo = EchoServer::start()?;
    let (mut fixture, mut server, mut client) =
        launch(ProcessFixture::single_tcp(echo.address())?)?;
    let address = fixture.public_address();
    assert_echo(address, b"before restart")?;

    server.terminate()?;
    let mut restarted = fixture.start_server()?;
    if let Err(error) = client.wait_for_line("event=registration_ready", Duration::from_secs(12)) {
        return Err(format!("{error}\nrestarted server output:\n{}", restarted.output()).into());
    }
    assert_echo(address, b"after restart")?;

    client.terminate()?;
    restarted.terminate()?;
    Ok(())
}

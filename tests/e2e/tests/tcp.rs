#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use rustgo_e2e::{
    EchoServer, HalfCloseServer, ManagedChild, ProcessFixture, ReservedPort, TcpTunnelSpec,
    TestResult,
};

const READY_TIMEOUT: Duration = Duration::from_secs(8);

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
    const TOTAL: usize = 32 * 1024 * 1024;
    const CHUNK: usize = 16 * 1024;
    let echo = EchoServer::start()?;
    let (fixture, mut server, mut client) = launch(ProcessFixture::single_tcp(echo.address())?)?;
    let stream = connect(fixture.public_address())?;
    socket2::SockRef::from(&stream).set_recv_buffer_size(CHUNK)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let (producer_complete, producer_result) = mpsc::channel();
    let writer_task = thread::spawn(move || {
        let chunk = vec![0x5a; CHUNK];
        let result = (|| -> TestResult {
            for _ in 0..(TOTAL / CHUNK) {
                writer.write_all(&chunk)?;
            }
            writer.shutdown(Shutdown::Write)?;
            Ok(())
        })();
        let _ = producer_complete.send(result);
    });
    let (open_read_gate, read_gate) = mpsc::channel();
    let (consumer_complete, consumer_result) = mpsc::channel();
    let reader_task = thread::spawn(move || {
        let result = (|| -> TestResult {
            read_gate.recv()?;
            let mut reader = stream;
            let mut received = 0;
            let mut chunk = [0_u8; CHUNK];
            while received < TOTAL {
                let read = reader.read(&mut chunk)?;
                if read == 0 {
                    return Err(
                        format!("slow reader received only {received} of {TOTAL} bytes").into(),
                    );
                }
                if chunk[..read].iter().any(|byte| *byte != 0x5a) {
                    return Err("slow reader observed changed payload bytes".into());
                }
                received += read;
            }
            Ok(())
        })();
        let _ = consumer_complete.send(result);
    });

    thread::sleep(Duration::from_millis(500));
    let producer_before_gate = producer_result.try_recv();
    let producer_was_blocked = matches!(&producer_before_gate, Err(mpsc::TryRecvError::Empty));
    open_read_gate.send(())?;
    let producer_after_gate = match producer_before_gate {
        Err(mpsc::TryRecvError::Empty) => producer_result.recv_timeout(Duration::from_secs(30))?,
        Ok(result) => result,
        Err(mpsc::TryRecvError::Disconnected) => {
            return Err("backpressure producer exited without a completion result".into());
        }
    };
    producer_after_gate?;
    consumer_result.recv_timeout(Duration::from_secs(30))??;
    writer_task
        .join()
        .map_err(|_| "backpressure writer panicked")?;
    reader_task
        .join()
        .map_err(|_| "backpressure reader panicked")?;
    if !producer_was_blocked {
        return Err("32 MiB producer completed while the reader gate was closed".into());
    }

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

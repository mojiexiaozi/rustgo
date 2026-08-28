use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

use rustgo_e2e::{EchoServer, ManagedChild, ProcessFixture, TestResult, UdpEchoServer};

const READY_TIMEOUT: Duration = Duration::from_secs(8);

fn with_protocol_versions(
    fixture: ProcessFixture,
    server_minor: u16,
    client_minor: u16,
) -> ProcessFixture {
    fixture
        .with_server_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_server_env("RUSTGO_TEST_PROTOCOL_MINOR", server_minor.to_string())
        .with_client_env("RUSTGO_INTERNAL_TESTING", "1")
        .with_client_env("RUSTGO_TEST_PROTOCOL_MINOR", client_minor.to_string())
}

fn launch(
    mut fixture: ProcessFixture,
    server_minor: u16,
    client_minor: u16,
) -> TestResult<(ProcessFixture, ManagedChild, ManagedChild)> {
    let mut server = fixture.start_server()?;
    let mut client = fixture.start_client()?;
    let negotiated_minor = server_minor.min(client_minor);
    let client_ready = client.wait_for_line("event=registration_ready", READY_TIMEOUT)?;
    assert!(
        client_ready.contains(&format!("protocol_minor={negotiated_minor}")),
        "{client_ready}"
    );
    assert!(
        client_ready.contains(&format!("local_protocol_minor={client_minor}")),
        "{client_ready}"
    );
    let server_ready = server.wait_for_line("event=registration_ready", READY_TIMEOUT)?;
    assert!(
        server_ready.contains(&format!("protocol_minor={negotiated_minor}")),
        "{server_ready}"
    );
    assert!(
        server_ready.contains(&format!("local_protocol_minor={server_minor}")),
        "{server_ready}"
    );
    Ok((fixture, server, client))
}

fn assert_tcp_data_path(server_minor: u16, client_minor: u16) -> TestResult {
    let echo = EchoServer::start()?;
    let fixture = with_protocol_versions(
        ProcessFixture::single_tcp(echo.address())?,
        server_minor,
        client_minor,
    );
    let (fixture, mut server, mut client) = launch(fixture, server_minor, client_minor)?;
    let mut public = TcpStream::connect_timeout(&fixture.public_address(), Duration::from_secs(2))?;
    public.set_read_timeout(Some(Duration::from_secs(5)))?;
    public.set_write_timeout(Some(Duration::from_secs(5)))?;
    let payload = format!("tcp mixed minor {server_minor} {client_minor}").into_bytes();
    public.write_all(&payload)?;
    let mut echoed = vec![0_u8; payload.len()];
    public.read_exact(&mut echoed)?;
    assert_eq!(echoed, payload);
    client.terminate()?;
    server.terminate()?;
    Ok(())
}

fn assert_udp_data_path(server_minor: u16, client_minor: u16) -> TestResult {
    let echo = UdpEchoServer::start()?;
    let fixture = with_protocol_versions(
        ProcessFixture::single_udp(echo.address(), 8, 1024)?,
        server_minor,
        client_minor,
    );
    let (fixture, mut server, mut client) = launch(fixture, server_minor, client_minor)?;
    client.wait_for_line("event=udp_channel_ready", READY_TIMEOUT)?;
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let payload = format!("udp mixed minor {server_minor} {client_minor}").into_bytes();
    socket.send_to(&payload, fixture.public_address())?;
    let mut echoed = vec![0_u8; payload.len()];
    let (length, _) = socket.recv_from(&mut echoed)?;
    assert_eq!(&echoed[..length], payload);
    client.terminate()?;
    server.terminate()?;
    Ok(())
}

fn assert_mixed_minor_data_paths(server_minor: u16, client_minor: u16) -> TestResult {
    assert_tcp_data_path(server_minor, client_minor)?;
    assert_udp_data_path(server_minor, client_minor)
}

#[test]
fn server_1_1_client_1_0_use_1_0_for_control_tcp_and_udp() -> TestResult {
    assert_mixed_minor_data_paths(1, 0)
}

#[test]
fn server_1_0_client_1_1_use_1_0_for_control_tcp_and_udp() -> TestResult {
    assert_mixed_minor_data_paths(0, 1)
}

use std::{env, error::Error, fs, path::PathBuf};

use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, BoundedVec, ClientAuthenticate, ClientHello,
    DataChannelBind, DataChannelKind, ErrorMessage, FrameCodec, Heartbeat, MAX_BINDING_TOKEN_BYTES,
    MAX_UDP_PAYLOAD_BYTES, Message, OpenTcpStream, OpenUdpChannel, ProtocolErrorCode,
    ProtocolVersion, RegisterTunnels, ServerChallenge, SocketAddress, TcpStreamReady,
    TelemetryReport, TunnelProtocol, TunnelRegistration, TunnelResult, TunnelResults,
    UDP_METADATA_LEN, UdpDatagram, UdpSessionRetired,
};

fn text<const MAX: usize>(value: &str) -> BoundedString<MAX> {
    BoundedString::try_from(value).expect("seed text is within its protocol bound")
}

fn bytes<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(value).expect("seed bytes are within their protocol bound")
}

fn seed_messages() -> Vec<(&'static str, Message)> {
    let tunnel = TunnelRegistration {
        tunnel_id: 41,
        name: text("ssh"),
        protocol: TunnelProtocol::TCP,
        remote_port: 2222,
    };
    vec![
        (
            "01-client-hello",
            Message::ClientHello(ClientHello {
                client_name: text("home-pc"),
                fingerprint: bytes(&[0x11; 32]),
                heartbeat_interval_secs: 20,
            }),
        ),
        (
            "02-server-challenge",
            Message::ServerChallenge(ServerChallenge {
                challenge: bytes(&[0x22; 32]),
                session_id: bytes(&[0x33; 16]),
            }),
        ),
        (
            "03-client-authenticate",
            Message::ClientAuthenticate(ClientAuthenticate {
                public_key: bytes(&[0x44; 32]),
                signature: bytes(&[0x55; 64]),
            }),
        ),
        (
            "04-auth-result",
            Message::AuthResult(AuthResult {
                accepted: true,
                error: None,
            }),
        ),
        (
            "05-register-tunnels",
            Message::RegisterTunnels(RegisterTunnels {
                tunnels: BoundedVec::try_from(vec![tunnel.clone()]).expect("bounded seed"),
            }),
        ),
        (
            "06-tunnel-results",
            Message::TunnelResults(TunnelResults {
                results: BoundedVec::try_from(vec![TunnelResult {
                    tunnel_id: tunnel.tunnel_id,
                    accepted: false,
                    error: Some(ProtocolErrorCode::TUNNEL_REJECTED),
                }])
                .expect("bounded seed"),
            }),
        ),
        (
            "07-open-tcp-stream",
            Message::OpenTcpStream(OpenTcpStream {
                tunnel_id: 41,
                connection_id: 9001,
                peer: SocketAddress::V4 {
                    octets: [203, 0, 113, 8],
                    port: 53_120,
                },
                binding_token: bytes(&[0x66; MAX_BINDING_TOKEN_BYTES]),
            }),
        ),
        (
            "08-tcp-stream-ready",
            Message::TcpStreamReady(TcpStreamReady {
                connection_id: 9001,
                accepted: true,
                error: None,
            }),
        ),
        (
            "09-udp-datagram",
            Message::UdpDatagram(UdpDatagram {
                tunnel_id: 42,
                session_id: 73,
                source: SocketAddress::V6 {
                    octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    port: 27_015,
                },
                payload: bytes(&[0, 1, 2, 0xff]),
            }),
        ),
        (
            "10-heartbeat",
            Message::Heartbeat(Heartbeat { sequence: 17 }),
        ),
        (
            "11-error",
            Message::Error(ErrorMessage {
                code: ProtocolErrorCode::INVALID_STATE,
                detail: text("out-of-order message"),
            }),
        ),
        (
            "12-open-udp-channel",
            Message::OpenUdpChannel(OpenUdpChannel {
                tunnel_id: 42,
                channel_id: 9002,
                binding_token: bytes(&[0x77; MAX_BINDING_TOKEN_BYTES]),
                max_sessions: 1024,
                idle_timeout_millis: 60_000,
                max_payload_bytes: 65_507,
                queue_capacity: 1024,
            }),
        ),
        (
            "13-data-channel-bind",
            Message::DataChannelBind(DataChannelBind {
                client_name: text("home-pc"),
                session_id: bytes(&[0x88; 32]),
                kind: DataChannelKind::TCP,
                tunnel_id: 41,
                target_id: 9001,
                binding_token: bytes(&[0x99; MAX_BINDING_TOKEN_BYTES]),
            }),
        ),
        (
            "14-udp-session-retired",
            Message::UdpSessionRetired(UdpSessionRetired {
                tunnel_id: 42,
                session_id: 73,
            }),
        ),
    ]
}

fn main() -> Result<(), Box<dyn Error>> {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: seed_corpus <output-directory>")?;
    fs::create_dir_all(&output)?;

    let codec = FrameCodec::new(UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES);
    let version = ProtocolVersion::new(1, 0);
    for (name, message) in seed_messages() {
        fs::write(output.join(name), codec.encode(version, 0, &message)?)?;
    }
    let telemetry = Message::TelemetryReport(TelemetryReport {
        sampled_unix_millis: 1_725_000_000_000,
        sequence: 1,
        cpu_basis_points: 5_000,
        memory_used_bytes: 4 * 1024 * 1024 * 1024,
        memory_total_bytes: 8 * 1024 * 1024 * 1024,
        disk_used_bytes: 500 * 1024 * 1024 * 1024,
        disk_total_bytes: 1_000 * 1024 * 1024 * 1024,
        tx_bytes_per_sec: 125_000,
        rx_bytes_per_sec: 250_000,
    });
    fs::write(
        output.join("30-telemetry-report"),
        codec.encode(ProtocolVersion::V0_3, 0, &telemetry)?,
    )?;
    Ok(())
}

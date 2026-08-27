use rustgo_protocol::{
    AuthResult, BoundedBytes, BoundedString, BoundedVec, ClientAuthenticate, ClientHandshakeState,
    ClientHello, Heartbeat, MAX_BINDING_TOKEN_BYTES, Message, OpenTcpStream, OpenUdpChannel,
    ProtocolErrorCode, ProtocolVersion, RegisterTunnels, ServerChallenge, SocketAddress,
    StateError, TunnelProtocol, TunnelRegistration,
};

fn text<const MAX: usize>(value: &str) -> BoundedString<MAX> {
    BoundedString::try_from(value).unwrap()
}

fn bytes<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(value).unwrap()
}

fn hello() -> Message {
    Message::ClientHello(ClientHello {
        client_name: text("home-pc"),
        fingerprint: bytes(&[1; 32]),
    })
}

fn challenge() -> Message {
    Message::ServerChallenge(ServerChallenge {
        challenge: bytes(&[2; 32]),
        session_id: bytes(&[3; 16]),
    })
}

fn authenticate() -> Message {
    Message::ClientAuthenticate(ClientAuthenticate {
        public_key: bytes(&[4; 32]),
        signature: bytes(&[5; 64]),
    })
}

fn auth_result(accepted: bool) -> Message {
    Message::AuthResult(AuthResult {
        accepted,
        error: (!accepted).then_some(ProtocolErrorCode::AUTHENTICATION_FAILED),
    })
}

fn registration() -> Message {
    Message::RegisterTunnels(RegisterTunnels {
        tunnels: BoundedVec::try_from(vec![TunnelRegistration {
            tunnel_id: 1,
            name: text("ssh"),
            protocol: TunnelProtocol::TCP,
            remote_port: 2222,
        }])
        .unwrap(),
    })
}

#[test]
fn valid_handshake_reaches_active_and_accepts_heartbeats() {
    let state = ClientHandshakeState::new()
        .transition(&hello())
        .unwrap()
        .transition(&challenge())
        .unwrap()
        .transition(&authenticate())
        .unwrap()
        .transition(&auth_result(true))
        .unwrap()
        .transition(&registration())
        .unwrap();

    assert!(state.is_active());
    assert_eq!(
        state
            .transition(&Message::Heartbeat(Heartbeat { sequence: 1 }))
            .unwrap(),
        state
    );
}

#[test]
fn authenticate_before_challenge_is_rejected_without_advancing() {
    let state = ClientHandshakeState::new().transition(&hello()).unwrap();
    assert_eq!(
        state.transition(&authenticate()),
        Err(StateError::invalid_state())
    );
    assert!(!state.is_active());
}

#[test]
fn registration_before_authentication_is_rejected() {
    let state = ClientHandshakeState::new()
        .transition(&hello())
        .unwrap()
        .transition(&challenge())
        .unwrap();
    assert_eq!(
        state.transition(&registration()),
        Err(StateError::invalid_state())
    );
}

#[test]
fn rejected_authentication_never_allows_registration() {
    let state = ClientHandshakeState::new()
        .transition(&hello())
        .unwrap()
        .transition(&challenge())
        .unwrap()
        .transition(&authenticate())
        .unwrap()
        .transition(&auth_result(false))
        .unwrap();
    assert!(state.is_rejected());
    assert_eq!(
        state.transition(&registration()),
        Err(StateError::invalid_state())
    );
}

#[test]
fn data_channel_binding_requires_the_active_known_session() {
    let state = ClientHandshakeState::new()
        .transition(&hello())
        .unwrap()
        .transition(&challenge())
        .unwrap()
        .transition(&authenticate())
        .unwrap()
        .transition(&auth_result(true))
        .unwrap()
        .transition(&registration())
        .unwrap();

    assert_eq!(state.validate_data_channel_session(&[3; 16]), Ok(()));
    assert_eq!(
        state.validate_data_channel_session(&[9; 16]),
        Err(StateError::unknown_session())
    );
}

#[test]
fn data_channel_binding_before_active_is_invalid_state() {
    assert_eq!(
        ClientHandshakeState::new().validate_data_channel_session(&[3; 16]),
        Err(StateError::invalid_state())
    );
}

#[test]
fn version_negotiation_requires_equal_major_and_uses_lower_minor() {
    assert_eq!(
        ProtocolVersion::new(1, 7).negotiate(ProtocolVersion::new(1, 3)),
        Ok(ProtocolVersion::new(1, 3))
    );
    assert_eq!(
        ProtocolVersion::new(1, 2).negotiate(ProtocolVersion::new(1, 9)),
        Ok(ProtocolVersion::new(1, 2))
    );
    assert_eq!(
        ProtocolVersion::new(1, 0).negotiate(ProtocolVersion::new(2, 0)),
        Err(ProtocolErrorCode::UNSUPPORTED_VERSION)
    );
}

#[test]
fn protocol_error_codes_are_explicit_and_stable() {
    assert_eq!(ProtocolErrorCode::UNSUPPORTED_VERSION.as_u16(), 1);
    assert_eq!(ProtocolErrorCode::UNKNOWN_MESSAGE.as_u16(), 2);
    assert_eq!(ProtocolErrorCode::INVALID_FRAME.as_u16(), 3);
    assert_eq!(ProtocolErrorCode::PAYLOAD_TOO_LARGE.as_u16(), 4);
    assert_eq!(ProtocolErrorCode::INVALID_STATE.as_u16(), 5);
    assert_eq!(ProtocolErrorCode::AUTHENTICATION_FAILED.as_u16(), 6);
    assert_eq!(ProtocolErrorCode::UNKNOWN_SESSION.as_u16(), 7);
    assert_eq!(ProtocolErrorCode::TUNNEL_REJECTED.as_u16(), 8);
    assert_eq!(ProtocolErrorCode::INTERNAL.as_u16(), 255);
}

#[test]
fn active_state_accepts_data_channel_control_notifications() {
    let state = ClientHandshakeState::new()
        .transition(&hello())
        .unwrap()
        .transition(&challenge())
        .unwrap()
        .transition(&authenticate())
        .unwrap()
        .transition(&auth_result(true))
        .unwrap()
        .transition(&registration())
        .unwrap();
    let token = bytes(&[9; MAX_BINDING_TOKEN_BYTES]);
    let tcp = Message::OpenTcpStream(OpenTcpStream {
        tunnel_id: 1,
        connection_id: 2,
        peer: SocketAddress::V4 {
            octets: [203, 0, 113, 1],
            port: 443,
        },
        binding_token: token.clone(),
    });
    let udp = Message::OpenUdpChannel(OpenUdpChannel {
        tunnel_id: 1,
        channel_id: 3,
        binding_token: token,
    });

    assert_eq!(state.transition(&tcp), Ok(state.clone()));
    assert_eq!(state.transition(&udp), Ok(state));
    assert_eq!(
        ClientHandshakeState::new().transition(&tcp),
        Err(StateError::invalid_state())
    );
}

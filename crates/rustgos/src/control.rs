use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::BytesMut;
use rustgo_protocol::{
    AuthResult, BoundedString, ClientHandshakeState, ErrorMessage, Frame, FrameCodec, FrameError,
    MAX_ERROR_DETAIL_BYTES, Message, ProtocolErrorCode, ProtocolVersion,
};
use rustgo_transport::TlsServer;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;

use crate::{
    auth::{AuthAttemptReservation, Authenticator, FailedAuthLimiter, TlsHandshakePermit},
    registry::ClientRegistry,
};

pub(crate) const SERVER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const MAX_CONTROL_PAYLOAD: usize = 70 * 1024;

pub(crate) struct ControlContext {
    tls_server: Arc<TlsServer>,
    authenticator: Authenticator,
    registry: ClientRegistry,
    limiter: FailedAuthLimiter,
    handshake_timeout: Duration,
    heartbeat_timeout: Duration,
}

impl ControlContext {
    pub(crate) fn new(
        tls_server: Arc<TlsServer>,
        authenticator: Authenticator,
        registry: ClientRegistry,
        limiter: FailedAuthLimiter,
        handshake_timeout: Duration,
        heartbeat_timeout: Duration,
    ) -> Self {
        Self {
            tls_server,
            authenticator,
            registry,
            limiter,
            handshake_timeout,
            heartbeat_timeout,
        }
    }
}

pub(crate) async fn serve_connection(
    context: ControlContext,
    socket: TcpStream,
    peer: SocketAddr,
    unauthenticated_permit: OwnedSemaphorePermit,
    tls_peer_permit: TlsHandshakePermit,
) -> Result<(), ControlError> {
    let handshake_deadline = tokio::time::Instant::now()
        .checked_add(context.handshake_timeout)
        .ok_or(ControlError::HandshakeTimeout)?;
    let stream = tokio::time::timeout_at(handshake_deadline, context.tls_server.handshake(socket))
        .await
        .map_err(|_| ControlError::HandshakeTimeout)??;
    let Some(mut auth_attempt) = context.limiter.reserve(peer.ip()) else {
        return Ok(());
    };
    let mut framed = FramedControl::new(stream);
    let authenticated = tokio::time::timeout_at(handshake_deadline, async {
        let mut state = ClientHandshakeState::new();
        let hello_frame = framed.receive().await?;
        let negotiated = match SERVER_VERSION.negotiate(hello_frame.version) {
            Ok(version) => version,
            Err(code) => {
                auth_attempt.fail();
                framed.send(SERVER_VERSION, protocol_error(code)).await?;
                return Ok(None);
            }
        };
        let Message::ClientHello(hello) = hello_frame.message else {
            return Err(ControlError::InvalidState);
        };
        state = state.transition(&Message::ClientHello(hello.clone()))?;
        let pending = context.authenticator.begin(hello, negotiated)?;
        let challenge = Message::ServerChallenge(pending.challenge()?);
        state = state.transition(&challenge)?;
        framed.send(negotiated, challenge).await?;

        let authentication_frame = framed.receive().await?;
        let Message::ClientAuthenticate(authentication) = authentication_frame.message else {
            return Err(ControlError::InvalidState);
        };
        state = state.transition(&Message::ClientAuthenticate(authentication.clone()))?;
        let identity = if authentication_frame.version == negotiated {
            context.authenticator.finish(pending, authentication).ok()
        } else {
            None
        };
        let guard = identity.and_then(|identity| context.registry.claim(identity).ok());
        let accepted = guard.is_some();
        let result = Message::AuthResult(AuthResult {
            accepted,
            error: (!accepted).then_some(ProtocolErrorCode::AUTHENTICATION_FAILED),
        });
        state = state.transition(&result)?;
        send_auth_result(&mut framed, &mut auth_attempt, negotiated, result, accepted).await?;
        if accepted {
            Ok(Some((guard.expect("accepted guard"), state, negotiated)))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(|_| ControlError::HandshakeTimeout)??;

    drop(unauthenticated_permit);
    drop(tls_peer_permit);
    let Some((mut guard, mut state, negotiated)) = authenticated else {
        return Ok(());
    };

    let registration_frame = tokio::time::timeout(context.heartbeat_timeout, framed.receive())
        .await
        .map_err(|_| ControlError::HeartbeatTimeout)??;
    if registration_frame.version != negotiated {
        return Err(ControlError::InvalidState);
    }
    let Message::RegisterTunnels(registration) = registration_frame.message else {
        return Err(ControlError::InvalidState);
    };
    state = state.transition(&Message::RegisterTunnels(registration.clone()))?;
    let results = guard.register_tunnels(registration).await;
    framed
        .send(negotiated, Message::TunnelResults(results))
        .await?;

    loop {
        let frame = tokio::time::timeout(context.heartbeat_timeout, framed.receive())
            .await
            .map_err(|_| ControlError::HeartbeatTimeout)??;
        if frame.version != negotiated {
            return Err(ControlError::InvalidState);
        }
        match frame.message {
            Message::Heartbeat(heartbeat) => {
                state = state.transition(&Message::Heartbeat(heartbeat))?;
            }
            _ => return Err(ControlError::InvalidState),
        }
    }
}

fn protocol_error(code: ProtocolErrorCode) -> Message {
    Message::Error(ErrorMessage {
        code,
        detail: BoundedString::<MAX_ERROR_DETAIL_BYTES>::try_from("protocol rejected")
            .expect("static detail is bounded"),
    })
}

async fn send_auth_result<S>(
    framed: &mut FramedControl<S>,
    attempt: &mut AuthAttemptReservation,
    version: ProtocolVersion,
    result: Message,
    accepted: bool,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if accepted {
        attempt.succeed();
    } else {
        attempt.fail();
    }
    framed.send(version, result).await
}

struct FramedControl<S> {
    stream: S,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl<S> FramedControl<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(MAX_CONTROL_PAYLOAD),
        }
    }

    async fn receive(&mut self) -> Result<Frame, ControlError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.read_buffer)? {
                return Ok(frame);
            }
            if self.read_buffer.len() >= MAX_CONTROL_PAYLOAD + rustgo_protocol::HEADER_LEN {
                return Err(ControlError::FrameTooLarge);
            }
            if self.stream.read_buf(&mut self.read_buffer).await? == 0 {
                return Err(ControlError::Closed);
            }
        }
    }

    async fn send(
        &mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), ControlError> {
        let frame = self.codec.encode(version, 0, &message)?;
        self.stream.write_all(&frame).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub(crate) enum ControlError {
    #[error("TLS transport failed: {0}")]
    Tls(#[from] rustgo_transport::TlsError),
    #[error("control frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("control I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("authentication failed: {0}")]
    Auth(#[from] crate::auth::AuthError),
    #[error("protocol state failed: {0}")]
    State(#[from] rustgo_protocol::StateError),
    #[error("control handshake timed out")]
    HandshakeTimeout,
    #[error("control heartbeat timed out")]
    HeartbeatTimeout,
    #[error("control connection closed")]
    Closed,
    #[error("control frame exceeded the configured maximum")]
    FrameTooLarge,
    #[error("invalid control protocol state")]
    InvalidState,
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use rustgo_protocol::{AuthResult, Message, ProtocolErrorCode};

    use super::{FramedControl, SERVER_VERSION, send_auth_result};
    use crate::auth::FailedAuthLimiter;

    #[tokio::test]
    async fn rejected_auth_is_charged_before_a_failed_result_write() {
        let limiter = FailedAuthLimiter::new(1, Duration::from_secs(60), 4, 4);
        let peer = IpAddr::from([192, 0, 2, 70]);
        let mut attempt = limiter.reserve(peer).unwrap();
        let (stream, closed_peer) = tokio::io::duplex(1024);
        drop(closed_peer);
        let mut framed = FramedControl::new(stream);
        let result = Message::AuthResult(AuthResult {
            accepted: false,
            error: Some(ProtocolErrorCode::AUTHENTICATION_FAILED),
        });

        assert!(
            send_auth_result(&mut framed, &mut attempt, SERVER_VERSION, result, false)
                .await
                .is_err()
        );
        drop(attempt);

        assert!(limiter.reserve(peer).is_none());
    }
}

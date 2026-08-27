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
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{AuthAttemptReservation, Authenticator, FailedAuthLimiter, TlsHandshakePermit},
    registry::{ClientRegistry, ControlSessionGuard},
    tcp,
};

pub(crate) const SERVER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const MAX_CONTROL_PAYLOAD: usize = 70 * 1024;
const CONTROL_COMMAND_CAPACITY: usize = 1024;

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
    shutdown: CancellationToken,
) -> Result<(), ControlError> {
    let handshake_deadline = tokio::time::Instant::now()
        .checked_add(context.handshake_timeout)
        .ok_or(ControlError::HandshakeTimeout)?;
    let stream = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout_at(handshake_deadline, context.tls_server.handshake(socket)) => {
            result.map_err(|_| ControlError::HandshakeTimeout)??
        }
    };
    let mut framed = FramedControl::new(stream);
    let first_frame = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout_at(handshake_deadline, framed.receive()) => {
            result.map_err(|_| ControlError::HandshakeTimeout)??
        }
    };
    if let Message::DataChannelBind(request) = first_frame.message {
        drop(unauthenticated_permit);
        drop(tls_peer_permit);
        return tokio::select! {
            biased;
            () = shutdown.cancelled() => Ok(()),
            result = tcp::serve_data_connection(
                context.registry,
                framed,
                first_frame.version,
                request,
            ) => result.map_err(Into::into),
        };
    }
    let Message::ClientHello(hello) = first_frame.message else {
        return Err(ControlError::InvalidState);
    };
    let Some(mut auth_attempt) = context.limiter.reserve(peer.ip()) else {
        return Ok(());
    };
    let (outbound, outbound_rx) = mpsc::channel(CONTROL_COMMAND_CAPACITY);
    let authenticated = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout_at(handshake_deadline, async {
            let mut state = ClientHandshakeState::new();
            let negotiated = match SERVER_VERSION.negotiate(first_frame.version) {
                Ok(version) => version,
                Err(code) => {
                    auth_attempt.fail();
                    framed.send(SERVER_VERSION, protocol_error(code)).await?;
                    return Ok(None);
                }
            };
            if hello.heartbeat_interval_secs == 0
                || u64::from(hello.heartbeat_interval_secs) >= context.heartbeat_timeout.as_secs()
            {
                auth_attempt.fail();
                framed
                    .send(
                        negotiated,
                        protocol_error(ProtocolErrorCode::INCOMPATIBLE_HEARTBEAT),
                    )
                    .await?;
                return Ok(None);
            }
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
            let guard = identity.and_then(|identity| {
                context
                    .registry
                    .claim_with_outbound(identity, outbound.clone())
                    .ok()
            });
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
        }) => result.map_err(|_| ControlError::HandshakeTimeout)??,
    };

    drop(unauthenticated_permit);
    drop(tls_peer_permit);
    let Some((guard, state, negotiated)) = authenticated else {
        return Ok(());
    };

    run_owned_control_session(
        framed,
        guard,
        state,
        negotiated,
        context.heartbeat_timeout,
        outbound_rx,
        shutdown,
    )
    .await
}

async fn run_owned_control_session<S>(
    mut framed: FramedControl<S>,
    mut guard: ControlSessionGuard,
    mut state: ClientHandshakeState,
    negotiated: ProtocolVersion,
    heartbeat_timeout: Duration,
    mut outbound_rx: mpsc::Receiver<Message>,
    shutdown: CancellationToken,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = tokio::select! {
        biased;
        () = shutdown.cancelled() => Ok(()),
        result = run_control_session(
            &mut framed,
            &mut guard,
            &mut state,
            negotiated,
            heartbeat_timeout,
            &mut outbound_rx,
        ) => result,
    };
    guard.shutdown().await;
    result
}

async fn run_control_session<S>(
    framed: &mut FramedControl<S>,
    guard: &mut ControlSessionGuard,
    state: &mut ClientHandshakeState,
    negotiated: ProtocolVersion,
    heartbeat_timeout: Duration,
    outbound_rx: &mut mpsc::Receiver<Message>,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let registration_frame = tokio::time::timeout(heartbeat_timeout, framed.receive())
        .await
        .map_err(|_| ControlError::HeartbeatTimeout)??;
    if registration_frame.version != negotiated {
        return Err(ControlError::InvalidState);
    }
    let Message::RegisterTunnels(registration) = registration_frame.message else {
        return Err(ControlError::InvalidState);
    };
    *state = state.transition(&Message::RegisterTunnels(registration.clone()))?;
    let results = guard.register_tunnels(registration).await;
    framed
        .send(negotiated, Message::TunnelResults(results))
        .await?;

    tracing::info!(client = %guard.identity().name(), listeners = guard.listener_count(), "event=registration_ready server tunnel registration ready");
    run_active_control(
        framed,
        guard,
        state,
        negotiated,
        heartbeat_timeout,
        outbound_rx,
    )
    .await
}

async fn run_active_control<S>(
    framed: &mut FramedControl<S>,
    guard: &mut ControlSessionGuard,
    state: &mut ClientHandshakeState,
    negotiated: ProtocolVersion,
    heartbeat_timeout: Duration,
    outbound: &mut mpsc::Receiver<Message>,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let heartbeat_deadline = tokio::time::sleep(heartbeat_timeout);
    tokio::pin!(heartbeat_deadline);
    loop {
        tokio::select! {
            biased;
            () = &mut heartbeat_deadline => return Err(ControlError::HeartbeatTimeout),
            outbound_message = outbound.recv() => {
                let Some(message) = outbound_message else {
                    return Err(ControlError::Closed);
                };
                *state = state.transition(&message)?;
                let write = framed.send(negotiated, message);
                tokio::select! {
                    biased;
                    () = &mut heartbeat_deadline => return Err(ControlError::HeartbeatTimeout),
                    result = write => result?,
                }
            }
            frame = framed.receive() => {
                let frame = frame?;
                if frame.version != negotiated {
                    return Err(ControlError::InvalidState);
                }
                match frame.message {
                    Message::Heartbeat(heartbeat) => {
                        let acknowledgement = Message::Heartbeat(heartbeat);
                        *state = state.transition(&acknowledgement)?;
                        let write = framed.send(negotiated, acknowledgement);
                        tokio::select! {
                            biased;
                            () = &mut heartbeat_deadline => return Err(ControlError::HeartbeatTimeout),
                            result = write => result?,
                        }
                        heartbeat_deadline.as_mut().reset(
                            tokio::time::Instant::now()
                                .checked_add(heartbeat_timeout)
                                .ok_or(ControlError::HeartbeatTimeout)?,
                        );
                    }
                    Message::TcpStreamReady(ready) if !ready.accepted => {
                        *state = state.transition(&Message::TcpStreamReady(ready.clone()))?;
                        guard.reject_tcp(ready.connection_id);
                    }
                    _ => return Err(ControlError::InvalidState),
                }
            }
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

pub(crate) struct FramedControl<S> {
    stream: S,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl<S> FramedControl<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(MAX_CONTROL_PAYLOAD),
        }
    }

    pub(crate) async fn receive(&mut self) -> Result<Frame, ControlError> {
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

    pub(crate) async fn send(
        &mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), ControlError> {
        let frame = self.codec.encode(version, 0, &message)?;
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    pub(crate) fn is_buffer_empty(&self) -> bool {
        self.read_buffer.is_empty()
    }

    pub(crate) fn into_stream(self) -> Result<S, ControlError> {
        if self.read_buffer.is_empty() {
            Ok(self.stream)
        } else {
            Err(ControlError::InvalidState)
        }
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
    use std::{
        io,
        net::{IpAddr, Ipv4Addr},
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use rustgo_protocol::{
        AuthResult, BoundedString, BoundedVec, ClientHandshakeState, FrameCodec, Message,
        ProtocolErrorCode, RegisterTunnels, TunnelProtocol, TunnelRegistration,
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        sync::mpsc,
    };
    use tokio_util::sync::CancellationToken;

    use super::{FramedControl, SERVER_VERSION, run_owned_control_session, send_auth_result};
    use crate::{AuthenticatedClient, auth::FailedAuthLimiter, registry::ClientRegistry};

    struct RegistrationThenWriteFailure {
        input: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for RegistrationThenWriteFailure {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let available = self.input.get_ref().len() - self.input.position() as usize;
            let read = available.min(buffer.remaining());
            if read != 0 {
                let start = self.input.position() as usize;
                buffer.put_slice(&self.input.get_ref()[start..start + read]);
                self.input.set_position((start + read) as u64);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RegistrationThenWriteFailure {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "scripted registration reply failure",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

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

    #[tokio::test]
    async fn tunnel_results_write_failure_joins_listener_before_releasing_identity() {
        let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let registry = ClientRegistry::new(
            1,
            1,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            1,
            Duration::from_secs(30),
        )
        .unwrap();
        let session_id = vec![0x51; 32];
        let identity = AuthenticatedClient::verified(
            "home-pc".to_owned(),
            "sha256:test".to_owned(),
            session_id.clone(),
        );
        let (outbound, outbound_rx) = mpsc::channel(1);
        let guard = registry.claim_with_outbound(identity, outbound).unwrap();
        let registration = Message::RegisterTunnels(RegisterTunnels {
            tunnels: BoundedVec::try_from(vec![TunnelRegistration {
                tunnel_id: 1,
                name: BoundedString::try_from("ssh").unwrap(),
                protocol: TunnelProtocol::TCP,
                remote_port: port,
            }])
            .unwrap(),
        });
        let encoded = FrameCodec::new(70 * 1024)
            .encode(SERVER_VERSION, 0, &registration)
            .unwrap();
        let framed = FramedControl::new(RegistrationThenWriteFailure {
            input: std::io::Cursor::new(encoded.to_vec()),
        });
        let state = ClientHandshakeState::AwaitingTunnelRegistration {
            session_id: rustgo_protocol::BoundedBytes::try_from(session_id.as_slice()).unwrap(),
        };

        let result = run_owned_control_session(
            framed,
            guard,
            state,
            SERVER_VERSION,
            Duration::from_secs(2),
            outbound_rx,
            CancellationToken::new(),
        )
        .await;

        assert!(matches!(result, Err(super::ControlError::Io(_))));
        assert_eq!(registry.active_count(), 0);
        let rebound = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        drop(rebound);
    }
}

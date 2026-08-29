use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use bytes::BytesMut;
use rustgo_protocol::{
    AuthResult, BoundedString, ClientHandshakeState, ErrorMessage, Frame, FrameCodec, FrameError,
    MAX_ERROR_DETAIL_BYTES, Message, ProtocolErrorCode, ProtocolVersion,
};
use rustgo_rendezvous::{RendezvousEnvelope, RendezvousPayload};
use rustgo_transport::{EventRateLimit, TlsServer, safe_display, short_fingerprint};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::{
    auth::{AuthAttemptReservation, Authenticator, FailedAuthLimiter, TlsHandshakePermit},
    observation::ObservationTokenIssuer,
    registry::{ClientRegistry, ControlSessionGuard},
    rendezvous::RendezvousCoordinator,
    tcp, udp,
};

pub(crate) const SERVER_VERSION: ProtocolVersion = ProtocolVersion::SUPPORTED;
const MAX_CONTROL_PAYLOAD: usize = 70 * 1024;
const CONTROL_COMMAND_CAPACITY: usize = 1024;
const AUTH_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(5);
static AUTH_FAILURE_LOG: OnceLock<EventRateLimit> = OnceLock::new();

pub(crate) struct ControlContext {
    tls_server: Arc<TlsServer>,
    authenticator: Authenticator,
    registry: ClientRegistry,
    limiter: FailedAuthLimiter,
    runtime: ControlRuntime,
}

pub(crate) struct ControlRuntime {
    handshake_timeout: Duration,
    heartbeat_timeout: Duration,
    version: ProtocolVersion,
    observation_token_issuer: Option<ObservationTokenIssuer>,
    rendezvous: RendezvousCoordinator,
}

impl ControlRuntime {
    pub(crate) fn new(
        handshake_timeout: Duration,
        heartbeat_timeout: Duration,
        version: ProtocolVersion,
        observation_token_issuer: Option<ObservationTokenIssuer>,
        rendezvous: RendezvousCoordinator,
    ) -> Self {
        Self {
            handshake_timeout,
            heartbeat_timeout,
            version,
            observation_token_issuer,
            rendezvous,
        }
    }
}

impl ControlContext {
    pub(crate) fn new_with_version(
        tls_server: Arc<TlsServer>,
        authenticator: Authenticator,
        registry: ClientRegistry,
        limiter: FailedAuthLimiter,
        runtime: ControlRuntime,
    ) -> Self {
        Self {
            tls_server,
            authenticator,
            registry,
            limiter,
            runtime,
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
        .checked_add(context.runtime.handshake_timeout)
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
        let result = if request.kind == rustgo_protocol::DataChannelKind::UDP {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => Ok(()),
                result = udp::serve_data_connection(
                    context.registry,
                    framed,
                    first_frame.version,
                    request,
                ) => result.map_err(Into::into),
            }
        } else {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => Ok(()),
                result = tcp::serve_data_connection(
                    context.registry,
                    framed,
                    first_frame.version,
                    request,
                ) => result.map_err(Into::into),
            }
        };
        // Data-bind admission covers identity lookup, one-time token redemption,
        // acknowledgement, and delivery to the owning control session.
        drop(unauthenticated_permit);
        drop(tls_peer_permit);
        return result;
    }
    let Message::ClientHello(hello) = first_frame.message else {
        return Err(ControlError::InvalidState);
    };
    let claimed_client = hello.client_name.as_str().to_owned();
    let claimed_fingerprint = std::str::from_utf8(hello.fingerprint.as_slice())
        .ok()
        .map(|value| short_fingerprint(&format!("sha256:{value}")))
        .unwrap_or_else(|| "invalid".to_owned());
    let Some(mut auth_attempt) = context.limiter.reserve(peer.ip()) else {
        return Ok(());
    };
    let (outbound, outbound_rx) = mpsc::channel(CONTROL_COMMAND_CAPACITY);
    let authenticated = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout_at(handshake_deadline, async {
            let mut state = ClientHandshakeState::new();
            let negotiated = match context.runtime.version.negotiate(first_frame.version) {
                Ok(version) => version,
                Err(code) => {
                    auth_attempt.fail();
                    framed
                        .send(context.runtime.version, protocol_error(code))
                        .await?;
                    return Ok(None);
                }
            };
            if hello.heartbeat_interval_secs == 0
                || u64::from(hello.heartbeat_interval_secs)
                    >= context.runtime.heartbeat_timeout.as_secs()
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
                    .claim_with_outbound(identity, outbound.clone(), negotiated)
                    .ok()
            });
            let accepted = guard.is_some();
            if let Some(guard) = guard.as_ref() {
                tracing::info!(
                    client = %safe_display(guard.identity().name()),
                    fingerprint = %safe_display(short_fingerprint(guard.identity().fingerprint())),
                    event = %"auth_ok",
                    "client authenticated"
                );
            } else if AUTH_FAILURE_LOG
                .get_or_init(|| EventRateLimit::new(AUTH_FAILURE_LOG_INTERVAL))
                .allow()
            {
                tracing::warn!(
                    client = %safe_display(&claimed_client),
                    fingerprint = %safe_display(&claimed_fingerprint),
                    event = %"auth_failed",
                    "client authentication rejected"
                );
            }
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
        outbound_rx,
        context.runtime,
        shutdown,
    )
    .await
}

async fn run_owned_control_session<S>(
    mut framed: FramedControl<S>,
    mut guard: ControlSessionGuard,
    mut state: ClientHandshakeState,
    negotiated: ProtocolVersion,
    mut outbound_rx: mpsc::Receiver<Message>,
    runtime: ControlRuntime,
    shutdown: CancellationToken,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let span = tracing::info_span!(
        "control_session",
        client = %safe_display(guard.identity().name()),
        fingerprint = %safe_display(short_fingerprint(guard.identity().fingerprint())),
        event = %"control_session"
    );
    async move {
        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => Ok(()),
            result = run_control_session(
                &mut framed,
                &mut guard,
                &mut state,
                negotiated,
                &mut outbound_rx,
                &runtime,
            ) => result,
        };
        let identity = guard.identity().clone();
        guard.mark_unavailable();
        runtime.rendezvous.remove_device(&identity).await;
        guard.shutdown().await;
        result
    }
    .instrument(span)
    .await
}

async fn run_control_session<S>(
    framed: &mut FramedControl<S>,
    guard: &mut ControlSessionGuard,
    state: &mut ClientHandshakeState,
    negotiated: ProtocolVersion,
    outbound_rx: &mut mpsc::Receiver<Message>,
    runtime: &ControlRuntime,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let registration_frame = tokio::time::timeout(runtime.heartbeat_timeout, framed.receive())
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

    tracing::info!(
        client = %safe_display(guard.identity().name()),
        listeners = guard.listener_count(),
        protocol_major = negotiated.major,
        protocol_minor = negotiated.minor,
        local_protocol_minor = runtime.version.minor,
        "event=registration_ready server tunnel registration ready"
    );
    run_active_control(framed, guard, state, negotiated, outbound_rx, runtime).await
}

async fn run_active_control<S>(
    framed: &mut FramedControl<S>,
    guard: &mut ControlSessionGuard,
    state: &mut ClientHandshakeState,
    negotiated: ProtocolVersion,
    outbound: &mut mpsc::Receiver<Message>,
    runtime: &ControlRuntime,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let heartbeat_deadline = tokio::time::sleep(runtime.heartbeat_timeout);
    tokio::pin!(heartbeat_deadline);
    let generation_cancellation = guard.cancellation();
    loop {
        tokio::select! {
            biased;
            () = generation_cancellation.cancelled() => {
                return Err(ControlError::ListenerGenerationTerminated);
            }
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
                if is_v02_control_message(&frame.message) && !supports_v02(negotiated) {
                    send_active_message(
                        framed,
                        state,
                        negotiated,
                        protocol_error(ProtocolErrorCode::UNSUPPORTED_VERSION),
                        &mut heartbeat_deadline,
                    )
                    .await?;
                    continue;
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
                                .checked_add(runtime.heartbeat_timeout)
                                .ok_or(ControlError::HeartbeatTimeout)?,
                        );
                    }
                    Message::TcpStreamReady(ready) if !ready.accepted => {
                        *state = state.transition(&Message::TcpStreamReady(ready.clone()))?;
                        guard.reject_tcp(ready.connection_id);
                    }
                    Message::ObservationGrantRequest(request) => {
                        *state = state.transition(&Message::ObservationGrantRequest(request))?;
                        let response = runtime.observation_token_issuer.as_ref()
                            .ok_or(ControlError::ObservationUnavailable)
                            .and_then(|issuer| {
                                issuer
                                    .issue(guard.identity())
                                    .map_err(|_| ControlError::ObservationUnavailable)
                            })
                            .and_then(|grant| {
                                grant
                                    .to_protocol_message()
                                    .map_err(|_| ControlError::ObservationUnavailable)
                            })
                            .unwrap_or_else(|_| protocol_error(ProtocolErrorCode::UNKNOWN_SESSION));
                        send_active_message(
                            framed,
                            state,
                            negotiated,
                            response,
                            &mut heartbeat_deadline,
                        )
                        .await?;
                    }
                    Message::PeerIdentityLookup(lookup) => {
                        let response = runtime.rendezvous.identity_binding(guard, lookup)
                            .unwrap_or_else(|_| protocol_error(ProtocolErrorCode::UNKNOWN_SESSION));
                        send_active_message(
                            framed, state, negotiated, response, &mut heartbeat_deadline,
                        ).await?;
                    }
                    message if is_rendezvous_message(&message) => {
                        let envelope = match RendezvousEnvelope::from_protocol_message(message) {
                            Ok(envelope) => envelope,
                            Err(_) => {
                                send_active_message(
                                    framed,
                                    state,
                                    negotiated,
                                    protocol_error(ProtocolErrorCode::INVALID_FRAME),
                                    &mut heartbeat_deadline,
                                )
                                .await?;
                                continue;
                            }
                        };
                        let result = match &envelope.payload {
                            RendezvousPayload::Request(_) => {
                                runtime.rendezvous.request(guard, envelope.clone()).await.map(drop)
                            }
                            RendezvousPayload::ProviderDecision(_) => {
                                runtime.rendezvous.provider_decision(guard, envelope.clone()).await
                            }
                            RendezvousPayload::Close(_) | RendezvousPayload::Error(_) => {
                                runtime.rendezvous.close_session(guard, envelope.clone()).await
                            }
                            _ => runtime.rendezvous.forward_envelope(guard, envelope.clone()).await,
                        };
                        if let Err(error) = result {
                            send_active_message(
                                framed,
                                state,
                                negotiated,
                                runtime.rendezvous.error_response(
                                    &envelope,
                                    error,
                                ),
                                &mut heartbeat_deadline,
                            )
                            .await?;
                        }
                    }
                    Message::PeerRelayFrame(opaque) => {
                        let message = Message::PeerRelayFrame(opaque);
                        let result = match rustgo_rendezvous::PeerRelayFrame::from_protocol_message(message) {
                            Ok(frame) => runtime.rendezvous.forward_relay_frame(guard, frame).await
                                .map_err(|_| ControlError::InvalidState),
                            Err(_) => {
                                tracing::warn!(
                                    sender = guard.identity().name(),
                                    reason = "malformed_frame",
                                    event = "peer_relay_frame_rejected",
                                    "peer relay frame rejected"
                                );
                                Err(ControlError::InvalidState)
                            }
                        };
                        if result.is_err() {
                            send_active_message(
                                framed, state, negotiated,
                                protocol_error(ProtocolErrorCode::INVALID_STATE),
                                &mut heartbeat_deadline,
                            ).await?;
                        }
                    }
                    Message::ObservationGrant(_)
                    | Message::ServerNotice(_)
                    | Message::PeerIdentityBinding(_) => {
                        send_active_message(
                            framed,
                            state,
                            negotiated,
                            protocol_error(ProtocolErrorCode::UNKNOWN_MESSAGE),
                            &mut heartbeat_deadline,
                        )
                        .await?;
                    }
                    _ => return Err(ControlError::InvalidState),
                }
            }
        }
    }
}

async fn send_active_message<S>(
    framed: &mut FramedControl<S>,
    state: &mut ClientHandshakeState,
    negotiated: ProtocolVersion,
    message: Message,
    heartbeat_deadline: &mut std::pin::Pin<&mut tokio::time::Sleep>,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    *state = state.transition(&message)?;
    let write = framed.send(negotiated, message);
    tokio::select! {
        biased;
        () = heartbeat_deadline => Err(ControlError::HeartbeatTimeout),
        result = write => result,
    }
}

fn supports_v02(version: ProtocolVersion) -> bool {
    version.major == ProtocolVersion::V0_2.major && version.minor >= ProtocolVersion::V0_2.minor
}

fn is_v02_control_message(message: &Message) -> bool {
    matches!(
        message,
        Message::ObservationGrantRequest(_)
            | Message::ObservationGrant(_)
            | Message::ServerNotice(_)
            | Message::RendezvousRequest(_)
            | Message::RendezvousProviderDecision(_)
            | Message::RendezvousCandidateSet(_)
            | Message::RendezvousCandidateSetV2(_)
            | Message::RendezvousConnectivityResult(_)
            | Message::RendezvousRelayRequest(_)
            | Message::RendezvousClose(_)
            | Message::RendezvousError(_)
            | Message::PeerRelayFrame(_)
            | Message::PeerIdentityBinding(_)
            | Message::PeerIdentityLookup(_)
            | Message::PunchGrant(_)
    )
}

fn is_rendezvous_message(message: &Message) -> bool {
    matches!(
        message,
        Message::RendezvousRequest(_)
            | Message::RendezvousProviderDecision(_)
            | Message::RendezvousCandidateSet(_)
            | Message::RendezvousCandidateSetV2(_)
            | Message::RendezvousConnectivityResult(_)
            | Message::RendezvousRelayRequest(_)
            | Message::RendezvousClose(_)
            | Message::RendezvousError(_)
    )
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
    #[error("a registered listener terminated its control generation")]
    ListenerGenerationTerminated,
    #[error("authenticated observation grant is unavailable")]
    ObservationUnavailable,
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

    use super::{
        ControlRuntime, FramedControl, SERVER_VERSION, run_owned_control_session, send_auth_result,
    };
    use crate::{
        AuthenticatedClient,
        auth::FailedAuthLimiter,
        registry::ClientRegistry,
        rendezvous::{RendezvousCoordinator, RendezvousLimits},
    };

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
        let guard = registry
            .claim_with_outbound(identity, outbound, SERVER_VERSION)
            .unwrap();
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
        let rendezvous = RendezvousCoordinator::new(
            registry.clone(),
            &[],
            RendezvousLimits {
                max_sessions: 1,
                max_sessions_per_device: 1,
                session_ttl: Duration::from_secs(1),
            },
        );

        let result = run_owned_control_session(
            framed,
            guard,
            state,
            SERVER_VERSION,
            outbound_rx,
            ControlRuntime::new(
                Duration::from_secs(2),
                Duration::from_secs(2),
                SERVER_VERSION,
                None,
                rendezvous,
            ),
            CancellationToken::new(),
        )
        .await;

        assert!(matches!(result, Err(super::ControlError::Io(_))));
        assert_eq!(registry.active_count(), 0);
        let rebound = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        drop(rebound);
    }
}

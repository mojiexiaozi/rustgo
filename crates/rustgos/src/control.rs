use std::{
    io,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use bytes::BytesMut;
use rustgo_crypto::DevicePublicKey;
use rustgo_observability::{HostMetrics, ObservationEvent};
use rustgo_protocol::{
    AuthResult, BoundedString, ClientHandshakeState, ControlMessageDirection,
    ENROLLMENT_PROTOCOL_VERSION, EnrollmentErrorCode, EnrollmentResultMessage, ErrorMessage, Frame,
    FrameCodec, FrameError, MAX_CLIENT_NAME_BYTES, MAX_ERROR_DETAIL_BYTES, Message,
    ProtocolErrorCode, ProtocolVersion, TelemetryReport,
};
use rustgo_rendezvous::{RendezvousEnvelope, RendezvousPayload};
use rustgo_transport::{EventRateLimit, TlsServer, safe_display, short_fingerprint};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::web::EnrollmentManagement;
use crate::{
    auth::{AuthAttemptReservation, Authenticator, FailedAuthLimiter, TlsHandshakePermit},
    enrollment::EnrollmentStoreError,
    observation::ObservationTokenIssuer,
    registry::{ClientRegistry, ControlSessionGuard, now_unix_millis},
    rendezvous::RendezvousCoordinator,
    tcp, udp,
};

pub(crate) const SERVER_VERSION: ProtocolVersion = ProtocolVersion::SUPPORTED;
const MAX_CONTROL_PAYLOAD: usize = 70 * 1024;
const CONTROL_COMMAND_CAPACITY: usize = 1024;
const AUTH_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(5);
const MIN_TELEMETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_TELEMETRY_SAMPLE_AGE_MILLIS: u64 = 10 * 60 * 1_000;
const MAX_TELEMETRY_FUTURE_SKEW_MILLIS: u64 = 5 * 60 * 1_000;
static AUTH_FAILURE_LOG: OnceLock<EventRateLimit> = OnceLock::new();

pub(crate) struct ControlContext {
    tls_server: Arc<TlsServer>,
    authenticator: Authenticator,
    registry: ClientRegistry,
    limiter: FailedAuthLimiter,
    enrollment: Option<EnrollmentManagement>,
    runtime: ControlRuntime,
}

pub(crate) struct ControlRuntime {
    handshake_timeout: Duration,
    heartbeat_timeout: Duration,
    version: ProtocolVersion,
    observation_token_issuer: Option<ObservationTokenIssuer>,
    rendezvous: RendezvousCoordinator,
    managed: Option<crate::TunnelManagement>,
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
            managed: None,
        }
    }

    pub(crate) fn with_managed_tunnels(mut self, managed: Option<crate::TunnelManagement>) -> Self {
        self.managed = managed;
        self
    }
}

impl ControlContext {
    pub(crate) fn new_with_version(
        tls_server: Arc<TlsServer>,
        authenticator: Authenticator,
        registry: ClientRegistry,
        limiter: FailedAuthLimiter,
        enrollment: Option<EnrollmentManagement>,
        runtime: ControlRuntime,
    ) -> Self {
        Self {
            tls_server,
            authenticator,
            registry,
            limiter,
            enrollment,
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
    if let Message::EnrollmentRequest(request) = first_frame.message {
        let Some(mut auth_attempt) = context.limiter.reserve(peer.ip()) else {
            return Ok(());
        };
        let result = serve_enrollment(
            &mut framed,
            context.enrollment,
            request,
            first_frame.version,
            handshake_deadline,
        )
        .await;
        if matches!(result, Ok(true)) {
            auth_attempt.succeed();
        } else {
            auth_attempt.fail();
        }
        drop(unauthenticated_permit);
        drop(tls_peer_permit);
        return result.map(drop);
    }
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
                    "客户端认证成功"
                );
            } else if AUTH_FAILURE_LOG
                .get_or_init(|| EventRateLimit::new(AUTH_FAILURE_LOG_INTERVAL))
                .allow()
            {
                tracing::warn!(
                    client = %safe_display(&claimed_client),
                    fingerprint = %safe_display(&claimed_fingerprint),
                    event = %"auth_failed",
                    "客户端认证被拒绝"
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

async fn serve_enrollment<S>(
    framed: &mut FramedControl<S>,
    management: Option<EnrollmentManagement>,
    request: rustgo_protocol::EnrollmentRequest,
    client_version: ProtocolVersion,
    deadline: tokio::time::Instant,
) -> Result<bool, ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let negotiated = match SERVER_VERSION.negotiate(client_version) {
        Ok(version) => version,
        Err(_) => {
            framed
                .send(
                    SERVER_VERSION,
                    enrollment_failure(EnrollmentErrorCode::UnsupportedVersion),
                )
                .await?;
            return Ok(false);
        }
    };
    if request.protocol_version != ENROLLMENT_PROTOCOL_VERSION {
        framed
            .send(
                negotiated,
                enrollment_failure(EnrollmentErrorCode::UnsupportedVersion),
            )
            .await?;
        return Ok(false);
    }
    let Some(management) = management else {
        framed
            .send(
                negotiated,
                enrollment_failure(EnrollmentErrorCode::Unavailable),
            )
            .await?;
        return Ok(false);
    };
    let public_key = match std::str::from_utf8(request.public_key.as_slice())
        .ok()
        .and_then(|value| DevicePublicKey::from_str(value).ok())
    {
        Some(public_key) => public_key,
        None => {
            framed
                .send(
                    negotiated,
                    enrollment_failure(EnrollmentErrorCode::InvalidKey),
                )
                .await?;
            return Ok(false);
        }
    };
    let enrollment_key = request.enrollment_key.as_str().to_owned();
    let approval = rustgo_protocol::RegistrationIntent::decode(&enrollment_key).ok();
    if let Some(intent) = &approval {
        let transcript = rustgo_crypto::AuthTranscript::new(
            b"rustgo-approval-v1".to_vec(),
            request.request_id.as_str().as_bytes().to_vec(),
            1,
            intent.encode(),
        );
        if !intent.signature.as_ref().is_some_and(|proof| {
            rustgo_crypto::verify_auth(&public_key, &transcript, proof).is_ok()
        }) {
            framed
                .send(
                    negotiated,
                    enrollment_failure(EnrollmentErrorCode::InvalidKey),
                )
                .await?;
            return Ok(false);
        }
    }
    let reenrollment = rustgo_protocol::EnrollmentKeyMaterial::decode(&enrollment_key)
        .is_ok_and(|key| key.purpose() == rustgo_protocol::EnrollmentPurpose::ReEnroll);
    let request_id = request.request_id.as_str().to_owned();
    let registry = management.registry.clone();
    let result = tokio::time::timeout_at(
        deadline,
        tokio::task::spawn_blocking(move || {
            if let Some(intent) = approval {
                return management.store.request_approval(
                    &intent.client_name,
                    intent.purpose,
                    &public_key,
                    &request_id,
                    std::time::SystemTime::now(),
                );
            }
            management.store.consume_token(
                &enrollment_key,
                &public_key,
                &request_id,
                std::time::SystemTime::now(),
            )
        }),
    )
    .await;
    let (message, accepted) = match result {
        Ok(Ok(Ok(result))) => {
            if reenrollment && let Some(registry) = registry {
                registry.terminate_by_name(result.display_id());
            }
            (
                Message::EnrollmentResult(EnrollmentResultMessage {
                    protocol_version: ENROLLMENT_PROTOCOL_VERSION,
                    accepted: true,
                    client_id: Some(
                        BoundedString::<MAX_CLIENT_NAME_BYTES>::try_from(result.display_id())
                            .map_err(|_| ControlError::InvalidState)?,
                    ),
                    revision: Some(result.revision()),
                    error: None,
                }),
                true,
            )
        }
        Ok(Ok(Err(EnrollmentStoreError::ApprovalPending))) => (
            enrollment_failure(EnrollmentErrorCode::PendingApproval),
            true,
        ),
        Ok(Ok(Err(error))) => (enrollment_failure(map_enrollment_error(&error)), false),
        Ok(Err(_)) | Err(_) => (enrollment_failure(EnrollmentErrorCode::Unavailable), false),
    };
    tokio::time::timeout_at(deadline, framed.send(negotiated, message))
        .await
        .map_err(|_| ControlError::HandshakeTimeout)??;
    Ok(accepted)
}

fn enrollment_failure(error: EnrollmentErrorCode) -> Message {
    Message::EnrollmentResult(EnrollmentResultMessage {
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        accepted: false,
        client_id: None,
        revision: None,
        error: Some(error),
    })
}

fn map_enrollment_error(error: &EnrollmentStoreError) -> EnrollmentErrorCode {
    match error {
        EnrollmentStoreError::ApprovalPending => EnrollmentErrorCode::PendingApproval,
        EnrollmentStoreError::ApprovalRejected => EnrollmentErrorCode::ApprovalRejected,
        EnrollmentStoreError::TokenExpired => EnrollmentErrorCode::Expired,
        EnrollmentStoreError::TokenAlreadyUsed => EnrollmentErrorCode::AlreadyUsed,
        EnrollmentStoreError::PurposeMismatch => EnrollmentErrorCode::PurposeMismatch,
        EnrollmentStoreError::ClientDisabled => EnrollmentErrorCode::Disabled,
        EnrollmentStoreError::PublicKeyConflict | EnrollmentStoreError::StaticIdentityConflict => {
            EnrollmentErrorCode::PublicKeyConflict
        }
        EnrollmentStoreError::ClientCapacity | EnrollmentStoreError::TokenCapacity => {
            EnrollmentErrorCode::CapacityReached
        }
        EnrollmentStoreError::Database(_) | EnrollmentStoreError::UnsupportedSchema(_) => {
            EnrollmentErrorCode::Unavailable
        }
        _ => EnrollmentErrorCode::InvalidKey,
    }
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
    let mut managed_snapshot = None;
    if negotiated.supports_managed_configuration() {
        let frame = tokio::time::timeout(runtime.heartbeat_timeout, framed.receive())
            .await
            .map_err(|_| ControlError::HeartbeatTimeout)??;
        if frame.version != negotiated {
            return Err(ControlError::InvalidState);
        }
        *state = state.transition_control(
            negotiated,
            rustgo_protocol::ControlMessageDirection::ClientToServer,
            &frame.message,
        )?;
        let Message::ManagedConfigRequest(request) = frame.message else {
            return Err(ControlError::InvalidState);
        };
        let configuration: rustgo_config::ManagedConfiguration =
            serde_json::from_slice(request.configuration.as_slice())
                .map_err(|_| ControlError::InvalidState)?;
        configuration
            .validate()
            .map_err(|_| ControlError::InvalidState)?;
        let snapshot = if let Some(management) = runtime.managed.clone() {
            let authenticated = guard.identity().clone();
            Some(
                tokio::task::spawn_blocking(move || {
                    management.sync_authenticated(&authenticated, &configuration)
                })
                .await
                .map_err(|_| ControlError::InvalidState)??,
            )
        } else {
            None
        };
        let response = rustgo_protocol::ManagedConfigSnapshot {
            revision: snapshot.as_ref().map_or(0, |snapshot| snapshot.revision),
            configuration: snapshot
                .as_ref()
                .map(|snapshot| {
                    serde_json::to_vec(&snapshot.configuration)
                        .map_err(|_| ControlError::InvalidState)
                        .and_then(|bytes| bytes.try_into().map_err(|_| ControlError::InvalidState))
                })
                .transpose()?,
        };
        let message = Message::ManagedConfigSnapshot(response);
        *state = state.transition_control(
            negotiated,
            rustgo_protocol::ControlMessageDirection::ServerToClient,
            &message,
        )?;
        framed.send(negotiated, message).await?;
        managed_snapshot = snapshot;
    }
    let registration_frame = tokio::time::timeout(runtime.heartbeat_timeout, framed.receive())
        .await
        .map_err(|_| ControlError::HeartbeatTimeout)??;
    if registration_frame.version != negotiated {
        return Err(ControlError::InvalidState);
    }
    if let Message::ManagedConfigReport(report) = &registration_frame.message {
        *state = state.transition_control(
            negotiated,
            rustgo_protocol::ControlMessageDirection::ClientToServer,
            &registration_frame.message,
        )?;
        let snapshot = managed_snapshot
            .as_ref()
            .ok_or(ControlError::InvalidState)?;
        if report.revision != snapshot.revision {
            return Err(ControlError::InvalidState);
        }
        let results: serde_json::Value = serde_json::from_slice(report.results.as_slice())
            .map_err(|_| ControlError::InvalidState)?;
        if !results
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item["state"] == "failed"))
        {
            return Err(ControlError::InvalidState);
        }
        let management = runtime.managed.clone().ok_or(ControlError::InvalidState)?;
        let identity = snapshot.identity.clone();
        let revision = report.revision;
        tokio::task::spawn_blocking(move || management.store.report(&identity, revision, results))
            .await
            .map_err(|_| ControlError::InvalidState)??;
        return Err(ControlError::InvalidState);
    }
    let Message::RegisterTunnels(registration) = registration_frame.message else {
        return Err(ControlError::InvalidState);
    };
    if let Some(snapshot) = &managed_snapshot {
        let matches = registration.tunnels.as_slice().len() == snapshot.configuration.tunnels.len()
            && registration
                .tunnels
                .as_slice()
                .iter()
                .zip(&snapshot.configuration.tunnels)
                .enumerate()
                .all(|(index, (actual, expected))| {
                    actual.tunnel_id == (index + 1) as u32
                        && actual.name.as_str() == expected.name
                        && u32::from(actual.remote_port) == expected.remote_port
                        && actual.protocol
                            == match expected.protocol {
                                rustgo_config::TunnelProtocol::Tcp => {
                                    rustgo_protocol::TunnelProtocol::TCP
                                }
                                rustgo_config::TunnelProtocol::Udp => {
                                    rustgo_protocol::TunnelProtocol::UDP
                                }
                            }
                });
        if !matches {
            return Err(ControlError::InvalidState);
        }
    }
    *state = state.transition(&Message::RegisterTunnels(registration.clone()))?;
    let results = guard.register_tunnels(registration).await;
    guard.publish_tunnel_inventory();
    framed
        .send(negotiated, Message::TunnelResults(results))
        .await?;

    tracing::info!(
        client = %safe_display(guard.identity().name()),
        listeners = guard.listener_count(),
        protocol_major = negotiated.major,
        protocol_minor = negotiated.minor,
        local_protocol_minor = runtime.version.minor,
        "event=registration_ready 服务端隧道注册已就绪"
    );
    run_active_control(
        framed,
        guard,
        state,
        negotiated,
        outbound_rx,
        runtime,
        managed_snapshot.map(|snapshot| (snapshot.identity, snapshot.revision)),
    )
    .await
}

async fn run_active_control<S>(
    framed: &mut FramedControl<S>,
    guard: &mut ControlSessionGuard,
    state: &mut ClientHandshakeState,
    negotiated: ProtocolVersion,
    outbound: &mut mpsc::Receiver<Message>,
    runtime: &ControlRuntime,
    managed_binding: Option<(String, u64)>,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let heartbeat_deadline = tokio::time::sleep(runtime.heartbeat_timeout);
    tokio::pin!(heartbeat_deadline);
    let generation_cancellation = guard.cancellation();
    let mut telemetry = TelemetryAdmission::default();
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
                    Message::ManagedConfigReport(report) => {
                        *state = state.transition_control(negotiated, rustgo_protocol::ControlMessageDirection::ClientToServer, &Message::ManagedConfigReport(report.clone()))?;
                        let (identity, revision) = managed_binding.as_ref().ok_or(ControlError::InvalidState)?;
                        if report.revision != *revision { return Err(ControlError::InvalidState); }
                        let results = serde_json::from_slice(report.results.as_slice()).map_err(|_| ControlError::InvalidState)?;
                        let management = runtime.managed.clone().ok_or(ControlError::InvalidState)?;
                        let identity = identity.clone();
                        let result = tokio::task::spawn_blocking(move || management.store.report(&identity, report.revision, results)).await.map_err(|_| ControlError::InvalidState)?;
                        match result { Ok(()) | Err(crate::managed::ManagedError::Conflict) => {}, Err(error) => return Err(error.into()) }
                    }
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
                        guard.runtime_observe(ObservationEvent::Heartbeat {
                            client: guard.observability_identity().clone(),
                            received_unix_millis: now_unix_millis(),
                        });
                    }
                    Message::TelemetryReport(report) => {
                        *state = state.transition_control(
                            negotiated,
                            ControlMessageDirection::ClientToServer,
                            &Message::TelemetryReport(report.clone()),
                        )?;
                        let received_unix_millis = now_unix_millis();
                        if telemetry.accept(&report, received_unix_millis) {
                            guard.runtime_observe(ObservationEvent::ClientTelemetryAccepted {
                                client: guard.observability_identity().clone(),
                                sequence: report.sequence,
                                received_unix_millis,
                                metrics: telemetry_metrics(report),
                            });
                        }
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
                                    "对端中继帧被拒绝"
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

#[derive(Default)]
struct TelemetryAdmission {
    last_sequence: Option<u64>,
    last_sampled_unix_millis: Option<u64>,
    last_accepted: Option<tokio::time::Instant>,
}

impl TelemetryAdmission {
    fn accept(&mut self, report: &TelemetryReport, received_unix_millis: u64) -> bool {
        if !valid_telemetry_report(report, received_unix_millis)
            || self
                .last_sequence
                .is_some_and(|sequence| report.sequence <= sequence)
            || self
                .last_sampled_unix_millis
                .is_some_and(|sampled| report.sampled_unix_millis < sampled)
        {
            return false;
        }
        self.last_sequence = Some(report.sequence);
        self.last_sampled_unix_millis = Some(report.sampled_unix_millis);
        if self
            .last_accepted
            .is_some_and(|accepted| accepted.elapsed() < MIN_TELEMETRY_INTERVAL)
        {
            return false;
        }
        self.last_accepted = Some(tokio::time::Instant::now());
        true
    }
}

fn valid_telemetry_report(report: &TelemetryReport, received_unix_millis: u64) -> bool {
    report.sequence != 0
        && report.sampled_unix_millis != 0
        && report.cpu_basis_points <= 10_000
        && report.memory_used_bytes <= report.memory_total_bytes
        && report.disk_used_bytes <= report.disk_total_bytes
        && report.sampled_unix_millis
            <= received_unix_millis.saturating_add(MAX_TELEMETRY_FUTURE_SKEW_MILLIS)
        && received_unix_millis.saturating_sub(report.sampled_unix_millis)
            <= MAX_TELEMETRY_SAMPLE_AGE_MILLIS
}

fn telemetry_metrics(report: TelemetryReport) -> HostMetrics {
    let (memory_used_bytes, memory_total_bytes) = (report.memory_total_bytes != 0)
        .then_some((report.memory_used_bytes, report.memory_total_bytes))
        .unzip();
    let (disk_used_bytes, disk_total_bytes) = (report.disk_total_bytes != 0)
        .then_some((report.disk_used_bytes, report.disk_total_bytes))
        .unzip();
    HostMetrics {
        sampled_unix_millis: report.sampled_unix_millis,
        cpu_basis_points: Some(report.cpu_basis_points),
        process_cpu_basis_points: None,
        memory_used_bytes,
        memory_total_bytes,
        process_memory_bytes: None,
        disk_used_bytes,
        disk_total_bytes,
        disk_read_bytes_per_sec: None,
        disk_write_bytes_per_sec: None,
        network_rx_bytes_per_sec: Some(report.rx_bytes_per_sec),
        network_tx_bytes_per_sec: Some(report.tx_bytes_per_sec),
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
    #[error("managed configuration failed: {0}")]
    Managed(#[from] crate::managed::ManagedError),
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
        AuthResult, BoundedBytes, BoundedString, BoundedVec, ClientHandshakeState,
        ENROLLMENT_PROTOCOL_VERSION, EnrollmentErrorCode, EnrollmentPurpose, EnrollmentRequest,
        FrameCodec, MAX_ENROLLMENT_KEY_BYTES, MAX_ENROLLMENT_REQUEST_ID_BYTES,
        MAX_PUBLIC_KEY_BYTES, Message, ProtocolErrorCode, RegisterTunnels, TunnelProtocol,
        TunnelRegistration,
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        sync::mpsc,
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        ControlRuntime, FramedControl, SERVER_VERSION, map_enrollment_error,
        run_owned_control_session, send_auth_result, serve_enrollment,
    };
    use crate::web::EnrollmentManagement;
    use crate::{
        AuthenticatedClient,
        auth::FailedAuthLimiter,
        enrollment::{DynamicClientStore, EnrollmentStoreError, EnrollmentStoreLimits},
        registry::ClientRegistry,
        rendezvous::{RendezvousCoordinator, RendezvousLimits},
    };
    use rustgo_crypto::DeviceKeypair;
    use std::sync::Arc;

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
    async fn enrollment_dispatch_consumes_token_and_returns_safe_result() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            DynamicClientStore::open(
                directory.path().join("enrollment.db"),
                EnrollmentStoreLimits {
                    max_active_clients: 4,
                    max_tokens: 4,
                },
            )
            .unwrap(),
        );
        let client = store.create_client("Dynamic.Node").unwrap();
        let issued = store
            .issue_token(
                client.internal_id(),
                EnrollmentPurpose::Enroll,
                "server.example:7443",
                [3; 32],
                Duration::from_secs(60),
                1,
            )
            .unwrap()
            .into_encoded();
        let keypair = DeviceKeypair::from_secret_bytes([44; 32]);
        let request = EnrollmentRequest {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            enrollment_key: BoundedString::<MAX_ENROLLMENT_KEY_BYTES>::try_from(issued.as_str())
                .unwrap(),
            public_key: BoundedBytes::<MAX_PUBLIC_KEY_BYTES>::try_from(
                keypair.public_key().to_string().as_bytes(),
            )
            .unwrap(),
            request_id: BoundedString::<MAX_ENROLLMENT_REQUEST_ID_BYTES>::try_from("request-1")
                .unwrap(),
        };
        let management = EnrollmentManagement::new(
            Arc::clone(&store),
            "server.example:7443".to_owned(),
            [3; 32],
            Duration::from_secs(60),
        );
        let (server, client_stream) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_enrollment(
                &mut FramedControl::new(server),
                Some(management),
                request,
                SERVER_VERSION,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
        });
        let mut client_framed = FramedControl::new(client_stream);
        let frame = client_framed.receive().await.unwrap();
        let Message::EnrollmentResult(result) = frame.message else {
            panic!("expected enrollment result");
        };
        assert!(result.accepted);
        assert_eq!(result.client_id.unwrap().as_str(), "Dynamic.Node");
        assert_eq!(result.revision, Some(2));
        assert!(task.await.unwrap().unwrap());

        assert_eq!(
            map_enrollment_error(&EnrollmentStoreError::ClientNotFound),
            EnrollmentErrorCode::InvalidKey
        );
        assert_eq!(
            map_enrollment_error(&EnrollmentStoreError::Database("private".to_owned())),
            EnrollmentErrorCode::Unavailable
        );
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
            .claim_with_outbound(identity, outbound, rustgo_protocol::ProtocolVersion::V0_3)
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
            .encode(rustgo_protocol::ProtocolVersion::V0_3, 0, &registration)
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
            rustgo_protocol::ProtocolVersion::V0_3,
            outbound_rx,
            ControlRuntime::new(
                Duration::from_secs(2),
                Duration::from_secs(2),
                rustgo_protocol::ProtocolVersion::V0_3,
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

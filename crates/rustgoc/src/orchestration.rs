//! Production ownership for P2P control events and relay-backed forward I/O.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::Arc,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use rand::{TryRngCore as _, rngs::OsRng};
use rustgo_config::{ClientConfig, TunnelProtocol};
use rustgo_crypto::{
    DeviceKeypair, DevicePublicKey, EphemeralPeerKey, PeerRole, PeerSessionKeys, PeerTranscript,
    sign_peer_envelope, verify_peer_envelope,
};
use rustgo_path::{
    PathAttempt, PathError, PathKind, PathManager, PathManagerConfig, RecheckAttemptFactory,
    SelectedPath,
};
use rustgo_protocol::{BoundedBytes, BoundedString, BoundedVec, Message, PeerIdentityBinding};
use rustgo_rendezvous::{
    Candidate, CandidateGeneration, CandidateSetV2, CandidateTransport, ObservationEndpoint,
    ObservationGrant, ObservationNonce, ObservationProbe, ObservationReply, PeerRelayFrame,
    ProviderDecision, RelayRequest, RendezvousClose, RendezvousEnvelope, RendezvousPayload,
    RendezvousRequest, SessionId, TransportKeyBinding,
};
use rustgo_transport::{
    EncryptedPeerTcp, PeerAuthentication, PeerAuthenticationFactory, PeerDatagram,
    PeerTcpAuthentication, PeerTcpAuthenticationFactory, QuicPathAttempt, QuicPeerConfig,
    QuicPeerError, QuicPeerPathHandle, TcpPathAttempt,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    BoxPeerDatagramSession, BoxPeerStream, ChildSessionContext, ClientError, ControlEvent,
    ExportRegistry, ForwardConnector, ForwardRuntime, PeerDatagramSession, PeerFuture,
    PeerGenerationHandler, PeerOpenRequest, PeerRelayChannel,
};

const ACTOR_CAPACITY: usize = 1024;
const SESSION_FRAME_CAPACITY: usize = 128;
// Production rustgos defaults to a 30-second rendezvous ceiling.
const SESSION_TTL: Duration = Duration::from_secs(25);
const CHANNEL_ID: u64 = 1;
const AUTH_RECORD: &[u8] = b"rustgo-relay-auth-v1";
const OPEN_OK: &[u8] = b"rustgo-relay-open-ok-v1";
const OPEN_REJECTED: &[u8] = b"rustgo-relay-open-rejected-v1";
const MAX_RELAY_PLAINTEXT: usize = 60 * 1024;
type OpenReply = oneshot::Sender<io::Result<OpenedIo>>;

#[derive(Clone)]
pub(crate) struct ProductionPeerRuntime {
    commands: mpsc::Sender<ActorInput>,
    receiver: Arc<std::sync::Mutex<Option<mpsc::Receiver<ActorInput>>>>,
    config: Arc<ClientConfig>,
    keypair: Arc<DeviceKeypair>,
    exports: ExportRegistry,
}

impl ProductionPeerRuntime {
    pub(crate) fn new(
        config: Arc<ClientConfig>,
        keypair: Arc<DeviceKeypair>,
        exports: ExportRegistry,
    ) -> Self {
        let (commands, receiver) = mpsc::channel(ACTOR_CAPACITY);
        Self {
            commands,
            receiver: Arc::new(std::sync::Mutex::new(Some(receiver))),
            config,
            keypair,
            exports,
        }
    }

    async fn open(
        &self,
        peer: &str,
        export: &str,
        resolve_only: bool,
        cancellation: CancellationToken,
    ) -> io::Result<OpenedIo> {
        let (reply, response) = oneshot::channel();
        let command = ActorInput::Open {
            peer: peer.to_owned(),
            export: export.to_owned(),
            resolve_only,
            cancellation: cancellation.clone(),
            reply,
        };
        let sent = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(cancelled()),
            result = self.commands.send(command) => result,
        };
        sent.map_err(|_| closed())?;
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(cancelled()),
            result = response => result.map_err(|_| closed())?,
        };
        tracing::trace!(
            success = result.is_ok(),
            error = result.as_ref().err().map(ToString::to_string),
            "peer open command completed"
        );
        result
    }
}

impl PeerGenerationHandler for ProductionPeerRuntime {
    fn run_generation(
        &self,
        context: ChildSessionContext,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<(), ClientError>> + Send + 'static>> {
        let receiver = self.receiver.lock().ok().and_then(|mut value| value.take());
        let runtime = self.clone();
        Box::pin(async move {
            let Some(receiver) = receiver else {
                return Err(ClientError::PeerGenerationFailed);
            };
            let actor = tokio::spawn(
                Actor::new(runtime.clone(), context, receiver, shutdown.clone()).run(),
            );
            let forward = match ForwardRuntime::start(
                runtime.config.forwards.clone(),
                Arc::new(runtime.clone()),
                shutdown.child_token(),
            )
            .await
            {
                Ok(forward) => forward,
                Err(error) => {
                    tracing::error!(error = %error, "failed to start peer forwards");
                    shutdown.cancel();
                    let _ = actor_result(actor.await);
                    return Err(ClientError::PeerGenerationFailed);
                }
            };
            tracing::info!(event = %"peer_forwards_ready", "peer forward listeners ready");
            shutdown.cancelled().await;
            forward.shutdown().await;
            actor_result(actor.await)
        })
    }

    fn run_event(
        &self,
        _context: ChildSessionContext,
        event: ControlEvent,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let accepted =
            !shutdown.is_cancelled() && self.commands.try_send(ActorInput::Event(event)).is_ok();
        Box::pin(async move {
            if !accepted {
                tracing::warn!("peer event queue unavailable");
            }
        })
    }
}

fn actor_result(result: Result<io::Result<()>, tokio::task::JoinError>) -> Result<(), ClientError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            tracing::error!(error = %error, "peer orchestration generation teardown failed");
            Err(ClientError::PeerGenerationFailed)
        }
        Err(error) => {
            tracing::error!(error = %error, "peer orchestration actor task failed");
            Err(ClientError::TaskJoin)
        }
    }
}

impl ForwardConnector for ProductionPeerRuntime {
    fn protocol<'a>(&'a self, peer: &'a str, export: &'a str) -> PeerFuture<'a, TunnelProtocol> {
        Box::pin(async move {
            match self
                .open(peer, export, true, CancellationToken::new())
                .await?
            {
                OpenedIo::Protocol(protocol) => Ok(protocol),
                OpenedIo::Tcp(_) => Ok(TunnelProtocol::Tcp),
                OpenedIo::Udp(_) => Ok(TunnelProtocol::Udp),
            }
        })
    }

    fn open_tcp<'a>(
        &'a self,
        peer: &'a str,
        export: &'a str,
        cancellation: CancellationToken,
    ) -> PeerFuture<'a, BoxPeerStream> {
        Box::pin(async move {
            match self.open(peer, export, false, cancellation).await? {
                OpenedIo::Tcp(stream) => Ok(stream),
                OpenedIo::Udp(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "peer export is UDP",
                )),
                OpenedIo::Protocol(_) => Err(invalid()),
            }
        })
    }

    fn open_udp<'a>(
        &'a self,
        peer: &'a str,
        export: &'a str,
        cancellation: CancellationToken,
    ) -> PeerFuture<'a, BoxPeerDatagramSession> {
        Box::pin(async move {
            match self.open(peer, export, false, cancellation).await? {
                OpenedIo::Udp(session) => Ok(session),
                OpenedIo::Tcp(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "peer export is TCP",
                )),
                OpenedIo::Protocol(_) => Err(invalid()),
            }
        })
    }
}

enum ActorInput {
    Open {
        peer: String,
        export: String,
        resolve_only: bool,
        cancellation: CancellationToken,
        reply: oneshot::Sender<io::Result<OpenedIo>>,
    },
    Event(ControlEvent),
    PathSelected {
        session_id: SessionId,
        result: Result<SelectedPath, PathError>,
    },
    Promoted {
        session_id: SessionId,
        kind: PathKind,
    },
    SessionFinished(SessionId),
    RelayAuthenticated {
        session_id: SessionId,
        ready: Arc<RelayReady>,
    },
    BuildRecheck {
        session_id: SessionId,
        generation: u64,
        cancellation: CancellationToken,
        reply: oneshot::Sender<Result<Vec<Arc<dyn PathAttempt>>, PathError>>,
    },
    ObservationResult {
        session_id: SessionId,
        result: io::Result<(std::net::UdpSocket, Vec<rustgo_protocol::SocketAddress>)>,
    },
    Sweep,
}

enum OpenedIo {
    Protocol(TunnelProtocol),
    Tcp(BoxPeerStream),
    Udp(BoxPeerDatagramSession),
}

#[derive(Clone)]
struct FlowMeta {
    session_id: String,
    open_id: u64,
    protocol: TunnelProtocol,
    generation: u64,
    path: PathKind,
    peer: String,
    export: String,
}

impl FlowMeta {
    fn log(&self, lifecycle: &'static str) {
        tracing::info!(
            session_id = %self.session_id,
            open_id = self.open_id,
            protocol = ?self.protocol,
            generation = self.generation,
            path = ?self.path,
            peer = %self.peer,
            export = %self.export,
            lifecycle,
            "peer service flow"
        );
    }
}

struct Actor {
    runtime: ProductionPeerRuntime,
    context: ChildSessionContext,
    input: mpsc::Receiver<ActorInput>,
    shutdown: CancellationToken,
    sessions: HashMap<SessionId, Session>,
    observation_waiters: VecDeque<SessionId>,
    promoted: HashSet<(String, String, TunnelProtocol)>,
    tasks: JoinSet<()>,
}

struct Session {
    peer: String,
    export: String,
    role: PeerRole,
    expiry: u64,
    protocol: Option<TunnelProtocol>,
    next_step: u64,
    local_ephemerals: HashMap<CandidateTransport, EphemeralPeerKey>,
    local_ephemeral_public: HashMap<CandidateTransport, [u8; 32]>,
    peer_ephemeral_public: HashMap<CandidateTransport, [u8; 32]>,
    peer_key: Option<DevicePublicKey>,
    binding_requested: bool,
    peer_relay_requested: bool,
    local_relay_requested: bool,
    worker: Option<mpsc::Sender<PeerRelayFrame>>,
    reply: Option<oneshot::Sender<io::Result<OpenedIo>>>,
    cancellation: CancellationToken,
    resolve_only: bool,
    pending: Vec<RendezvousEnvelope>,
    peer_candidates: Vec<Candidate>,
    direct_started: bool,
    direct_failed: bool,
    generation: CandidateGeneration,
    direct_attempt: Option<Arc<dyn PathAttempt>>,
    recheck_reply: Option<PathRecheckReply>,
    manager: Option<Arc<PathManager>>,
    relay_ready: Option<Arc<RelayReady>>,
    candidate_sent_generation: u64,
    quic_socket: Option<std::net::UdpSocket>,
    observed_udp: Vec<rustgo_protocol::SocketAddress>,
}

type PathRecheckReply = oneshot::Sender<Result<Vec<Arc<dyn PathAttempt>>, PathError>>;

impl Actor {
    fn new(
        runtime: ProductionPeerRuntime,
        context: ChildSessionContext,
        input: mpsc::Receiver<ActorInput>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            runtime,
            context,
            input,
            shutdown,
            sessions: HashMap::new(),
            observation_waiters: VecDeque::new(),
            promoted: HashSet::new(),
            tasks: JoinSet::new(),
        }
    }

    async fn run(mut self) -> io::Result<()> {
        let mut sweep = tokio::time::interval(Duration::from_secs(1));
        while let Some(input) = tokio::select! {
            biased;
            () = self.shutdown.cancelled() => None,
            input = self.input.recv() => input,
            _ = sweep.tick() => Some(ActorInput::Sweep),
            joined = self.tasks.join_next(), if !self.tasks.is_empty() => { let _ = joined; Some(ActorInput::Sweep) },
        } {
            let result = match input {
                ActorInput::Open {
                    peer,
                    export,
                    resolve_only,
                    cancellation,
                    reply,
                } => {
                    self.begin_open(peer, export, resolve_only, cancellation, reply)
                        .await
                }
                ActorInput::Event(event) => self.handle_event(event).await,
                ActorInput::PathSelected { session_id, result } => {
                    self.handle_direct_result(session_id, result).await
                }
                ActorInput::Promoted { session_id, kind } => {
                    if let Some(session) = self.sessions.get(&session_id)
                        && let Some(protocol) = session.protocol
                    {
                        self.promoted.insert((
                            session.peer.clone(),
                            session.export.clone(),
                            protocol,
                        ));
                        tracing::info!(generation = session.generation.get(), path = ?kind, "fresh direct path promoted for subsequent service opens; existing relay I/O remains fenced");
                    }
                    Ok(())
                }
                ActorInput::SessionFinished(session_id) => {
                    self.finish_session(session_id).await;
                    Ok(())
                }
                ActorInput::RelayAuthenticated { session_id, ready } => {
                    self.start_path_manager(session_id, ready).await
                }
                ActorInput::BuildRecheck {
                    session_id,
                    generation,
                    cancellation,
                    reply,
                } => {
                    self.begin_recheck(session_id, generation, cancellation, reply)
                        .await
                }
                ActorInput::ObservationResult { session_id, result } => match result {
                    Ok((socket, addresses)) => {
                        if let Some(session) = self.sessions.get_mut(&session_id) {
                            session.quic_socket = Some(socket);
                            session.observed_udp = addresses;
                        }
                        tracing::info!(
                            session = ?session_id,
                            "authenticated NAT observation candidates ready"
                        );
                        match self.send_candidates(session_id).await {
                            Ok(()) => self.ensure_direct(session_id).await,
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "NAT observation failed; relay fallback remains available");
                        Ok(())
                    }
                },
                ActorInput::Sweep => {
                    self.expire_sessions();
                    Ok(())
                }
            };
            if let Err(error) = result {
                tracing::warn!(error = %error, "peer orchestration event rejected");
            }
            self.remove_cancelled();
        }
        let mut managers = Vec::new();
        let mut pending_replies = Vec::new();
        for (_, mut session) in self.sessions.drain() {
            session.cancellation.cancel();
            if let Some(manager) = session.manager.take() {
                managers.push(manager);
            }
            if let Some(reply) = session.reply.take() {
                pending_replies.push(reply);
            }
        }
        for manager in managers {
            let _ = manager.close().await;
        }
        let mut forced_abort = false;
        if tokio::time::timeout(Duration::from_secs(5), async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tracing::warn!(
                remaining = self.tasks.len(),
                "peer generation graceful task drain timed out; aborting remaining owned tasks"
            );
            forced_abort = true;
            self.tasks.abort_all();
            let watchdog = tokio::time::sleep(Duration::from_secs(5));
            tokio::pin!(watchdog);
            let mut watchdog_fired = false;
            while !self.tasks.is_empty() {
                tokio::select! {
                    _ = &mut watchdog, if !watchdog_fired => {
                        watchdog_fired = true;
                        tracing::error!(
                            remaining = self.tasks.len(),
                            "peer generation abort watchdog fired; fail-stop is holding generation ownership until every task joins"
                        );
                    }
                    _ = self.tasks.join_next() => {}
                }
            }
        }
        for reply in pending_replies {
            let _ = reply.send(Err(closed()));
        }
        if forced_abort {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer generation required forced task abort during teardown",
            ))
        } else {
            Ok(())
        }
    }

    async fn begin_open(
        &mut self,
        peer: String,
        export: String,
        resolve_only: bool,
        cancellation: CancellationToken,
        reply: oneshot::Sender<io::Result<OpenedIo>>,
    ) -> io::Result<()> {
        tracing::trace!(peer = %peer, export = %export, resolve_only, "peer open command admitted");
        if self
            .runtime
            .config
            .p2p
            .as_ref()
            .is_none_or(|p2p| !p2p.enabled)
        {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "P2P is disabled",
            )));
            return Ok(());
        }
        let session_id = random_session_id()?;
        let expiry = now().saturating_add(SESSION_TTL.as_secs());
        let (ephemerals, publics) = fresh_transport_keys();
        let envelope = self.signed_envelope(
            session_id,
            &peer,
            1,
            expiry,
            RendezvousPayload::Request(RendezvousRequest {
                export: BoundedString::try_from(export.as_str()).map_err(|_| invalid())?,
            }),
        )?;
        self.sessions.insert(
            session_id,
            Session {
                peer,
                export,
                role: PeerRole::Initiator,
                expiry,
                protocol: None,
                next_step: 2,
                local_ephemerals: ephemerals,
                local_ephemeral_public: publics,
                peer_ephemeral_public: HashMap::new(),
                peer_key: None,
                binding_requested: false,
                peer_relay_requested: false,
                local_relay_requested: false,
                worker: None,
                reply: Some(reply),
                cancellation: cancellation.child_token(),
                resolve_only,
                pending: Vec::new(),
                peer_candidates: Vec::new(),
                direct_started: false,
                direct_failed: false,
                generation: CandidateGeneration::INITIAL,
                direct_attempt: None,
                recheck_reply: None,
                manager: None,
                relay_ready: None,
                candidate_sent_generation: 0,
                quic_socket: None,
                observed_udp: Vec::new(),
            },
        );
        if !resolve_only {
            self.request_observation(session_id).await?;
        }
        self.send_envelope(&envelope).await
    }

    async fn start_path_manager(
        &mut self,
        id: SessionId,
        ready: Arc<RelayReady>,
    ) -> io::Result<()> {
        let p2p = self.runtime.config.p2p.as_ref().ok_or_else(invalid)?;
        let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
        if session.manager.is_some() {
            return Err(invalid());
        }
        session.relay_ready = Some(ready.clone());
        let manager = Arc::new(PathManager::new(
            PathManagerConfig::new(
                Duration::from_secs(p2p.direct_timeout_secs.max(2)),
                Duration::from_millis(500),
                Duration::from_secs(p2p.direct_timeout_secs.max(1)),
                Duration::from_secs(p2p.reconnect_timeout_secs),
            )
            .map_err(|_| invalid())?,
        ));
        session.manager = Some(manager.clone());
        let forced = std::env::var_os("RUSTGO_INTERNAL_TESTING").is_some()
            && std::env::var_os("RUSTGO_INTERNAL_TEST_FORCE_INITIAL_RELAY").is_some();
        let promoted = session.protocol.is_some_and(|protocol| {
            self.promoted
                .contains(&(session.peer.clone(), session.export.clone(), protocol))
        });
        let mut attempts = Vec::<Arc<dyn PathAttempt>>::new();
        if p2p.prefer_direct
            && (!forced || promoted)
            && let Some(direct) = session.direct_attempt.take()
        {
            attempts.push(direct);
        }
        attempts.push(Arc::new(EstablishedRelayAttempt { ready }));
        let factory = p2p.prefer_direct.then(|| {
            Arc::new(ActorRecheckFactory {
                actor: self.runtime.commands.clone(),
                session_id: id,
            }) as Arc<dyn RecheckAttemptFactory>
        });
        let cancellation = session.cancellation.child_token();
        let sender = self.runtime.commands.clone();
        self.tasks.spawn(async move {
            let result = manager
                .connect_with_recheck(attempts, factory, cancellation)
                .await;
            let _ = sender
                .send(ActorInput::PathSelected {
                    session_id: id,
                    result,
                })
                .await;
        });
        Ok(())
    }

    async fn begin_recheck(
        &mut self,
        id: SessionId,
        requested: u64,
        cancellation: CancellationToken,
        reply: oneshot::Sender<Result<Vec<Arc<dyn PathAttempt>>, PathError>>,
    ) -> io::Result<()> {
        let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
        let expected = session.generation.get().saturating_add(1);
        if requested.saturating_add(1) != expected
            || expected > 32
            || session.expiry <= now()
            || cancellation.is_cancelled()
            || session.recheck_reply.is_some()
        {
            let _ = reply.send(Err(PathError::Cancelled));
            return Ok(());
        }
        if session.role == PeerRole::Responder {
            // The initiator owns the strict +1 step. The responder's factory
            // waits for that authenticated envelope, then replies once.
            session.recheck_reply = Some(reply);
            return Ok(());
        }
        let next = CandidateGeneration::new(expected).ok_or_else(invalid)?;
        let (private, public) = fresh_transport_keys();
        session.generation = next;
        session.local_ephemerals = private;
        session.local_ephemeral_public = public;
        session.peer_ephemeral_public.clear();
        session.peer_candidates.clear();
        session.direct_started = false;
        session.direct_failed = false;
        session.direct_attempt = None;
        session.recheck_reply = Some(reply);
        session.quic_socket = None;
        session.observed_udp.clear();
        tracing::info!(
            generation = next.get(),
            "starting fresh direct-path generation; active relay stays fenced for existing I/O"
        );
        self.request_observation(id).await?;
        self.send_candidates(id).await
    }

    async fn handle_event(&mut self, event: ControlEvent) -> io::Result<()> {
        tracing::trace!(kind = event_kind(&event), "peer control event admitted");
        match event {
            ControlEvent::Rendezvous(envelope) => self.handle_envelope(envelope).await,
            ControlEvent::PeerIdentityBinding(binding) => self.handle_binding(binding).await,
            ControlEvent::PeerRelayFrame(frame) => {
                if let Some(worker) = self
                    .sessions
                    .get(&frame.session_id)
                    .and_then(|s| s.worker.clone())
                {
                    worker.try_send(frame).map_err(|_| {
                        io::Error::new(io::ErrorKind::WouldBlock, "relay session queue full")
                    })?;
                }
                Ok(())
            }
            ControlEvent::ServerNotice(notice) => self.fail_session(
                SessionId::from(notice.session_id),
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("server rejected rendezvous with code {}", notice.code),
                ),
            ),
            ControlEvent::ObservationGrant(grant) => self.handle_observation_grant(grant),
        }
    }

    fn observation_endpoints(&self) -> Option<(String, String)> {
        let p2p = self.runtime.config.p2p.as_ref()?;
        Some((
            p2p.observation_primary_addr.clone()?,
            p2p.observation_alternate_addr.clone()?,
        ))
    }

    fn handle_observation_grant(&mut self, grant: ObservationGrant) -> io::Result<()> {
        if grant.expires_unix_secs() <= now() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expired observation grant",
            ));
        }
        let Some((primary, alternate)) = self.observation_endpoints() else {
            return Ok(());
        };
        let session_id = self.observation_waiters.pop_front().ok_or_else(invalid)?;
        let role = self.sessions.get(&session_id).ok_or_else(invalid)?.role;
        let socket = bind_quic_socket(&self.runtime.config, session_id, role)?;
        socket.set_nonblocking(true)?;
        let observer = socket.try_clone()?;
        let sender = self.runtime.commands.clone();
        let cancellation = self
            .sessions
            .get(&session_id)
            .ok_or_else(invalid)?
            .cancellation
            .child_token();
        self.tasks.spawn(async move {
            let result = match observe_nat(observer, primary, alternate, grant, cancellation).await {
                Ok((_observer, addresses)) => Ok((socket, addresses)),
                Err(error) => {
                    tracing::warn!(error = %error, "NAT observation failed; retained fixed socket for local candidate and relay fallback");
                    Ok((socket, Vec::new()))
                }
            };
            let _ = sender.send(ActorInput::ObservationResult { session_id, result }).await;
        });
        Ok(())
    }

    async fn request_observation(&mut self, id: SessionId) -> io::Result<()> {
        if self.observation_endpoints().is_none() {
            return Ok(());
        }
        self.observation_waiters.push_back(id);
        self.context
            .send_peer_control(
                Message::ObservationGrantRequest(rustgo_protocol::ObservationGrantRequest {}),
                &self.shutdown,
            )
            .await
            .map_err(|_| closed())
    }

    async fn handle_envelope(&mut self, envelope: RendezvousEnvelope) -> io::Result<()> {
        if envelope.is_expired_at(now()) {
            return Err(invalid());
        }
        if !self.sessions.contains_key(&envelope.session_id) {
            if !matches!(envelope.payload, RendezvousPayload::Request(_)) {
                // A close can cross an already queued peer event on the shared control stream.
                return Ok(());
            }
            let export = match &envelope.payload {
                RendezvousPayload::Request(value) => value.export.as_str().to_owned(),
                _ => unreachable!(),
            };
            let protocol = self
                .runtime
                .exports
                .authorize(envelope.sender.as_str(), &export, TunnelProtocol::Tcp)
                .map(|_| TunnelProtocol::Tcp)
                .or_else(|_| {
                    self.runtime
                        .exports
                        .authorize(envelope.sender.as_str(), &export, TunnelProtocol::Udp)
                        .map(|_| TunnelProtocol::Udp)
                });
            let (ephemerals, publics) = fresh_transport_keys();
            self.sessions.insert(
                envelope.session_id,
                Session {
                    peer: envelope.sender.as_str().to_owned(),
                    export,
                    role: PeerRole::Responder,
                    expiry: envelope.expires_unix_secs,
                    protocol: protocol.ok(),
                    next_step: envelope.step + 1,
                    local_ephemerals: ephemerals,
                    local_ephemeral_public: publics,
                    peer_ephemeral_public: HashMap::new(),
                    peer_key: None,
                    binding_requested: true,
                    peer_relay_requested: false,
                    local_relay_requested: false,
                    worker: None,
                    reply: None,
                    cancellation: self.shutdown.child_token(),
                    pending: vec![envelope.clone()],
                    resolve_only: false,
                    peer_candidates: Vec::new(),
                    direct_started: false,
                    direct_failed: false,
                    generation: CandidateGeneration::INITIAL,
                    direct_attempt: None,
                    recheck_reply: None,
                    manager: None,
                    relay_ready: None,
                    candidate_sent_generation: 0,
                    quic_socket: None,
                    observed_udp: Vec::new(),
                },
            );
            self.request_observation(envelope.session_id).await?;
            self.lookup_identity(envelope.session_id).await?;
            return Ok(());
        }
        let verified = self
            .sessions
            .get(&envelope.session_id)
            .is_some_and(|session| {
                session
                    .peer_key
                    .as_ref()
                    .is_some_and(|key| verify_peer_envelope(key, &envelope).is_ok())
                    && envelope.sender.as_str() == session.peer
                    && envelope.target.as_str() == self.runtime.config.client.name
                    && envelope.expires_unix_secs == session.expiry
            });
        if !verified {
            let id = envelope.session_id;
            let session = self
                .sessions
                .get_mut(&envelope.session_id)
                .ok_or_else(invalid)?;
            session.pending.push(envelope);
            if !session.binding_requested {
                session.binding_requested = true;
                self.lookup_identity(id).await?;
            }
            return Ok(());
        }
        self.apply_verified(envelope).await
    }

    async fn handle_binding(&mut self, binding: PeerIdentityBinding) -> io::Result<()> {
        let id = SessionId::from(binding.session_id);
        let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
        if binding.peer.as_str() != session.peer || binding.expires_unix_secs != session.expiry {
            return Err(invalid());
        }
        let expected_provider = session.role == PeerRole::Initiator;
        if binding.peer_is_provider != expected_provider {
            return Err(invalid());
        }
        let key = binding
            .public_key
            .as_str()
            .parse::<DevicePublicKey>()
            .map_err(|_| invalid())?;
        if session.peer_key.replace(key).is_some() {
            return Err(invalid());
        }
        let pending = std::mem::take(&mut session.pending);
        for envelope in pending {
            let session = self.sessions.get(&id).ok_or_else(invalid)?;
            verify_peer_envelope(session.peer_key.as_ref().ok_or_else(invalid)?, &envelope)
                .map_err(|_| invalid())?;
            if envelope.sender.as_str() != session.peer
                || envelope.target.as_str() != self.runtime.config.client.name
            {
                return Err(invalid());
            }
            self.apply_verified(envelope).await?;
        }
        Ok(())
    }

    async fn apply_verified(&mut self, envelope: RendezvousEnvelope) -> io::Result<()> {
        let id = envelope.session_id;
        let incoming_generation = envelope.generation;
        let current_generation = self.sessions.get(&id).ok_or_else(invalid)?.generation;
        let mut needs_observation = false;
        if incoming_generation != current_generation {
            if !matches!(envelope.payload, RendezvousPayload::CandidateSetV2(_))
                || incoming_generation.get() != current_generation.get().saturating_add(1)
            {
                return Err(invalid());
            }
            let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
            let (private, public) = fresh_transport_keys();
            session.generation = incoming_generation;
            session.local_ephemerals = private;
            session.local_ephemeral_public = public;
            session.peer_ephemeral_public.clear();
            session.peer_candidates.clear();
            session.direct_started = false;
            session.direct_failed = false;
            session.quic_socket = None;
            session.observed_udp.clear();
            needs_observation = true;
        }
        if needs_observation {
            self.request_observation(id).await?;
        }
        {
            let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
            session.next_step = session.next_step.max(envelope.step.saturating_add(1));
        }
        match envelope.payload {
            RendezvousPayload::Request(_) => self.provider_accept(id).await?,
            RendezvousPayload::ProviderDecision(decision) => {
                if !decision.is_accepted() {
                    return self.fail_session(
                        id,
                        io::Error::new(io::ErrorKind::PermissionDenied, "peer export rejected"),
                    );
                }
                let protocol = decision
                    .protocol()
                    .map(protocol_from_wire)
                    .ok_or_else(invalid)?;
                let resolve = self
                    .sessions
                    .get(&id)
                    .is_some_and(|session| session.resolve_only);
                self.sessions.get_mut(&id).ok_or_else(invalid)?.protocol = Some(protocol);
                if resolve {
                    if let Some(reply) = self
                        .sessions
                        .get_mut(&id)
                        .and_then(|session| session.reply.take())
                    {
                        tracing::trace!(?protocol, "resolving peer export protocol");
                        let sent = reply.send(Ok(OpenedIo::Protocol(protocol))).is_ok();
                        tracing::trace!(sent, "peer export protocol response sent");
                    }
                    let (peer, expiry) = self
                        .sessions
                        .get(&id)
                        .map(|session| (session.peer.clone(), session.expiry))
                        .ok_or_else(invalid)?;
                    let close = self.signed_envelope(
                        id,
                        &peer,
                        u64::MAX - 1,
                        expiry,
                        RendezvousPayload::Close(RendezvousClose { detail: None }),
                    )?;
                    let _ = self.send_envelope(&close).await;
                    self.fail_session(id, closed())?;
                }
            }
            RendezvousPayload::CandidateSet(set) => {
                let public: [u8; 32] = set
                    .ephemeral_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid())?;
                self.sessions
                    .get_mut(&id)
                    .ok_or_else(invalid)?
                    .peer_ephemeral_public
                    .insert(CandidateTransport::Relay, public);
                self.sessions
                    .get_mut(&id)
                    .ok_or_else(invalid)?
                    .peer_candidates = set.candidates.into_vec();
                if self.sessions[&id].role == PeerRole::Initiator {
                    self.send_candidates(id).await?;
                }
                self.ensure_direct(id).await?;
                self.ensure_relay_request(id).await?;
            }
            RendezvousPayload::CandidateSetV2(set) => {
                let expected_initiator = self.sessions[&id].role == PeerRole::Responder;
                if set.owner_is_initiator != expected_initiator {
                    return Err(invalid());
                }
                let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
                for binding in set.bindings.into_vec() {
                    let public: [u8; 32] = binding
                        .ephemeral_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid())?;
                    if session
                        .peer_ephemeral_public
                        .insert(binding.transport, public)
                        .is_some()
                    {
                        return Err(invalid());
                    }
                }
                session.peer_candidates = set.candidates.into_vec();
                if self.sessions[&id].candidate_sent_generation
                    < self.sessions[&id].generation.get()
                {
                    self.send_candidates(id).await?;
                }
                self.ensure_direct(id).await?;
                self.ensure_relay_request(id).await?;
            }
            RendezvousPayload::RelayRequest(_) => {
                self.sessions
                    .get_mut(&id)
                    .ok_or_else(invalid)?
                    .peer_relay_requested = true;
                self.ensure_relay_request(id).await?;
                self.ensure_worker(id).await?;
            }
            RendezvousPayload::Close(_) | RendezvousPayload::Error(_) => {
                self.fail_session(id, closed())?;
            }
            RendezvousPayload::ConnectivityResult(_) => {}
        }
        Ok(())
    }

    async fn provider_accept(&mut self, id: SessionId) -> io::Result<()> {
        let session = self.sessions.get(&id).ok_or_else(invalid)?;
        let decision = match session.protocol {
            Some(protocol) => ProviderDecision::accepted(protocol_to_wire(protocol)),
            None => ProviderDecision::rejected(None),
        };
        self.send_payload(id, RendezvousPayload::ProviderDecision(decision))
            .await?;
        if self.sessions.get(&id).and_then(|s| s.protocol).is_some() {
            self.send_candidates(id).await?;
        }
        Ok(())
    }

    async fn send_candidates(&mut self, id: SessionId) -> io::Result<()> {
        let session = self.sessions.get(&id).ok_or_else(invalid)?;
        if session.protocol.is_none() || session.resolve_only {
            return Ok(());
        }
        if self.observation_endpoints().is_some() && session.quic_socket.is_none() {
            return Ok(());
        }
        let bindings = session
            .local_ephemeral_public
            .iter()
            .map(|(transport, public)| {
                Ok(TransportKeyBinding {
                    transport: *transport,
                    ephemeral_public_key: BoundedBytes::try_from(public.as_slice())
                        .map_err(|_| invalid())?,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let owner_is_initiator = session.role == PeerRole::Initiator;
        let mut candidates =
            local_candidates(&self.runtime.config, id, session.expiry, session.generation)?;
        if let Some(bound) = session
            .quic_socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
            && let Some(candidate) = candidates
                .iter_mut()
                .find(|candidate| candidate.transport == CandidateTransport::QuicUdp)
        {
            candidate.address = protocol_socket(bound);
        }
        for (index, address) in session.observed_udp.iter().take(2).cloned().enumerate() {
            candidates.push(Candidate {
                transport: CandidateTransport::QuicUdp,
                address,
                priority: 700_u32.saturating_sub(index as u32),
                foundation: BoundedString::try_from(if index == 0 {
                    "observed-primary"
                } else {
                    "observed-alternate"
                })
                .map_err(|_| invalid())?,
                generation: session.generation,
                expires_unix_secs: session.expiry,
                observation_source: BoundedString::try_from("rustgos-authenticated-observation")
                    .map_err(|_| invalid())?,
            });
        }
        self.send_payload(
            id,
            RendezvousPayload::CandidateSetV2(CandidateSetV2 {
                owner_is_initiator,
                bindings: BoundedVec::try_from(bindings).map_err(|_| invalid())?,
                candidates: BoundedVec::try_from(candidates).map_err(|_| invalid())?,
            }),
        )
        .await?;
        let generation = self.sessions.get(&id).ok_or_else(invalid)?.generation.get();
        self.sessions
            .get_mut(&id)
            .ok_or_else(invalid)?
            .candidate_sent_generation = generation;
        Ok(())
    }

    async fn ensure_direct(&mut self, id: SessionId) -> io::Result<()> {
        let forced_initial_relay = std::env::var_os("RUSTGO_INTERNAL_TESTING").is_some()
            && std::env::var_os("RUSTGO_INTERNAL_TEST_FORCE_INITIAL_RELAY").is_some();
        let promoted = self.sessions.get(&id).is_some_and(|session| {
            session.protocol.is_some_and(|protocol| {
                self.promoted
                    .contains(&(session.peer.clone(), session.export.clone(), protocol))
            })
        });
        let observation_enabled = self.observation_endpoints().is_some();
        let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
        let p2p = self.runtime.config.p2p.as_ref().ok_or_else(invalid)?;
        if session.direct_started || !p2p.prefer_direct || session.resolve_only {
            return Ok(());
        }
        if forced_initial_relay && session.generation == CandidateGeneration::INITIAL && !promoted {
            session.direct_failed = true;
            return Ok(());
        }
        let transport = if session.protocol == Some(TunnelProtocol::Udp) {
            CandidateTransport::QuicUdp
        } else {
            CandidateTransport::NativeTcp
        };
        if transport == CandidateTransport::QuicUdp
            && observation_enabled
            && session.quic_socket.is_none()
        {
            return Ok(());
        }
        let peer_candidate = session
            .peer_candidates
            .iter()
            .filter(|candidate| candidate.transport == transport)
            .max_by_key(|candidate| candidate.priority)
            .cloned();
        let Some(peer_candidate) = peer_candidate else {
            session.direct_failed = true;
            return Ok(());
        };
        let local_key = session
            .local_ephemerals
            .remove(&transport)
            .ok_or_else(invalid)?;
        let peer_public = *session
            .peer_ephemeral_public
            .get(&transport)
            .ok_or_else(invalid)?;
        let local_public = session.local_ephemeral_public[&transport];
        let local_identity = self.runtime.keypair.public_key();
        let peer_identity = *session.peer_key.as_ref().ok_or_else(invalid)?;
        let (initiator_identity, responder_identity, initiator_ephemeral, responder_ephemeral) =
            match session.role {
                PeerRole::Initiator => (local_identity, peer_identity, local_public, peer_public),
                PeerRole::Responder => (peer_identity, local_identity, peer_public, local_public),
            };
        let transcript = PeerTranscript::new(
            id,
            session.generation,
            initiator_identity,
            responder_identity,
            initiator_ephemeral,
            responder_ephemeral,
            BoundedString::try_from(session.export.as_str()).map_err(|_| invalid())?,
            self.context.protocol_version(),
            transcript_hash_for_transport(id, session, &self.runtime.config.client.name, transport),
        );
        let local = local_socket(&self.runtime.config, id, transport)?;
        let remote = socket_addr(&peer_candidate.address);
        tracing::info!(
            session_id = %session_log_id(id),
            ?transport,
            ?local,
            ?remote,
            role = ?session.role,
            generation = session.generation.get(),
            "starting authenticated direct path attempt"
        );
        let attempt: Arc<dyn PathAttempt> = match transport {
            CandidateTransport::QuicUdp => {
                let auth = Arc::new(OneQuicAuth(Mutex::new(Some(
                    PeerAuthentication::new(session.role, local_key, transcript)
                        .map_err(|_| invalid())?,
                ))));
                if let Some(socket) = session.quic_socket.take() {
                    Arc::new(
                        QuicPathAttempt::with_socket(
                            socket,
                            remote,
                            QuicPeerConfig::default(),
                            auth,
                        )
                        .map_err(|_| invalid())?,
                    )
                } else {
                    Arc::new(QuicPathAttempt::new(
                        local,
                        remote,
                        QuicPeerConfig::default(),
                        auth,
                    ))
                }
            }
            CandidateTransport::NativeTcp => Arc::new(TcpPathAttempt::new(
                local,
                vec![remote],
                Duration::from_secs(p2p.direct_timeout_secs),
                Duration::from_secs(5),
                Arc::new(OneTcpAuth(Mutex::new(Some(
                    PeerTcpAuthentication::new(session.role, local_key, transcript)
                        .map_err(|_| invalid())?,
                )))),
            )),
            CandidateTransport::Relay => return Err(invalid()),
        };
        session.direct_started = true;
        if let Some(reply) = session.recheck_reply.take() {
            let _ = reply.send(Ok(vec![attempt]));
        } else {
            session.direct_attempt = Some(attempt);
        }
        Ok(())
    }

    async fn handle_direct_result(
        &mut self,
        id: SessionId,
        result: Result<SelectedPath, PathError>,
    ) -> io::Result<()> {
        match result {
            Err(error) => {
                tracing::warn!(session_id = %session_log_id(id), error = %error, "direct path attempt failed; using relay fallback");
                if let Some(session) = self.sessions.get_mut(&id) {
                    session.direct_failed = true;
                }
                self.ensure_relay_request(id).await
            }
            Ok(path) => {
                let promoted_open = self.sessions.get(&id).is_some_and(|session| {
                    session.protocol.is_some_and(|protocol| {
                        self.promoted.contains(&(
                            session.peer.clone(),
                            session.export.clone(),
                            protocol,
                        ))
                    })
                });
                let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
                let role = session.role;
                let protocol = session.protocol.ok_or_else(invalid)?;
                let peer = session.peer.clone();
                let export = session.export.clone();
                let reply = if path.kind() == PathKind::Relay {
                    None
                } else {
                    session.reply.take()
                };
                let cancellation = session.cancellation.child_token();
                let exports = self.runtime.exports.clone();
                let meta = FlowMeta {
                    session_id: session_log_id(id),
                    open_id: CHANNEL_ID,
                    protocol,
                    generation: session.generation.get(),
                    path: path.kind(),
                    peer: peer.clone(),
                    export: export.clone(),
                };
                meta.log("selected");
                tracing::info!(path = ?path.kind(), generation = session.generation.get(), peer = %peer, export = %export, promoted_open, "authoritative peer path selected");
                if promoted_open && path.kind().is_direct() {
                    tracing::info!(path = ?path.kind(), generation = session.generation.get(), peer = %peer, export = %export, "selected promoted direct path for new service open");
                }
                if path.kind().is_direct()
                    && session.generation != CandidateGeneration::INITIAL
                    && session.worker.is_some()
                {
                    self.promoted.insert((peer, export, protocol));
                    tracing::info!(generation = session.generation.get(), path = ?path.kind(), "fresh direct path promoted for subsequent service opens; existing relay I/O remains on its generation");
                    return Ok(());
                }
                if path.kind() == PathKind::Relay {
                    let relay_reply = session.reply.take();
                    session
                        .relay_ready
                        .as_ref()
                        .ok_or_else(invalid)?
                        .select(relay_reply);
                    return Ok(());
                }
                if let Some(ready) = &session.relay_ready {
                    ready.reject();
                }
                if let Some(tcp) = path.handle::<EncryptedPeerTcp>() {
                    let sender = self.runtime.commands.clone();
                    let flow = meta.clone();
                    self.tasks.spawn(async move {
                        flow.log("io_start");
                        run_direct_tcp(role, peer, export, tcp, exports, reply, cancellation).await;
                        flow.log("io_finished");
                        let _ = sender.send(ActorInput::SessionFinished(id)).await;
                    });
                } else if let Some(quic) = path.handle::<QuicPeerPathHandle>() {
                    let sender = self.runtime.commands.clone();
                    let flow = meta.clone();
                    self.tasks.spawn(async move {
                        flow.log("io_start");
                        run_direct_quic(
                            role,
                            protocol,
                            peer,
                            export,
                            quic,
                            exports,
                            reply,
                            cancellation,
                        )
                        .await;
                        flow.log("io_finished");
                        let _ = sender.send(ActorInput::SessionFinished(id)).await;
                    });
                } else {
                    return Err(invalid());
                }
                Ok(())
            }
        }
    }

    async fn ensure_relay_request(&mut self, id: SessionId) -> io::Result<()> {
        let session = self.sessions.get(&id).ok_or_else(invalid)?;
        if self
            .runtime
            .config
            .p2p
            .as_ref()
            .is_none_or(|p2p| !p2p.allow_relay_fallback)
        {
            return Ok(());
        }
        // Relay authentication is prepared eagerly, but application I/O remains
        // gated until PathManager selects it after the direct grace window.
        let ordered_turn = session.role == PeerRole::Responder || session.peer_relay_requested;
        if session.local_relay_requested
            || !session
                .peer_ephemeral_public
                .contains_key(&CandidateTransport::Relay)
            || session.protocol.is_none()
            || !ordered_turn
        {
            return Ok(());
        }
        let datagram = session.protocol == Some(TunnelProtocol::Udp);
        self.send_payload(
            id,
            RendezvousPayload::RelayRequest(RelayRequest { datagram }),
        )
        .await?;
        self.sessions
            .get_mut(&id)
            .ok_or_else(invalid)?
            .local_relay_requested = true;
        self.ensure_worker(id).await
    }

    async fn ensure_worker(&mut self, id: SessionId) -> io::Result<()> {
        let ready = self.sessions.get(&id).is_some_and(|s| {
            s.worker.is_none()
                && s.local_relay_requested
                && s.peer_relay_requested
                && s.peer_key.is_some()
                && s.peer_ephemeral_public
                    .contains_key(&CandidateTransport::Relay)
        });
        if !ready {
            return Ok(());
        }
        let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
        let local_ephemeral = session
            .local_ephemerals
            .remove(&CandidateTransport::Relay)
            .ok_or_else(invalid)?;
        let peer_public = *session
            .peer_ephemeral_public
            .get(&CandidateTransport::Relay)
            .ok_or_else(invalid)?;
        let local_identity = self.runtime.keypair.public_key();
        let peer_identity = *session.peer_key.as_ref().ok_or_else(invalid)?;
        let (initiator_identity, responder_identity, initiator_ephemeral, responder_ephemeral) =
            match session.role {
                PeerRole::Initiator => (
                    local_identity,
                    peer_identity,
                    session.local_ephemeral_public[&CandidateTransport::Relay],
                    peer_public,
                ),
                PeerRole::Responder => (
                    peer_identity,
                    local_identity,
                    peer_public,
                    session.local_ephemeral_public[&CandidateTransport::Relay],
                ),
            };
        let transcript = PeerTranscript::new(
            id,
            session.generation,
            initiator_identity,
            responder_identity,
            initiator_ephemeral,
            responder_ephemeral,
            BoundedString::try_from(session.export.as_str()).map_err(|_| invalid())?,
            self.context.protocol_version(),
            transcript_hash(id, session, &self.runtime.config.client.name),
        );
        let mut keys = PeerSessionKeys::derive(session.role, local_ephemeral, &transcript)
            .map_err(|_| invalid())?;
        let relay = Arc::new(if session.protocol == Some(TunnelProtocol::Udp) {
            PeerRelayChannel::datagram(&mut keys, CHANNEL_ID).map_err(|_| invalid())?
        } else {
            PeerRelayChannel::stream(&mut keys, CHANNEL_ID).map_err(|_| invalid())?
        });
        let (frames, receiver) = mpsc::channel(SESSION_FRAME_CAPACITY);
        session.worker = Some(frames);
        let role = session.role;
        let protocol = session.protocol.ok_or_else(invalid)?;
        let peer = session.peer.clone();
        let export = session.export.clone();
        let cancellation = session.cancellation.child_token();
        let context = self.context.clone();
        let exports = self.runtime.exports.clone();
        let sender = self.runtime.commands.clone();
        let worker_sender = sender.clone();
        let flow = FlowMeta {
            session_id: session_log_id(id),
            open_id: CHANNEL_ID,
            protocol,
            generation: session.generation.get(),
            path: PathKind::Relay,
            peer: peer.clone(),
            export: export.clone(),
        };
        self.tasks.spawn(async move {
            let owned_flow = run_relay_session(RelayWorker {
                session_id: id,
                actor: worker_sender,
                role,
                protocol,
                peer,
                export,
                relay,
                frames: receiver,
                context,
                exports,
                reply: None,
                selection_reply: None,
                cancellation,
                flow: flow.clone(),
            })
            .await;
            if owned_flow {
                flow.log("io_finished");
                let _ = sender.send(ActorInput::SessionFinished(id)).await;
            }
        });
        Ok(())
    }

    async fn send_payload(&mut self, id: SessionId, payload: RendezvousPayload) -> io::Result<()> {
        let (peer, step, expiry) = {
            let session = self.sessions.get_mut(&id).ok_or_else(invalid)?;
            let step = session.next_step;
            session.next_step = step.checked_add(1).ok_or_else(invalid)?;
            (session.peer.clone(), step, session.expiry)
        };
        let envelope = self.signed_envelope(id, &peer, step, expiry, payload)?;
        self.send_envelope(&envelope).await
    }

    fn signed_envelope(
        &self,
        id: SessionId,
        peer: &str,
        step: u64,
        expiry: u64,
        payload: RendezvousPayload,
    ) -> io::Result<RendezvousEnvelope> {
        let mut envelope = RendezvousEnvelope {
            version: self.context.protocol_version(),
            session_id: id,
            sender: BoundedString::try_from(self.runtime.config.client.name.as_str())
                .map_err(|_| invalid())?,
            target: BoundedString::try_from(peer).map_err(|_| invalid())?,
            step,
            generation: self
                .sessions
                .get(&id)
                .map_or(CandidateGeneration::INITIAL, |session| session.generation),
            expires_unix_secs: expiry,
            payload,
            signature: BoundedBytes::try_from(Vec::new()).map_err(|_| invalid())?,
        };
        envelope.signature =
            sign_peer_envelope(&self.runtime.keypair, &envelope).map_err(|_| invalid())?;
        Ok(envelope)
    }

    async fn send_envelope(&self, envelope: &RendezvousEnvelope) -> io::Result<()> {
        tracing::trace!(
            message_id = envelope.message_id().as_u16(),
            step = envelope.step,
            "sending peer envelope"
        );
        let message = envelope.to_protocol_message().map_err(|_| invalid())?;
        self.context
            .send_peer_control(message, &self.shutdown)
            .await
            .map_err(|_| closed())
    }

    async fn lookup_identity(&self, id: SessionId) -> io::Result<()> {
        let session = self.sessions.get(&id).ok_or_else(invalid)?;
        self.context
            .send_peer_control(
                Message::PeerIdentityLookup(rustgo_protocol::PeerIdentityLookup {
                    session_id: *id.as_bytes(),
                    peer: BoundedString::try_from(session.peer.as_str()).map_err(|_| invalid())?,
                }),
                &self.shutdown,
            )
            .await
            .map_err(|_| closed())
    }

    fn fail_session(&mut self, id: SessionId, error: io::Error) -> io::Result<()> {
        if let Some(mut session) = self.sessions.remove(&id) {
            session.cancellation.cancel();
            if let Some(reply) = session.reply.take() {
                let _ = reply.send(Err(error));
            }
        }
        Ok(())
    }

    fn remove_cancelled(&mut self) {
        self.sessions
            .retain(|_, session| !session.cancellation.is_cancelled());
    }

    fn expire_sessions(&mut self) {
        let current = now();
        let expired = self
            .sessions
            .iter()
            .filter_map(|(id, session)| (session.expiry <= current).then_some(*id))
            .collect::<Vec<_>>();
        for id in expired {
            let _ = self.fail_session(
                id,
                io::Error::new(io::ErrorKind::TimedOut, "peer session expired"),
            );
        }
    }

    async fn finish_session(&mut self, id: SessionId) {
        let Some(mut session) = self.sessions.remove(&id) else {
            return;
        };
        session.cancellation.cancel();
        if let Some(manager) = session.manager.take() {
            let _ = manager.close().await;
        }
        if let Some(reply) = session.reply.take() {
            let _ = reply.send(Err(closed()));
        }
        let envelope = self.signed_envelope(
            id,
            &session.peer,
            session.next_step,
            session.expiry,
            RendezvousPayload::Close(RendezvousClose { detail: None }),
        );
        if let Ok(envelope) = envelope {
            let _ = self.send_envelope(&envelope).await;
        }
    }
}

struct RelayWorker {
    session_id: SessionId,
    actor: mpsc::Sender<ActorInput>,
    role: PeerRole,
    protocol: TunnelProtocol,
    peer: String,
    export: String,
    relay: Arc<PeerRelayChannel>,
    frames: mpsc::Receiver<PeerRelayFrame>,
    context: ChildSessionContext,
    exports: ExportRegistry,
    reply: Option<oneshot::Sender<io::Result<OpenedIo>>>,
    selection_reply: Option<oneshot::Receiver<Option<OpenReply>>>,
    cancellation: CancellationToken,
    flow: FlowMeta,
}

struct RelayReady {
    gate: Mutex<Option<oneshot::Sender<bool>>>,
    reply: Mutex<Option<oneshot::Sender<Option<OpenReply>>>>,
}

impl RelayReady {
    fn select(&self, reply: Option<OpenReply>) {
        if let Ok(mut target) = self.reply.lock()
            && let Some(target) = target.take()
        {
            let _ = target.send(reply);
        }
        if let Ok(mut gate) = self.gate.lock()
            && let Some(gate) = gate.take()
        {
            let _ = gate.send(true);
        }
    }

    fn reject(&self) {
        if let Ok(mut gate) = self.gate.lock()
            && let Some(gate) = gate.take()
        {
            let _ = gate.send(false);
        }
    }
}

struct EstablishedRelayAttempt {
    ready: Arc<RelayReady>,
}

#[async_trait]
impl PathAttempt for EstablishedRelayAttempt {
    fn kind(&self) -> PathKind {
        PathKind::Relay
    }
    async fn connect(&self, cancellation: CancellationToken) -> Result<SelectedPath, PathError> {
        if cancellation.is_cancelled() {
            Err(PathError::Cancelled)
        } else {
            Ok(SelectedPath::authenticated_with(
                PathKind::Relay,
                self.ready.clone(),
            ))
        }
    }
}

struct ActorRecheckFactory {
    actor: mpsc::Sender<ActorInput>,
    session_id: SessionId,
}

#[async_trait]
impl RecheckAttemptFactory for ActorRecheckFactory {
    async fn create(
        &self,
        generation: u64,
        cancellation: CancellationToken,
    ) -> Result<Vec<Arc<dyn PathAttempt>>, PathError> {
        let (reply, result) = oneshot::channel();
        self.actor
            .send(ActorInput::BuildRecheck {
                session_id: self.session_id,
                generation,
                cancellation: cancellation.clone(),
                reply,
            })
            .await
            .map_err(|_| PathError::Cancelled)?;
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(PathError::Cancelled),
            result = result => result.map_err(|_| PathError::Cancelled)?.map(|attempts| attempts.into_iter().map(|inner| Arc::new(PromotionAttempt { inner, actor: self.actor.clone(), session_id: self.session_id }) as Arc<dyn PathAttempt>).collect()),
        };
        if let Err(error) = &result {
            tracing::warn!(session_id = %session_log_id(self.session_id), error = %error, "fresh direct promotion generation could not create an attempt");
        }
        result
    }
}

struct PromotionAttempt {
    inner: Arc<dyn PathAttempt>,
    actor: mpsc::Sender<ActorInput>,
    session_id: SessionId,
}

#[async_trait]
impl PathAttempt for PromotionAttempt {
    fn kind(&self) -> PathKind {
        self.inner.kind()
    }
    async fn connect(&self, cancellation: CancellationToken) -> Result<SelectedPath, PathError> {
        let path = match self.inner.connect(cancellation).await {
            Ok(path) => path,
            Err(error) => {
                tracing::warn!(path = ?self.inner.kind(), error = %error, "fresh direct promotion attempt failed");
                return Err(error);
            }
        };
        let _ = self
            .actor
            .send(ActorInput::Promoted {
                session_id: self.session_id,
                kind: path.kind(),
            })
            .await;
        Ok(path)
    }
}

async fn run_relay_session(mut worker: RelayWorker) -> bool {
    let result = run_relay_session_inner(&mut worker).await;
    let not_selected = result
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock);
    if let (Err(error), Some(reply)) = (result, worker.reply.take()) {
        let _ = reply.send(Err(error));
    }
    !not_selected
}

async fn run_relay_session_inner(worker: &mut RelayWorker) -> io::Result<()> {
    send_plain(worker, AUTH_RECORD, false).await?;
    let auth = recv_plain(worker).await?;
    if auth != AUTH_RECORD {
        return Err(invalid());
    }
    let (gate, selected) = oneshot::channel();
    let (reply, selection_reply) = oneshot::channel();
    let ready = Arc::new(RelayReady {
        gate: Mutex::new(Some(gate)),
        reply: Mutex::new(Some(reply)),
    });
    worker.selection_reply = Some(selection_reply);
    worker
        .actor
        .send(ActorInput::RelayAuthenticated {
            session_id: worker.session_id,
            ready,
        })
        .await
        .map_err(|_| closed())?;
    let selected = tokio::select! {
        biased;
        () = worker.cancellation.cancelled() => return Err(cancelled()),
        selected = selected => selected.map_err(|_| closed())?,
    };
    if !selected {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "relay path was not selected",
        ));
    }
    worker.reply = worker
        .selection_reply
        .take()
        .ok_or_else(invalid)?
        .await
        .map_err(|_| closed())?;
    worker.flow.log("io_start");
    match worker.role {
        PeerRole::Initiator => {
            let accepted = recv_plain(worker).await?;
            if accepted != OPEN_OK {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "peer rejected export open",
                ));
            }
            match worker.protocol {
                TunnelProtocol::Tcp => {
                    let (application, relay) = tokio::io::duplex(256 * 1024);
                    if let Some(reply) = worker.reply.take() {
                        let _ = reply.send(Ok(OpenedIo::Tcp(Box::new(application))));
                    }
                    pump_stream(worker, relay).await
                }
                TunnelProtocol::Udp => {
                    let (outbound, outbound_rx) = mpsc::channel(64);
                    let (inbound_tx, inbound) = mpsc::channel(64);
                    if let Some(reply) = worker.reply.take() {
                        let _ = reply.send(Ok(OpenedIo::Udp(Box::new(RelayDatagram {
                            outbound,
                            inbound,
                        }))));
                    }
                    pump_datagram(worker, outbound_rx, inbound_tx).await
                }
            }
        }
        PeerRole::Responder => {
            let request = PeerOpenRequest::new(CHANNEL_ID, worker.export.clone(), worker.protocol);
            match worker.protocol {
                TunnelProtocol::Tcp => match worker
                    .exports
                    .open_tcp(&worker.peer, &request, worker.cancellation.child_token())
                    .await
                {
                    Ok(stream) => {
                        send_plain(worker, OPEN_OK, false).await?;
                        pump_stream(worker, stream).await
                    }
                    Err(_) => {
                        let _ = send_plain(worker, OPEN_REJECTED, true).await;
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "export rejected",
                        ))
                    }
                },
                TunnelProtocol::Udp => match worker
                    .exports
                    .open_udp(&worker.peer, &request, worker.cancellation.child_token())
                    .await
                {
                    Ok(socket) => {
                        send_plain(worker, OPEN_OK, false).await?;
                        pump_udp_target(worker, socket).await
                    }
                    Err(_) => {
                        let _ = send_plain(worker, OPEN_REJECTED, true).await;
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "export rejected",
                        ))
                    }
                },
            }
        }
    }
}

async fn send_plain(worker: &RelayWorker, payload: &[u8], fin: bool) -> io::Result<()> {
    let frame = worker.relay.seal(payload, fin).map_err(|_| invalid())?;
    worker
        .context
        .send_peer_control(
            frame.to_protocol_message().map_err(|_| invalid())?,
            &worker.cancellation,
        )
        .await
        .map_err(|_| closed())
}

async fn recv_plain(worker: &mut RelayWorker) -> io::Result<Vec<u8>> {
    let frame = tokio::select! {
        biased;
        () = worker.cancellation.cancelled() => return Err(cancelled()),
        frame = worker.frames.recv() => frame.ok_or_else(closed)?,
    };
    worker.relay.open(&frame).map_err(|_| invalid())
}

async fn pump_stream<S>(worker: &mut RelayWorker, stream: S) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = vec![0_u8; MAX_RELAY_PLAINTEXT];
    loop {
        tokio::select! {
            biased;
            () = worker.cancellation.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => {
                let length = read?;
                send_plain(worker, &buffer[..length], length == 0).await?;
                if length == 0 { return Ok(()); }
            }
            frame = worker.frames.recv() => {
                let frame = frame.ok_or_else(closed)?;
                let fin = frame.flags.bits() & rustgo_rendezvous::PeerRelayFlags::FIN.bits() != 0;
                let payload = worker.relay.open(&frame).map_err(|_| invalid())?;
                if !payload.is_empty() { writer.write_all(&payload).await?; }
                if fin { writer.shutdown().await?; return Ok(()); }
            }
        }
    }
}

async fn pump_datagram(
    worker: &mut RelayWorker,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            biased;
            () = worker.cancellation.cancelled() => return Ok(()),
            payload = outbound.recv() => send_plain(worker, &payload.ok_or_else(closed)?, false).await?,
            frame = worker.frames.recv() => {
                let payload = worker.relay.open(&frame.ok_or_else(closed)?).map_err(|_| invalid())?;
                inbound.send(payload).await.map_err(|_| closed())?;
            }
        }
    }
}

async fn pump_udp_target(worker: &mut RelayWorker, socket: UdpSocket) -> io::Result<()> {
    let mut buffer = vec![0_u8; 65_507];
    loop {
        tokio::select! {
            biased;
            () = worker.cancellation.cancelled() => return Ok(()),
            received = socket.recv(&mut buffer) => {
                let length = received?;
                send_plain(worker, &buffer[..length], false).await?;
            }
            frame = worker.frames.recv() => {
                let payload = worker.relay.open(&frame.ok_or_else(closed)?).map_err(|_| invalid())?;
                socket.send(&payload).await?;
            }
        }
    }
}

struct RelayDatagram {
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<Vec<u8>>,
}
impl PeerDatagramSession for RelayDatagram {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> PeerFuture<'a, ()> {
        Box::pin(async move {
            self.outbound
                .send(payload.to_vec())
                .await
                .map_err(|_| closed())
        })
    }
    fn receive<'a>(&'a mut self) -> PeerFuture<'a, Vec<u8>> {
        Box::pin(async move { self.inbound.recv().await.ok_or_else(closed) })
    }
}

struct OneQuicAuth(Mutex<Option<PeerAuthentication>>);
impl PeerAuthenticationFactory for OneQuicAuth {
    fn create(&self) -> Result<PeerAuthentication, QuicPeerError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(QuicPeerError::AuthenticationMaterialUnavailable)
    }
}

struct OneTcpAuth(Mutex<Option<PeerTcpAuthentication>>);
impl PeerTcpAuthenticationFactory for OneTcpAuth {
    fn create(&self) -> Result<PeerTcpAuthentication, rustgo_transport::PeerTcpError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(rustgo_transport::PeerTcpError::AuthenticationMaterialUnavailable)
    }
}

async fn run_direct_tcp(
    role: PeerRole,
    peer: String,
    export: String,
    transport: Arc<EncryptedPeerTcp>,
    exports: ExportRegistry,
    mut reply: Option<oneshot::Sender<io::Result<OpenedIo>>>,
    cancellation: CancellationToken,
) {
    let result = async {
        match role {
            PeerRole::Initiator => {
                let accepted = transport
                    .receive()
                    .await
                    .map_err(|_| invalid())?
                    .ok_or_else(closed)?;
                if accepted != OPEN_OK {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "peer rejected export",
                    ));
                }
                let (application, relay) = tokio::io::duplex(256 * 1024);
                if let Some(reply) = reply.take() {
                    let _ = reply.send(Ok(OpenedIo::Tcp(Box::new(application))));
                }
                pump_encrypted_tcp(transport, relay, cancellation).await
            }
            PeerRole::Responder => {
                let request = PeerOpenRequest::new(CHANNEL_ID, export, TunnelProtocol::Tcp);
                let target = exports
                    .open_tcp(&peer, &request, cancellation.child_token())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "export rejected")
                    })?;
                transport.send(OPEN_OK).await.map_err(|_| closed())?;
                pump_encrypted_tcp(transport, target, cancellation).await
            }
        }
    }
    .await;
    if let (Err(error), Some(reply)) = (result, reply) {
        let _ = reply.send(Err(error));
    }
}

async fn pump_encrypted_tcp<S>(
    transport: Arc<EncryptedPeerTcp>,
    stream: S,
    cancellation: CancellationToken,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = vec![0_u8; MAX_RELAY_PLAINTEXT];
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => {
                let length = read?;
                if length == 0 { transport.shutdown().await.map_err(|_| closed())?; return Ok(()); }
                transport.send(&buffer[..length]).await.map_err(|_| closed())?;
            }
            payload = transport.receive() => match payload.map_err(|_| closed())? {
                Some(payload) => writer.write_all(&payload).await?,
                None => { writer.shutdown().await?; return Ok(()); }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_direct_quic(
    role: PeerRole,
    protocol: TunnelProtocol,
    peer: String,
    export: String,
    handle: Arc<QuicPeerPathHandle>,
    exports: ExportRegistry,
    mut reply: Option<oneshot::Sender<io::Result<OpenedIo>>>,
    cancellation: CancellationToken,
) {
    let result = async {
        let session = handle.session().map_err(|_| closed())?;
        if protocol != TunnelProtocol::Udp {
            return Err(invalid());
        }
        let datagram = session.datagrams();
        match role {
            PeerRole::Initiator => {
                let accepted = datagram
                    .receive(cancellation.child_token())
                    .await
                    .map_err(|_| closed())?;
                if accepted != OPEN_OK {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "peer rejected export",
                    ));
                }
                if let Some(reply) = reply.take() {
                    let _ = reply.send(Ok(OpenedIo::Udp(Box::new(QuicDatagramSession {
                        datagram,
                        cancellation: cancellation.child_token(),
                    }))));
                }
                cancellation.cancelled().await;
                Ok(())
            }
            PeerRole::Responder => {
                let request = PeerOpenRequest::new(CHANNEL_ID, export, TunnelProtocol::Udp);
                let socket = exports
                    .open_udp(&peer, &request, cancellation.child_token())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "export rejected")
                    })?;
                datagram.send(OPEN_OK).map_err(|_| closed())?;
                let mut buffer = vec![0_u8; 1024];
                loop {
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => return Ok(()),
                        received = socket.recv(&mut buffer) => {
                            let length = received?;
                            datagram.send(&buffer[..length]).map_err(|_| closed())?;
                        }
                        payload = datagram.receive(cancellation.child_token()) => {
                            socket.send(&payload.map_err(|_| closed())?).await?;
                        }
                    }
                }
            }
        }
    }
    .await;
    if let (Err(error), Some(reply)) = (result, reply) {
        let _ = reply.send(Err(error));
    }
}

struct QuicDatagramSession {
    datagram: PeerDatagram,
    cancellation: CancellationToken,
}
impl PeerDatagramSession for QuicDatagramSession {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> PeerFuture<'a, ()> {
        Box::pin(async move { self.datagram.send(payload).map_err(|_| closed()) })
    }
    fn receive<'a>(&'a mut self) -> PeerFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.datagram
                .receive(self.cancellation.child_token())
                .await
                .map_err(|_| closed())
        })
    }
}

fn local_candidates(
    config: &ClientConfig,
    id: SessionId,
    expiry: u64,
    generation: CandidateGeneration,
) -> io::Result<Vec<Candidate>> {
    let ip = local_ip(config)?;
    [
        (
            CandidateTransport::QuicUdp,
            local_socket(config, id, CandidateTransport::QuicUdp)?,
        ),
        (
            CandidateTransport::NativeTcp,
            local_socket(config, id, CandidateTransport::NativeTcp)?,
        ),
    ]
    .into_iter()
    .map(|(transport, address)| {
        Ok(Candidate {
            transport,
            address: protocol_socket(address),
            priority: if transport == CandidateTransport::QuicUdp {
                500
            } else {
                400
            },
            foundation: BoundedString::try_from(if transport == CandidateTransport::QuicUdp {
                "local-quic"
            } else {
                "local-tcp"
            })
            .map_err(|_| invalid())?,
            generation,
            expires_unix_secs: expiry,
            observation_source: BoundedString::try_from(if ip.is_loopback() {
                "loopback"
            } else {
                "local-route"
            })
            .map_err(|_| invalid())?,
        })
    })
    .collect()
}

fn local_socket(
    config: &ClientConfig,
    id: SessionId,
    transport: CandidateTransport,
) -> io::Result<SocketAddr> {
    let p2p = config.p2p.as_ref().ok_or_else(invalid)?;
    let range = match transport {
        CandidateTransport::QuicUdp => &p2p.udp_port_range,
        CandidateTransport::NativeTcp => &p2p.tcp_port_range,
        CandidateTransport::Relay => return Err(invalid()),
    };
    let width = u32::from(range.end) - u32::from(range.start) + 1;
    let session_marker =
        u32::from_be_bytes(id.as_bytes()[..4].try_into().expect("fixed session id"));
    let client_marker = config
        .client
        .name
        .bytes()
        .fold(2_166_136_261_u32, |hash, byte| {
            hash.wrapping_mul(16_777_619) ^ u32::from(byte)
        });
    // Both peers share a session id. Salt the deterministic choice with the
    // authenticated client name so simultaneous NAT mappings do not compete
    // for the same public five-tuple.
    let marker = session_marker ^ client_marker;
    let port = u32::from(range.start) + marker % width;
    Ok(SocketAddr::new(
        local_ip(config)?,
        u16::try_from(port).map_err(|_| invalid())?,
    ))
}

fn bind_quic_socket(
    config: &ClientConfig,
    id: SessionId,
    role: PeerRole,
) -> io::Result<std::net::UdpSocket> {
    let p2p = config.p2p.as_ref().ok_or_else(invalid)?;
    let width = u32::from(p2p.udp_port_range.end) - u32::from(p2p.udp_port_range.start) + 1;
    let marker = u32::from_be_bytes(id.as_bytes()[..4].try_into().expect("fixed session id"));
    let preferred_offset = (marker + if role == PeerRole::Responder { 1 } else { 0 }) % width;
    let ip = local_ip(config)?;
    for offset in 0..width {
        let port = u32::from(p2p.udp_port_range.start) + (preferred_offset + offset) % width;
        let address = SocketAddr::new(ip, u16::try_from(port).map_err(|_| invalid())?);
        match std::net::UdpSocket::bind(address) {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "configured P2P UDP port range is fully occupied",
    ))
}

fn local_ip(config: &ClientConfig) -> io::Result<IpAddr> {
    let remote = config
        .client
        .server_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(invalid)?;
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(remote)?;
    Ok(socket.local_addr()?.ip())
}

fn protocol_socket(address: SocketAddr) -> rustgo_protocol::SocketAddress {
    match address {
        SocketAddr::V4(value) => rustgo_protocol::SocketAddress::V4 {
            octets: value.ip().octets(),
            port: value.port(),
        },
        SocketAddr::V6(value) => rustgo_protocol::SocketAddress::V6 {
            octets: value.ip().octets(),
            port: value.port(),
        },
    }
}

async fn observe_nat(
    socket: std::net::UdpSocket,
    primary: String,
    alternate: String,
    grant: ObservationGrant,
    cancellation: CancellationToken,
) -> io::Result<(std::net::UdpSocket, Vec<rustgo_protocol::SocketAddress>)> {
    if grant.expires_unix_secs() <= now() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "expired observation grant",
        ));
    }
    let primary = primary.to_socket_addrs()?.next().ok_or_else(invalid)?;
    let alternate = alternate.to_socket_addrs()?.next().ok_or_else(invalid)?;
    if primary == alternate || primary.is_ipv4() != alternate.is_ipv4() {
        return Err(invalid());
    }
    if socket.local_addr()?.is_ipv4() != primary.is_ipv4() {
        return Err(invalid());
    }
    let io_socket = UdpSocket::from_std(socket.try_clone()?)?;
    let mut observed = Vec::with_capacity(2);
    for (remote, endpoint, token) in [
        (
            primary,
            ObservationEndpoint::Primary,
            grant.primary_token().clone(),
        ),
        (
            alternate,
            ObservationEndpoint::Alternate,
            grant.alternate_token().clone(),
        ),
    ] {
        let mut nonce_bytes = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| io::Error::other("OS randomness unavailable"))?;
        let nonce = ObservationNonce::from(nonce_bytes);
        let probe = ObservationProbe::new(token, nonce)
            .encode()
            .map_err(|_| invalid())?;
        io_socket.send_to(&probe, remote).await?;
        let mut buffer = [0_u8; ObservationReply::MAX_WIRE_BYTES + 1];
        let received = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(cancelled()),
            result = tokio::time::timeout(Duration::from_secs(2), io_socket.recv_from(&mut buffer)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "observation endpoint timed out"))??,
        };
        if received.1 != remote || received.0 > ObservationReply::MAX_WIRE_BYTES {
            return Err(invalid());
        }
        let reply = ObservationReply::decode(&buffer[..received.0]).map_err(|_| invalid())?;
        if reply.nonce() != nonce
            || reply.endpoint() != endpoint
            || grant.expires_unix_secs() <= now()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "observation reply binding mismatch",
            ));
        }
        observed.push(reply.observed_source().clone());
    }
    drop(io_socket);
    Ok((socket, observed))
}
fn socket_addr(address: &rustgo_protocol::SocketAddress) -> SocketAddr {
    match address {
        rustgo_protocol::SocketAddress::V4 { octets, port } => {
            SocketAddr::new(IpAddr::from(*octets), *port)
        }
        rustgo_protocol::SocketAddress::V6 { octets, port } => {
            SocketAddr::new(IpAddr::from(*octets), *port)
        }
    }
}

fn random_session_id() -> io::Result<SessionId> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| io::Error::other("OS randomness unavailable"))?;
    Ok(SessionId::from(bytes))
}
fn session_log_id(id: SessionId) -> String {
    let mut value = String::with_capacity(64);
    for byte in id.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}
fn fresh_transport_keys() -> (
    HashMap<CandidateTransport, EphemeralPeerKey>,
    HashMap<CandidateTransport, [u8; 32]>,
) {
    let mut private = HashMap::new();
    let mut public = HashMap::new();
    for transport in [
        CandidateTransport::QuicUdp,
        CandidateTransport::NativeTcp,
        CandidateTransport::Relay,
    ] {
        let key = EphemeralPeerKey::generate();
        public.insert(transport, key.public_key());
        private.insert(transport, key);
    }
    (private, public)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs())
}
fn protocol_to_wire(value: TunnelProtocol) -> rustgo_protocol::TunnelProtocol {
    match value {
        TunnelProtocol::Tcp => rustgo_protocol::TunnelProtocol::TCP,
        TunnelProtocol::Udp => rustgo_protocol::TunnelProtocol::UDP,
    }
}
fn protocol_from_wire(value: rustgo_protocol::TunnelProtocol) -> TunnelProtocol {
    if value == rustgo_protocol::TunnelProtocol::UDP {
        TunnelProtocol::Udp
    } else {
        TunnelProtocol::Tcp
    }
}
fn transcript_hash(id: SessionId, session: &Session, local: &str) -> [u8; 32] {
    transcript_hash_for_transport(id, session, local, CandidateTransport::Relay)
}
fn transcript_hash_for_transport(
    id: SessionId,
    session: &Session,
    local: &str,
    transport: CandidateTransport,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"rustgo-rendezvous-transcript-v1");
    hash.update(id.as_bytes());
    let (initiator, responder) = match session.role {
        PeerRole::Initiator => (local, session.peer.as_str()),
        PeerRole::Responder => (session.peer.as_str(), local),
    };
    hash.update(initiator.as_bytes());
    hash.update(responder.as_bytes());
    hash.update(session.export.as_bytes());
    hash.update(session.expiry.to_be_bytes());
    hash.update([match transport {
        CandidateTransport::QuicUdp => 1,
        CandidateTransport::NativeTcp => 2,
        CandidateTransport::Relay => 3,
    }]);
    hash.finalize().into()
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid peer orchestration state",
    )
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "peer control generation closed")
}
fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "peer operation cancelled")
}
fn event_kind(event: &ControlEvent) -> &'static str {
    match event {
        ControlEvent::ObservationGrant(_) => "observation_grant",
        ControlEvent::Rendezvous(_) => "rendezvous",
        ControlEvent::ServerNotice(_) => "server_notice",
        ControlEvent::PeerRelayFrame(_) => "relay_frame",
        ControlEvent::PeerIdentityBinding(_) => "identity_binding",
    }
}

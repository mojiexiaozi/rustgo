use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use rustgo_config::TunnelProtocol as ConfigTunnelProtocol;
use rustgo_protocol::{
    BoundedBytes, BoundedString, DataChannelBind, DataChannelKind, Frame, FrameCodec, FrameError,
    MAX_CLIENT_NAME_BYTES, MAX_SESSION_ID_BYTES, MAX_UDP_PAYLOAD_BYTES, Message, OpenUdpChannel,
    ProtocolVersion, SocketAddress, UDP_METADATA_LEN, UdpDatagram,
};
use rustgo_transport::{TlsClient, safe_display, short_id};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::MissedTickBehavior,
};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::{
    ChildSessionContext, ChildSessionRequest, ChildSessionSupervisor, ControlClient,
    tcp::TcpSessionSupervisor, telemetry::LogicalTraffic,
};

const MAX_CLIENT_UDP_CHANNELS: usize = rustgo_protocol::MAX_TUNNELS;
const UDP_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_LOCAL_SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const DATA_FRAME_MAX: usize = UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES;

#[derive(Debug, Clone, Copy)]
struct NegotiatedUdpLimits {
    max_sessions: usize,
    idle_timeout: Duration,
    max_payload: usize,
    queue_capacity: usize,
    session_queue_capacity: usize,
    sweep_interval: Duration,
    sweep_batch: usize,
}

impl TryFrom<&OpenUdpChannel> for NegotiatedUdpLimits {
    type Error = UdpClientError;

    fn try_from(request: &OpenUdpChannel) -> Result<Self, Self::Error> {
        if !request.has_valid_limits() {
            return Err(UdpClientError::InvalidNegotiatedLimits);
        }
        let max_sessions = usize::try_from(request.max_sessions)
            .map_err(|_| UdpClientError::InvalidNegotiatedLimits)?;
        let max_payload = usize::try_from(request.max_payload_bytes)
            .map_err(|_| UdpClientError::InvalidNegotiatedLimits)?;
        let queue_capacity = usize::try_from(request.queue_capacity)
            .map_err(|_| UdpClientError::InvalidNegotiatedLimits)?;
        let idle_timeout = Duration::from_millis(u64::from(request.idle_timeout_millis));
        let sweep_interval = idle_timeout.min(Duration::from_secs(1));
        let sweep_batch = minimum_sweep_batch(max_sessions, idle_timeout, sweep_interval)
            .ok_or(UdpClientError::InvalidNegotiatedLimits)?;
        Ok(Self {
            max_sessions,
            idle_timeout,
            max_payload,
            queue_capacity,
            session_queue_capacity: queue_capacity.min(64),
            sweep_interval,
            sweep_batch,
        })
    }
}

fn minimum_sweep_batch(
    capacity: usize,
    idle_timeout: Duration,
    sweep_interval: Duration,
) -> Option<usize> {
    let sweeps_before_timeout = idle_timeout
        .as_nanos()
        .checked_div(sweep_interval.as_nanos())?
        .max(1);
    let capacity = u128::try_from(capacity).ok()?;
    usize::try_from(capacity.div_ceil(sweeps_before_timeout)).ok()
}

pub(crate) struct RelaySessionSupervisor {
    tcp: TcpSessionSupervisor,
    udp: UdpSessionSupervisor,
}

impl RelaySessionSupervisor {
    pub(crate) fn new(control: &ControlClient, traffic: Arc<LogicalTraffic>) -> Self {
        Self {
            tcp: TcpSessionSupervisor::new(control, traffic.clone()),
            udp: UdpSessionSupervisor::new(control, traffic),
        }
    }
}

impl ChildSessionSupervisor for RelaySessionSupervisor {
    fn run_child(
        &self,
        context: ChildSessionContext,
        request: ChildSessionRequest,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        match request {
            ChildSessionRequest::Tcp(request) => {
                self.tcp
                    .run_child(context, ChildSessionRequest::Tcp(request), shutdown)
            }
            ChildSessionRequest::Udp(request) => {
                self.udp
                    .run_child(context, ChildSessionRequest::Udp(request), shutdown)
            }
        }
    }
}

struct UdpSessionSupervisor {
    client_name: String,
    server_addr: String,
    tls_client: TlsClient,
    local_targets: Arc<HashMap<u32, UdpTunnelTarget>>,
    permits: Arc<Semaphore>,
    traffic: Arc<LogicalTraffic>,
}

#[derive(Clone)]
struct UdpTunnelTarget {
    name: String,
    local_address: String,
}

impl UdpSessionSupervisor {
    fn new(control: &ControlClient, traffic: Arc<LogicalTraffic>) -> Self {
        let local_targets = control
            .config()
            .tunnels
            .iter()
            .enumerate()
            .filter(|(_, tunnel)| tunnel.protocol == ConfigTunnelProtocol::Udp)
            .filter_map(|(index, tunnel)| {
                u32::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    .map(|tunnel_id| {
                        (
                            tunnel_id,
                            UdpTunnelTarget {
                                name: tunnel.name.clone(),
                                local_address: tunnel.local_addr.clone(),
                            },
                        )
                    })
            })
            .collect();
        Self {
            client_name: control.config().client.name.clone(),
            server_addr: control.config().client.server_addr.clone(),
            tls_client: control.tls_client(),
            local_targets: Arc::new(local_targets),
            permits: Arc::new(Semaphore::new(MAX_CLIENT_UDP_CHANNELS)),
            traffic,
        }
    }
}

impl ChildSessionSupervisor for UdpSessionSupervisor {
    fn run_child(
        &self,
        context: ChildSessionContext,
        request: ChildSessionRequest,
        shutdown: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let client_name = self.client_name.clone();
        let server_addr = self.server_addr.clone();
        let tls_client = self.tls_client.clone();
        let local_targets = self.local_targets.clone();
        let permits = self.permits.clone();
        let traffic = self.traffic.clone();
        Box::pin(async move {
            let ChildSessionRequest::Udp(request) = request else {
                return;
            };
            let limits = match NegotiatedUdpLimits::try_from(&request) {
                Ok(limits) => limits,
                Err(error) => {
                    tracing::warn!(tunnel_id = request.tunnel_id, error = %safe_display(&error), "invalid negotiated UDP limits");
                    return;
                }
            };
            let Ok(permit) = permits.try_acquire_owned() else {
                tracing::warn!(
                    tunnel_id = request.tunnel_id,
                    "UDP channel admission limit reached"
                );
                return;
            };
            let Some(target) = local_targets.get(&request.tunnel_id).cloned() else {
                return;
            };
            let protocol_version = context.protocol_version();
            let setup = setup_data_channel(
                &client_name,
                &server_addr,
                &tls_client,
                protocol_version,
                context.session_id(),
                &request,
            );
            let data = tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                result = tokio::time::timeout(UDP_SETUP_TIMEOUT, setup) => match result {
                    Ok(Ok(data)) => data,
                    Ok(Err(error)) => {
                        tracing::warn!(tunnel_id = request.tunnel_id, error = %safe_display(&error), "UDP data setup failed");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(tunnel_id = request.tunnel_id, "UDP data setup timed out");
                        return;
                    }
                },
            };
            tracing::info!(
                tunnel_id = request.tunnel_id,
                channel_id = request.channel_id,
                generation = context.generation().get(),
                max_sessions = request.max_sessions,
                idle_timeout_millis = request.idle_timeout_millis,
                max_payload_bytes = request.max_payload_bytes,
                queue_capacity = request.queue_capacity,
                "event=udp_channel_ready client UDP data channel ready"
            );
            if let Err(error) = relay_local_datagrams(
                data,
                protocol_version,
                &client_name,
                target,
                request.tunnel_id,
                context.generation().get(),
                limits,
                traffic,
                shutdown,
            )
            .await
            {
                tracing::debug!(
                    tunnel_id = request.tunnel_id,
                    channel_id = request.channel_id,
                    error = %safe_display(&error),
                    "UDP local relay ended"
                );
            }
            drop(permit);
        })
    }
}

async fn setup_data_channel(
    client_name: &str,
    server_addr: &str,
    tls_client: &TlsClient,
    protocol_version: ProtocolVersion,
    session_id: &[u8],
    request: &OpenUdpChannel,
) -> Result<TlsStream<TcpStream>, UdpClientError> {
    let mut data = tls_client.connect(server_addr).await?;
    let bind = Message::DataChannelBind(DataChannelBind {
        client_name: BoundedString::<MAX_CLIENT_NAME_BYTES>::try_from(client_name)
            .map_err(|_| UdpClientError::InvalidBinding)?,
        session_id: BoundedBytes::<MAX_SESSION_ID_BYTES>::try_from(session_id)
            .map_err(|_| UdpClientError::InvalidBinding)?,
        kind: DataChannelKind::UDP,
        tunnel_id: request.tunnel_id,
        target_id: request.channel_id,
        binding_token: request.binding_token.clone(),
    });
    let codec = FrameCodec::new(1024);
    let encoded = codec.encode(protocol_version, 0, &bind)?;
    data.write_all(&encoded).await?;

    let acknowledgement = read_frame_exact(&mut data, codec).await?;
    if acknowledgement.version != protocol_version {
        return Err(UdpClientError::InvalidAcknowledgement);
    }
    let Message::OpenUdpChannel(ready) = acknowledgement.message else {
        return Err(UdpClientError::InvalidAcknowledgement);
    };
    if &ready != request {
        return Err(UdpClientError::InvalidAcknowledgement);
    }
    Ok(data)
}

async fn read_frame_exact<R>(stream: &mut R, codec: FrameCodec) -> Result<Frame, UdpClientError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; rustgo_protocol::HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let needed = match codec.decode_exact(&header) {
        Err(FrameError::Truncated { needed, .. }) => needed,
        Ok(frame) => return Ok(frame),
        Err(error) => return Err(error.into()),
    };
    let mut frame = BytesMut::from(header.as_slice());
    frame.resize(needed, 0);
    stream
        .read_exact(&mut frame[rustgo_protocol::HEADER_LEN..])
        .await?;
    codec.decode_exact(&frame).map_err(Into::into)
}

struct ClientSession {
    lease: u64,
    external: SocketAddr,
    sender: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
    last_activity: Arc<Mutex<tokio::time::Instant>>,
    previous: Option<u64>,
    next: Option<u64>,
}

struct ClientSessionTable {
    sessions: HashMap<u64, ClientSession>,
    sweep_head: Option<u64>,
    sweep_tail: Option<u64>,
}

impl ClientSessionTable {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            sweep_head: None,
            sweep_tail: None,
        }
    }

    fn insert(&mut self, session_id: u64, mut session: ClientSession) -> bool {
        if self.sessions.contains_key(&session_id) {
            return false;
        }
        session.previous = self.sweep_tail;
        session.next = None;
        if let Some(previous) = self.sweep_tail {
            let Some(previous) = self.sessions.get_mut(&previous) else {
                return false;
            };
            previous.next = Some(session_id);
        } else {
            self.sweep_head = Some(session_id);
        }
        self.sweep_tail = Some(session_id);
        self.sessions.insert(session_id, session);
        true
    }

    fn remove(&mut self, session_id: u64) -> bool {
        let Some(session) = self.sessions.remove(&session_id) else {
            return false;
        };
        session.cancellation.cancel();
        if let Some(previous) = session.previous {
            if let Some(previous) = self.sessions.get_mut(&previous) {
                previous.next = session.next;
            }
        } else {
            self.sweep_head = session.next;
        }
        if let Some(next) = session.next {
            if let Some(next) = self.sessions.get_mut(&next) {
                next.previous = session.previous;
            }
        } else {
            self.sweep_tail = session.previous;
        }
        true
    }

    fn remove_if_lease(&mut self, session_id: u64, lease: u64) -> bool {
        if !self
            .sessions
            .get(&session_id)
            .is_some_and(|session| session.lease == lease)
        {
            return false;
        }
        self.remove(session_id)
    }

    fn rotate_sweep_head(&mut self, session_id: u64) -> bool {
        if self.sweep_head != Some(session_id) {
            return false;
        }
        if self.sweep_tail == Some(session_id) {
            return true;
        }
        let Some(next) = self
            .sessions
            .get(&session_id)
            .and_then(|session| session.next)
        else {
            return false;
        };
        let Some(tail) = self.sweep_tail else {
            return false;
        };
        let Some(next_session) = self.sessions.get_mut(&next) else {
            return false;
        };
        next_session.previous = None;
        let Some(tail_session) = self.sessions.get_mut(&tail) else {
            return false;
        };
        tail_session.next = Some(session_id);
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return false;
        };
        session.previous = Some(tail);
        session.next = None;
        self.sweep_head = Some(next);
        self.sweep_tail = Some(session_id);
        true
    }

    fn sweep_expired(
        &mut self,
        now: tokio::time::Instant,
        idle_timeout: Duration,
        maximum: usize,
    ) -> Result<usize, UdpClientError> {
        let mut expired = 0;
        let inspected = maximum.min(self.sessions.len());
        for _ in 0..inspected {
            let Some(session_id) = self.sweep_head else {
                break;
            };
            let is_expired = if let Some(session) = self.sessions.get(&session_id) {
                let last_activity = *session
                    .last_activity
                    .lock()
                    .map_err(|_| UdpClientError::ActivityState)?;
                now.saturating_duration_since(last_activity) >= idle_timeout
            } else {
                false
            };
            if is_expired {
                expired += usize::from(self.remove(session_id));
            } else if !self.rotate_sweep_head(session_id) {
                break;
            }
        }
        Ok(expired)
    }

    fn clear(&mut self) {
        for session in self.sessions.values() {
            session.cancellation.cancel();
        }
        self.sessions.clear();
        self.sweep_head = None;
        self.sweep_tail = None;
    }
}

#[derive(Default)]
struct UdpMetrics {
    sessions: AtomicUsize,
    data_queued: AtomicUsize,
    local_queued: AtomicUsize,
    data_queue_drops: AtomicU64,
    session_queue_drops: AtomicU64,
    session_limit_drops: AtomicU64,
    invalid_drops: AtomicU64,
}

impl UdpMetrics {
    fn record_drop(counter: &AtomicU64, tunnel_id: u32, reason: &'static str) {
        let total = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if total == 1 || total.is_power_of_two() {
            tracing::warn!(
                tunnel_id,
                reason,
                total,
                "event=udp_drop UDP datagram dropped"
            );
        }
    }
}

enum QueueResult {
    Queued,
    Full,
    Closed,
}

fn try_queue<T>(sender: &mpsc::Sender<T>, value: T, queued: &AtomicUsize) -> QueueResult {
    queued.fetch_add(1, Ordering::AcqRel);
    match sender.try_send(value) {
        Ok(()) => QueueResult::Queued,
        Err(mpsc::error::TrySendError::Full(_)) => {
            queued.fetch_sub(1, Ordering::AcqRel);
            QueueResult::Full
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            queued.fetch_sub(1, Ordering::AcqRel);
            QueueResult::Closed
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_local_datagrams(
    data: TlsStream<TcpStream>,
    protocol_version: ProtocolVersion,
    client_name: &str,
    target: UdpTunnelTarget,
    tunnel_id: u32,
    generation: u64,
    limits: NegotiatedUdpLimits,
    traffic: Arc<LogicalTraffic>,
    shutdown: CancellationToken,
) -> Result<(), UdpClientError> {
    let UdpTunnelTarget {
        name: tunnel_name,
        local_address: local_target,
    } = target;
    let (reader, writer) = tokio::io::split(data);
    let mut reader = UdpFrameReader::new(reader);
    let (data_outbound, data_receiver) = mpsc::channel(limits.queue_capacity);
    let metrics = Arc::new(UdpMetrics::default());
    let relay_shutdown = CancellationToken::new();
    let mut writer_task = tokio::spawn(write_frames(
        writer,
        data_receiver,
        metrics.clone(),
        relay_shutdown.clone(),
        protocol_version,
        traffic.clone(),
    ));
    let mut writer_finished = false;
    let mut sessions = ClientSessionTable::new();
    let mut local_tasks = JoinSet::new();
    let mut next_local_lease = 0_u64;
    let first_sweep = tokio::time::Instant::now()
        .checked_add(limits.sweep_interval)
        .ok_or(UdpClientError::InvalidRuntime)?;
    let mut sweep = tokio::time::interval_at(first_sweep, limits.sweep_interval);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let result = loop {
        tokio::select! {
            () = shutdown.cancelled() => break Ok(()),
            joined = &mut writer_task => {
                writer_finished = true;
                break match joined {
                    Ok(Ok(())) => Err(UdpClientError::DataChannelClosed),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(UdpClientError::TaskJoin),
                };
            }
            _ = sweep.tick() => {
                let expired = sessions.sweep_expired(
                    tokio::time::Instant::now(),
                    limits.idle_timeout,
                    limits.sweep_batch,
                )?;
                if expired != 0 {
                    metrics.sessions.store(sessions.sessions.len(), Ordering::Release);
                    tracing::debug!(tunnel_id, generation, expired, sessions = sessions.sessions.len(), "event=udp_idle_sweep expired local UDP sessions");
                }
            }
            joined = local_tasks.join_next(), if !local_tasks.is_empty() => {
                let Some(joined) = joined else {
                    continue;
                };
                let (session_id, lease, result) = joined.map_err(|_| UdpClientError::TaskJoin)?;
                sessions.remove_if_lease(session_id, lease);
                metrics.sessions.store(sessions.sessions.len(), Ordering::Release);
                if let Err(error) = result {
                    tracing::warn!(tunnel_id, session_id, error = %safe_display(&error), "event=udp_session_end local UDP session ended");
                }
            }
            frame = reader.receive() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => break Err(error),
                };
                if frame.version != protocol_version {
                    break Err(UdpClientError::InvalidFrame);
                }
                let datagram = match frame.message {
                    Message::UdpDatagram(datagram) => datagram,
                    Message::UdpSessionRetired(retired) => {
                        if retired.tunnel_id != tunnel_id || retired.session_id == 0 {
                            break Err(UdpClientError::InvalidFrame);
                        }
                        let removed = sessions.remove(retired.session_id);
                        if removed {
                            metrics.sessions.store(sessions.sessions.len(), Ordering::Release);
                        }
                        tracing::info!(
                            tunnel_id,
                            generation,
                            session_id = retired.session_id,
                            removed,
                            sessions = sessions.sessions.len(),
                            "event=udp_session_retired server retired local UDP flow"
                        );
                        continue;
                    }
                    _ => break Err(UdpClientError::InvalidFrame),
                };
                if datagram.tunnel_id != tunnel_id || datagram.session_id == 0 {
                    break Err(UdpClientError::InvalidFrame);
                }
                if datagram.payload.as_slice().len() > limits.max_payload {
                    UdpMetrics::record_drop(
                        &metrics.invalid_drops,
                        tunnel_id,
                        "oversize_server_datagram",
                    );
                    continue;
                }
                let external = socket_addr_from_wire(&datagram.source);
                let now = tokio::time::Instant::now();
                if !sessions.sessions.contains_key(&datagram.session_id) {
                    if sessions.sessions.len() >= limits.max_sessions
                        || local_tasks.len() >= limits.max_sessions
                    {
                        UdpMetrics::record_drop(&metrics.session_limit_drops, tunnel_id, "client_session_limit");
                        continue;
                    }
                    let session_shutdown = relay_shutdown.child_token();
                    let (sender, receiver) = mpsc::channel(limits.session_queue_capacity);
                    let local_target = local_target.clone();
                    let session_id = datagram.session_id;
                    let data_outbound = data_outbound.clone();
                    let task_metrics = metrics.clone();
                    let task_traffic = traffic.clone();
                    let task_shutdown = session_shutdown.clone();
                    let last_activity = Arc::new(Mutex::new(now));
                    let task_activity = last_activity.clone();
                    let lease = next_local_lease
                        .checked_add(1)
                        .ok_or(UdpClientError::InvalidRuntime)?;
                    next_local_lease = lease;
                    local_tasks.spawn(async move {
                        let result = run_local_session(
                            local_target,
                            tunnel_id,
                            session_id,
                            external,
                            receiver,
                            data_outbound,
                            task_metrics,
                            task_activity,
                            limits.max_payload,
                            task_traffic,
                            task_shutdown,
                        )
                        .await;
                        (session_id, lease, result)
                    });
                    if !sessions.insert(
                        datagram.session_id,
                        ClientSession {
                            lease,
                            external,
                            sender,
                            cancellation: session_shutdown,
                            last_activity,
                            previous: None,
                            next: None,
                        },
                    ) {
                        break Err(UdpClientError::InvalidRuntime);
                    }
                    metrics.sessions.store(sessions.sessions.len(), Ordering::Release);
                    tracing::info!(
                        client = %safe_display(client_name),
                        tunnel = %safe_display(&tunnel_name),
                        conn = %short_id(datagram.session_id),
                        event = %"udp_session_open",
                        "UDP local relay session opened"
                    );
                }
                let Some(session) = sessions.sessions.get_mut(&datagram.session_id) else {
                    continue;
                };
                if session.external != external {
                    UdpMetrics::record_drop(&metrics.invalid_drops, tunnel_id, "mismatched_session_source");
                    continue;
                }
                *session
                    .last_activity
                    .lock()
                    .map_err(|_| UdpClientError::ActivityState)? = now;
                match try_queue(
                    &session.sender,
                    datagram.payload.into_vec(),
                    &metrics.local_queued,
                ) {
                    QueueResult::Queued => {}
                    QueueResult::Full => UdpMetrics::record_drop(
                        &metrics.session_queue_drops,
                        tunnel_id,
                        "session_queue_full",
                    ),
                    QueueResult::Closed => {
                        sessions.remove(datagram.session_id);
                        metrics.sessions.store(sessions.sessions.len(), Ordering::Release);
                    }
                }
            }
        }
    };

    relay_shutdown.cancel();
    drop(data_outbound);
    sessions.clear();
    while local_tasks.join_next().await.is_some() {}
    if !writer_finished {
        let _ = writer_task.await;
    }
    metrics.sessions.store(0, Ordering::Release);
    metrics.data_queued.store(0, Ordering::Release);
    metrics.local_queued.store(0, Ordering::Release);
    tracing::info!(
        tunnel_id,
        generation,
        sessions = metrics.sessions.load(Ordering::Acquire),
        queue = metrics.data_queued.load(Ordering::Acquire),
        local_queue = metrics.local_queued.load(Ordering::Acquire),
        drops_queue = metrics.data_queue_drops.load(Ordering::Relaxed),
        drops_session_queue = metrics.session_queue_drops.load(Ordering::Relaxed),
        drops_sessions = metrics.session_limit_drops.load(Ordering::Relaxed),
        drops_invalid = metrics.invalid_drops.load(Ordering::Relaxed),
        "event=udp_cleanup client UDP relay state released"
    );
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_local_session(
    local_target: String,
    tunnel_id: u32,
    session_id: u64,
    external: SocketAddr,
    mut requests: mpsc::Receiver<Vec<u8>>,
    data_outbound: mpsc::Sender<Message>,
    metrics: Arc<UdpMetrics>,
    last_activity: Arc<Mutex<tokio::time::Instant>>,
    max_payload: usize,
    traffic: Arc<LogicalTraffic>,
    cancellation: CancellationToken,
) -> Result<(), UdpClientError> {
    let setup = async {
        let target = lookup_host(&local_target)
            .await?
            .next()
            .ok_or(UdpClientError::InvalidLocalTarget)?;
        let bind_address = if target.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind_address).await?;
        socket.connect(target).await?;
        Ok::<_, UdpClientError>(socket)
    };
    let socket = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Ok(()),
        result = tokio::time::timeout(UDP_LOCAL_SETUP_TIMEOUT, setup) => {
            result.map_err(|_| UdpClientError::LocalSetupTimeout)??
        }
    };
    let mut response = vec![0_u8; max_payload.saturating_add(1)];
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            request = requests.recv() => {
                let Some(request) = request else {
                    break;
                };
                metrics.local_queued.fetch_sub(1, Ordering::AcqRel);
                let send = socket.send(&request);
                let sent = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => break,
                    sent = send => sent?,
                };
                if sent != request.len() {
                    return Err(UdpClientError::ShortDatagramWrite);
                }
                traffic.record_received(sent);
            }
            received = socket.recv(&mut response) => {
                let received = match received {
                    Ok(received) => received,
                    Err(error) if is_oversized_datagram_error(&error) => {
                        UdpMetrics::record_drop(&metrics.invalid_drops, tunnel_id, "oversize_local_reply");
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                if received > max_payload {
                    UdpMetrics::record_drop(&metrics.invalid_drops, tunnel_id, "oversize_local_reply");
                    continue;
                }
                let payload = BoundedBytes::<MAX_UDP_PAYLOAD_BYTES>::try_from(&response[..received])
                    .map_err(|_| UdpClientError::InvalidFrame)?;
                *last_activity
                    .lock()
                    .map_err(|_| UdpClientError::ActivityState)? = tokio::time::Instant::now();
                let message = Message::UdpDatagram(UdpDatagram {
                    tunnel_id,
                    session_id,
                    source: wire_socket_addr(external),
                    payload,
                });
                match try_queue(&data_outbound, message, &metrics.data_queued) {
                    QueueResult::Queued => {}
                    QueueResult::Full => UdpMetrics::record_drop(
                        &metrics.data_queue_drops,
                        tunnel_id,
                        "data_queue_full",
                    ),
                    QueueResult::Closed => break,
                }
            }
        }
    }
    while requests.try_recv().is_ok() {
        metrics.local_queued.fetch_sub(1, Ordering::AcqRel);
    }
    Ok(())
}

async fn write_frames<W>(
    mut writer: W,
    mut receiver: mpsc::Receiver<Message>,
    metrics: Arc<UdpMetrics>,
    cancellation: CancellationToken,
    protocol_version: ProtocolVersion,
    traffic: Arc<LogicalTraffic>,
) -> Result<(), UdpClientError>
where
    W: AsyncWrite + Unpin,
{
    let codec = FrameCodec::new(DATA_FRAME_MAX);
    let result = loop {
        let message = tokio::select! {
            biased;
            () = cancellation.cancelled() => break Ok(()),
            message = receiver.recv() => match message {
                Some(message) => message,
                None => break Ok(()),
            },
        };
        metrics.data_queued.fetch_sub(1, Ordering::AcqRel);
        let logical_bytes = match &message {
            Message::UdpDatagram(datagram) => datagram.payload.as_slice().len(),
            _ => 0,
        };
        let encoded = codec.encode(protocol_version, 0, &message)?;
        let write = writer.write_all(&encoded);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break Ok(()),
            result = write => result?,
        }
        traffic.record_sent(logical_bytes);
    };
    while receiver.try_recv().is_ok() {
        metrics.data_queued.fetch_sub(1, Ordering::AcqRel);
    }
    result
}

struct UdpFrameReader<R> {
    reader: R,
    buffer: BytesMut,
    codec: FrameCodec,
}

impl<R> UdpFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: BytesMut::with_capacity(rustgo_protocol::HEADER_LEN + DATA_FRAME_MAX),
            codec: FrameCodec::new(DATA_FRAME_MAX),
        }
    }

    async fn receive(&mut self) -> Result<Frame, UdpClientError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffer)? {
                return Ok(frame);
            }
            if self.buffer.len() >= rustgo_protocol::HEADER_LEN + DATA_FRAME_MAX {
                return Err(UdpClientError::FrameTooLarge);
            }
            if self.reader.read_buf(&mut self.buffer).await? == 0 {
                return Err(UdpClientError::DataChannelClosed);
            }
        }
    }
}

fn canonical_socket_addr(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), address.port()))
            .unwrap_or(SocketAddr::V6(address)),
        SocketAddr::V4(_) => address,
    }
}

fn wire_socket_addr(address: SocketAddr) -> SocketAddress {
    match canonical_socket_addr(address) {
        SocketAddr::V4(address) => SocketAddress::V4 {
            octets: address.ip().octets(),
            port: address.port(),
        },
        SocketAddr::V6(address) => SocketAddress::V6 {
            octets: address.ip().octets(),
            port: address.port(),
        },
    }
}

fn socket_addr_from_wire(address: &SocketAddress) -> SocketAddr {
    canonical_socket_addr(match address {
        SocketAddress::V4 { octets, port } => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*octets)), *port)
        }
        SocketAddress::V6 { octets, port } => SocketAddr::new(IpAddr::V6((*octets).into()), *port),
    })
}

fn is_oversized_datagram_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(10040) || error.kind() == io::ErrorKind::InvalidData
}

#[derive(Debug, Error)]
enum UdpClientError {
    #[error("UDP I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("UDP TLS data connection failed: {0}")]
    Tls(#[from] rustgo_transport::TlsError),
    #[error("UDP data frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("invalid UDP data-channel binding")]
    InvalidBinding,
    #[error("invalid UDP data-channel acknowledgement")]
    InvalidAcknowledgement,
    #[error("invalid negotiated UDP channel limits")]
    InvalidNegotiatedLimits,
    #[error("invalid UDP data frame")]
    InvalidFrame,
    #[error("UDP frame exceeded its maximum")]
    FrameTooLarge,
    #[error("UDP data channel closed")]
    DataChannelClosed,
    #[error("UDP local target did not resolve")]
    InvalidLocalTarget,
    #[error("UDP local setup timed out")]
    LocalSetupTimeout,
    #[error("UDP send wrote a partial datagram")]
    ShortDatagramWrite,
    #[error("UDP relay child task failed")]
    TaskJoin,
    #[error("invalid UDP runtime deadline")]
    InvalidRuntime,
    #[error("UDP activity state was poisoned")]
    ActivityState,
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use rustgo_protocol::{
        BoundedBytes, MAX_BINDING_TOKEN_BYTES, MAX_UDP_PAYLOAD_BYTES, MAX_UDP_QUEUE_CAPACITY,
        MAX_UDP_SESSIONS_PER_TUNNEL, OpenUdpChannel,
    };
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::{ClientSession, ClientSessionTable, NegotiatedUdpLimits, canonical_socket_addr};

    fn negotiated_request() -> OpenUdpChannel {
        OpenUdpChannel {
            tunnel_id: 1,
            channel_id: 2,
            binding_token: BoundedBytes::<MAX_BINDING_TOKEN_BYTES>::try_from(&[3; 32][..]).unwrap(),
            max_sessions: 1,
            idle_timeout_millis: 150,
            max_payload_bytes: 16,
            queue_capacity: 1,
        }
    }

    #[test]
    fn invalid_negotiated_limits_are_rejected_by_the_preconnect_gate() {
        let valid = negotiated_request();
        let limits = NegotiatedUdpLimits::try_from(&valid).unwrap();
        assert_eq!(limits.max_sessions, 1);
        assert_eq!(limits.idle_timeout, std::time::Duration::from_millis(150));
        assert_eq!(limits.max_payload, 16);
        assert_eq!(limits.queue_capacity, 1);

        for invalid in [
            OpenUdpChannel {
                tunnel_id: 0,
                ..valid.clone()
            },
            OpenUdpChannel {
                channel_id: 0,
                ..valid.clone()
            },
            OpenUdpChannel {
                max_sessions: 0,
                ..valid.clone()
            },
            OpenUdpChannel {
                max_sessions: MAX_UDP_SESSIONS_PER_TUNNEL + 1,
                ..valid.clone()
            },
            OpenUdpChannel {
                idle_timeout_millis: 0,
                ..valid.clone()
            },
            OpenUdpChannel {
                max_payload_bytes: 0,
                ..valid.clone()
            },
            OpenUdpChannel {
                max_payload_bytes: MAX_UDP_PAYLOAD_BYTES as u32 + 1,
                ..valid.clone()
            },
            OpenUdpChannel {
                queue_capacity: 0,
                ..valid.clone()
            },
            OpenUdpChannel {
                queue_capacity: MAX_UDP_QUEUE_CAPACITY + 1,
                ..valid.clone()
            },
        ] {
            assert!(NegotiatedUdpLimits::try_from(&invalid).is_err());
        }
    }

    #[test]
    fn million_session_sweep_completes_within_the_idle_timeout() {
        let request = OpenUdpChannel {
            max_sessions: MAX_UDP_SESSIONS_PER_TUNNEL,
            idle_timeout_millis: 60_000,
            ..negotiated_request()
        };
        let limits = NegotiatedUdpLimits::try_from(&request).unwrap();
        assert_eq!(limits.sweep_interval, Duration::from_secs(1));
        assert_eq!(limits.sweep_batch, 16_667);
    }

    #[test]
    fn old_local_task_completion_cannot_remove_a_recreated_session_id() {
        let mut sessions = ClientSessionTable::new();
        let old_cancellation = CancellationToken::new();
        let (old_sender, _old_receiver) = mpsc::channel(1);
        assert!(sessions.insert(
            7,
            ClientSession {
                lease: 1,
                external: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_007),
                sender: old_sender,
                cancellation: old_cancellation.clone(),
                last_activity: Arc::new(Mutex::new(tokio::time::Instant::now())),
                previous: None,
                next: None,
            },
        ));
        assert!(sessions.remove(7));
        assert!(old_cancellation.is_cancelled());

        let replacement_cancellation = CancellationToken::new();
        let (replacement_sender, _replacement_receiver) = mpsc::channel(1);
        assert!(sessions.insert(
            7,
            ClientSession {
                lease: 2,
                external: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_007),
                sender: replacement_sender,
                cancellation: replacement_cancellation.clone(),
                last_activity: Arc::new(Mutex::new(tokio::time::Instant::now())),
                previous: None,
                next: None,
            },
        ));

        assert!(!sessions.remove_if_lease(7, 1));
        assert_eq!(sessions.sessions[&7].lease, 2);
        assert!(!replacement_cancellation.is_cancelled());
    }

    #[test]
    fn removed_local_sessions_do_not_grow_the_bounded_sweep_ring() {
        let mut sessions = ClientSessionTable::new();
        for session_id in 1..=128 {
            let (sender, receiver) = mpsc::channel(1);
            drop(receiver);
            assert!(sessions.insert(
                session_id,
                ClientSession {
                    lease: session_id,
                    external: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_000),
                    sender,
                    cancellation: CancellationToken::new(),
                    last_activity: Arc::new(Mutex::new(tokio::time::Instant::now())),
                    previous: None,
                    next: None,
                },
            ));
            assert!(sessions.remove(session_id));
            assert!(sessions.sessions.is_empty());
            assert_eq!(sessions.sweep_head, None);
            assert_eq!(sessions.sweep_tail, None);
        }
    }

    #[test]
    fn ipv4_mapped_recipients_are_canonicalized_before_session_routing() {
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
            ])),
            27015,
        );
        assert_eq!(
            canonical_socket_addr(mapped),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 27015)
        );
    }

    #[test]
    fn removing_a_middle_local_session_keeps_sweep_links_consistent() {
        let mut sessions = ClientSessionTable::new();
        for session_id in 1..=3 {
            let (sender, receiver) = mpsc::channel(1);
            drop(receiver);
            assert!(sessions.insert(
                session_id,
                ClientSession {
                    lease: session_id,
                    external: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_000),
                    sender,
                    cancellation: CancellationToken::new(),
                    last_activity: Arc::new(Mutex::new(tokio::time::Instant::now())),
                    previous: None,
                    next: None,
                },
            ));
        }

        assert!(sessions.remove(2));
        assert_eq!(sessions.sweep_head, Some(1));
        assert_eq!(sessions.sweep_tail, Some(3));
        assert_eq!(sessions.sessions[&1].next, Some(3));
        assert_eq!(sessions.sessions[&3].previous, Some(1));
        assert!(sessions.rotate_sweep_head(1));
        assert_eq!(sessions.sweep_head, Some(3));
        assert_eq!(sessions.sweep_tail, Some(1));
    }
}

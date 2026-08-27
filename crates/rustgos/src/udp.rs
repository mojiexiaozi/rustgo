use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use rand::{TryRngCore, rngs::OsRng};
use rustgo_protocol::{
    BoundedBytes, DataChannelKind, Frame, FrameCodec, FrameError, MAX_UDP_PAYLOAD_BYTES, Message,
    OpenUdpChannel, ProtocolVersion, SocketAddress, UDP_METADATA_LEN, UdpDatagram,
    UdpSessionRetired,
};
use rustgo_transport::{safe_display, short_id};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time::MissedTickBehavior,
};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::{
    control::{ControlError, FramedControl, SERVER_VERSION},
    registry::{ClientRegistry, PendingUdpOpen, RegistryError, SessionRuntime},
};

const MAX_SESSION_ID_ATTEMPTS: usize = 16;
const DATA_ACKNOWLEDGEMENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
pub(crate) struct UdpRuntimeLimits {
    pub(crate) queue_capacity: usize,
    pub(crate) idle_timeout: Duration,
    pub(crate) sweep_interval: Duration,
    pub(crate) sweep_batch: usize,
    pub(crate) writer_delay: Duration,
    pub(crate) test_disconnect_after_replies: Option<u64>,
}

impl Default for UdpRuntimeLimits {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            idle_timeout: Duration::from_secs(60),
            sweep_interval: Duration::from_secs(1),
            sweep_batch: 64,
            writer_delay: Duration::ZERO,
            test_disconnect_after_replies: None,
        }
    }
}

impl UdpRuntimeLimits {
    pub(crate) fn is_valid(self) -> bool {
        self.queue_capacity > 0
            && !self.idle_timeout.is_zero()
            && self.idle_timeout.as_millis() <= u128::from(u32::MAX)
            && !self.sweep_interval.is_zero()
            && self.sweep_batch > 0
            && self.test_disconnect_after_replies != Some(0)
    }

    pub(crate) fn open_channel(
        self,
        tunnel_id: u32,
        channel_id: u64,
        binding_token: BoundedBytes<{ rustgo_protocol::MAX_BINDING_TOKEN_BYTES }>,
        max_sessions: usize,
        max_payload: usize,
    ) -> Result<OpenUdpChannel, UdpRelayError> {
        let request = OpenUdpChannel {
            tunnel_id,
            channel_id,
            binding_token,
            max_sessions: u32::try_from(max_sessions).map_err(|_| UdpRelayError::InvalidLimits)?,
            idle_timeout_millis: u32::try_from(self.idle_timeout.as_millis())
                .map_err(|_| UdpRelayError::InvalidLimits)?,
            max_payload_bytes: u32::try_from(max_payload)
                .map_err(|_| UdpRelayError::InvalidLimits)?,
            queue_capacity: u32::try_from(self.queue_capacity)
                .map_err(|_| UdpRelayError::InvalidLimits)?,
        };
        request
            .has_valid_limits()
            .then_some(request)
            .ok_or(UdpRelayError::InvalidLimits)
    }
}

pub(crate) struct UdpListenerTask {
    address: SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl UdpListenerTask {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        listener: UdpSocket,
        pending: PendingUdpOpen,
        tunnel_id: u32,
        tunnel_name: String,
        runtime: Arc<SessionRuntime>,
        max_sessions: usize,
        max_payload: usize,
        limits: UdpRuntimeLimits,
    ) -> Self {
        let address = listener
            .local_addr()
            .expect("a bound UDP listener has a local address");
        let span = tracing::info_span!(
            "udp_tunnel",
            client = %safe_display(runtime.client()),
            tunnel = %safe_display(&tunnel_name),
            event = %"udp_tunnel"
        );
        let handle = tokio::spawn(
            run_listener(
                listener,
                pending,
                tunnel_id,
                tunnel_name,
                runtime,
                max_sessions,
                max_payload,
                limits,
            )
            .instrument(span),
        );
        Self {
            address,
            handle: Some(handle),
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl std::fmt::Debug for UdpListenerTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpListenerTask")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Drop for UdpListenerTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_listener(
    listener: UdpSocket,
    pending: PendingUdpOpen,
    tunnel_id: u32,
    tunnel_name: String,
    runtime: Arc<SessionRuntime>,
    max_sessions: usize,
    max_payload: usize,
    limits: UdpRuntimeLimits,
) {
    let cancellation = runtime.cancellation();
    let result = run_listener_inner(
        listener,
        pending,
        tunnel_id,
        &tunnel_name,
        runtime.clone(),
        max_sessions,
        max_payload,
        limits,
        cancellation.clone(),
    )
    .await;
    if let Err(error) = result {
        tracing::warn!(
            tunnel = %safe_display(&tunnel_name),
            tunnel_id,
            error = %safe_display(&error),
            "event=udp_generation_fatal UDP listener ended its control generation"
        );
        if !cancellation.is_cancelled() {
            runtime.fail_generation();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_listener_inner(
    listener: UdpSocket,
    pending: PendingUdpOpen,
    tunnel_id: u32,
    tunnel_name: &str,
    runtime: Arc<SessionRuntime>,
    max_sessions: usize,
    max_payload: usize,
    limits: UdpRuntimeLimits,
    cancellation: CancellationToken,
) -> Result<(), UdpRelayError> {
    let channel_id = pending.channel_id;
    let request = Message::OpenUdpChannel(limits.open_channel(
        tunnel_id,
        channel_id,
        pending.binding_token,
        max_sessions,
        max_payload,
    )?);
    let control_outbound = runtime.outbound();
    let sent = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Ok(()),
        result = control_outbound.send(request) => result,
    };
    if sent.is_err() {
        runtime.cancel_pending_udp(channel_id);
        return Err(UdpRelayError::ControlChannelClosed);
    }
    let data_channel = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Ok(()),
        result = tokio::time::timeout(runtime.binding_ttl(), pending.data_channel) => {
            match result {
                Ok(Ok(data_channel)) => data_channel,
                Ok(Err(_)) => return Err(UdpRelayError::DataChannelClosed),
                Err(_) => return Err(UdpRelayError::DataChannelSetupTimeout),
            }
        }
    };

    tracing::info!(tunnel = %safe_display(tunnel_name), tunnel_id, channel_id, "event=udp_channel_ready server UDP data channel ready");
    relay_datagrams(
        listener,
        data_channel,
        tunnel_id,
        tunnel_name,
        max_sessions,
        max_payload,
        limits,
        cancellation,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    source: SocketAddr,
    destination: SocketAddr,
}

#[derive(Debug)]
struct FlowEntry {
    key: FlowKey,
    last_activity: tokio::time::Instant,
    previous: Option<u64>,
    next: Option<u64>,
}

struct FlowTable {
    capacity: usize,
    by_flow: HashMap<FlowKey, u64>,
    by_id: HashMap<u64, FlowEntry>,
    sweep_head: Option<u64>,
    sweep_tail: Option<u64>,
}

impl FlowTable {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            by_flow: HashMap::with_capacity(capacity.min(4096)),
            by_id: HashMap::with_capacity(capacity.min(4096)),
            sweep_head: None,
            sweep_tail: None,
        }
    }

    fn session_for(
        &mut self,
        key: FlowKey,
        now: tokio::time::Instant,
    ) -> Result<(u64, bool), FlowError> {
        if let Some(session_id) = self.by_flow.get(&key).copied() {
            if let Some(entry) = self.by_id.get_mut(&session_id) {
                entry.last_activity = now;
                return Ok((session_id, false));
            }
            return Err(FlowError::Inconsistent);
        }
        if self.by_id.len() >= self.capacity {
            return Err(FlowError::Capacity);
        }
        let session_id = self.allocate_session_id()?;
        self.by_flow.insert(key, session_id);
        let previous = self.sweep_tail;
        self.by_id.insert(
            session_id,
            FlowEntry {
                key,
                last_activity: now,
                previous,
                next: None,
            },
        );
        if let Some(previous) = previous {
            self.by_id
                .get_mut(&previous)
                .ok_or(FlowError::Inconsistent)?
                .next = Some(session_id);
        } else {
            self.sweep_head = Some(session_id);
        }
        self.sweep_tail = Some(session_id);
        Ok((session_id, true))
    }

    fn allocate_session_id(&self) -> Result<u64, FlowError> {
        for _ in 0..MAX_SESSION_ID_ATTEMPTS {
            let session_id = OsRng
                .try_next_u64()
                .map_err(|_| FlowError::EntropyUnavailable)?;
            if session_id != 0 && !self.by_id.contains_key(&session_id) {
                return Ok(session_id);
            }
        }
        Err(FlowError::EntropyUnavailable)
    }

    fn remove(&mut self, session_id: u64) -> bool {
        let Some(entry) = self.by_id.remove(&session_id) else {
            return false;
        };
        self.by_flow.remove(&entry.key);
        if let Some(previous) = entry.previous {
            if let Some(previous) = self.by_id.get_mut(&previous) {
                previous.next = entry.next;
            }
        } else {
            self.sweep_head = entry.next;
        }
        if let Some(next) = entry.next {
            if let Some(next) = self.by_id.get_mut(&next) {
                next.previous = entry.previous;
            }
        } else {
            self.sweep_tail = entry.previous;
        }
        true
    }

    fn rotate_sweep_head(&mut self, session_id: u64) -> Result<(), FlowError> {
        if self.sweep_head != Some(session_id) {
            return Err(FlowError::Inconsistent);
        }
        if self.sweep_tail == Some(session_id) {
            return Ok(());
        }
        let next = self
            .by_id
            .get(&session_id)
            .and_then(|entry| entry.next)
            .ok_or(FlowError::Inconsistent)?;
        let tail = self.sweep_tail.ok_or(FlowError::Inconsistent)?;
        self.by_id
            .get_mut(&next)
            .ok_or(FlowError::Inconsistent)?
            .previous = None;
        self.by_id
            .get_mut(&tail)
            .ok_or(FlowError::Inconsistent)?
            .next = Some(session_id);
        let entry = self
            .by_id
            .get_mut(&session_id)
            .ok_or(FlowError::Inconsistent)?;
        entry.previous = Some(tail);
        entry.next = None;
        self.sweep_head = Some(next);
        self.sweep_tail = Some(session_id);
        Ok(())
    }

    fn validate_reply(
        &mut self,
        session_id: u64,
        recipient: SocketAddr,
        destination: SocketAddr,
        now: tokio::time::Instant,
    ) -> bool {
        let Some(entry) = self.by_id.get_mut(&session_id) else {
            return false;
        };
        if entry.key.source != recipient || entry.key.destination != destination {
            return false;
        }
        entry.last_activity = now;
        true
    }

    fn sweep_expired(
        &mut self,
        now: tokio::time::Instant,
        idle_timeout: Duration,
        maximum: usize,
    ) -> Result<Vec<u64>, FlowError> {
        let mut expired = Vec::with_capacity(maximum.min(self.by_id.len()));
        let inspected = maximum.min(self.by_id.len());
        for _ in 0..inspected {
            let Some(session_id) = self.sweep_head else {
                break;
            };
            let is_expired = self.by_id.get(&session_id).is_some_and(|entry| {
                now.saturating_duration_since(entry.last_activity) >= idle_timeout
            });
            if is_expired {
                if self.remove(session_id) {
                    expired.push(session_id);
                }
            } else {
                self.rotate_sweep_head(session_id)?;
            }
        }
        Ok(expired)
    }

    fn len(&self) -> usize {
        self.by_id.len()
    }

    fn clear(&mut self) {
        self.by_flow.clear();
        self.by_id.clear();
        self.sweep_head = None;
        self.sweep_tail = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowError {
    Capacity,
    EntropyUnavailable,
    Inconsistent,
}

#[derive(Default)]
struct UdpMetrics {
    sessions: AtomicUsize,
    queued: AtomicUsize,
    queue_drops: AtomicU64,
    session_drops: AtomicU64,
    oversize_drops: AtomicU64,
    invalid_drops: AtomicU64,
}

impl UdpMetrics {
    fn set_sessions(&self, sessions: usize) {
        self.sessions.store(sessions, Ordering::Release);
    }

    fn record_drop(counter: &AtomicU64, tunnel_name: &str, reason: &'static str) {
        let total = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if total == 1 || total.is_power_of_two() {
            tracing::warn!(tunnel = %safe_display(tunnel_name), reason, total, "event=udp_drop UDP datagram dropped");
        }
    }
}

enum EnqueueResult {
    Queued,
    Full,
    Closed,
}

fn try_enqueue(
    outbound: &mpsc::Sender<Message>,
    message: Message,
    metrics: &UdpMetrics,
) -> EnqueueResult {
    metrics.queued.fetch_add(1, Ordering::AcqRel);
    match outbound.try_send(message) {
        Ok(()) => EnqueueResult::Queued,
        Err(mpsc::error::TrySendError::Full(_)) => {
            metrics.queued.fetch_sub(1, Ordering::AcqRel);
            EnqueueResult::Full
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            metrics.queued.fetch_sub(1, Ordering::AcqRel);
            EnqueueResult::Closed
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_datagrams(
    public: UdpSocket,
    data: TlsStream<TcpStream>,
    tunnel_id: u32,
    tunnel_name: &str,
    max_sessions: usize,
    max_payload: usize,
    limits: UdpRuntimeLimits,
    cancellation: CancellationToken,
) -> Result<(), UdpRelayError> {
    let public_destination = canonical_socket_addr(public.local_addr()?);
    let (reader, writer) = tokio::io::split(data);
    let mut reader = UdpFrameReader::new(reader);
    let (outbound, receiver) = mpsc::channel(limits.queue_capacity);
    let metrics = Arc::new(UdpMetrics::default());
    let relay_shutdown = CancellationToken::new();
    let mut writer_task = tokio::spawn(write_frames(
        writer,
        receiver,
        metrics.clone(),
        relay_shutdown.clone(),
        limits.writer_delay,
    ));
    let mut writer_finished = false;
    let mut flows = FlowTable::new(max_sessions);
    let mut forwarded_replies = 0_u64;
    let mut receive_buffer = vec![0_u8; max_payload.saturating_add(1)];
    let first_sweep = tokio::time::Instant::now()
        .checked_add(limits.sweep_interval)
        .ok_or(UdpRelayError::InvalidLimits)?;
    let mut sweep = tokio::time::interval_at(first_sweep, limits.sweep_interval);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let result = 'relay: loop {
        tokio::select! {
            () = cancellation.cancelled() => break Ok(()),
            joined = &mut writer_task => {
                writer_finished = true;
                break match joined {
                    Ok(Ok(())) => Err(UdpRelayError::DataChannelClosed),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(UdpRelayError::TaskJoin),
                };
            }
            _ = sweep.tick() => {
                let expired = flows.sweep_expired(
                    tokio::time::Instant::now(),
                    limits.idle_timeout,
                    limits.sweep_batch,
                ).map_err(|_| UdpRelayError::SessionAllocation)?;
                if !expired.is_empty() {
                    metrics.set_sessions(flows.len());
                    let expired_count = expired.len();
                    for session_id in expired {
                        let retirement = Message::UdpSessionRetired(UdpSessionRetired {
                            tunnel_id,
                            session_id,
                        });
                        match try_enqueue(&outbound, retirement, &metrics) {
                            EnqueueResult::Queued => {}
                            EnqueueResult::Full => {
                                UdpMetrics::record_drop(
                                    &metrics.queue_drops,
                                    tunnel_name,
                                    "retirement_queue_full",
                                );
                                break 'relay Err(UdpRelayError::RetirementDeliveryFailed);
                            }
                            EnqueueResult::Closed => {
                                break 'relay Err(UdpRelayError::RetirementDeliveryFailed);
                            }
                        }
                    }
                    tracing::debug!(tunnel = %safe_display(tunnel_name), expired = expired_count, sessions = flows.len(), "event=udp_idle_sweep expired UDP sessions");
                }
            }
            received = public.recv_from(&mut receive_buffer) => {
                let (length, source) = match received {
                    Ok(received) => received,
                    Err(error) if is_oversized_datagram_error(&error) => {
                        UdpMetrics::record_drop(&metrics.oversize_drops, tunnel_name, "oversize_public");
                        continue;
                    }
                    Err(error) => break Err(error.into()),
                };
                if length > max_payload {
                    UdpMetrics::record_drop(&metrics.oversize_drops, tunnel_name, "oversize_public");
                    continue;
                }
                let key = FlowKey {
                    source: canonical_socket_addr(source),
                    destination: public_destination,
                };
                let (session_id, inserted) = match flows.session_for(key, tokio::time::Instant::now()) {
                    Ok(session) => session,
                    Err(FlowError::Capacity) => {
                        UdpMetrics::record_drop(&metrics.session_drops, tunnel_name, "session_limit");
                        continue;
                    }
                    Err(FlowError::EntropyUnavailable | FlowError::Inconsistent) => {
                        break Err(UdpRelayError::SessionAllocation);
                    }
                };
                let payload = BoundedBytes::<MAX_UDP_PAYLOAD_BYTES>::try_from(
                    &receive_buffer[..length],
                )
                .map_err(|_| UdpRelayError::PayloadTooLarge)?;
                let message = Message::UdpDatagram(UdpDatagram {
                    tunnel_id,
                    session_id,
                    source: wire_socket_addr(key.source),
                    payload,
                });
                match try_enqueue(&outbound, message, &metrics) {
                    EnqueueResult::Queued => {
                        if inserted {
                            metrics.set_sessions(flows.len());
                            let session = tracing::info_span!(
                                "udp_session",
                                conn = %short_id(session_id),
                                event = %"udp_session_open"
                            );
                            tracing::info!(parent: &session, "UDP relay session opened");
                        }
                    }
                    EnqueueResult::Full => {
                        if inserted {
                            flows.remove(session_id);
                            metrics.set_sessions(flows.len());
                        }
                        UdpMetrics::record_drop(&metrics.queue_drops, tunnel_name, "data_queue_full");
                    }
                    EnqueueResult::Closed => break Err(UdpRelayError::DataChannelClosed),
                }
            }
            frame = reader.receive() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => break Err(error),
                };
                if frame.version != SERVER_VERSION {
                    break Err(UdpRelayError::InvalidFrame);
                }
                let Message::UdpDatagram(datagram) = frame.message else {
                    break Err(UdpRelayError::InvalidFrame);
                };
                if datagram.tunnel_id != tunnel_id {
                    break Err(UdpRelayError::InvalidFrame);
                }
                if datagram.payload.as_slice().len() > max_payload {
                    UdpMetrics::record_drop(&metrics.oversize_drops, tunnel_name, "oversize_data_frame");
                    continue;
                }
                let Some(recipient) = socket_addr_from_wire(&datagram.source) else {
                    break Err(UdpRelayError::InvalidFrame);
                };
                if !flows.validate_reply(
                    datagram.session_id,
                    recipient,
                    public_destination,
                    tokio::time::Instant::now(),
                ) {
                    UdpMetrics::record_drop(&metrics.invalid_drops, tunnel_name, "unknown_or_mismatched_session");
                    continue;
                }
                let send = public.send_to(datagram.payload.as_slice(), recipient);
                let sent = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => break Ok(()),
                    sent = send => sent?,
                };
                if sent != datagram.payload.as_slice().len() {
                    break Err(UdpRelayError::ShortDatagramWrite);
                }
                forwarded_replies = forwarded_replies.saturating_add(1);
                if limits.test_disconnect_after_replies == Some(forwarded_replies) {
                    tracing::warn!(
                        tunnel = %safe_display(tunnel_name),
                        forwarded_replies,
                        "event=udp_test_data_disconnect internal test closed UDP data channel"
                    );
                    break Err(UdpRelayError::InternalTestDisconnect);
                }
            }
        }
    };

    relay_shutdown.cancel();
    drop(outbound);
    if !writer_finished {
        let _ = writer_task.await;
    }
    flows.clear();
    metrics.set_sessions(0);
    metrics.queued.store(0, Ordering::Release);
    tracing::info!(
        tunnel = %safe_display(tunnel_name),
        sessions = metrics.sessions.load(Ordering::Acquire),
        queue = metrics.queued.load(Ordering::Acquire),
        drops_queue = metrics.queue_drops.load(Ordering::Relaxed),
        drops_sessions = metrics.session_drops.load(Ordering::Relaxed),
        drops_oversize = metrics.oversize_drops.load(Ordering::Relaxed),
        drops_invalid = metrics.invalid_drops.load(Ordering::Relaxed),
        "event=udp_cleanup UDP relay state released"
    );
    result
}

async fn write_frames<W>(
    mut writer: W,
    mut receiver: mpsc::Receiver<Message>,
    metrics: Arc<UdpMetrics>,
    cancellation: CancellationToken,
    writer_delay: Duration,
) -> Result<(), UdpRelayError>
where
    W: AsyncWrite + Unpin,
{
    let codec = FrameCodec::new(UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES);
    let result = loop {
        let message = tokio::select! {
            biased;
            () = cancellation.cancelled() => break Ok(()),
            message = receiver.recv() => match message {
                Some(message) => message,
                None => break Ok(()),
            },
        };
        metrics.queued.fetch_sub(1, Ordering::AcqRel);
        let encoded = codec.encode(SERVER_VERSION, 0, &message)?;
        if !writer_delay.is_zero() {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break Ok(()),
                () = tokio::time::sleep(writer_delay) => {}
            }
        }
        let write = writer.write_all(&encoded);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break Ok(()),
            write = write => write?,
        }
    };
    while receiver.try_recv().is_ok() {
        metrics.queued.fetch_sub(1, Ordering::AcqRel);
    }
    result
}

struct UdpFrameReader<R> {
    reader: R,
    buffer: BytesMut,
    codec: FrameCodec,
    maximum_frame: usize,
}

impl<R> UdpFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(reader: R) -> Self {
        let maximum_frame = rustgo_protocol::HEADER_LEN + UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES;
        Self {
            reader,
            buffer: BytesMut::with_capacity(maximum_frame),
            codec: FrameCodec::new(UDP_METADATA_LEN + MAX_UDP_PAYLOAD_BYTES),
            maximum_frame,
        }
    }

    async fn receive(&mut self) -> Result<Frame, UdpRelayError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffer)? {
                return Ok(frame);
            }
            if self.buffer.len() >= self.maximum_frame {
                return Err(UdpRelayError::FrameTooLarge);
            }
            if self.reader.read_buf(&mut self.buffer).await? == 0 {
                return Err(UdpRelayError::DataChannelClosed);
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

fn socket_addr_from_wire(address: &SocketAddress) -> Option<SocketAddr> {
    let address = match address {
        SocketAddress::V4 { octets, port } => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*octets)), *port)
        }
        SocketAddress::V6 { octets, port } => SocketAddr::new(IpAddr::V6((*octets).into()), *port),
    };
    Some(canonical_socket_addr(address))
}

fn is_oversized_datagram_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(10040) || error.kind() == io::ErrorKind::InvalidData
}

pub(crate) async fn serve_data_connection(
    registry: ClientRegistry,
    framed: FramedControl<TlsStream<TcpStream>>,
    version: ProtocolVersion,
    request: rustgo_protocol::DataChannelBind,
) -> Result<(), UdpDataError> {
    if version != SERVER_VERSION
        || request.kind != DataChannelKind::UDP
        || !framed.is_buffer_empty()
    {
        return Err(UdpDataError::InvalidFirstFrame);
    }
    let stream = framed.into_stream().map_err(UdpDataError::Control)?;
    let acknowledgement = registry.udp_open_channel(
        request.tunnel_id,
        request.target_id,
        request.binding_token.clone(),
    )?;
    let mut authenticated = registry.authenticate_data_channel(stream, &request)?;
    let acknowledgement = FrameCodec::new(1024).encode(
        SERVER_VERSION,
        0,
        &Message::OpenUdpChannel(acknowledgement),
    )?;
    let cancellation = authenticated.cancellation();
    let write = authenticated.stream_mut()?.write_all(&acknowledgement);
    tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(UdpDataError::Cancelled),
        result = tokio::time::timeout(DATA_ACKNOWLEDGEMENT_TIMEOUT, write) => {
            result.map_err(|_| UdpDataError::AcknowledgementTimeout)??;
        }
    }
    authenticated.deliver()?;
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum UdpRelayError {
    #[error("UDP relay I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("UDP data frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("UDP data channel closed")]
    DataChannelClosed,
    #[error("UDP control command channel closed")]
    ControlChannelClosed,
    #[error("UDP data channel setup timed out")]
    DataChannelSetupTimeout,
    #[error("UDP session retirement could not enter the bounded data queue")]
    RetirementDeliveryFailed,
    #[error("invalid UDP data frame")]
    InvalidFrame,
    #[error("UDP frame exceeded the configured maximum")]
    FrameTooLarge,
    #[error("UDP payload exceeded the configured maximum")]
    PayloadTooLarge,
    #[error("UDP session ID allocation failed")]
    SessionAllocation,
    #[error("UDP send wrote a partial datagram")]
    ShortDatagramWrite,
    #[error("UDP data writer task failed")]
    TaskJoin,
    #[error("internal test disconnected the UDP data channel")]
    InternalTestDisconnect,
    #[error("invalid UDP runtime limits")]
    InvalidLimits,
}

#[derive(Debug, Error)]
pub(crate) enum UdpDataError {
    #[error("invalid TLS UDP data-channel first frame")]
    InvalidFirstFrame,
    #[error("control framing failed: {0}")]
    Control(#[source] ControlError),
    #[error("data-channel registry binding failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("UDP data-channel frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("UDP data-channel I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("UDP data-channel acknowledgement timed out")]
    AcknowledgementTimeout,
    #[error("UDP data-channel control owner was cancelled")]
    Cancelled,
}

impl From<UdpDataError> for ControlError {
    fn from(error: UdpDataError) -> Self {
        match error {
            UdpDataError::Control(error) => error,
            UdpDataError::Io(error) => ControlError::Io(error),
            UdpDataError::Frame(error) => ControlError::Frame(error),
            UdpDataError::InvalidFirstFrame
            | UdpDataError::Registry(_)
            | UdpDataError::AcknowledgementTimeout
            | UdpDataError::Cancelled => ControlError::InvalidState,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use super::{FlowError, FlowKey, FlowTable, canonical_socket_addr};

    #[test]
    fn rolled_back_sessions_do_not_grow_the_bounded_sweep_ring() {
        let mut flows = FlowTable::new(1);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7000);
        for port in 10_000..10_128 {
            let key = FlowKey {
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                destination,
            };
            let (session_id, inserted) =
                flows.session_for(key, tokio::time::Instant::now()).unwrap();
            assert!(inserted);
            assert!(flows.remove(session_id));
            assert_eq!(flows.len(), 0);
            assert_eq!(flows.sweep_head, None);
            assert_eq!(flows.sweep_tail, None);
        }
    }

    #[test]
    fn ipv4_mapped_sources_share_the_native_ipv4_flow_identity() {
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
            ])),
            5353,
        );
        assert_eq!(
            canonical_socket_addr(mapped),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)
        );
    }

    #[test]
    fn session_ids_are_nonzero_and_unique_until_the_configured_limit() {
        let mut flows = FlowTable::new(128);
        let now = tokio::time::Instant::now();
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7000);
        let mut identifiers = HashSet::new();
        for port in 20_000..20_128 {
            let (session_id, inserted) = flows
                .session_for(
                    FlowKey {
                        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                        destination,
                    },
                    now,
                )
                .unwrap();
            assert!(inserted);
            assert_ne!(session_id, 0);
            assert!(identifiers.insert(session_id));
        }
        assert_eq!(flows.len(), 128);
        assert!(flows.sweep_head.is_some());
        assert!(flows.sweep_tail.is_some());
        assert_eq!(
            flows.session_for(
                FlowKey {
                    source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_000),
                    destination,
                },
                now,
            ),
            Err(FlowError::Capacity)
        );
    }

    #[test]
    fn one_idle_sweep_inspects_at_most_the_configured_batch() {
        let mut flows = FlowTable::new(3);
        let started = tokio::time::Instant::now();
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7000);
        for port in 31_000..31_003 {
            flows
                .session_for(
                    FlowKey {
                        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                        destination,
                    },
                    started,
                )
                .unwrap();
        }

        let expired = flows
            .sweep_expired(started + Duration::from_secs(2), Duration::from_secs(1), 1)
            .unwrap();

        assert_eq!(expired.len(), 1);
        assert_eq!(flows.len(), 2);
        assert!(flows.sweep_head.is_some());
        assert!(flows.sweep_tail.is_some());
    }

    #[test]
    fn removing_a_middle_flow_keeps_constant_time_sweep_links_consistent() {
        let mut flows = FlowTable::new(3);
        let now = tokio::time::Instant::now();
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7000);
        let mut identifiers = Vec::new();
        for port in 32_000..32_003 {
            identifiers.push(
                flows
                    .session_for(
                        FlowKey {
                            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                            destination,
                        },
                        now,
                    )
                    .unwrap()
                    .0,
            );
        }

        assert!(flows.remove(identifiers[1]));
        assert_eq!(flows.sweep_head, Some(identifiers[0]));
        assert_eq!(flows.sweep_tail, Some(identifiers[2]));
        assert_eq!(flows.by_id[&identifiers[0]].next, Some(identifiers[2]));
        assert_eq!(flows.by_id[&identifiers[2]].previous, Some(identifiers[0]));
        assert!(
            flows
                .sweep_expired(now, Duration::from_secs(1), 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(flows.sweep_head, Some(identifiers[2]));
        assert_eq!(flows.sweep_tail, Some(identifiers[0]));
    }
}

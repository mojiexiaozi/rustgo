use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use rustgo_observability::{BoundedLabel, ObservationEvent, ShortSessionId, TrafficCounters};
use rustgo_protocol::{
    FrameCodec, Message, OpenTcpStream, ProtocolVersion, SocketAddress, TcpStreamReady,
};
use rustgo_transport::{copy_bidirectional_bounded, safe_display, short_id};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::{
    control::{ControlError, FramedControl},
    registry::{ClientRegistry, RegistryError, SessionRuntime, now_unix_millis},
};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DATA_ACKNOWLEDGEMENT_TIMEOUT: Duration = Duration::from_secs(10);
const OBSERVABILITY_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) struct TcpListenerTask {
    address: SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl TcpListenerTask {
    pub(crate) fn spawn(
        listener: TcpListener,
        tunnel_id: u32,
        tunnel_name: String,
        runtime: Arc<SessionRuntime>,
        max_connections: usize,
    ) -> Self {
        let address = listener
            .local_addr()
            .expect("a bound TCP listener has a local address");
        let span = tracing::info_span!(
            "tcp_tunnel",
            client = %safe_display(runtime.client()),
            tunnel = %safe_display(&tunnel_name),
            event = %"tcp_tunnel"
        );
        let handle = tokio::spawn(
            run_listener(listener, tunnel_id, tunnel_name, runtime, max_connections)
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

impl std::fmt::Debug for TcpListenerTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpListenerTask")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Drop for TcpListenerTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

async fn run_listener(
    listener: TcpListener,
    tunnel_id: u32,
    tunnel_name: String,
    runtime: Arc<SessionRuntime>,
    max_connections: usize,
) {
    let cancellation = runtime.cancellation();
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            joined = connections.join_next(), if !connections.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    tracing::warn!(tunnel = %safe_display(&tunnel_name), "TCP relay task failed to join");
                }
            }
            accepted = listener.accept() => {
                let Ok((public, peer)) = accepted else {
                    if !cancellation.is_cancelled() {
                        tracing::warn!(tunnel = %safe_display(&tunnel_name), "TCP public listener failed");
                    }
                    break;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!(tunnel = %safe_display(&tunnel_name), peer = %safe_display(peer), "TCP tunnel connection limit reached");
                    drop(public);
                    continue;
                };
                connections.spawn(relay_public_connection(
                    public,
                    peer,
                    tunnel_id,
                    tunnel_name.clone(),
                    runtime.clone(),
                    permit,
                ));
            }
        }
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
}

async fn relay_public_connection(
    mut public: TcpStream,
    peer: SocketAddr,
    tunnel_id: u32,
    tunnel_name: String,
    runtime: Arc<SessionRuntime>,
    _permit: OwnedSemaphorePermit,
) {
    let pending = match runtime.prepare_tcp(tunnel_id) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(tunnel = %safe_display(&tunnel_name), peer = %safe_display(peer), error = %safe_display(&error), "TCP binding allocation failed");
            return;
        }
    };
    let connection_id = pending.connection_id;
    let request = Message::OpenTcpStream(OpenTcpStream {
        tunnel_id,
        connection_id,
        peer: socket_address(peer),
        binding_token: pending.binding_token,
    });
    let cancellation = runtime.cancellation();
    let outbound = runtime.outbound();
    let sent = tokio::select! {
        biased;
        () = cancellation.cancelled() => false,
        result = outbound.send(request) => result.is_ok(),
    };
    if !sent {
        runtime.cancel_pending(connection_id);
        return;
    }

    let data_channel = tokio::select! {
        biased;
        () = cancellation.cancelled() => None,
        result = tokio::time::timeout(runtime.binding_ttl(), pending.data_channel) => {
            result.ok().and_then(Result::ok)
        }
    };
    let Some(mut data_channel) = data_channel else {
        runtime.cancel_pending(connection_id);
        return;
    };

    let connection = tracing::info_span!(
        "tcp_connection",
        client = %safe_display(runtime.client()),
        tunnel = %safe_display(&tunnel_name),
        conn = %short_id(connection_id),
        event = %"tcp_open"
    );
    tracing::info!(parent: &connection, peer = %safe_display(peer), "TCP relay connected");
    let result = if runtime.observability_enabled() {
        relay_observed_connection(
            &mut public,
            &mut data_channel,
            connection_id,
            &tunnel_name,
            &runtime,
            cancellation,
        )
        .await
    } else {
        copy_bidirectional_bounded(
            &mut public,
            &mut data_channel,
            TCP_IDLE_TIMEOUT,
            cancellation,
        )
        .await
    };
    if let Err(error) = result {
        tracing::debug!(parent: &connection, peer = %safe_display(peer), error = %safe_display(&error), "TCP relay ended");
    }
}

async fn relay_observed_connection<A, B>(
    public: &mut A,
    data_channel: &mut B,
    connection_id: u64,
    tunnel_name: &str,
    runtime: &SessionRuntime,
    cancellation: CancellationToken,
) -> Result<rustgo_transport::CopyReport, rustgo_transport::CopyError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let session_id = ShortSessionId::from_bytes(&connection_id.to_be_bytes());
    let traffic = Arc::new(ObservedTraffic::default());
    runtime.try_observe(ObservationEvent::TcpSessionOpened {
        client: runtime.observability_identity().clone(),
        session_id: session_id.clone(),
        tunnel: Some(
            BoundedLabel::try_from(tunnel_name).expect("registered tunnel names are bounded"),
        ),
        opened_unix_millis: now_unix_millis(),
    });
    let mut public = WriteCountedIo::new(public, traffic.sent.clone());
    let mut data_channel = WriteCountedIo::new(data_channel, traffic.received.clone());
    let copy = copy_bidirectional_bounded(
        &mut public,
        &mut data_channel,
        TCP_IDLE_TIMEOUT,
        cancellation,
    );
    tokio::pin!(copy);
    let mut flush = tokio::time::interval(OBSERVABILITY_FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            result = &mut copy => break result,
            _ = flush.tick() => traffic.flush(runtime, Some(session_id.clone())),
        }
    };
    traffic.flush(runtime, Some(session_id.clone()));
    runtime.try_observe(ObservationEvent::TcpSessionClosed {
        client: runtime.observability_identity().clone(),
        session_id,
        closed_unix_millis: now_unix_millis(),
        terminal_reason: Some(
            BoundedLabel::try_from(if result.is_ok() { "eof" } else { "ended" })
                .expect("static terminal reasons are bounded"),
        ),
    });
    result
}

#[derive(Default)]
struct ObservedTraffic {
    received: Arc<AtomicU64>,
    sent: Arc<AtomicU64>,
}

impl ObservedTraffic {
    fn flush(&self, runtime: &SessionRuntime, session_id: Option<ShortSessionId>) {
        let counters = TrafficCounters {
            received_bytes: self.received.swap(0, Ordering::AcqRel),
            sent_bytes: self.sent.swap(0, Ordering::AcqRel),
        };
        if counters != TrafficCounters::default() {
            runtime.try_observe(ObservationEvent::ByteCounterDelta {
                client: runtime.observability_identity().clone(),
                session_id,
                counters,
            });
        }
    }
}

struct WriteCountedIo<T> {
    inner: T,
    written: Arc<AtomicU64>,
}

impl<T> WriteCountedIo<T> {
    fn new(inner: T, written: Arc<AtomicU64>) -> Self {
        Self { inner, written }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WriteCountedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WriteCountedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                saturating_add(&this.written, written as u64);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

fn saturating_add(counter: &AtomicU64, delta: u64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_add(delta))
    });
}

fn socket_address(address: SocketAddr) -> SocketAddress {
    match address {
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

pub(crate) async fn serve_data_connection(
    registry: ClientRegistry,
    framed: FramedControl<tokio_rustls::server::TlsStream<TcpStream>>,
    version: ProtocolVersion,
    request: rustgo_protocol::DataChannelBind,
) -> Result<(), TcpDataError> {
    if request.kind != rustgo_protocol::DataChannelKind::TCP || !framed.is_buffer_empty() {
        return Err(TcpDataError::InvalidFirstFrame);
    }
    let stream = framed.into_stream().map_err(TcpDataError::Control)?;
    let connection_id = request.target_id;
    let mut authenticated = registry.authenticate_data_channel(stream, &request, version)?;
    let protocol_version = authenticated.protocol_version();
    let acknowledgement = FrameCodec::new(1024).encode(
        protocol_version,
        0,
        &Message::TcpStreamReady(TcpStreamReady {
            connection_id,
            accepted: true,
            error: None,
        }),
    )?;
    let cancellation = authenticated.cancellation();
    write_data_acknowledgement(authenticated.stream_mut()?, &acknowledgement, cancellation).await?;
    authenticated.deliver()?;
    Ok(())
}

async fn write_data_acknowledgement<W>(
    stream: &mut W,
    acknowledgement: &[u8],
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<(), TcpDataError>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(TcpDataError::Cancelled),
        result = tokio::time::timeout(
            DATA_ACKNOWLEDGEMENT_TIMEOUT,
            stream.write_all(acknowledgement),
        ) => {
            result
                .map_err(|_| TcpDataError::AcknowledgementTimeout)?
                .map_err(TcpDataError::Io)
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum TcpDataError {
    #[error("invalid TLS data-channel first frame")]
    InvalidFirstFrame,
    #[error("control framing failed: {0}")]
    Control(#[source] ControlError),
    #[error("data-channel protocol frame failed: {0}")]
    Frame(#[from] rustgo_protocol::FrameError),
    #[error("data-channel registry binding failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("data-channel I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("data-channel acknowledgement timed out")]
    AcknowledgementTimeout,
    #[error("data-channel control owner was cancelled")]
    Cancelled,
}

impl From<TcpDataError> for ControlError {
    fn from(error: TcpDataError) -> Self {
        match error {
            TcpDataError::Control(error) => error,
            TcpDataError::Io(error) => ControlError::Io(error),
            TcpDataError::Frame(error) => ControlError::Frame(error),
            TcpDataError::InvalidFirstFrame
            | TcpDataError::Registry(_)
            | TcpDataError::AcknowledgementTimeout
            | TcpDataError::Cancelled => ControlError::InvalidState,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::{TcpDataError, write_data_acknowledgement};

    #[tokio::test]
    async fn control_cancellation_interrupts_a_backpressured_data_acknowledgement() {
        let (mut blocked, _peer) = tokio::io::duplex(1);
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            trigger.cancel();
        });

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            write_data_acknowledgement(&mut blocked, &[0_u8; 64], cancellation),
        )
        .await;

        assert!(matches!(result, Ok(Err(TcpDataError::Cancelled))));
    }
}

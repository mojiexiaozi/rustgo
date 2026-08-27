use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustgo_protocol::{
    FrameCodec, Message, OpenTcpStream, ProtocolVersion, SocketAddress, TcpStreamReady,
};
use rustgo_transport::copy_bidirectional_bounded;
use thiserror::Error;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};

use crate::{
    control::{ControlError, FramedControl, SERVER_VERSION},
    registry::{ClientRegistry, RegistryError, SessionRuntime},
};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DATA_ACKNOWLEDGEMENT_TIMEOUT: Duration = Duration::from_secs(10);

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
        let handle = tokio::spawn(run_listener(
            listener,
            tunnel_id,
            tunnel_name,
            runtime,
            max_connections,
        ));
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
                    tracing::warn!(tunnel = %tunnel_name, "TCP relay task failed to join");
                }
            }
            accepted = listener.accept() => {
                let Ok((public, peer)) = accepted else {
                    if !cancellation.is_cancelled() {
                        tracing::warn!(tunnel = %tunnel_name, "TCP public listener failed");
                    }
                    break;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!(tunnel = %tunnel_name, peer = %peer, "TCP tunnel connection limit reached");
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
            tracing::warn!(tunnel = %tunnel_name, peer = %peer, %error, "TCP binding allocation failed");
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

    tracing::debug!(tunnel = %tunnel_name, connection_id, peer = %peer, "TCP relay connected");
    if let Err(error) = copy_bidirectional_bounded(
        &mut public,
        &mut data_channel,
        TCP_IDLE_TIMEOUT,
        cancellation,
    )
    .await
    {
        tracing::debug!(tunnel = %tunnel_name, connection_id, peer = %peer, %error, "TCP relay ended");
    }
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
    if version != SERVER_VERSION || !framed.is_buffer_empty() {
        return Err(TcpDataError::InvalidFirstFrame);
    }
    let stream = framed.into_stream().map_err(TcpDataError::Control)?;
    let connection_id = request.target_id;
    let mut authenticated = registry.authenticate_data_channel(stream, &request)?;
    let acknowledgement = FrameCodec::new(1024).encode(
        SERVER_VERSION,
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

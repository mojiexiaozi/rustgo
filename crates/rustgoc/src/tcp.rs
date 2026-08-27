use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use bytes::BytesMut;
use rustgo_protocol::{
    BoundedBytes, BoundedString, DataChannelBind, DataChannelKind, Frame, FrameCodec, FrameError,
    MAX_CLIENT_NAME_BYTES, MAX_SESSION_ID_BYTES, Message, ProtocolErrorCode, TcpStreamReady,
};
use rustgo_transport::{TlsClient, copy_bidirectional_bounded};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::{ChildSessionContext, ChildSessionRequest, ChildSessionSupervisor, ControlClient};

const MAX_CLIENT_TCP_CONNECTIONS: usize = 4096;
const MAX_CLIENT_CONCURRENT_TLS_HANDSHAKES: usize = 4;
const TCP_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DATA_FRAME_MAX: usize = 1024;

pub(crate) struct TcpSessionSupervisor {
    client_name: String,
    server_addr: String,
    tls_client: TlsClient,
    local_targets: Arc<HashMap<u32, String>>,
    permits: Arc<Semaphore>,
    handshake_permits: Arc<Semaphore>,
}

impl TcpSessionSupervisor {
    pub(crate) fn new(control: &ControlClient) -> Self {
        let local_targets = control
            .config()
            .tunnels
            .iter()
            .enumerate()
            .filter_map(|(index, tunnel)| {
                u32::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    .map(|tunnel_id| (tunnel_id, tunnel.local_addr.clone()))
            })
            .collect();
        Self {
            client_name: control.config().client.name.clone(),
            server_addr: control.config().client.server_addr.clone(),
            tls_client: control.tls_client(),
            local_targets: Arc::new(local_targets),
            permits: Arc::new(Semaphore::new(MAX_CLIENT_TCP_CONNECTIONS)),
            handshake_permits: Arc::new(Semaphore::new(MAX_CLIENT_CONCURRENT_TLS_HANDSHAKES)),
        }
    }
}

impl ChildSessionSupervisor for TcpSessionSupervisor {
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
        let handshake_permits = self.handshake_permits.clone();
        Box::pin(async move {
            match request {
                ChildSessionRequest::Tcp(request) => {
                    run_tcp(
                        client_name,
                        server_addr,
                        tls_client,
                        local_targets,
                        permits,
                        handshake_permits,
                        context,
                        request,
                        shutdown,
                    )
                    .await;
                }
                ChildSessionRequest::Udp(_) => shutdown.cancelled().await,
            }
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp(
    client_name: String,
    server_addr: String,
    tls_client: TlsClient,
    local_targets: Arc<HashMap<u32, String>>,
    permits: Arc<Semaphore>,
    handshake_permits: Arc<Semaphore>,
    context: ChildSessionContext,
    request: rustgo_protocol::OpenTcpStream,
    shutdown: CancellationToken,
) {
    let permit = match permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            report_failure(&context, request.connection_id, &shutdown).await;
            return;
        }
    };
    let Some(local_address) = local_targets.get(&request.tunnel_id).cloned() else {
        report_failure(&context, request.connection_id, &shutdown).await;
        return;
    };
    let setup = async {
        let handshake_permit = handshake_permits
            .acquire_owned()
            .await
            .map_err(|_| TcpClientError::HandshakeAdmissionClosed)?;
        let result = setup_tcp(
            &client_name,
            &server_addr,
            &tls_client,
            &local_address,
            context.session_id(),
            &request,
        )
        .await;
        drop(handshake_permit);
        result
    };
    let setup = tokio::select! {
        biased;
        () = shutdown.cancelled() => return,
        result = tokio::time::timeout(TCP_SETUP_TIMEOUT, setup) => result,
    };
    let (mut local, mut data) = match setup {
        Ok(Ok(streams)) => streams,
        Ok(Err(error)) => {
            tracing::warn!(connection_id = request.connection_id, %error, "TCP data setup failed");
            report_failure(&context, request.connection_id, &shutdown).await;
            return;
        }
        Err(_) => {
            tracing::warn!(
                connection_id = request.connection_id,
                "TCP data setup timed out"
            );
            report_failure(&context, request.connection_id, &shutdown).await;
            return;
        }
    };

    relay_local_connection(
        &mut local,
        &mut data,
        request.connection_id,
        shutdown,
        permit,
    )
    .await;
}

async fn setup_tcp(
    client_name: &str,
    server_addr: &str,
    tls_client: &TlsClient,
    local_address: &str,
    session_id: &[u8],
    request: &rustgo_protocol::OpenTcpStream,
) -> Result<(TcpStream, TlsStream<TcpStream>), TcpClientError> {
    let local = TcpStream::connect(local_address).await?;
    let mut data = tls_client.connect(server_addr).await?;
    let bind = Message::DataChannelBind(DataChannelBind {
        client_name: BoundedString::<MAX_CLIENT_NAME_BYTES>::try_from(client_name)
            .map_err(|_| TcpClientError::InvalidBinding)?,
        session_id: BoundedBytes::<MAX_SESSION_ID_BYTES>::try_from(session_id)
            .map_err(|_| TcpClientError::InvalidBinding)?,
        kind: DataChannelKind::TCP,
        tunnel_id: request.tunnel_id,
        target_id: request.connection_id,
        binding_token: request.binding_token.clone(),
    });
    let codec = FrameCodec::new(DATA_FRAME_MAX);
    let encoded = codec.encode(crate::CLIENT_VERSION, 0, &bind)?;
    data.write_all(&encoded).await?;

    let acknowledgement = read_frame_exact(&mut data, codec).await?;
    if acknowledgement.version != crate::CLIENT_VERSION {
        return Err(TcpClientError::InvalidAcknowledgement);
    }
    let Message::TcpStreamReady(ready) = acknowledgement.message else {
        return Err(TcpClientError::InvalidAcknowledgement);
    };
    if ready.connection_id != request.connection_id || !ready.accepted || ready.error.is_some() {
        return Err(TcpClientError::InvalidAcknowledgement);
    }
    Ok((local, data))
}

async fn read_frame_exact<R>(stream: &mut R, codec: FrameCodec) -> Result<Frame, TcpClientError>
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

async fn relay_local_connection(
    local: &mut TcpStream,
    data: &mut TlsStream<TcpStream>,
    connection_id: u64,
    shutdown: CancellationToken,
    _permit: OwnedSemaphorePermit,
) {
    if let Err(error) = copy_bidirectional_bounded(local, data, TCP_IDLE_TIMEOUT, shutdown).await {
        tracing::debug!(connection_id, %error, "TCP local relay ended");
    }
}

async fn report_failure(
    context: &ChildSessionContext,
    connection_id: u64,
    shutdown: &CancellationToken,
) {
    context
        .send_control(
            Message::TcpStreamReady(TcpStreamReady {
                connection_id,
                accepted: false,
                error: Some(ProtocolErrorCode::INTERNAL),
            }),
            shutdown,
        )
        .await;
}

#[derive(Debug, Error)]
enum TcpClientError {
    #[error("TCP I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS data connection failed: {0}")]
    Tls(#[from] rustgo_transport::TlsError),
    #[error("data-channel frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("invalid data-channel binding")]
    InvalidBinding,
    #[error("invalid data-channel acknowledgement")]
    InvalidAcknowledgement,
    #[error("data-channel TLS handshake admission closed")]
    HandshakeAdmissionClosed,
}

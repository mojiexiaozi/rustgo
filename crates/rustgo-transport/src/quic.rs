use std::{
    fmt, io,
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustgo_crypto::{
    EphemeralPeerKey, PEER_HANDSHAKE_TAG_BYTES, PEER_TRANSPORT_BINDING_BYTES, PeerCryptoError,
    PeerRole, PeerSessionKeys, PeerTranscript,
};
use rustgo_path::{PathAttempt, PathError, PathKind, SelectedPath};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const QUIC_ALPN: &[u8] = b"rustgo-peer-quic-v1";
const QUIC_SERVER_NAME: &str = "peer.rustgo.invalid";
const EXPORTER_LABEL: &[u8] = b"rustgo-peer-quic-transport-binding-v1";
const EXPORTER_CONTEXT: &[u8] = b"mutual-peer-authentication";
const AUTH_MAGIC: &[u8; 8] = b"RGOQUIC1";
const AUTH_RECORD_BYTES: usize = AUTH_MAGIC.len() + 1 + PEER_HANDSHAKE_TAG_BYTES;
const AUTH_INITIATOR: u8 = 1;
const AUTH_RESPONDER: u8 = 2;
const CLOSE_NORMAL: u32 = 0;
const CLOSE_AUTHENTICATION_FAILED: u32 = 1;
const CLOSE_CANCELLED: u32 = 2;
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 64;
const MAX_CONCURRENT_UNI_STREAMS: u32 = 0;
const STREAM_RECEIVE_WINDOW_BYTES: u32 = 256 * 1024;
const CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
const SEND_WINDOW_BYTES: u64 = 4 * 1024 * 1024;
const DATAGRAM_BUFFER_BYTES: usize = 64 * 1024;

/// Hard application payload ceiling, kept below QUIC's minimum path datagram capacity.
pub const MAX_PEER_DATAGRAM_BYTES: usize = 1024;
const PUNCH_MAGIC: &[u8; 8] = b"RGOPNCH1";

#[derive(Debug, Clone)]
pub struct QuicPunchConfig {
    pub session_id: [u8; 32],
    pub generation: u64,
    pub start_unix_millis: u64,
    pub window: Duration,
    pub cadence: Duration,
    pub token: [u8; 32],
    pub role: PeerRole,
}

#[derive(Debug, Clone)]
pub struct QuicPeerConfig {
    idle_timeout: Duration,
    authentication_timeout: Duration,
}

impl Default for QuicPeerConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            authentication_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Error)]
pub enum QuicPeerError {
    #[error("QUIC endpoint I/O failed")]
    EndpointIo(#[source] io::Error),
    #[error("QUIC transport configuration failed")]
    Configuration,
    #[error("QUIC connection failed")]
    Connection,
    #[error("QUIC peer connection is closed")]
    ConnectionClosed,
    #[error("QUIC peer authentication failed")]
    AuthenticationFailed,
    #[error("QUIC peer authentication timed out")]
    AuthenticationTimedOut,
    #[error("QUIC peer authentication has the wrong role")]
    WrongAuthenticationRole,
    #[error("fresh peer authentication material is unavailable")]
    AuthenticationMaterialUnavailable,
    #[error("QUIC operation was cancelled")]
    Cancelled,
    #[error("QUIC stream operation failed")]
    Stream,
    #[error("QUIC datagrams are unsupported by this connection")]
    DatagramsUnsupported,
    #[error("QUIC datagram of {size} bytes exceeds the {max}-byte bound")]
    DatagramTooLarge { size: usize, max: usize },
    #[error("peer key derivation failed")]
    PeerCrypto(#[from] PeerCryptoError),
}

/// Single-use authentication material for one exact peer connection.
///
/// The transcript must be constructed only after its signed rendezvous envelopes have been
/// verified against the externally authenticated Ed25519 peer identity. Construction consumes
/// the OS-random ephemeral key and creates exactly one Task 3 key schedule.
pub struct PeerAuthentication {
    role: PeerRole,
    keys: PeerSessionKeys,
}

impl PeerAuthentication {
    pub fn new(
        role: PeerRole,
        local_ephemeral: EphemeralPeerKey,
        transcript: PeerTranscript,
    ) -> Result<Self, QuicPeerError> {
        let keys = PeerSessionKeys::derive(role, local_ephemeral, &transcript)?;
        Ok(Self { role, keys })
    }
}

impl fmt::Debug for PeerAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerAuthentication([REDACTED])")
    }
}

/// Creates fresh, non-reconstructable authentication material for every path attempt.
pub trait PeerAuthenticationFactory: Send + Sync {
    fn create(&self) -> Result<PeerAuthentication, QuicPeerError>;
}

struct EndpointOwner {
    endpoint: Mutex<Option<quinn::Endpoint>>,
}

impl EndpointOwner {
    fn endpoint(&self) -> Result<quinn::Endpoint, QuicPeerError> {
        self.endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(QuicPeerError::ConnectionClosed)
    }

    fn take(&self) -> Option<quinn::Endpoint> {
        self.endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn release(&self, code: u32, reason: &'static [u8]) {
        if let Some(endpoint) = self.take() {
            endpoint.close(quinn::VarInt::from_u32(code), reason);
        }
    }
}

impl Drop for EndpointOwner {
    fn drop(&mut self) {
        self.release(CLOSE_NORMAL, b"endpoint dropped");
    }
}

#[derive(Clone)]
pub struct QuicPeerEndpoint {
    inner: Arc<EndpointOwner>,
    config: QuicPeerConfig,
}

impl QuicPeerEndpoint {
    pub fn bind(local_addr: SocketAddr, config: QuicPeerConfig) -> Result<Self, QuicPeerError> {
        let server_config = server_config(&config)?;
        let mut endpoint = quinn::Endpoint::server(server_config, local_addr)
            .map_err(QuicPeerError::EndpointIo)?;
        endpoint.set_default_client_config(client_config(&config)?);
        Ok(Self {
            inner: Arc::new(EndpointOwner {
                endpoint: Mutex::new(Some(endpoint)),
            }),
            config,
        })
    }

    pub fn from_socket(socket: UdpSocket, config: QuicPeerConfig) -> Result<Self, QuicPeerError> {
        let server_config = server_config(&config)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(QuicPeerError::EndpointIo)?;
        endpoint.set_default_client_config(client_config(&config)?);
        Ok(Self {
            inner: Arc::new(EndpointOwner {
                endpoint: Mutex::new(Some(endpoint)),
            }),
            config,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicPeerError> {
        self.inner
            .endpoint()?
            .local_addr()
            .map_err(QuicPeerError::EndpointIo)
    }

    pub fn rebind(&self, local_addr: SocketAddr) -> Result<SocketAddr, QuicPeerError> {
        let socket = UdpSocket::bind(local_addr).map_err(QuicPeerError::EndpointIo)?;
        let rebound = socket.local_addr().map_err(QuicPeerError::EndpointIo)?;
        self.inner
            .endpoint()?
            .rebind(socket)
            .map_err(QuicPeerError::EndpointIo)?;
        Ok(rebound)
    }

    pub async fn connect(
        &self,
        remote_addr: SocketAddr,
        authentication: PeerAuthentication,
        cancellation: CancellationToken,
    ) -> Result<QuicPeerSession, QuicPeerError> {
        if authentication.role != PeerRole::Initiator {
            return Err(QuicPeerError::WrongAuthenticationRole);
        }
        let endpoint = self.inner.endpoint()?;
        let connecting = endpoint
            .connect(remote_addr, QUIC_SERVER_NAME)
            .map_err(|_| QuicPeerError::Connection)?;
        let connection = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(QuicPeerError::Cancelled),
            result = connecting => result.map_err(|_| QuicPeerError::Connection)?,
        };
        let result = authenticate_connection(
            &connection,
            authentication,
            &cancellation,
            self.config.authentication_timeout,
        )
        .await;
        if let Err(error) = result {
            close_for_error(&connection, &error);
            return Err(error);
        }
        Ok(QuicPeerSession::authenticated(
            self.inner.clone(),
            connection,
        ))
    }

    pub async fn accept(
        &self,
        authentication: PeerAuthentication,
        cancellation: CancellationToken,
    ) -> Result<QuicPeerSession, QuicPeerError> {
        if authentication.role != PeerRole::Responder {
            return Err(QuicPeerError::WrongAuthenticationRole);
        }
        let endpoint = self.inner.endpoint()?;
        let incoming = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(QuicPeerError::Cancelled),
            incoming = endpoint.accept() => incoming.ok_or(QuicPeerError::ConnectionClosed)?,
        };
        let connecting = incoming.accept().map_err(|_| QuicPeerError::Connection)?;
        let connection = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(QuicPeerError::Cancelled),
            result = connecting => result.map_err(|_| QuicPeerError::Connection)?,
        };
        let result = authenticate_connection(
            &connection,
            authentication,
            &cancellation,
            self.config.authentication_timeout,
        )
        .await;
        if let Err(error) = result {
            close_for_error(&connection, &error);
            return Err(error);
        }
        Ok(QuicPeerSession::authenticated(
            self.inner.clone(),
            connection,
        ))
    }

    fn release(&self, code: u32, reason: &'static [u8]) {
        self.inner.release(code, reason);
    }

    async fn shutdown(&self, code: u32, reason: &'static [u8]) {
        if let Some(endpoint) = self.inner.take() {
            endpoint.close(quinn::VarInt::from_u32(code), reason);
            endpoint.wait_idle().await;
        }
    }
}

struct SessionInner {
    _endpoint: Arc<EndpointOwner>,
    connection: Mutex<Option<quinn::Connection>>,
}

impl SessionInner {
    fn connection(&self) -> Result<quinn::Connection, QuicPeerError> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(QuicPeerError::ConnectionClosed)
    }

    fn release(&self, code: u32, reason: &'static [u8]) {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(connection) = connection {
            connection.close(quinn::VarInt::from_u32(code), reason);
        }
    }
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        self.release(CLOSE_NORMAL, b"session dropped");
    }
}

#[derive(Clone)]
pub struct QuicPeerSession {
    inner: Arc<SessionInner>,
}

impl QuicPeerSession {
    fn authenticated(endpoint: Arc<EndpointOwner>, connection: quinn::Connection) -> Self {
        Self {
            inner: Arc::new(SessionInner {
                _endpoint: endpoint,
                connection: Mutex::new(Some(connection)),
            }),
        }
    }

    pub async fn open_stream(
        &self,
        cancellation: CancellationToken,
    ) -> Result<PeerStream, QuicPeerError> {
        let connection = self.inner.connection()?;
        let (send, recv) = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(QuicPeerError::Cancelled),
            stream = connection.open_bi() => stream.map_err(|_| QuicPeerError::Stream)?,
        };
        Ok(PeerStream { send, recv })
    }

    pub async fn accept_stream(
        &self,
        cancellation: CancellationToken,
    ) -> Result<PeerStream, QuicPeerError> {
        let connection = self.inner.connection()?;
        let (send, recv) = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(QuicPeerError::Cancelled),
            stream = connection.accept_bi() => stream.map_err(|_| QuicPeerError::Stream)?,
        };
        Ok(PeerStream { send, recv })
    }

    pub fn datagrams(&self) -> PeerDatagram {
        PeerDatagram {
            inner: self.inner.clone(),
        }
    }

    pub fn close(&self) {
        self.inner.release(CLOSE_NORMAL, b"session closed");
    }
}

pub struct PeerStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for PeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for PeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), context)
    }
}

#[derive(Clone)]
pub struct PeerDatagram {
    inner: Arc<SessionInner>,
}

impl PeerDatagram {
    pub fn send(&self, payload: &[u8]) -> Result<(), QuicPeerError> {
        if payload.len() > MAX_PEER_DATAGRAM_BYTES {
            return Err(QuicPeerError::DatagramTooLarge {
                size: payload.len(),
                max: MAX_PEER_DATAGRAM_BYTES,
            });
        }
        let connection = self.inner.connection()?;
        let peer_max = connection
            .max_datagram_size()
            .ok_or(QuicPeerError::DatagramsUnsupported)?;
        if payload.len() > peer_max {
            return Err(QuicPeerError::DatagramTooLarge {
                size: payload.len(),
                max: peer_max,
            });
        }
        connection
            .send_datagram(Bytes::copy_from_slice(payload))
            .map_err(|error| match error {
                quinn::SendDatagramError::UnsupportedByPeer => QuicPeerError::DatagramsUnsupported,
                quinn::SendDatagramError::Disabled => QuicPeerError::DatagramsUnsupported,
                quinn::SendDatagramError::TooLarge => QuicPeerError::DatagramTooLarge {
                    size: payload.len(),
                    max: peer_max,
                },
                quinn::SendDatagramError::ConnectionLost(_) => QuicPeerError::ConnectionClosed,
            })
    }

    pub async fn receive(&self, cancellation: CancellationToken) -> Result<Vec<u8>, QuicPeerError> {
        let connection = self.inner.connection()?;
        let payload = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(QuicPeerError::Cancelled),
            payload = connection.read_datagram() => payload.map_err(|_| QuicPeerError::ConnectionClosed)?,
        };
        if payload.len() > MAX_PEER_DATAGRAM_BYTES {
            return Err(QuicPeerError::DatagramTooLarge {
                size: payload.len(),
                max: MAX_PEER_DATAGRAM_BYTES,
            });
        }
        Ok(payload.to_vec())
    }
}

pub struct QuicPathAttempt {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    config: QuicPeerConfig,
    authentication_factory: Arc<dyn PeerAuthenticationFactory>,
    kind: PathKind,
    socket: Mutex<Option<UdpSocket>>,
    punch: Option<QuicPunchConfig>,
}

impl QuicPathAttempt {
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: QuicPeerConfig,
        authentication_factory: Arc<dyn PeerAuthenticationFactory>,
    ) -> Self {
        let kind = if remote_addr.is_ipv6() {
            PathKind::QuicV6
        } else {
            PathKind::QuicV4
        };
        Self {
            local_addr,
            remote_addr,
            config,
            authentication_factory,
            kind,
            socket: Mutex::new(None),
            punch: None,
        }
    }

    pub fn with_socket(
        socket: UdpSocket,
        remote_addr: SocketAddr,
        config: QuicPeerConfig,
        authentication_factory: Arc<dyn PeerAuthenticationFactory>,
    ) -> Result<Self, QuicPeerError> {
        let local_addr = socket.local_addr().map_err(QuicPeerError::EndpointIo)?;
        let mut attempt = Self::new(local_addr, remote_addr, config, authentication_factory);
        attempt.socket = Mutex::new(Some(socket));
        Ok(attempt)
    }

    pub fn with_punch(mut self, punch: QuicPunchConfig) -> Self {
        self.punch = Some(punch);
        self
    }
}

#[async_trait]
impl PathAttempt for QuicPathAttempt {
    fn kind(&self) -> PathKind {
        self.kind
    }

    async fn connect(&self, cancellation: CancellationToken) -> Result<SelectedPath, PathError> {
        if cancellation.is_cancelled() {
            return Err(PathError::Cancelled);
        }
        let socket = self
            .socket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .map(Ok)
            .unwrap_or_else(|| UdpSocket::bind(self.local_addr));
        let socket = socket.map_err(|_| PathError::AttemptFailed(self.kind))?;
        if let Some(punch) = &self.punch {
            coordinated_punch(
                socket
                    .try_clone()
                    .map_err(|_| PathError::AttemptFailed(self.kind))?,
                self.remote_addr,
                punch,
                cancellation.clone(),
            )
            .await?;
        }
        let endpoint = QuicPeerEndpoint::from_socket(socket, self.config.clone())
            .map_err(|_| PathError::AttemptFailed(self.kind))?;
        let authentication = match self.authentication_factory.create() {
            Ok(authentication) => authentication,
            Err(QuicPeerError::Cancelled) => {
                endpoint.shutdown(CLOSE_CANCELLED, b"path cancelled").await;
                return Err(PathError::Cancelled);
            }
            Err(_) => {
                endpoint.shutdown(CLOSE_NORMAL, b"path failed").await;
                return Err(PathError::AttemptFailed(self.kind));
            }
        };
        let role = authentication.role;
        let established = async {
            match role {
                PeerRole::Initiator => {
                    endpoint
                        .connect(self.remote_addr, authentication, cancellation.clone())
                        .await
                }
                PeerRole::Responder => endpoint.accept(authentication, cancellation.clone()).await,
            }
        };
        let session = match established.await {
            Ok(session) => session,
            Err(QuicPeerError::Cancelled) => {
                endpoint.shutdown(CLOSE_CANCELLED, b"path cancelled").await;
                return Err(PathError::Cancelled);
            }
            Err(_) => {
                endpoint.shutdown(CLOSE_NORMAL, b"path failed").await;
                return Err(PathError::AttemptFailed(self.kind));
            }
        };
        if cancellation.is_cancelled() {
            session.close();
            endpoint.shutdown(CLOSE_CANCELLED, b"path cancelled").await;
            return Err(PathError::Cancelled);
        }
        let handle = Arc::new(QuicPeerPathHandle::new(endpoint, session, cancellation));
        Ok(SelectedPath::authenticated_with(self.kind, handle))
    }
}

async fn coordinated_punch(
    socket: UdpSocket,
    remote: SocketAddr,
    config: &QuicPunchConfig,
    cancellation: CancellationToken,
) -> Result<(), PathError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let start = Duration::from_millis(config.start_unix_millis);
    if start > now {
        tokio::select! {
            () = cancellation.cancelled() => return Err(PathError::Cancelled),
            () = tokio::time::sleep(start - now) => {}
        }
    }
    let mut probe = Vec::with_capacity(81);
    probe.extend_from_slice(PUNCH_MAGIC);
    probe.extend_from_slice(&config.session_id);
    probe.extend_from_slice(&config.generation.to_be_bytes());
    probe.push(if config.role == PeerRole::Initiator {
        1
    } else {
        2
    });
    probe.extend_from_slice(&config.token);
    let expected_role = if config.role == PeerRole::Initiator {
        2
    } else {
        1
    };
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|_| PathError::AttemptFailed(PathKind::QuicV4))?;
    let deadline = tokio::time::Instant::now() + config.window;
    let mut interval = tokio::time::interval(config.cadence);
    let mut buffer = [0_u8; 96];
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(PathError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Ok(()),
            _ = interval.tick() => { let _ = socket.send_to(&probe, remote).await; }
            received = socket.recv_from(&mut buffer) => {
                // Validate and discard only this exact grant's probes. Keep the
                // socket in the shared bounded phase even after success so the
                // two Quinn endpoints transition together.
                let _valid_peer_probe = received.is_ok_and(|(size, source)| {
                    source == remote
                        && size == probe.len()
                        && buffer[..8] == *PUNCH_MAGIC
                        && buffer[8..40] == config.session_id
                        && buffer[40..48] == config.generation.to_be_bytes()
                        && buffer[48] == expected_role
                        && buffer[49..81] == config.token
                });
            }
        }
    }
}

pub struct QuicPeerPathHandle {
    resources: Arc<Mutex<Option<PathResources>>>,
    cancellation_watcher: JoinHandle<()>,
}

struct PathResources {
    endpoint: QuicPeerEndpoint,
    session: QuicPeerSession,
}

impl QuicPeerPathHandle {
    fn new(
        endpoint: QuicPeerEndpoint,
        session: QuicPeerSession,
        cancellation: CancellationToken,
    ) -> Self {
        let resources = Arc::new(Mutex::new(Some(PathResources { endpoint, session })));
        let watched_resources = resources.clone();
        let cancellation_watcher = tokio::spawn(async move {
            cancellation.cancelled().await;
            close_path_resources(&watched_resources, CLOSE_CANCELLED, b"path cancelled");
        });
        Self {
            resources,
            cancellation_watcher,
        }
    }

    pub fn session(&self) -> Result<QuicPeerSession, QuicPeerError> {
        self.resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|resources| resources.session.clone())
            .ok_or(QuicPeerError::ConnectionClosed)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicPeerError> {
        self.resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .ok_or(QuicPeerError::ConnectionClosed)?
            .endpoint
            .local_addr()
    }

    pub fn close(&self) {
        close_path_resources(&self.resources, CLOSE_NORMAL, b"path closed");
    }
}

impl Drop for QuicPeerPathHandle {
    fn drop(&mut self) {
        self.cancellation_watcher.abort();
        self.close();
    }
}

fn close_path_resources(
    resources: &Mutex<Option<PathResources>>,
    code: u32,
    reason: &'static [u8],
) {
    let resources = resources
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(resources) = resources {
        resources.session.close();
        resources.endpoint.release(code, reason);
    }
}

async fn authenticate_connection(
    connection: &quinn::Connection,
    authentication: PeerAuthentication,
    cancellation: &CancellationToken,
    timeout: Duration,
) -> Result<(), QuicPeerError> {
    let future = async move {
        match authentication.role {
            PeerRole::Initiator => authenticate_initiator(connection, authentication.keys).await,
            PeerRole::Responder => authenticate_responder(connection, authentication.keys).await,
        }
    };
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(QuicPeerError::Cancelled),
        result = tokio::time::timeout(timeout, future) => {
            result.map_err(|_| QuicPeerError::AuthenticationTimedOut)?
        }
    }
}

async fn authenticate_initiator(
    connection: &quinn::Connection,
    keys: PeerSessionKeys,
) -> Result<(), QuicPeerError> {
    let binding = transport_binding(connection)?;
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    let record = authentication_record(AUTH_INITIATOR, keys.handshake_tag(&binding));
    send.write_all(&record)
        .await
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    send.finish()
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    let peer_record = receive
        .read_to_end(AUTH_RECORD_BYTES)
        .await
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    let peer_tag = parse_authentication_record(&peer_record, AUTH_RESPONDER)?;
    keys.verify_handshake_tag(&binding, &peer_tag)
        .map_err(|_| QuicPeerError::AuthenticationFailed)
}

async fn authenticate_responder(
    connection: &quinn::Connection,
    keys: PeerSessionKeys,
) -> Result<(), QuicPeerError> {
    let binding = transport_binding(connection)?;
    let (mut send, mut receive) = connection
        .accept_bi()
        .await
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    let peer_record = receive
        .read_to_end(AUTH_RECORD_BYTES)
        .await
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    let peer_tag = parse_authentication_record(&peer_record, AUTH_INITIATOR)?;
    keys.verify_handshake_tag(&binding, &peer_tag)
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    let record = authentication_record(AUTH_RESPONDER, keys.handshake_tag(&binding));
    send.write_all(&record)
        .await
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    send.finish()
        .map_err(|_| QuicPeerError::AuthenticationFailed)
}

fn transport_binding(
    connection: &quinn::Connection,
) -> Result<[u8; PEER_TRANSPORT_BINDING_BYTES], QuicPeerError> {
    let mut binding = [0_u8; PEER_TRANSPORT_BINDING_BYTES];
    connection
        .export_keying_material(&mut binding, EXPORTER_LABEL, EXPORTER_CONTEXT)
        .map_err(|_| QuicPeerError::AuthenticationFailed)?;
    Ok(binding)
}

fn authentication_record(role: u8, tag: [u8; PEER_HANDSHAKE_TAG_BYTES]) -> [u8; AUTH_RECORD_BYTES] {
    let mut record = [0_u8; AUTH_RECORD_BYTES];
    record[..AUTH_MAGIC.len()].copy_from_slice(AUTH_MAGIC);
    record[AUTH_MAGIC.len()] = role;
    record[AUTH_MAGIC.len() + 1..].copy_from_slice(&tag);
    record
}

fn parse_authentication_record(
    record: &[u8],
    expected_role: u8,
) -> Result<[u8; PEER_HANDSHAKE_TAG_BYTES], QuicPeerError> {
    if record.len() != AUTH_RECORD_BYTES
        || &record[..AUTH_MAGIC.len()] != AUTH_MAGIC
        || record[AUTH_MAGIC.len()] != expected_role
    {
        return Err(QuicPeerError::AuthenticationFailed);
    }
    record[AUTH_MAGIC.len() + 1..]
        .try_into()
        .map_err(|_| QuicPeerError::AuthenticationFailed)
}

fn close_for_error(connection: &quinn::Connection, error: &QuicPeerError) {
    let (code, reason): (u32, &'static [u8]) = match error {
        QuicPeerError::Cancelled => (CLOSE_CANCELLED, b"authentication cancelled"),
        _ => (CLOSE_AUTHENTICATION_FAILED, b"authentication failed"),
    };
    connection.close(quinn::VarInt::from_u32(code), reason);
}

struct EphemeralTransportCertificate {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

fn ephemeral_transport_certificate() -> Result<&'static EphemeralTransportCertificate, QuicPeerError>
{
    static CERTIFICATE: OnceLock<Result<EphemeralTransportCertificate, ()>> = OnceLock::new();
    CERTIFICATE
        .get_or_init(|| {
            let certified = rcgen::generate_simple_self_signed(vec![QUIC_SERVER_NAME.to_owned()])
                .map_err(|_| ())?;
            Ok(EphemeralTransportCertificate {
                certificate_der: certified.cert.der().to_vec(),
                private_key_der: certified.signing_key.serialize_der(),
            })
        })
        .as_ref()
        .map_err(|_| QuicPeerError::Configuration)
}

fn server_config(config: &QuicPeerConfig) -> Result<quinn::ServerConfig, QuicPeerError> {
    let certificate = ephemeral_transport_certificate()?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| QuicPeerError::Configuration)?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certificate.private_key_der.clone(),
            )),
        )
        .map_err(|_| QuicPeerError::Configuration)?;
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).map_err(|_| QuicPeerError::Configuration)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(transport_config(config)?);
    Ok(server)
}

fn client_config(config: &QuicPeerConfig) -> Result<quinn::ClientConfig, QuicPeerError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(EphemeralCertificateVerifier(provider.clone()));
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| QuicPeerError::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).map_err(|_| QuicPeerError::Configuration)?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport_config(config)?);
    Ok(client)
}

fn transport_config(config: &QuicPeerConfig) -> Result<Arc<quinn::TransportConfig>, QuicPeerError> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        config
            .idle_timeout
            .try_into()
            .map_err(|_| QuicPeerError::Configuration)?,
    ));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_CONCURRENT_BIDI_STREAMS));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_CONCURRENT_UNI_STREAMS));
    transport.stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW_BYTES));
    transport.receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW_BYTES));
    transport.send_window(SEND_WINDOW_BYTES);
    transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_BYTES));
    transport.datagram_send_buffer_size(DATAGRAM_BUFFER_BYTES);
    Ok(Arc::new(transport))
}

/// Private certificate verifier used only to bootstrap transport encryption. The accepted
/// certificate never authenticates a peer; `authenticate_connection` must succeed before a
/// `QuicPeerSession` can exist.
#[derive(Debug)]
struct EphemeralCertificateVerifier(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for EphemeralCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

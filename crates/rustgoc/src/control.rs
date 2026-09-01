use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use rustgo_config::{ClientConfig, TunnelProtocol as ConfigTunnelProtocol};
use rustgo_crypto::{AuthTranscript, CryptoError, DeviceKeypair, sign_auth};
use rustgo_protocol::{
    BoundedBytes, BoundedString, BoundedVec, ClientAuthenticate, ClientHandshakeState, ClientHello,
    Frame, FrameCodec, FrameError, MAX_CLIENT_NAME_BYTES, MAX_FINGERPRINT_BYTES,
    MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES, MAX_TUNNEL_NAME_BYTES, Message, ProtocolErrorCode,
    ProtocolVersion, RegisterTunnels, TunnelProtocol, TunnelRegistration,
};
use rustgo_rendezvous::{ObservationGrant, PeerRelayFrame, RendezvousEnvelope};
use rustgo_transport::{TlsClient, TlsError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::telemetry::TelemetryControlWriteGate;

pub const CLIENT_VERSION: ProtocolVersion = ProtocolVersion::SUPPORTED;
const MAX_CONTROL_PAYLOAD: usize = 70 * 1024;
const CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ControlClient {
    config: Arc<ClientConfig>,
    keypair: Arc<DeviceKeypair>,
    tls_client: TlsClient,
    heartbeat_interval: Duration,
    version: ProtocolVersion,
}

impl ControlClient {
    /// Loads every local credential used by the production client without
    /// creating or connecting a network socket.
    pub fn validate_credentials(config: &ClientConfig) -> Result<(), ClientError> {
        load_credentials(config).map(drop)
    }

    /// Builds every local security dependency before any network socket is opened.
    pub fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let (keypair, tls_client, heartbeat_interval) = load_credentials(&config)?;
        let version = internal_test_protocol_version()?;
        Ok(Self {
            config: Arc::new(config),
            keypair: Arc::new(keypair),
            tls_client,
            heartbeat_interval,
            version,
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub(crate) fn tls_client(&self) -> TlsClient {
        self.tls_client.clone()
    }

    pub(crate) fn keypair(&self) -> Arc<DeviceKeypair> {
        self.keypair.clone()
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub async fn connect(&self) -> Result<ControlSession, ClientError> {
        tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, self.connect_inner())
            .await
            .map_err(|_| ClientError::HandshakeTimeout)?
    }

    async fn connect_inner(&self) -> Result<ControlSession, ClientError> {
        let stream = self
            .tls_client
            .connect(&self.config.client.server_addr)
            .await?;
        let mut framed = FramedControl::new(stream);
        let mut state = ClientHandshakeState::new();

        let public_key = self.keypair.public_key();
        let fingerprint = public_key.fingerprint().to_string();
        let fingerprint = fingerprint
            .strip_prefix("sha256:")
            .ok_or(ClientError::InvalidIdentity)?;
        let hello = Message::ClientHello(ClientHello {
            client_name: BoundedString::<MAX_CLIENT_NAME_BYTES>::try_from(
                self.config.client.name.as_str(),
            )
            .map_err(|_| ClientError::InvalidConfiguration)?,
            fingerprint: BoundedBytes::<MAX_FINGERPRINT_BYTES>::try_from(fingerprint.as_bytes())
                .map_err(|_| ClientError::InvalidIdentity)?,
            heartbeat_interval_secs: u32::try_from(self.config.client.heartbeat_interval_secs)
                .map_err(|_| ClientError::InvalidConfiguration)?,
        });
        state = state.transition(&hello)?;
        framed.send(self.version, hello).await?;

        let challenge_frame = framed.receive().await?;
        let negotiated = negotiated_version(self.version, challenge_frame.version)?;
        let challenge = match challenge_frame.message {
            Message::ServerChallenge(challenge) => challenge,
            Message::Error(error) => return Err(ClientError::Protocol(error.code)),
            _ => return Err(ClientError::InvalidState),
        };
        state = state.transition(&Message::ServerChallenge(challenge.clone()))?;

        let transcript = AuthTranscript::new(
            challenge.challenge.as_slice().to_vec(),
            challenge.session_id.as_slice().to_vec(),
            transcript_version(negotiated)?,
            self.config.client.name.clone(),
        );
        let authentication = Message::ClientAuthenticate(ClientAuthenticate {
            public_key: BoundedBytes::<MAX_PUBLIC_KEY_BYTES>::try_from(
                public_key.to_string().as_bytes(),
            )
            .map_err(|_| ClientError::InvalidIdentity)?,
            signature: BoundedBytes::<MAX_SIGNATURE_BYTES>::try_from(
                sign_auth(&self.keypair, &transcript).as_slice(),
            )
            .map_err(|_| ClientError::InvalidIdentity)?,
        });
        state = state.transition(&authentication)?;
        framed.send(negotiated, authentication).await?;

        let auth_frame = framed.receive().await?;
        require_version(auth_frame.version, negotiated)?;
        let result = match auth_frame.message {
            Message::AuthResult(result) => result,
            Message::Error(error) => return Err(ClientError::Protocol(error.code)),
            _ => return Err(ClientError::InvalidState),
        };
        state = state.transition(&Message::AuthResult(result.clone()))?;
        if !result.accepted {
            return Err(ClientError::AuthenticationRejected);
        }

        let registration = registration_message(&self.config)?;
        state = state.transition(&registration)?;
        if !state.is_active() {
            return Err(ClientError::InvalidState);
        }
        framed.send(negotiated, registration).await?;

        let results_frame = framed.receive().await?;
        require_version(results_frame.version, negotiated)?;
        let results = match results_frame.message {
            Message::TunnelResults(results) => results,
            Message::Error(error) => return Err(ClientError::Protocol(error.code)),
            _ => return Err(ClientError::InvalidState),
        };
        let registered_tunnels = correlate_results(&self.config, results.results.into_vec())?;

        Ok(ControlSession::new(
            framed,
            negotiated,
            challenge.session_id.into_vec(),
            self.heartbeat_interval,
            registered_tunnels,
        ))
    }
}

fn load_credentials(
    config: &ClientConfig,
) -> Result<(DeviceKeypair, TlsClient, Duration), ClientError> {
    config
        .validate()
        .map_err(|_| ClientError::InvalidConfiguration)?;
    let heartbeat_interval_secs = u32::try_from(config.client.heartbeat_interval_secs)
        .map_err(|_| ClientError::InvalidConfiguration)?;
    if heartbeat_interval_secs == 0 {
        return Err(ClientError::InvalidConfiguration);
    }
    let keypair = DeviceKeypair::load_private_file(&config.client.private_key_file)?;
    let tls_client = TlsClient::from_ca_file(
        &config.client.certificate_authority_file,
        &config.client.server_name,
    )?;
    Ok((
        keypair,
        tls_client,
        Duration::from_secs(u64::from(heartbeat_interval_secs)),
    ))
}

fn negotiated_version(
    local_version: ProtocolVersion,
    server_version: ProtocolVersion,
) -> Result<ProtocolVersion, ClientError> {
    let negotiated = local_version
        .negotiate(server_version)
        .map_err(ClientError::Protocol)?;
    if negotiated != server_version {
        return Err(ClientError::InvalidState);
    }
    Ok(negotiated)
}

fn internal_test_protocol_version() -> Result<ProtocolVersion, ClientError> {
    if std::env::var("RUSTGO_INTERNAL_TESTING").as_deref() != Ok("1") {
        return Ok(CLIENT_VERSION);
    }
    let minor = std::env::var("RUSTGO_TEST_PROTOCOL_MINOR")
        .ok()
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| ClientError::InvalidConfiguration)
        })
        .transpose()?
        .unwrap_or(CLIENT_VERSION.minor);
    Ok(ProtocolVersion::new(CLIENT_VERSION.major, minor))
}

fn require_version(
    actual: ProtocolVersion,
    negotiated: ProtocolVersion,
) -> Result<(), ClientError> {
    if actual == negotiated {
        Ok(())
    } else {
        Err(ClientError::InvalidState)
    }
}

fn transcript_version(version: ProtocolVersion) -> Result<u16, ClientError> {
    if version.major > u16::from(u8::MAX) || version.minor > u16::from(u8::MAX) {
        return Err(ClientError::InvalidState);
    }
    Ok((version.major << 8) | version.minor)
}

fn registration_message(config: &ClientConfig) -> Result<Message, ClientError> {
    let mut tunnels = Vec::with_capacity(config.tunnels.len());
    for (index, tunnel) in config.tunnels.iter().enumerate() {
        let tunnel_id = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ClientError::InvalidConfiguration)?;
        tunnels.push(TunnelRegistration {
            tunnel_id,
            name: BoundedString::<MAX_TUNNEL_NAME_BYTES>::try_from(tunnel.name.as_str())
                .map_err(|_| ClientError::InvalidConfiguration)?,
            protocol: match tunnel.protocol {
                ConfigTunnelProtocol::Tcp => TunnelProtocol::TCP,
                ConfigTunnelProtocol::Udp => TunnelProtocol::UDP,
            },
            remote_port: u16::try_from(tunnel.remote_port)
                .map_err(|_| ClientError::InvalidConfiguration)?,
        });
    }
    Ok(Message::RegisterTunnels(RegisterTunnels {
        tunnels: BoundedVec::try_from(tunnels).map_err(|_| ClientError::InvalidConfiguration)?,
    }))
}

fn correlate_results(
    config: &ClientConfig,
    results: Vec<rustgo_protocol::TunnelResult>,
) -> Result<Arc<[RegisteredTunnel]>, ClientError> {
    if results.len() != config.tunnels.len() {
        return Err(ClientError::InvalidTunnelResults);
    }
    let mut by_id = HashMap::with_capacity(results.len());
    for result in results {
        if result.tunnel_id == 0 || by_id.insert(result.tunnel_id, result).is_some() {
            return Err(ClientError::InvalidTunnelResults);
        }
    }
    let mut registered = Vec::with_capacity(config.tunnels.len());
    for (index, tunnel) in config.tunnels.iter().enumerate() {
        let tunnel_id = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ClientError::InvalidTunnelResults)?;
        let result = by_id
            .remove(&tunnel_id)
            .ok_or(ClientError::InvalidTunnelResults)?;
        registered.push(RegisteredTunnel {
            tunnel_id,
            name: tunnel.name.clone(),
            protocol: tunnel.protocol,
            local_addr: tunnel.local_addr.clone(),
            remote_port: u16::try_from(tunnel.remote_port)
                .map_err(|_| ClientError::InvalidTunnelResults)?,
            accepted: result.accepted,
            error: result.error,
        });
    }
    if !by_id.is_empty() {
        return Err(ClientError::InvalidTunnelResults);
    }
    Ok(registered.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredTunnel {
    tunnel_id: u32,
    name: String,
    protocol: ConfigTunnelProtocol,
    local_addr: String,
    remote_port: u16,
    accepted: bool,
    error: Option<ProtocolErrorCode>,
}

impl RegisteredTunnel {
    #[cfg(test)]
    pub(crate) fn accepted_for_test(tunnel_id: u32, protocol: ConfigTunnelProtocol) -> Self {
        Self {
            tunnel_id,
            name: format!("test-{tunnel_id}"),
            protocol,
            local_addr: "127.0.0.1:1".to_owned(),
            remote_port: 1,
            accepted: true,
            error: None,
        }
    }

    pub const fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn protocol(&self) -> ConfigTunnelProtocol {
        self.protocol
    }

    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }

    pub const fn remote_port(&self) -> u16 {
        self.remote_port
    }

    pub const fn accepted(&self) -> bool {
        self.accepted
    }

    pub const fn error(&self) -> Option<ProtocolErrorCode> {
        self.error
    }
}

pub struct ControlSession {
    pub(crate) framed: FramedControl,
    pub(crate) version: ProtocolVersion,
    pub(crate) session_id: Vec<u8>,
    pub(crate) heartbeat_interval: Duration,
    registered_tunnels: Arc<[RegisteredTunnel]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    ObservationGrant(ObservationGrant),
    Rendezvous(RendezvousEnvelope),
    ServerNotice(rustgo_protocol::ServerNotice),
    PeerRelayFrame(PeerRelayFrame),
    PeerIdentityBinding(rustgo_protocol::PeerIdentityBinding),
    PunchGrant(rustgo_protocol::PunchGrant),
}

impl ControlSession {
    pub(crate) fn new(
        framed: FramedControl,
        version: ProtocolVersion,
        session_id: Vec<u8>,
        heartbeat_interval: Duration,
        registered_tunnels: Arc<[RegisteredTunnel]>,
    ) -> Self {
        Self {
            framed,
            version,
            session_id,
            heartbeat_interval,
            registered_tunnels,
        }
    }

    pub fn registered_tunnels(&self) -> &[RegisteredTunnel] {
        &self.registered_tunnels
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub(crate) const fn supports_telemetry(&self) -> bool {
        self.version.supports_telemetry()
    }

    pub async fn request_observation_grant(&mut self) -> Result<(), ClientError> {
        self.require_v02()?;
        self.framed
            .send(
                self.version,
                Message::ObservationGrantRequest(rustgo_protocol::ObservationGrantRequest {}),
            )
            .await
    }

    pub async fn request_peer_identity(
        &mut self,
        session_id: rustgo_rendezvous::SessionId,
        peer: &str,
    ) -> Result<(), ClientError> {
        self.require_v02()?;
        self.framed
            .send(
                self.version,
                Message::PeerIdentityLookup(rustgo_protocol::PeerIdentityLookup {
                    session_id: *session_id.as_bytes(),
                    peer: BoundedString::try_from(peer).map_err(|_| ClientError::InvalidState)?,
                }),
            )
            .await
    }

    pub async fn send_rendezvous_envelope(
        &mut self,
        envelope: &RendezvousEnvelope,
    ) -> Result<(), ClientError> {
        self.require_v02()?;
        if envelope.version != self.version {
            return Err(ClientError::InvalidState);
        }
        let message = envelope
            .to_protocol_message()
            .map_err(|_| ClientError::InvalidState)?;
        self.framed.send(self.version, message).await
    }

    pub async fn send_peer_relay_frame(
        &mut self,
        frame: &PeerRelayFrame,
    ) -> Result<(), ClientError> {
        self.require_v02()?;
        let message = frame
            .to_protocol_message()
            .map_err(|_| ClientError::InvalidState)?;
        self.framed.send(self.version, message).await
    }

    pub async fn next_control_event(&mut self) -> Result<ControlEvent, ClientError> {
        self.require_v02()?;
        let frame = self.framed.receive().await?;
        require_version(frame.version, self.version)?;
        match frame.message {
            message @ Message::ObservationGrant(_) => {
                ObservationGrant::from_protocol_message(message)
                    .map(ControlEvent::ObservationGrant)
                    .map_err(|_| ClientError::InvalidState)
            }
            message if is_rendezvous_message(&message) => {
                RendezvousEnvelope::from_protocol_message(message)
                    .map(ControlEvent::Rendezvous)
                    .map_err(|_| ClientError::InvalidState)
            }
            Message::ServerNotice(notice) => Ok(ControlEvent::ServerNotice(notice)),
            message @ Message::PeerRelayFrame(_) => PeerRelayFrame::from_protocol_message(message)
                .map(ControlEvent::PeerRelayFrame)
                .map_err(|_| ClientError::InvalidState),
            Message::PeerIdentityBinding(binding) => Ok(ControlEvent::PeerIdentityBinding(binding)),
            Message::PunchGrant(grant) => Ok(ControlEvent::PunchGrant(grant)),
            Message::Error(error) => Err(ClientError::Protocol(error.code)),
            _ => Err(ClientError::InvalidState),
        }
    }

    fn require_v02(&self) -> Result<(), ClientError> {
        if self.version.major == ProtocolVersion::V0_2.major
            && self.version.minor >= ProtocolVersion::V0_2.minor
        {
            Ok(())
        } else {
            Err(ClientError::Protocol(
                ProtocolErrorCode::UNSUPPORTED_VERSION,
            ))
        }
    }

    pub(crate) fn registered_tunnels_shared(&self) -> Arc<[RegisteredTunnel]> {
        self.registered_tunnels.clone()
    }
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

impl std::fmt::Debug for ControlSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlSession")
            .field("version", &self.version)
            .field("session_id", &"[REDACTED]")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("registered_tunnels", &self.registered_tunnels)
            .finish_non_exhaustive()
    }
}

trait ControlIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ControlIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct GatedControlIo {
    inner: Box<dyn ControlIo>,
    gate: Arc<dyn TelemetryControlWriteGate>,
}

impl AsyncRead for GatedControlIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for GatedControlIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.gate.poll_write(context).is_pending() {
            Poll::Pending
        } else {
            Pin::new(&mut *self.inner).poll_write(context, buffer)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }
}

pub(crate) struct FramedControl {
    stream: Box<dyn ControlIo>,
    read_buffer: BytesMut,
    codec: FrameCodec,
}

impl FramedControl {
    pub(crate) fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            stream: Box::new(stream),
            read_buffer: BytesMut::new(),
            codec: FrameCodec::new(MAX_CONTROL_PAYLOAD),
        }
    }

    pub(crate) fn install_telemetry_write_gate(
        &mut self,
        gate: Arc<dyn TelemetryControlWriteGate>,
    ) {
        let (placeholder, _) = tokio::io::duplex(1);
        let inner = std::mem::replace(&mut self.stream, Box::new(placeholder));
        self.stream = Box::new(GatedControlIo { inner, gate });
    }

    pub(crate) async fn receive(&mut self) -> Result<Frame, ClientError> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.read_buffer)? {
                return Ok(frame);
            }
            if self.read_buffer.len() >= MAX_CONTROL_PAYLOAD + rustgo_protocol::HEADER_LEN {
                return Err(ClientError::FrameTooLarge);
            }
            if self.stream.read_buf(&mut self.read_buffer).await? == 0 {
                return Err(ClientError::Closed);
            }
        }
    }

    pub(crate) async fn send(
        &mut self,
        version: ProtocolVersion,
        message: Message,
    ) -> Result<(), ClientError> {
        let encoded = self.codec.encode(version, 0, &message)?;
        self.stream.write_all(&encoded).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid client configuration")]
    InvalidConfiguration,
    #[error("invalid client identity")]
    InvalidIdentity,
    #[error("TLS transport failed: {0}")]
    Tls(#[from] TlsError),
    #[error("device identity failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("control frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("control protocol state failed: {0}")]
    State(#[from] rustgo_protocol::StateError),
    #[error("control I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("server rejected authentication")]
    AuthenticationRejected,
    #[error("server rejected control protocol operation with code {0:?}")]
    Protocol(ProtocolErrorCode),
    #[error("server returned an invalid control protocol state")]
    InvalidState,
    #[error("server returned invalid tunnel registration results")]
    InvalidTunnelResults,
    #[error("control connection closed")]
    Closed,
    #[error("control frame exceeded the configured maximum")]
    FrameTooLarge,
    #[error("client task failed to join")]
    TaskJoin,
    #[error("peer generation owner failed during teardown")]
    PeerGenerationFailed,
    #[error("a persistent data session terminated while its control generation was active")]
    DataSessionTerminated,
    #[error("client session generation exhausted")]
    GenerationExhausted,
    #[error("client heartbeat sequence exhausted")]
    SequenceExhausted,
    #[error("server heartbeat response timed out")]
    HeartbeatTimeout,
    #[error("control connection handshake timed out")]
    HandshakeTimeout,
    #[error("active control write timed out")]
    ControlWriteTimeout,
    #[error("low-priority telemetry write timed out; control generation must reconnect")]
    TelemetryWriteTimeout,
}

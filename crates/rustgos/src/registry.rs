use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use rand::{TryRngCore, rngs::OsRng};
use rustgo_protocol::{
    BoundedBytes, BoundedVec, DataChannelBind, DataChannelKind, MAX_BINDING_TOKEN_BYTES,
    MAX_TUNNELS, Message, OpenUdpChannel, ProtocolErrorCode, RegisterTunnels, TunnelProtocol,
    TunnelResult, TunnelResults,
};
use rustgo_transport::{BindingError, ChannelBinding, ChannelBindingStore, ChannelKind};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::{
    AuthenticatedClient,
    tcp::TcpListenerTask,
    udp::{UdpListenerTask, UdpRuntimeLimits},
};

const MAX_CONNECTION_ID_ATTEMPTS: usize = 16;
type ServerDataStream = TlsStream<TcpStream>;

#[derive(Clone)]
pub struct ClientRegistry {
    inner: Arc<Mutex<RegistryState>>,
    max_clients: usize,
    max_tunnels_per_client: usize,
    max_tcp_connections_per_tunnel: usize,
    max_udp_sessions_per_tunnel: usize,
    max_udp_payload_bytes: usize,
    listener_ip: IpAddr,
    binding_capacity: usize,
    binding_ttl: Duration,
    udp_runtime_limits: UdpRuntimeLimits,
}

#[derive(Default)]
struct RegistryState {
    active: HashMap<String, ActiveSession>,
}

struct ActiveSession {
    name: String,
    session_id: Vec<u8>,
    runtime: Arc<SessionRuntime>,
}

impl std::fmt::Debug for ClientRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientRegistry")
            .field("max_clients", &self.max_clients)
            .field("max_tunnels_per_client", &self.max_tunnels_per_client)
            .field(
                "max_tcp_connections_per_tunnel",
                &self.max_tcp_connections_per_tunnel,
            )
            .field(
                "max_udp_sessions_per_tunnel",
                &self.max_udp_sessions_per_tunnel,
            )
            .field("max_udp_payload_bytes", &self.max_udp_payload_bytes)
            .field("listener_ip", &self.listener_ip)
            .finish_non_exhaustive()
    }
}

impl ClientRegistry {
    #[cfg(test)]
    pub(crate) fn new(
        max_clients: usize,
        max_tunnels_per_client: usize,
        listener_ip: IpAddr,
        binding_capacity: usize,
        binding_ttl: Duration,
    ) -> Result<Self, RegistryError> {
        Self::new_with_tcp_limit(
            max_clients,
            max_tunnels_per_client,
            1,
            listener_ip,
            binding_capacity,
            binding_ttl,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_tcp_limit(
        max_clients: usize,
        max_tunnels_per_client: usize,
        max_tcp_connections_per_tunnel: usize,
        listener_ip: IpAddr,
        binding_capacity: usize,
        binding_ttl: Duration,
    ) -> Result<Self, RegistryError> {
        Self::new_with_relay_limits(
            max_clients,
            max_tunnels_per_client,
            max_tcp_connections_per_tunnel,
            1,
            rustgo_protocol::MAX_UDP_PAYLOAD_BYTES,
            listener_ip,
            binding_capacity,
            binding_ttl,
            UdpRuntimeLimits::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_relay_limits(
        max_clients: usize,
        max_tunnels_per_client: usize,
        max_tcp_connections_per_tunnel: usize,
        max_udp_sessions_per_tunnel: usize,
        max_udp_payload_bytes: usize,
        listener_ip: IpAddr,
        binding_capacity: usize,
        binding_ttl: Duration,
        udp_runtime_limits: UdpRuntimeLimits,
    ) -> Result<Self, RegistryError> {
        if max_clients == 0
            || max_tunnels_per_client == 0
            || max_tcp_connections_per_tunnel == 0
            || max_udp_sessions_per_tunnel == 0
            || max_udp_payload_bytes == 0
            || max_udp_payload_bytes > rustgo_protocol::MAX_UDP_PAYLOAD_BYTES
            || binding_capacity == 0
            || binding_ttl.is_zero()
            || !udp_runtime_limits.is_valid()
        {
            return Err(RegistryError::InvalidConfiguration);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(RegistryState::default())),
            max_clients,
            max_tunnels_per_client,
            max_tcp_connections_per_tunnel,
            max_udp_sessions_per_tunnel,
            max_udp_payload_bytes,
            listener_ip,
            binding_capacity,
            binding_ttl,
            udp_runtime_limits,
        })
    }

    pub fn active_count(&self) -> usize {
        self.inner.lock().map_or(0, |state| state.active.len())
    }

    pub fn is_active(&self, fingerprint: &str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|state| state.active.contains_key(fingerprint))
    }

    #[cfg(test)]
    pub(crate) fn claim(
        &self,
        identity: AuthenticatedClient,
    ) -> Result<ControlSessionGuard, RegistryError> {
        let (outbound, receiver) = mpsc::channel(1);
        drop(receiver);
        self.claim_with_outbound(identity, outbound)
    }

    pub(crate) fn claim_with_outbound(
        &self,
        identity: AuthenticatedClient,
        outbound: mpsc::Sender<Message>,
    ) -> Result<ControlSessionGuard, RegistryError> {
        let binding_store = ChannelBindingStore::new(
            identity.name(),
            identity.session_id(),
            self.binding_capacity,
            self.binding_ttl,
        )?;
        let runtime = Arc::new(SessionRuntime {
            bindings: Mutex::new(SessionBindings {
                store: binding_store,
                pending_tcp: HashMap::new(),
                pending_udp: HashMap::new(),
            }),
            outbound,
            cancellation: CancellationToken::new(),
            binding_ttl: self.binding_ttl,
        });
        {
            let mut state = self.inner.lock().map_err(|_| RegistryError::Internal)?;
            if state.active.contains_key(identity.fingerprint())
                || state
                    .active
                    .values()
                    .any(|active| active.name == identity.name())
            {
                return Err(RegistryError::AlreadyConnected);
            }
            if state.active.len() >= self.max_clients {
                return Err(RegistryError::CapacityReached);
            }
            state.active.insert(
                identity.fingerprint().to_owned(),
                ActiveSession {
                    name: identity.name().to_owned(),
                    session_id: identity.session_id().to_vec(),
                    runtime: runtime.clone(),
                },
            );
        }

        Ok(ControlSessionGuard {
            registry: self.clone(),
            identity,
            runtime,
            listeners: Vec::new(),
            tunnel_ids: HashMap::new(),
            tunnel_names: HashSet::new(),
            data_channels: Vec::new(),
            released: false,
        })
    }

    pub(crate) fn authenticate_data_channel(
        &self,
        stream: ServerDataStream,
        request: &DataChannelBind,
    ) -> Result<AuthenticatedDataChannel, RegistryError> {
        let runtimes = self
            .inner
            .lock()
            .map_err(|_| RegistryError::Internal)?
            .active
            .values()
            .map(|active| active.runtime.clone())
            .collect::<Vec<_>>();
        for runtime in runtimes {
            if let Some(result) = runtime.redeem_if_present(request) {
                let (binding, destination) = result?;
                return Ok(AuthenticatedDataChannel {
                    stream: Some(stream),
                    binding,
                    destination: Some(destination),
                    cancellation: runtime.cancellation(),
                });
            }
        }
        Err(RegistryError::Binding(BindingError::Rejected))
    }

    pub(crate) fn udp_open_channel(
        &self,
        tunnel_id: u32,
        channel_id: u64,
        binding_token: BoundedBytes<MAX_BINDING_TOKEN_BYTES>,
    ) -> Result<OpenUdpChannel, RegistryError> {
        self.udp_runtime_limits
            .open_channel(
                tunnel_id,
                channel_id,
                binding_token,
                self.max_udp_sessions_per_tunnel,
                self.max_udp_payload_bytes,
            )
            .map_err(|_| RegistryError::InvalidConfiguration)
    }

    fn release(&self, identity: &AuthenticatedClient) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let owns_entry = state
            .active
            .get(identity.fingerprint())
            .is_some_and(|active| {
                active.name == identity.name() && active.session_id == identity.session_id()
            });
        if owns_entry {
            state.active.remove(identity.fingerprint());
        }
    }
}

pub(crate) struct PendingTcpOpen {
    pub(crate) connection_id: u64,
    pub(crate) binding_token: BoundedBytes<MAX_BINDING_TOKEN_BYTES>,
    pub(crate) data_channel: oneshot::Receiver<ServerDataStream>,
}

pub(crate) struct PendingUdpOpen {
    pub(crate) channel_id: u64,
    pub(crate) binding_token: BoundedBytes<MAX_BINDING_TOKEN_BYTES>,
    pub(crate) data_channel: oneshot::Receiver<ServerDataStream>,
}

struct PendingTcp {
    channel_kind: ChannelKind,
    binding_token: BoundedBytes<MAX_BINDING_TOKEN_BYTES>,
    destination: oneshot::Sender<ServerDataStream>,
}

struct PendingUdp {
    channel_kind: ChannelKind,
    binding_token: BoundedBytes<MAX_BINDING_TOKEN_BYTES>,
    destination: oneshot::Sender<ServerDataStream>,
}

struct SessionBindings {
    store: ChannelBindingStore,
    pending_tcp: HashMap<u64, PendingTcp>,
    pending_udp: HashMap<u64, PendingUdp>,
}

pub(crate) struct SessionRuntime {
    bindings: Mutex<SessionBindings>,
    outbound: mpsc::Sender<Message>,
    cancellation: CancellationToken,
    binding_ttl: Duration,
}

impl SessionRuntime {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) const fn binding_ttl(&self) -> Duration {
        self.binding_ttl
    }

    pub(crate) fn outbound(&self) -> mpsc::Sender<Message> {
        self.outbound.clone()
    }

    pub(crate) fn prepare_tcp(&self, tunnel_id: u32) -> Result<PendingTcpOpen, RegistryError> {
        for _ in 0..MAX_CONNECTION_ID_ATTEMPTS {
            let connection_id = OsRng
                .try_next_u64()
                .map_err(|_| RegistryError::EntropyUnavailable)?;
            if connection_id == 0 {
                continue;
            }
            let channel_kind = ChannelKind::Tcp {
                tunnel_id,
                connection_id,
            };
            let (destination, data_channel) = oneshot::channel();
            let mut bindings = self.bindings.lock().map_err(|_| RegistryError::Internal)?;
            if bindings.pending_tcp.contains_key(&connection_id) {
                continue;
            }
            let binding_token = bindings.store.issue(channel_kind)?;
            bindings.pending_tcp.insert(
                connection_id,
                PendingTcp {
                    channel_kind,
                    binding_token: binding_token.clone(),
                    destination,
                },
            );
            return Ok(PendingTcpOpen {
                connection_id,
                binding_token,
                data_channel,
            });
        }
        Err(RegistryError::EntropyUnavailable)
    }

    pub(crate) fn prepare_udp(&self, tunnel_id: u32) -> Result<PendingUdpOpen, RegistryError> {
        for _ in 0..MAX_CONNECTION_ID_ATTEMPTS {
            let channel_id = OsRng
                .try_next_u64()
                .map_err(|_| RegistryError::EntropyUnavailable)?;
            if channel_id == 0 {
                continue;
            }
            let channel_kind = ChannelKind::Udp {
                tunnel_id,
                channel_id,
            };
            let (destination, data_channel) = oneshot::channel();
            let mut bindings = self.bindings.lock().map_err(|_| RegistryError::Internal)?;
            if bindings.pending_udp.contains_key(&channel_id) {
                continue;
            }
            let binding_token = bindings.store.issue(channel_kind)?;
            bindings.pending_udp.insert(
                channel_id,
                PendingUdp {
                    channel_kind,
                    binding_token: binding_token.clone(),
                    destination,
                },
            );
            return Ok(PendingUdpOpen {
                channel_id,
                binding_token,
                data_channel,
            });
        }
        Err(RegistryError::EntropyUnavailable)
    }

    pub(crate) fn cancel_pending(&self, connection_id: u64) {
        let Ok(mut bindings) = self.bindings.lock() else {
            return;
        };
        let Some(pending) = bindings.pending_tcp.remove(&connection_id) else {
            return;
        };
        bindings
            .store
            .revoke(pending.channel_kind, pending.binding_token.as_slice());
    }

    pub(crate) fn cancel_pending_udp(&self, channel_id: u64) {
        let Ok(mut bindings) = self.bindings.lock() else {
            return;
        };
        let Some(pending) = bindings.pending_udp.remove(&channel_id) else {
            return;
        };
        bindings
            .store
            .revoke(pending.channel_kind, pending.binding_token.as_slice());
    }

    fn redeem_if_present(
        &self,
        request: &DataChannelBind,
    ) -> Option<Result<(ChannelBinding, oneshot::Sender<ServerDataStream>), RegistryError>> {
        let channel_kind = if request.kind == DataChannelKind::TCP {
            ChannelKind::Tcp {
                tunnel_id: request.tunnel_id,
                connection_id: request.target_id,
            }
        } else {
            ChannelKind::Udp {
                tunnel_id: request.tunnel_id,
                channel_id: request.target_id,
            }
        };
        let mut bindings = match self.bindings.lock() {
            Ok(bindings) => bindings,
            Err(_) => return Some(Err(RegistryError::Internal)),
        };
        if !bindings.store.recognizes(request.binding_token.as_slice()) {
            return None;
        }
        let binding = match bindings.store.redeem(
            request.client_name.as_str(),
            request.session_id.as_slice(),
            channel_kind,
            request.binding_token.as_slice(),
        ) {
            Ok(binding) => binding,
            Err(error) => return Some(Err(error.into())),
        };
        let destination = if request.kind == DataChannelKind::TCP {
            let Some(pending) = bindings.pending_tcp.remove(&request.target_id) else {
                return Some(Err(RegistryError::Binding(BindingError::Rejected)));
            };
            if pending.channel_kind != channel_kind {
                return Some(Err(RegistryError::Binding(BindingError::Rejected)));
            }
            pending.destination
        } else {
            let Some(pending) = bindings.pending_udp.remove(&request.target_id) else {
                return Some(Err(RegistryError::Binding(BindingError::Rejected)));
            };
            if pending.channel_kind != channel_kind {
                return Some(Err(RegistryError::Binding(BindingError::Rejected)));
            }
            pending.destination
        };
        Some(Ok((binding, destination)))
    }

    fn issue(
        &self,
        channel_kind: ChannelKind,
    ) -> Result<BoundedBytes<MAX_BINDING_TOKEN_BYTES>, RegistryError> {
        self.bindings
            .lock()
            .map_err(|_| RegistryError::Internal)?
            .store
            .issue(channel_kind)
            .map_err(RegistryError::Binding)
    }

    fn redeem(
        &self,
        presented_client: &str,
        presented_session_id: &[u8],
        channel_kind: ChannelKind,
        token: &[u8],
    ) -> Result<ChannelBinding, RegistryError> {
        self.bindings
            .lock()
            .map_err(|_| RegistryError::Internal)?
            .store
            .redeem(presented_client, presented_session_id, channel_kind, token)
            .map_err(RegistryError::Binding)
    }

    fn cancel(&self) {
        self.cancellation.cancel();
        if let Ok(mut bindings) = self.bindings.lock() {
            let pending = std::mem::take(&mut bindings.pending_tcp);
            for pending in pending.into_values() {
                bindings
                    .store
                    .revoke(pending.channel_kind, pending.binding_token.as_slice());
            }
            let pending = std::mem::take(&mut bindings.pending_udp);
            for pending in pending.into_values() {
                bindings
                    .store
                    .revoke(pending.channel_kind, pending.binding_token.as_slice());
            }
        }
    }
}

pub struct ControlSessionGuard {
    registry: ClientRegistry,
    identity: AuthenticatedClient,
    runtime: Arc<SessionRuntime>,
    listeners: Vec<ListenerLease>,
    tunnel_ids: HashMap<u32, TunnelProtocol>,
    tunnel_names: HashSet<String>,
    data_channels: Vec<AuthenticatedDataChannel>,
    released: bool,
}

impl std::fmt::Debug for ControlSessionGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlSessionGuard")
            .field("client", &self.identity.name())
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

impl ControlSessionGuard {
    pub fn identity(&self) -> &AuthenticatedClient {
        &self.identity
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    pub async fn register_tunnels(&mut self, request: RegisterTunnels) -> TunnelResults {
        let mut results = Vec::with_capacity(request.tunnels.as_slice().len());
        for tunnel in request.tunnels.into_vec() {
            let accepted = if self.listeners.len() >= self.registry.max_tunnels_per_client
                || tunnel.remote_port == 0
                || tunnel.name.as_str().trim().is_empty()
                || self.tunnel_ids.contains_key(&tunnel.tunnel_id)
                || self.tunnel_names.contains(tunnel.name.as_str())
            {
                false
            } else {
                self.bind_listener(
                    tunnel.tunnel_id,
                    tunnel.name.as_str(),
                    tunnel.protocol,
                    tunnel.remote_port,
                )
                .await
                .is_ok_and(|lease| {
                    self.tunnel_ids.insert(tunnel.tunnel_id, tunnel.protocol);
                    self.tunnel_names.insert(tunnel.name.as_str().to_owned());
                    self.listeners.push(lease);
                    true
                })
            };
            results.push(TunnelResult {
                tunnel_id: tunnel.tunnel_id,
                accepted,
                error: (!accepted).then_some(ProtocolErrorCode::TUNNEL_REJECTED),
            });
        }
        TunnelResults {
            results: BoundedVec::<TunnelResult, MAX_TUNNELS>::try_from(results)
                .expect("wire request already enforces the tunnel count bound"),
        }
    }

    pub fn reject_tcp(&self, connection_id: u64) {
        self.runtime.cancel_pending(connection_id);
    }

    pub fn issue_data_channel_binding(
        &mut self,
        channel_kind: ChannelKind,
    ) -> Result<BoundedBytes<MAX_BINDING_TOKEN_BYTES>, RegistryError> {
        let tunnel_id = match channel_kind {
            ChannelKind::Tcp { tunnel_id, .. } | ChannelKind::Udp { tunnel_id, .. } => tunnel_id,
        };
        let required = match channel_kind {
            ChannelKind::Tcp { .. } => TunnelProtocol::TCP,
            ChannelKind::Udp { .. } => TunnelProtocol::UDP,
        };
        if self.tunnel_ids.get(&tunnel_id) != Some(&required) {
            return Err(RegistryError::UnknownTunnel);
        }
        self.runtime.issue(channel_kind)
    }

    /// Redeems a one-time binding only while consuming an established TLS data stream.
    pub fn authenticate_data_channel(
        &mut self,
        stream: ServerDataStream,
        presented_client: &str,
        presented_session_id: &[u8],
        channel_kind: ChannelKind,
        token: &[u8],
    ) -> Result<&AuthenticatedDataChannel, RegistryError> {
        let binding =
            self.runtime
                .redeem(presented_client, presented_session_id, channel_kind, token)?;
        self.data_channels.push(AuthenticatedDataChannel {
            stream: Some(stream),
            binding,
            destination: None,
            cancellation: self.runtime.cancellation(),
        });
        Ok(self
            .data_channels
            .last()
            .expect("a data channel was just inserted"))
    }

    pub async fn shutdown(&mut self) {
        if self.released {
            return;
        }
        self.runtime.cancel();
        for listener in &mut self.listeners {
            listener.shutdown().await;
        }
        self.listeners.clear();
        self.data_channels.clear();
        self.registry.release(&self.identity);
        self.released = true;
    }

    async fn bind_listener(
        &self,
        tunnel_id: u32,
        tunnel_name: &str,
        protocol: TunnelProtocol,
        port: u16,
    ) -> Result<ListenerLease, std::io::Error> {
        let address = SocketAddr::new(self.registry.listener_ip, port);
        if protocol == TunnelProtocol::TCP {
            let listener = TcpListener::bind(address).await?;
            Ok(ListenerLease::Tcp(TcpListenerTask::spawn(
                listener,
                tunnel_id,
                tunnel_name.to_owned(),
                self.runtime.clone(),
                self.registry.max_tcp_connections_per_tunnel,
            )))
        } else {
            let socket = UdpSocket::bind(address).await?;
            Ok(ListenerLease::Udp(UdpListenerTask::spawn(
                socket,
                tunnel_id,
                tunnel_name.to_owned(),
                self.runtime.clone(),
                self.registry.max_udp_sessions_per_tunnel,
                self.registry.max_udp_payload_bytes,
                self.registry.udp_runtime_limits,
            )))
        }
    }
}

impl Drop for ControlSessionGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.runtime.cancel();
        self.data_channels.clear();
        self.listeners.clear();
        self.registry.release(&self.identity);
        self.released = true;
    }
}

enum ListenerLease {
    Tcp(TcpListenerTask),
    Udp(UdpListenerTask),
}

impl ListenerLease {
    async fn shutdown(&mut self) {
        match self {
            Self::Tcp(listener) => listener.shutdown().await,
            Self::Udp(listener) => listener.shutdown().await,
        }
    }
}

impl std::fmt::Debug for ListenerLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(listener) => formatter.debug_tuple("Tcp").field(listener).finish(),
            Self::Udp(listener) => formatter.debug_tuple("Udp").field(listener).finish(),
        }
    }
}

pub struct AuthenticatedDataChannel {
    stream: Option<ServerDataStream>,
    binding: ChannelBinding,
    destination: Option<oneshot::Sender<ServerDataStream>>,
    cancellation: CancellationToken,
}

impl AuthenticatedDataChannel {
    pub fn binding(&self) -> &ChannelBinding {
        &self.binding
    }

    pub(crate) fn stream_mut(&mut self) -> Result<&mut ServerDataStream, RegistryError> {
        self.stream.as_mut().ok_or(RegistryError::Internal)
    }

    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) fn deliver(mut self) -> Result<(), RegistryError> {
        let stream = self.stream.take().ok_or(RegistryError::Internal)?;
        self.destination
            .take()
            .ok_or(RegistryError::Internal)?
            .send(stream)
            .map_err(|_| RegistryError::Binding(BindingError::Rejected))
    }
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid registry configuration")]
    InvalidConfiguration,
    #[error("client is already connected")]
    AlreadyConnected,
    #[error("client registry capacity reached")]
    CapacityReached,
    #[error("unknown tunnel")]
    UnknownTunnel,
    #[error("channel binding failed: {0}")]
    Binding(#[from] BindingError),
    #[error("secure connection ID entropy is unavailable")]
    EntropyUnavailable,
    #[error("internal registry failure")]
    Internal,
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, net::IpAddr, path::PathBuf, time::Duration};

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustgo_protocol::{
        BoundedBytes, BoundedString, DataChannelBind, DataChannelKind, MAX_BINDING_TOKEN_BYTES,
        MAX_CLIENT_NAME_BYTES, MAX_SESSION_ID_BYTES, TunnelProtocol,
    };
    use rustgo_transport::{ChannelKind, TlsClient, TlsServer};
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;

    use super::ClientRegistry;
    use crate::AuthenticatedClient;

    const SERVER_NAME: &str = "data.example.test";

    fn bind_request(
        client: &str,
        session_id: &[u8],
        kind: DataChannelKind,
        tunnel_id: u32,
        target_id: u64,
        token: &[u8],
    ) -> DataChannelBind {
        DataChannelBind {
            client_name: BoundedString::<MAX_CLIENT_NAME_BYTES>::try_from(client).unwrap(),
            session_id: BoundedBytes::<MAX_SESSION_ID_BYTES>::try_from(session_id).unwrap(),
            kind,
            tunnel_id,
            target_id,
            binding_token: BoundedBytes::<MAX_BINDING_TOKEN_BYTES>::try_from(token).unwrap(),
        }
    }

    struct TestPki {
        _directory: TempDir,
        ca_file: PathBuf,
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    }

    impl TestPki {
        fn generate() -> Result<Self, Box<dyn Error>> {
            let directory = tempfile::tempdir()?;
            let ca_file = directory.path().join("ca.pem");
            let certificate_file = directory.path().join("server.pem");
            let private_key_file = directory.path().join("server.key");

            let mut ca_parameters = CertificateParams::new(Vec::<String>::new())?;
            ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_parameters
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Rustgo data test CA");
            ca_parameters.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
            ];
            let ca_key = KeyPair::generate()?;
            let ca_certificate = ca_parameters.self_signed(&ca_key)?;
            let issuer = Issuer::new(ca_parameters, ca_key);

            let mut server_parameters = CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
            server_parameters
                .distinguished_name
                .push(rcgen::DnType::CommonName, SERVER_NAME);
            server_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server_key = KeyPair::generate()?;
            let server_certificate = server_parameters.signed_by(&server_key, &issuer)?;

            fs::write(&ca_file, ca_certificate.pem())?;
            fs::write(&certificate_file, server_certificate.pem())?;
            fs::write(&private_key_file, server_key.serialize_pem())?;
            Ok(Self {
                _directory: directory,
                ca_file,
                certificate_file,
                private_key_file,
            })
        }
    }

    #[tokio::test]
    async fn guard_owns_redeemed_tls_data_stream_until_it_drops() -> Result<(), Box<dyn Error>> {
        let pki = TestPki::generate()?;
        let session_id = vec![3; 32];
        let identity = AuthenticatedClient::verified(
            "home-pc".to_owned(),
            "sha256:test".to_owned(),
            session_id.clone(),
        );
        let registry = ClientRegistry::new(
            1,
            1,
            IpAddr::from([127, 0, 0, 1]),
            1,
            Duration::from_secs(30),
        )?;
        let mut guard = registry.claim(identity)?;
        guard.tunnel_ids.insert(1, TunnelProtocol::TCP);
        let channel_kind = ChannelKind::Tcp {
            tunnel_id: 1,
            connection_id: 9,
        };
        let token = guard.issue_data_channel_binding(channel_kind)?;

        let tls_server =
            TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
        let address = tls_server.local_addr()?;
        let server_task = tokio::spawn(async move {
            let (socket, _) = tls_server.accept_tcp().await?;
            tls_server.handshake(socket).await
        });
        let tls_client = TlsClient::from_ca_file(&pki.ca_file, SERVER_NAME)?;
        let mut client_stream = tls_client.connect(address).await?;
        let server_stream = server_task.await??;

        let data_channel = guard.authenticate_data_channel(
            server_stream,
            "home-pc",
            &session_id,
            channel_kind,
            token.as_slice(),
        )?;
        assert_eq!(data_channel.binding().client_id, "home-pc");
        assert_eq!(data_channel.binding().session_id, session_id);
        assert_eq!(data_channel.binding().channel_kind, channel_kind);
        assert_eq!(registry.active_count(), 1);

        drop(guard);
        assert_eq!(registry.active_count(), 0);
        let mut byte = [0_u8; 1];
        let read =
            tokio::time::timeout(Duration::from_secs(1), client_stream.read(&mut byte)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))));
        Ok(())
    }

    #[tokio::test]
    async fn dispatcher_consumes_known_tokens_on_wrong_binding_fields_and_reuse()
    -> Result<(), Box<dyn Error>> {
        let pki = TestPki::generate()?;
        let session_id = vec![3; 32];
        let identity = AuthenticatedClient::verified(
            "home-pc".to_owned(),
            "sha256:test".to_owned(),
            session_id.clone(),
        );
        let registry = ClientRegistry::new(
            1,
            1,
            IpAddr::from([127, 0, 0, 1]),
            16,
            Duration::from_secs(30),
        )?;
        let mut guard = registry.claim(identity)?;
        guard.tunnel_ids.insert(1, TunnelProtocol::TCP);
        let tls_server =
            TlsServer::bind("127.0.0.1:0", &pki.certificate_file, &pki.private_key_file).await?;
        let address = tls_server.local_addr()?;
        let tls_client = TlsClient::from_ca_file(&pki.ca_file, SERVER_NAME)?;

        for case in 0..4 {
            let pending = guard.runtime.prepare_tcp(1)?;
            let correct = bind_request(
                "home-pc",
                &session_id,
                DataChannelKind::TCP,
                1,
                pending.connection_id,
                pending.binding_token.as_slice(),
            );
            let invalid = match case {
                0 => bind_request(
                    "other-client",
                    &session_id,
                    DataChannelKind::TCP,
                    1,
                    pending.connection_id,
                    pending.binding_token.as_slice(),
                ),
                1 => bind_request(
                    "home-pc",
                    &[4; 32],
                    DataChannelKind::TCP,
                    1,
                    pending.connection_id,
                    pending.binding_token.as_slice(),
                ),
                2 => bind_request(
                    "home-pc",
                    &session_id,
                    DataChannelKind::UDP,
                    1,
                    pending.connection_id,
                    pending.binding_token.as_slice(),
                ),
                _ => bind_request(
                    "home-pc",
                    &session_id,
                    DataChannelKind::TCP,
                    1,
                    pending.connection_id.wrapping_add(1),
                    pending.binding_token.as_slice(),
                ),
            };
            let (invalid_server, _invalid_client) =
                tls_pair(&tls_server, &tls_client, address).await?;
            assert!(
                registry
                    .authenticate_data_channel(invalid_server, &invalid)
                    .is_err()
            );
            let (retry_server, _retry_client) = tls_pair(&tls_server, &tls_client, address).await?;
            assert!(
                registry
                    .authenticate_data_channel(retry_server, &correct)
                    .is_err()
            );
            guard.runtime.cancel_pending(pending.connection_id);
        }

        let pending = guard.runtime.prepare_tcp(1)?;
        let correct = bind_request(
            "home-pc",
            &session_id,
            DataChannelKind::TCP,
            1,
            pending.connection_id,
            pending.binding_token.as_slice(),
        );
        let (first_server, _first_client) = tls_pair(&tls_server, &tls_client, address).await?;
        let authenticated = registry.authenticate_data_channel(first_server, &correct)?;
        drop(authenticated);
        let (reused_server, _reused_client) = tls_pair(&tls_server, &tls_client, address).await?;
        assert!(
            registry
                .authenticate_data_channel(reused_server, &correct)
                .is_err()
        );

        let unknown = bind_request(
            "home-pc",
            &session_id,
            DataChannelKind::TCP,
            1,
            99,
            &[0x55; MAX_BINDING_TOKEN_BYTES],
        );
        let (unknown_server, _unknown_client) = tls_pair(&tls_server, &tls_client, address).await?;
        assert!(
            registry
                .authenticate_data_channel(unknown_server, &unknown)
                .is_err()
        );
        Ok(())
    }

    async fn tls_pair(
        server: &TlsServer,
        client: &TlsClient,
        address: std::net::SocketAddr,
    ) -> Result<
        (
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        ),
        Box<dyn Error>,
    > {
        let server_side = async {
            let (socket, _) = server.accept_tcp().await?;
            server.handshake(socket).await
        };
        let (server_stream, client_stream) =
            tokio::try_join!(server_side, client.connect(address))?;
        Ok((server_stream, client_stream))
    }
}

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use rustgo_protocol::{
    BoundedBytes, BoundedVec, MAX_BINDING_TOKEN_BYTES, MAX_TUNNELS, ProtocolErrorCode,
    RegisterTunnels, TunnelProtocol, TunnelResult, TunnelResults,
};
use rustgo_transport::{BindingError, ChannelBinding, ChannelBindingStore, ChannelKind};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};

use crate::AuthenticatedClient;

#[derive(Clone)]
pub struct ClientRegistry {
    inner: Arc<Mutex<RegistryState>>,
    max_clients: usize,
    max_tunnels_per_client: usize,
    listener_ip: IpAddr,
    binding_capacity: usize,
    binding_ttl: Duration,
}

#[derive(Default)]
struct RegistryState {
    active: HashMap<String, ActiveSession>,
}

struct ActiveSession {
    name: String,
    session_id: Vec<u8>,
}

impl std::fmt::Debug for ClientRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientRegistry")
            .field("max_clients", &self.max_clients)
            .field("max_tunnels_per_client", &self.max_tunnels_per_client)
            .field("listener_ip", &self.listener_ip)
            .finish_non_exhaustive()
    }
}

impl ClientRegistry {
    pub(crate) fn new(
        max_clients: usize,
        max_tunnels_per_client: usize,
        listener_ip: IpAddr,
        binding_capacity: usize,
        binding_ttl: Duration,
    ) -> Result<Self, RegistryError> {
        if max_clients == 0
            || max_tunnels_per_client == 0
            || binding_capacity == 0
            || binding_ttl.is_zero()
        {
            return Err(RegistryError::InvalidConfiguration);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(RegistryState::default())),
            max_clients,
            max_tunnels_per_client,
            listener_ip,
            binding_capacity,
            binding_ttl,
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

    pub(crate) fn claim(
        &self,
        identity: AuthenticatedClient,
    ) -> Result<ControlSessionGuard, RegistryError> {
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
                },
            );
        }

        let binding_store = match ChannelBindingStore::new(
            identity.name(),
            identity.session_id(),
            self.binding_capacity,
            self.binding_ttl,
        ) {
            Ok(store) => store,
            Err(error) => {
                self.release(&identity);
                return Err(RegistryError::Binding(error));
            }
        };
        Ok(ControlSessionGuard {
            registry: self.clone(),
            identity,
            listeners: Vec::new(),
            tunnel_ids: HashMap::new(),
            tunnel_names: HashSet::new(),
            binding_store: Some(binding_store),
            data_channels: Vec::new(),
        })
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

pub struct ControlSessionGuard {
    registry: ClientRegistry,
    identity: AuthenticatedClient,
    listeners: Vec<ListenerLease>,
    tunnel_ids: HashMap<u32, TunnelProtocol>,
    tunnel_names: HashSet<String>,
    binding_store: Option<ChannelBindingStore>,
    data_channels: Vec<AuthenticatedDataChannel>,
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
                self.bind_listener(tunnel.protocol, tunnel.remote_port)
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
        self.binding_store
            .as_mut()
            .ok_or(RegistryError::Internal)?
            .issue(channel_kind)
            .map_err(RegistryError::Binding)
    }

    /// Redeems a one-time binding only while consuming an established TLS data stream.
    ///
    /// There is intentionally no Rustgos API that redeems a token from a plaintext socket or
    /// from token bytes alone. Payload relay is supplied by Tasks 8 and 9.
    pub fn authenticate_data_channel(
        &mut self,
        stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        presented_client: &str,
        presented_session_id: &[u8],
        channel_kind: ChannelKind,
        token: &[u8],
    ) -> Result<&AuthenticatedDataChannel, RegistryError> {
        let binding = self
            .binding_store
            .as_mut()
            .ok_or(RegistryError::Internal)?
            .redeem(presented_client, presented_session_id, channel_kind, token)
            .map_err(RegistryError::Binding)?;
        self.data_channels.push(AuthenticatedDataChannel {
            _stream: stream,
            binding,
        });
        Ok(self
            .data_channels
            .last()
            .expect("a data channel was just inserted"))
    }

    async fn bind_listener(
        &self,
        protocol: TunnelProtocol,
        port: u16,
    ) -> Result<ListenerLease, std::io::Error> {
        let address = SocketAddr::new(self.registry.listener_ip, port);
        if protocol == TunnelProtocol::TCP {
            TcpListener::bind(address).await.map(ListenerLease::Tcp)
        } else {
            UdpSocket::bind(address).await.map(ListenerLease::Udp)
        }
    }
}

impl Drop for ControlSessionGuard {
    fn drop(&mut self) {
        self.data_channels.clear();
        self.listeners.clear();
        self.binding_store.take();
        self.registry.release(&self.identity);
    }
}

enum ListenerLease {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

impl std::fmt::Debug for ListenerLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(listener) => formatter
                .debug_tuple("Tcp")
                .field(&listener.local_addr().ok())
                .finish(),
            Self::Udp(socket) => formatter
                .debug_tuple("Udp")
                .field(&socket.local_addr().ok())
                .finish(),
        }
    }
}

pub struct AuthenticatedDataChannel {
    _stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    binding: ChannelBinding,
}

impl AuthenticatedDataChannel {
    pub fn binding(&self) -> &ChannelBinding {
        &self.binding
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
    use rustgo_protocol::TunnelProtocol;
    use rustgo_transport::{ChannelKind, TlsClient, TlsServer};
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;

    use super::ClientRegistry;
    use crate::AuthenticatedClient;

    const SERVER_NAME: &str = "data.example.test";

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
}

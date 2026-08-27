use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand::{TryRngCore, rngs::OsRng};
use rustgo_protocol::{
    BoundedBytes, MAX_BINDING_TOKEN_BYTES, MAX_CLIENT_NAME_BYTES, MAX_SESSION_ID_BYTES,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const BINDING_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_GENERATION_ATTEMPTS: usize = 16;

/// The authenticated purpose of one TLS data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    Tcp { tunnel_id: u32, connection_id: u64 },
    Udp { tunnel_id: u32, channel_id: u64 },
}

/// Identity recovered after consuming a valid one-time binding token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBinding {
    pub client_id: String,
    pub session_id: Vec<u8>,
    pub channel_kind: ChannelKind,
}

#[derive(Debug)]
struct PendingBinding {
    channel_kind: ChannelKind,
    expires_at: tokio::time::Instant,
}

/// Bounded one-time token state owned by one authenticated control session.
///
/// Call [`Self::redeem`] only after a data socket has successfully completed
/// [`TlsServer::handshake`]. Removing a known token before validating the
/// presentation makes every known token single-use, including failed attempts.
pub struct ChannelBindingStore {
    client_id: String,
    session_id: Vec<u8>,
    capacity: usize,
    time_to_live: Duration,
    pending: HashMap<[u8; BINDING_TOKEN_BYTES], PendingBinding>,
}

impl std::fmt::Debug for ChannelBindingStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChannelBindingStore")
            .field("capacity", &self.capacity)
            .field("time_to_live", &self.time_to_live)
            .field("pending_count", &self.pending.len())
            .finish()
    }
}

impl ChannelBindingStore {
    pub fn new(
        client_id: &str,
        session_id: &[u8],
        capacity: usize,
        time_to_live: Duration,
    ) -> Result<Self, BindingError> {
        if client_id.is_empty()
            || client_id.len() > MAX_CLIENT_NAME_BYTES
            || session_id.is_empty()
            || session_id.len() > MAX_SESSION_ID_BYTES
            || capacity == 0
            || time_to_live.is_zero()
            || tokio::time::Instant::now()
                .checked_add(time_to_live)
                .is_none()
        {
            return Err(BindingError::InvalidConfiguration);
        }
        Ok(Self {
            client_id: client_id.to_owned(),
            session_id: session_id.to_vec(),
            capacity,
            time_to_live,
            pending: HashMap::new(),
        })
    }

    /// Issues a 256-bit token from the operating-system CSPRNG.
    pub fn issue(
        &mut self,
        channel_kind: ChannelKind,
    ) -> Result<BoundedBytes<MAX_BINDING_TOKEN_BYTES>, BindingError> {
        let now = tokio::time::Instant::now();
        self.pending.retain(|_, binding| binding.expires_at > now);
        if self.pending.len() >= self.capacity {
            return Err(BindingError::CapacityReached);
        }
        let expires_at = now
            .checked_add(self.time_to_live)
            .ok_or(BindingError::InvalidConfiguration)?;

        for _ in 0..MAX_TOKEN_GENERATION_ATTEMPTS {
            let mut token = [0_u8; BINDING_TOKEN_BYTES];
            OsRng
                .try_fill_bytes(&mut token)
                .map_err(|_| BindingError::EntropyUnavailable)?;
            if let std::collections::hash_map::Entry::Vacant(entry) = self.pending.entry(token) {
                entry.insert(PendingBinding {
                    channel_kind,
                    expires_at,
                });
                return BoundedBytes::try_from(token.as_slice())
                    .map_err(|_| BindingError::InvalidConfiguration);
            }
        }
        Err(BindingError::EntropyUnavailable)
    }

    /// Consumes a token and authenticates its complete control-session binding.
    pub fn redeem(
        &mut self,
        client_id: &str,
        session_id: &[u8],
        channel_kind: ChannelKind,
        token: &[u8],
    ) -> Result<ChannelBinding, BindingError> {
        let token: [u8; BINDING_TOKEN_BYTES] =
            token.try_into().map_err(|_| BindingError::Rejected)?;
        let pending = self.pending.remove(&token).ok_or(BindingError::Rejected)?;
        if pending.expires_at <= tokio::time::Instant::now()
            || client_id != self.client_id
            || session_id != self.session_id
            || channel_kind != pending.channel_kind
        {
            return Err(BindingError::Rejected);
        }
        Ok(ChannelBinding {
            client_id: self.client_id.clone(),
            session_id: self.session_id.clone(),
            channel_kind,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BindingError {
    #[error("invalid channel-binding configuration")]
    InvalidConfiguration,
    #[error("channel-binding capacity reached")]
    CapacityReached,
    #[error("secure token entropy is unavailable")]
    EntropyUnavailable,
    #[error("channel binding rejected")]
    Rejected,
}

/// A TLS 1.3-only server listener.
///
/// [`Self::accept_tcp`] returns the accepted TCP socket without starting TLS.
/// The server runtime can therefore acquire a handshake-concurrency permit and
/// wrap [`Self::handshake`] in its configured timeout before polling it.
pub struct TlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for TlsServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("TlsServer").finish_non_exhaustive()
    }
}

impl TlsServer {
    /// Loads and validates all TLS material before binding the socket.
    pub async fn bind<A: ToSocketAddrs>(
        address: A,
        certificate_file: impl AsRef<Path>,
        private_key_file: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        let certificates = load_certificates(certificate_file.as_ref())?;
        let private_key = load_private_key(private_key_file.as_ref())?;
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|_| TlsError::InvalidTlsIdentity)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(address)
            .await
            .map_err(|source| TlsError::Bind { source })?;
        Ok(Self { listener, acceptor })
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts TCP only. No TLS handshake work is performed by this method.
    pub async fn accept_tcp(&self) -> Result<(TcpStream, std::net::SocketAddr), TlsError> {
        self.listener
            .accept()
            .await
            .map_err(|source| TlsError::Accept { source })
    }

    /// Performs only the TLS handshake on an already accepted TCP socket.
    pub async fn handshake(
        &self,
        socket: TcpStream,
    ) -> Result<ServerTlsStream<TcpStream>, TlsError> {
        self.acceptor
            .accept(socket)
            .await
            .map_err(|_| TlsError::HandshakeFailed)
    }
}

/// A TLS 1.3-only client that verifies an explicit CA file and server name.
#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("TlsClient").finish_non_exhaustive()
    }
}

impl TlsClient {
    pub fn from_ca_file(
        certificate_authority_file: impl AsRef<Path>,
        server_name: &str,
    ) -> Result<Self, TlsError> {
        let certificates = load_certificates(certificate_authority_file.as_ref())?;
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| TlsError::InvalidCertificateFile {
                    path: certificate_authority_file.as_ref().to_owned(),
                })?;
        }
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| TlsError::InvalidServerName)?;

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    pub async fn connect<A: ToSocketAddrs>(
        &self,
        address: A,
    ) -> Result<ClientTlsStream<TcpStream>, TlsError> {
        let socket = TcpStream::connect(address)
            .await
            .map_err(|source| TlsError::Connect { source })?;
        self.handshake(socket).await
    }

    pub async fn handshake(
        &self,
        socket: TcpStream,
    ) -> Result<ClientTlsStream<TcpStream>, TlsError> {
        self.connector
            .connect(self.server_name.clone(), socket)
            .await
            .map_err(|_| TlsError::HandshakeFailed)
    }
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to read TLS certificate file {path}: {source}")]
    ReadCertificateFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid TLS certificate file {path}")]
    InvalidCertificateFile { path: PathBuf },
    #[error("failed to read TLS private key file {path}: {source}")]
    ReadPrivateKeyFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid TLS private key file {path}")]
    InvalidPrivateKeyFile { path: PathBuf },
    #[error("TLS certificate and private key are not a valid identity")]
    InvalidTlsIdentity,
    #[error("invalid TLS server name")]
    InvalidServerName,
    #[error("failed to bind TLS listener: {source}")]
    Bind {
        #[source]
        source: io::Error,
    },
    #[error("failed to accept TCP connection: {source}")]
    Accept {
        #[source]
        source: io::Error,
    },
    #[error("failed to connect TCP socket: {source}")]
    Connect {
        #[source]
        source: io::Error,
    },
    #[error("TLS handshake failed")]
    HandshakeFailed,
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path).map_err(|source| TlsError::ReadCertificateFile {
        path: path.to_owned(),
        source,
    })?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::InvalidCertificateFile {
            path: path.to_owned(),
        })?;
    if certificates.is_empty() {
        return Err(TlsError::InvalidCertificateFile {
            path: path.to_owned(),
        });
    }
    for certificate in &certificates {
        match x509_parser::parse_x509_certificate(certificate.as_ref()) {
            Ok(([], _)) => {}
            _ => {
                return Err(TlsError::InvalidCertificateFile {
                    path: path.to_owned(),
                });
            }
        }
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path).map_err(|source| TlsError::ReadPrivateKeyFile {
        path: path.to_owned(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|_| TlsError::InvalidPrivateKeyFile {
            path: path.to_owned(),
        })?
        .ok_or_else(|| TlsError::InvalidPrivateKeyFile {
            path: path.to_owned(),
        })?;
    if rustls_pemfile::private_key(&mut reader)
        .map_err(|_| TlsError::InvalidPrivateKeyFile {
            path: path.to_owned(),
        })?
        .is_some()
    {
        return Err(TlsError::InvalidPrivateKeyFile {
            path: path.to_owned(),
        });
    }
    Ok(key)
}

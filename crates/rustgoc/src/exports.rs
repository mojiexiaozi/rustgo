use std::{collections::HashMap, net::SocketAddr};

use rustgo_config::{ExportConfig, TunnelProtocol};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerOpenRequest {
    request_id: u64,
    export: String,
    protocol: TunnelProtocol,
}

impl PeerOpenRequest {
    pub fn new(request_id: u64, export: impl Into<String>, protocol: TunnelProtocol) -> Self {
        Self {
            request_id,
            export: export.into(),
            protocol,
        }
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub fn export(&self) -> &str {
        &self.export
    }
    pub const fn protocol(&self) -> TunnelProtocol {
        self.protocol
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerOpenResult {
    Accepted { request_id: u64 },
    Rejected { request_id: u64, error: ExportError },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExportError {
    #[error("duplicate export name")]
    DuplicateExport,
    #[error("unknown export")]
    UnknownExport,
    #[error("authenticated peer is not allowed")]
    PeerDenied,
    #[error("export protocol does not match")]
    ProtocolMismatch,
    #[error("invalid local target address")]
    InvalidLocalTarget,
    #[error("local target is unavailable")]
    LocalTargetUnavailable,
    #[error("operation cancelled")]
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct AuthorizedExport {
    config: ExportConfig,
    local_addr: SocketAddr,
}

impl AuthorizedExport {
    pub fn config(&self) -> &ExportConfig {
        &self.config
    }
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[derive(Debug, Clone)]
pub struct ExportRegistry {
    exports: HashMap<String, AuthorizedExport>,
}

impl ExportRegistry {
    pub fn new(exports: Vec<ExportConfig>) -> Result<Self, ExportError> {
        let mut by_name = HashMap::with_capacity(exports.len());
        for config in exports {
            let local_addr = config
                .local_addr
                .parse()
                .map_err(|_| ExportError::InvalidLocalTarget)?;
            let name = config.name.clone();
            if by_name
                .insert(name, AuthorizedExport { config, local_addr })
                .is_some()
            {
                return Err(ExportError::DuplicateExport);
            }
        }
        Ok(Self { exports: by_name })
    }

    pub fn authorize(
        &self,
        authenticated_peer: &str,
        export: &str,
        protocol: TunnelProtocol,
    ) -> Result<&AuthorizedExport, ExportError> {
        let authorized = self.exports.get(export).ok_or(ExportError::UnknownExport)?;
        if authorized.config.protocol != protocol {
            return Err(ExportError::ProtocolMismatch);
        }
        if !authorized.config.allows_peer(authenticated_peer) {
            return Err(ExportError::PeerDenied);
        }
        Ok(authorized)
    }

    pub async fn open_tcp(
        &self,
        authenticated_peer: &str,
        request: &PeerOpenRequest,
        cancellation: CancellationToken,
    ) -> Result<TcpStream, ExportError> {
        let target = self.authorize(authenticated_peer, request.export(), request.protocol())?;
        if cancellation.is_cancelled() {
            return Err(ExportError::Cancelled);
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ExportError::Cancelled),
            result = TcpStream::connect(target.local_addr) => result.map_err(|_| ExportError::LocalTargetUnavailable),
        }
    }

    pub async fn open_udp(
        &self,
        authenticated_peer: &str,
        request: &PeerOpenRequest,
        cancellation: CancellationToken,
    ) -> Result<UdpSocket, ExportError> {
        let target = self.authorize(authenticated_peer, request.export(), request.protocol())?;
        if cancellation.is_cancelled() {
            return Err(ExportError::Cancelled);
        }
        let bind = if target.local_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|_| ExportError::LocalTargetUnavailable)?;
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ExportError::Cancelled),
            result = socket.connect(target.local_addr) => result.map_err(|_| ExportError::LocalTargetUnavailable),
        }?;
        Ok(socket)
    }
}

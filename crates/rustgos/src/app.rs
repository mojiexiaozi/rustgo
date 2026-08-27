use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rustgo_config::ServerConfig;
use rustgo_transport::{TlsError, TlsServer};
use thiserror::Error;
use tokio::{sync::Semaphore, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{Authenticator, FailedAuthLimiter},
    control,
    registry::{ClientRegistry, RegistryError},
};

const MAX_RUNTIME_COUNT: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct ServerRuntimeLimits {
    pub handshake_timeout: Duration,
    pub max_unauthenticated_connections: usize,
    pub max_failed_auth_attempts_per_peer: usize,
    pub failed_auth_window: Duration,
    pub max_tracked_auth_peers: usize,
    pub max_pending_data_channel_tokens_per_client: usize,
    pub binding_token_ttl: Duration,
}

impl Default for ServerRuntimeLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            max_unauthenticated_connections: 64,
            max_failed_auth_attempts_per_peer: 8,
            failed_auth_window: Duration::from_secs(60),
            max_tracked_auth_peers: 1024,
            max_pending_data_channel_tokens_per_client: 4096,
            binding_token_ttl: Duration::from_secs(30),
        }
    }
}

impl ServerRuntimeLimits {
    fn validate(&self) -> Result<(), ServerError> {
        if self.handshake_timeout.is_zero()
            || self.max_unauthenticated_connections == 0
            || self.max_failed_auth_attempts_per_peer == 0
            || self.failed_auth_window.is_zero()
            || self.max_tracked_auth_peers == 0
            || self.max_pending_data_channel_tokens_per_client == 0
            || self.binding_token_ttl.is_zero()
            || self.max_unauthenticated_connections > MAX_RUNTIME_COUNT
            || self.max_failed_auth_attempts_per_peer > MAX_RUNTIME_COUNT
            || self.max_tracked_auth_peers > MAX_RUNTIME_COUNT
            || self.max_pending_data_channel_tokens_per_client > MAX_RUNTIME_COUNT
            || tokio::time::Instant::now()
                .checked_add(self.handshake_timeout)
                .is_none()
            || tokio::time::Instant::now()
                .checked_add(self.failed_auth_window)
                .is_none()
            || tokio::time::Instant::now()
                .checked_add(self.binding_token_ttl)
                .is_none()
        {
            return Err(ServerError::InvalidRuntimeLimits);
        }
        Ok(())
    }
}

pub struct ServerApp {
    tls_server: Arc<TlsServer>,
    authenticator: Authenticator,
    registry: ClientRegistry,
    unauthenticated: Arc<Semaphore>,
    limiter: FailedAuthLimiter,
    runtime_limits: ServerRuntimeLimits,
    heartbeat_timeout: Duration,
}

impl ServerApp {
    pub async fn bind(config: ServerConfig) -> Result<Self, ServerError> {
        Self::bind_with_runtime_limits(config, ServerRuntimeLimits::default()).await
    }

    pub async fn bind_with_runtime_limits(
        config: ServerConfig,
        runtime_limits: ServerRuntimeLimits,
    ) -> Result<Self, ServerError> {
        runtime_limits.validate()?;
        let heartbeat_timeout = Duration::from_secs(config.server.heartbeat_timeout_secs);
        if tokio::time::Instant::now()
            .checked_add(heartbeat_timeout)
            .is_none()
        {
            return Err(ServerError::InvalidRuntimeLimits);
        }
        let max_clients = usize::try_from(config.limits.max_clients)
            .map_err(|_| ServerError::InvalidRuntimeLimits)?;
        let max_tunnels = usize::try_from(config.limits.max_tunnels_per_client)
            .map_err(|_| ServerError::InvalidRuntimeLimits)?;
        let authenticator =
            Authenticator::new(&config.clients).map_err(|_| ServerError::AuthenticationSetup)?;
        let tls_server = Arc::new(
            TlsServer::bind(
                &config.server.bind_addr,
                &config.server.certificate_file,
                &config.server.private_key_file,
            )
            .await?,
        );
        let listener_ip = tls_server.local_addr()?.ip();
        let per_tunnel_bindings = u64::from(config.limits.max_tcp_connections_per_tunnel)
            .saturating_add(u64::from(config.limits.max_udp_sessions_per_tunnel));
        let configured_binding_capacity = u64::try_from(max_tunnels)
            .unwrap_or(u64::MAX)
            .saturating_mul(per_tunnel_bindings);
        let binding_capacity = usize::try_from(
            configured_binding_capacity.min(
                u64::try_from(runtime_limits.max_pending_data_channel_tokens_per_client)
                    .unwrap_or(u64::MAX),
            ),
        )
        .map_err(|_| ServerError::InvalidRuntimeLimits)?;
        let registry = ClientRegistry::new(
            max_clients,
            max_tunnels,
            listener_ip,
            binding_capacity,
            runtime_limits.binding_token_ttl,
        )?;
        let limiter = FailedAuthLimiter::new(
            runtime_limits.max_failed_auth_attempts_per_peer,
            runtime_limits.failed_auth_window,
            runtime_limits.max_tracked_auth_peers,
        );
        let unauthenticated = Arc::new(Semaphore::new(
            runtime_limits.max_unauthenticated_connections,
        ));
        Ok(Self {
            tls_server,
            authenticator,
            registry,
            unauthenticated,
            limiter,
            heartbeat_timeout,
            runtime_limits,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tls_server.local_addr()
    }

    pub fn registry(&self) -> ClientRegistry {
        self.registry.clone()
    }

    pub async fn run(self) -> Result<(), ServerError> {
        self.run_until(CancellationToken::new()).await
    }

    pub async fn run_until(self, shutdown: CancellationToken) -> Result<(), ServerError> {
        let session_shutdown = CancellationToken::new();
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                accepted = self.tls_server.accept_tcp() => {
                    let (socket, peer) = accepted?;
                    let Ok(permit) = self.unauthenticated.clone().try_acquire_owned() else {
                        continue;
                    };
                    let tls_server = self.tls_server.clone();
                    let authenticator = self.authenticator.clone();
                    let registry = self.registry.clone();
                    let limiter = self.limiter.clone();
                    let handshake_timeout = self.runtime_limits.handshake_timeout;
                    let heartbeat_timeout = self.heartbeat_timeout;
                    let context = control::ControlContext::new(
                        tls_server,
                        authenticator,
                        registry,
                        limiter,
                        handshake_timeout,
                        heartbeat_timeout,
                    );
                    let child_shutdown = session_shutdown.child_token();
                    sessions.spawn(async move {
                        tokio::select! {
                            () = child_shutdown.cancelled() => {}
                            result = control::serve_connection(
                                context,
                                socket,
                                peer,
                                permit,
                            ) => {
                                if let Err(error) = result {
                                    tracing::debug!(peer = %peer, %error, "control session ended");
                                }
                            }
                        }
                    });
                }
            }
            while sessions.try_join_next().is_some() {}
        }
        session_shutdown.cancel();
        while sessions.join_next().await.is_some() {}
        Ok(())
    }
}

impl std::fmt::Debug for ServerApp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerApp")
            .field("local_addr", &self.local_addr().ok())
            .field("runtime_limits", &self.runtime_limits)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("TLS server failed: {0}")]
    Tls(#[from] TlsError),
    #[error("server I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("server authentication setup failed")]
    AuthenticationSetup,
    #[error("server registry setup failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("invalid server runtime limits")]
    InvalidRuntimeLimits,
}

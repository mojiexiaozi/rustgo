use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rustgo_config::ServerConfig;
use rustgo_transport::{TlsError, TlsServer};
use thiserror::Error;
use tokio::{sync::Semaphore, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{Authenticator, FailedAuthLimiter, TlsHandshakeLimiter},
    control,
    registry::{ClientRegistry, RegistryError},
    udp::UdpRuntimeLimits,
};

const MAX_UNAUTHENTICATED_CONNECTIONS: usize = 1024;
const MAX_UNAUTHENTICATED_CONNECTIONS_PER_PEER: usize = 64;
const MAX_FAILED_AUTH_ATTEMPTS_PER_PEER: usize = 64;
const MAX_TRACKED_AUTH_PEERS: usize = 16_384;
const MAX_AUTH_ATTEMPT_RECORDS: usize = 65_536;
const MIN_AUTH_ATTEMPTS_PER_WINDOW: usize = 16;
const MAX_AUTH_ATTEMPTS_PER_WINDOW: usize = 65_536;
const MAX_PENDING_DATA_CHANNEL_TOKENS_PER_CLIENT: usize = 65_536;
const MAX_UDP_QUEUE_CAPACITY: usize = 65_536;
const MAX_UDP_SWEEP_BATCH: usize = 65_536;

#[derive(Debug, Clone)]
pub struct ServerRuntimeLimits {
    pub handshake_timeout: Duration,
    pub max_unauthenticated_connections: usize,
    pub max_unauthenticated_connections_per_peer: usize,
    pub max_failed_auth_attempts_per_peer: usize,
    pub failed_auth_window: Duration,
    pub max_tracked_auth_peers: usize,
    pub max_auth_attempt_records: usize,
    pub max_auth_attempts_per_window: usize,
    pub max_pending_data_channel_tokens_per_client: usize,
    pub binding_token_ttl: Duration,
    pub udp_queue_capacity: usize,
    pub udp_idle_timeout: Duration,
    pub udp_sweep_interval: Duration,
    pub udp_sweep_batch: usize,
    pub udp_writer_delay: Duration,
}

impl Default for ServerRuntimeLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            max_unauthenticated_connections: 64,
            max_unauthenticated_connections_per_peer: 4,
            max_failed_auth_attempts_per_peer: 8,
            failed_auth_window: Duration::from_secs(60),
            max_tracked_auth_peers: 1024,
            max_auth_attempt_records: 8192,
            max_auth_attempts_per_window: 8192,
            max_pending_data_channel_tokens_per_client: 4096,
            binding_token_ttl: Duration::from_secs(30),
            udp_queue_capacity: 1024,
            udp_idle_timeout: Duration::from_secs(60),
            udp_sweep_interval: Duration::from_secs(1),
            udp_sweep_batch: 64,
            udp_writer_delay: Duration::ZERO,
        }
    }
}

impl ServerRuntimeLimits {
    fn validate(&self) -> Result<(), ServerError> {
        if self.handshake_timeout.is_zero()
            || self.max_unauthenticated_connections < 2
            || self.max_unauthenticated_connections_per_peer == 0
            || self.max_failed_auth_attempts_per_peer == 0
            || self.failed_auth_window.is_zero()
            || self.max_tracked_auth_peers == 0
            || self.max_auth_attempt_records == 0
            || self.max_auth_attempts_per_window < MIN_AUTH_ATTEMPTS_PER_WINDOW
            || self.max_pending_data_channel_tokens_per_client == 0
            || self.binding_token_ttl.is_zero()
            || self.udp_queue_capacity == 0
            || self.udp_idle_timeout.is_zero()
            || self.udp_sweep_interval.is_zero()
            || self.udp_sweep_batch == 0
            || self.max_unauthenticated_connections > MAX_UNAUTHENTICATED_CONNECTIONS
            || self.max_unauthenticated_connections_per_peer
                > MAX_UNAUTHENTICATED_CONNECTIONS_PER_PEER
            || (self.max_unauthenticated_connections > 1
                && self.max_unauthenticated_connections_per_peer
                    >= self.max_unauthenticated_connections)
            || self.max_failed_auth_attempts_per_peer > MAX_FAILED_AUTH_ATTEMPTS_PER_PEER
            || self.max_tracked_auth_peers > MAX_TRACKED_AUTH_PEERS
            || self.max_auth_attempt_records > MAX_AUTH_ATTEMPT_RECORDS
            || self.max_auth_attempts_per_window > MAX_AUTH_ATTEMPTS_PER_WINDOW
            || self.max_pending_data_channel_tokens_per_client
                > MAX_PENDING_DATA_CHANNEL_TOKENS_PER_CLIENT
            || self.udp_queue_capacity > MAX_UDP_QUEUE_CAPACITY
            || self.udp_sweep_batch > MAX_UDP_SWEEP_BATCH
            || self.udp_writer_delay > Duration::from_secs(60)
            || self.max_failed_auth_attempts_per_peer > self.max_auth_attempt_records
            || self.max_tracked_auth_peers > self.max_auth_attempt_records
            || tokio::time::Instant::now()
                .checked_add(self.handshake_timeout)
                .is_none()
            || tokio::time::Instant::now()
                .checked_add(self.failed_auth_window)
                .is_none()
            || tokio::time::Instant::now()
                .checked_add(self.binding_token_ttl)
                .is_none()
            || tokio::time::Instant::now()
                .checked_add(self.udp_idle_timeout)
                .is_none()
            || tokio::time::Instant::now()
                .checked_add(self.udp_sweep_interval)
                .is_none()
            || tokio::time::Instant::now()
                .checked_add(self.udp_writer_delay)
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
    tls_handshakes: TlsHandshakeLimiter,
    limiter: FailedAuthLimiter,
    runtime_limits: ServerRuntimeLimits,
    heartbeat_timeout: Duration,
}

impl ServerApp {
    pub async fn bind(config: ServerConfig) -> Result<Self, ServerError> {
        let mut runtime_limits = ServerRuntimeLimits::default();
        runtime_limits.apply_internal_test_overrides()?;
        Self::bind_with_runtime_limits(config, runtime_limits).await
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
        let max_tcp_connections = usize::try_from(config.limits.max_tcp_connections_per_tunnel)
            .map_err(|_| ServerError::InvalidRuntimeLimits)?;
        let max_udp_sessions = usize::try_from(config.limits.max_udp_sessions_per_tunnel)
            .map_err(|_| ServerError::InvalidRuntimeLimits)?;
        let max_udp_payload = usize::try_from(config.limits.max_udp_payload_bytes)
            .map_err(|_| ServerError::InvalidRuntimeLimits)?;
        let registry = ClientRegistry::new_with_relay_limits(
            max_clients,
            max_tunnels,
            max_tcp_connections,
            max_udp_sessions,
            max_udp_payload,
            listener_ip,
            binding_capacity,
            runtime_limits.binding_token_ttl,
            UdpRuntimeLimits {
                queue_capacity: runtime_limits.udp_queue_capacity,
                idle_timeout: runtime_limits.udp_idle_timeout,
                sweep_interval: runtime_limits.udp_sweep_interval,
                sweep_batch: runtime_limits.udp_sweep_batch,
                writer_delay: runtime_limits.udp_writer_delay,
            },
        )?;
        let limiter = FailedAuthLimiter::new_with_attempt_budget(
            runtime_limits.max_failed_auth_attempts_per_peer,
            runtime_limits.failed_auth_window,
            runtime_limits.max_tracked_auth_peers,
            runtime_limits.max_auth_attempt_records,
            runtime_limits.max_auth_attempts_per_window,
        );
        let unauthenticated = Arc::new(Semaphore::new(
            runtime_limits.max_unauthenticated_connections,
        ));
        let tls_handshakes =
            TlsHandshakeLimiter::new(runtime_limits.max_unauthenticated_connections_per_peer);
        Ok(Self {
            tls_server,
            authenticator,
            registry,
            unauthenticated,
            tls_handshakes,
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
        let result = loop {
            tokio::select! {
                () = shutdown.cancelled() => break Ok(()),
                accepted = self.tls_server.accept_tcp() => {
                    let (socket, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(error.into()),
                    };
                    let Some(peer_permit) = self.tls_handshakes.try_acquire(peer.ip()) else {
                        continue;
                    };
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
                        if let Err(error) = control::serve_connection(
                            context,
                            socket,
                            peer,
                            permit,
                            peer_permit,
                            child_shutdown,
                        )
                        .await
                        {
                            tracing::debug!(peer = %peer, %error, "control session ended");
                        }
                    });
                }
            }
            while sessions.try_join_next().is_some() {}
        };
        session_shutdown.cancel();
        while sessions.join_next().await.is_some() {}
        result
    }
}

impl ServerRuntimeLimits {
    fn apply_internal_test_overrides(&mut self) -> Result<(), ServerError> {
        if std::env::var("RUSTGO_INTERNAL_TESTING").as_deref() != Ok("1") {
            return Ok(());
        }

        fn parse(name: &str) -> Result<Option<u64>, ServerError> {
            std::env::var(name)
                .ok()
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|_| ServerError::InvalidRuntimeLimits)
                })
                .transpose()
        }

        if let Some(value) = parse("RUSTGO_TEST_UDP_QUEUE_CAPACITY")? {
            self.udp_queue_capacity =
                usize::try_from(value).map_err(|_| ServerError::InvalidRuntimeLimits)?;
        }
        if let Some(value) = parse("RUSTGO_TEST_UDP_IDLE_TIMEOUT_MS")? {
            self.udp_idle_timeout = Duration::from_millis(value);
        }
        if let Some(value) = parse("RUSTGO_TEST_UDP_SWEEP_INTERVAL_MS")? {
            self.udp_sweep_interval = Duration::from_millis(value);
        }
        if let Some(value) = parse("RUSTGO_TEST_UDP_SWEEP_BATCH")? {
            self.udp_sweep_batch =
                usize::try_from(value).map_err(|_| ServerError::InvalidRuntimeLimits)?;
        }
        if let Some(value) = parse("RUSTGO_TEST_UDP_WRITE_DELAY_MS")? {
            self.udp_writer_delay = Duration::from_millis(value);
        }
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

#[cfg(test)]
mod tests {
    use super::{ServerError, ServerRuntimeLimits};

    fn assert_invalid(limits: ServerRuntimeLimits) {
        assert!(matches!(
            limits.validate(),
            Err(ServerError::InvalidRuntimeLimits)
        ));
    }

    #[test]
    fn runtime_count_limits_accept_documented_hard_boundaries() {
        let limits = ServerRuntimeLimits {
            max_unauthenticated_connections: 1024,
            max_unauthenticated_connections_per_peer: 64,
            max_failed_auth_attempts_per_peer: 64,
            max_tracked_auth_peers: 16_384,
            max_auth_attempt_records: 65_536,
            max_auth_attempts_per_window: 65_536,
            max_pending_data_channel_tokens_per_client: 65_536,
            ..ServerRuntimeLimits::default()
        };

        assert!(limits.validate().is_ok());
    }

    #[test]
    fn runtime_count_limits_reject_values_above_each_hard_boundary() {
        let cases: [fn(&mut ServerRuntimeLimits); 9] = [
            |limits| limits.max_unauthenticated_connections = 1025,
            |limits| limits.max_unauthenticated_connections_per_peer = 65,
            |limits| limits.max_failed_auth_attempts_per_peer = 65,
            |limits| limits.max_tracked_auth_peers = 16_385,
            |limits| limits.max_auth_attempt_records = 65_537,
            |limits| limits.max_auth_attempts_per_window = 65_537,
            |limits| limits.max_pending_data_channel_tokens_per_client = 65_537,
            |limits| limits.udp_queue_capacity = 65_537,
            |limits| limits.udp_sweep_batch = 65_537,
        ];

        for change in cases {
            let mut limits = ServerRuntimeLimits::default();
            change(&mut limits);
            assert_invalid(limits);
        }
    }

    #[test]
    fn runtime_limits_reject_incoherent_auth_record_budgets() {
        let too_few_for_one_peer = ServerRuntimeLimits {
            max_auth_attempt_records: 7,
            ..ServerRuntimeLimits::default()
        };
        assert_invalid(too_few_for_one_peer);

        let too_few_for_tracked_peers = ServerRuntimeLimits {
            max_tracked_auth_peers: 8192,
            max_auth_attempt_records: 4096,
            ..ServerRuntimeLimits::default()
        };
        assert_invalid(too_few_for_tracked_peers);

        let peer_tls_leaves_no_global_fairness_slot = ServerRuntimeLimits {
            max_unauthenticated_connections: 4,
            max_unauthenticated_connections_per_peer: 4,
            ..ServerRuntimeLimits::default()
        };
        assert_invalid(peer_tls_leaves_no_global_fairness_slot);

        let one_global_slot_cannot_be_reserved_for_another_peer = ServerRuntimeLimits {
            max_unauthenticated_connections: 1,
            max_unauthenticated_connections_per_peer: 1,
            ..ServerRuntimeLimits::default()
        };
        assert_invalid(one_global_slot_cannot_be_reserved_for_another_peer);

        let too_few_global_attempts_for_fair_shards = ServerRuntimeLimits {
            max_auth_attempts_per_window: 15,
            ..ServerRuntimeLimits::default()
        };
        assert_invalid(too_few_global_attempts_for_fair_shards);
    }
}

use std::{
    collections::BTreeMap,
    future, io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use rustgo_config::ServerConfig;
use rustgo_observability::{
    AuthenticatedClientIdentity, ClientHistorySample, ClientLifecycleKind, ClientLifecycleRecord,
    HistoryBatch, HistoryConfig, HistoryConfigError, HistoryService, HistoryWorker,
    HistoryWorkerError, HistoryWorkerHandle, HostSampler, ObservabilitySink, ObservabilityStore,
    ObservabilityWorker, ObservationEvent, OverviewSnapshot, ServerHistorySample, SessionSnapshot,
};
use rustgo_protocol::ProtocolVersion;
use rustgo_transport::{TlsError, TlsServer, safe_display};
use thiserror::Error;
use tokio::{
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{Authenticator, FailedAuthLimiter, TlsHandshakeLimiter},
    control,
    observation::{ObservationRuntimeLimits, ObservationService, ObservationTokenIssuer},
    registry::{ClientRegistry, RegistryError},
    rendezvous::{RendezvousCoordinator, RendezvousLimits},
    udp::UdpRuntimeLimits,
    web::{DashboardDataSources, WebError, WebRuntimeLimits, WebServer},
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
const MAX_RENDEZVOUS_SESSIONS: usize = 65_536;
const MAX_RENDEZVOUS_SESSIONS_PER_DEVICE: usize = 1_024;
const MAX_RENDEZVOUS_SESSION_TTL: Duration = Duration::from_secs(300);
const SERVER_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
const HISTORY_PROJECTION_INTERVAL: Duration = Duration::from_secs(2);
const WEB_RESTART_INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const WEB_RESTART_MAX_BACKOFF: Duration = Duration::from_secs(2);
const TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const PROJECTION_DRAIN_POLL: Duration = Duration::from_millis(10);

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
    pub max_rendezvous_sessions: usize,
    pub max_rendezvous_sessions_per_device: usize,
    pub rendezvous_session_ttl: Duration,
    #[doc(hidden)]
    pub udp_test_disconnect_after_replies: Option<u64>,
    #[doc(hidden)]
    pub web_test_exit_after_accepts: Option<usize>,
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
            max_rendezvous_sessions: 4096,
            max_rendezvous_sessions_per_device: 64,
            rendezvous_session_ttl: Duration::from_secs(30),
            udp_test_disconnect_after_replies: None,
            web_test_exit_after_accepts: None,
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
            || self.max_rendezvous_sessions == 0
            || self.max_rendezvous_sessions_per_device == 0
            || self.rendezvous_session_ttl < Duration::from_secs(1)
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
            || self.max_rendezvous_sessions > MAX_RENDEZVOUS_SESSIONS
            || self.max_rendezvous_sessions_per_device > MAX_RENDEZVOUS_SESSIONS_PER_DEVICE
            || self.max_rendezvous_sessions_per_device > self.max_rendezvous_sessions
            || self.rendezvous_session_ttl > MAX_RENDEZVOUS_SESSION_TTL
            || self.udp_writer_delay > Duration::from_secs(60)
            || self.udp_test_disconnect_after_replies == Some(0)
            || self.web_test_exit_after_accepts == Some(0)
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
            || tokio::time::Instant::now()
                .checked_add(self.rendezvous_session_ttl)
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
    protocol_version: ProtocolVersion,
    observation: Option<ObservationService>,
    observation_token_issuer: Option<ObservationTokenIssuer>,
    rendezvous: RendezvousCoordinator,
    observability_sink: Option<ObservabilitySink>,
    dashboard: Option<DashboardRuntime>,
}

struct DashboardRuntime {
    store: ObservabilityStore,
    projection_worker: ObservabilityWorker,
    history: HistoryService,
    history_worker: HistoryWorker,
    web_server: WebServer,
    web_restart_config: ServerConfig,
    web_restart_limits: WebRuntimeLimits,
    web_data_sources: DashboardDataSources,
    web_local_addr: SocketAddr,
}

impl ServerApp {
    /// Loads every local credential used by the production server without
    /// creating or binding a network socket.
    pub fn validate_credentials(config: &ServerConfig) -> Result<(), ServerError> {
        load_authenticator(config)?;
        TlsServer::validate_identity(
            &config.server.certificate_file,
            &config.server.private_key_file,
        )?;
        Ok(())
    }

    /// Validates every runtime-only Web/history rule without binding a socket
    /// or starting the SQLite worker.
    pub fn validate_configuration(config: &ServerConfig) -> Result<(), ServerError> {
        Self::validate_credentials(config)?;
        if let Some(web) = config.web.as_ref().filter(|web| web.enabled) {
            WebServer::validate_configuration(config, &WebRuntimeLimits::default())?;
            let (_service, _worker) = HistoryService::new(HistoryConfig {
                database_path: web.database_path.clone(),
                history_days: web.history_days,
                database_max_mib: web.database_max_mib,
            })?;
        }
        Ok(())
    }

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
        let protocol_version = internal_test_protocol_version()?;
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
        let authenticator = load_authenticator(&config)?;
        let tls_server = Arc::new(
            TlsServer::bind(
                &config.server.bind_addr,
                &config.server.certificate_file,
                &config.server.private_key_file,
            )
            .await?,
        );
        let listener_ip = tls_server.local_addr()?.ip();
        let udp_listener_ip = config
            .server
            .udp_bind_ip
            .or_else(|| (!listener_ip.is_unspecified()).then_some(listener_ip));
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
            udp_listener_ip,
            binding_capacity,
            runtime_limits.binding_token_ttl,
            UdpRuntimeLimits {
                queue_capacity: runtime_limits.udp_queue_capacity,
                idle_timeout: runtime_limits.udp_idle_timeout,
                sweep_interval: runtime_limits.udp_sweep_interval,
                sweep_batch: runtime_limits.udp_sweep_batch,
                writer_delay: runtime_limits.udp_writer_delay,
                test_disconnect_after_replies: runtime_limits.udp_test_disconnect_after_replies,
            },
        )?;
        let observation = match (
            config.server.p2p_observation_bind.as_deref(),
            config.server.p2p_observation_alternate_bind.as_deref(),
        ) {
            (None, None) => None,
            (Some(primary), Some(alternate)) => {
                let primary = primary
                    .parse::<SocketAddr>()
                    .map_err(|_| ServerError::InvalidObservationConfiguration)?;
                let alternate = alternate
                    .parse::<SocketAddr>()
                    .map_err(|_| ServerError::InvalidObservationConfiguration)?;
                Some(
                    ObservationService::bind(
                        primary,
                        alternate,
                        ObservationRuntimeLimits::default(),
                    )
                    .await?,
                )
            }
            _ => return Err(ServerError::InvalidObservationConfiguration),
        };
        let observation_token_issuer = observation
            .as_ref()
            .map(|service| service.token_issuer(registry.clone()));
        let rendezvous = RendezvousCoordinator::new(
            registry.clone(),
            &config.clients,
            RendezvousLimits {
                max_sessions: runtime_limits.max_rendezvous_sessions,
                max_sessions_per_device: runtime_limits.max_rendezvous_sessions_per_device,
                session_ttl: runtime_limits.rendezvous_session_ttl,
            },
        );
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
        let (observability_sink, dashboard) = if let Some(web) =
            config.web.as_ref().filter(|web| web.enabled)
        {
            let (store, sink, projection_worker) = ObservabilityStore::new();
            registry.install_observability_sink(sink.clone())?;
            let (history, history_worker) = HistoryService::new(HistoryConfig {
                database_path: web.database_path.clone(),
                history_days: web.history_days,
                database_max_mib: web.database_max_mib,
            })?;
            let web_data_sources = DashboardDataSources::new(store.clone(), Some(history.clone()));
            let web_limits = WebRuntimeLimits {
                test_exit_after_accepts: runtime_limits.web_test_exit_after_accepts,
                ..WebRuntimeLimits::default()
            };
            let web_server = WebServer::bind_with_data_sources(
                &config,
                web_limits.clone(),
                web_data_sources.clone(),
            )
            .await?;
            let web_local_addr = web_server.local_addr()?;
            let mut web_restart_config = config.clone();
            web_restart_config
                .web
                .as_mut()
                .expect("enabled Web configuration remains present")
                .bind = web_local_addr.to_string();
            let mut web_restart_limits = web_limits;
            web_restart_limits.test_exit_after_accepts = None;
            (
                Some(sink),
                Some(DashboardRuntime {
                    store,
                    projection_worker,
                    history,
                    history_worker,
                    web_server,
                    web_restart_config,
                    web_restart_limits,
                    web_data_sources,
                    web_local_addr,
                }),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            tls_server,
            authenticator,
            registry,
            unauthenticated,
            tls_handshakes,
            limiter,
            heartbeat_timeout,
            runtime_limits,
            protocol_version,
            observation,
            observation_token_issuer,
            rendezvous,
            observability_sink,
            dashboard,
        })
    }

    /// Injects the non-blocking projection sink before the server runtime starts.
    pub fn with_observability_sink(mut self, sink: ObservabilitySink) -> Result<Self, ServerError> {
        self.registry.install_observability_sink(sink.clone())?;
        self.observability_sink = Some(sink);
        Ok(self)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tls_server.local_addr()
    }

    pub fn web_local_addr(&self) -> Option<SocketAddr> {
        self.dashboard
            .as_ref()
            .map(|dashboard| dashboard.web_local_addr)
    }

    pub fn registry(&self) -> ClientRegistry {
        self.registry.clone()
    }

    pub fn observation_local_addrs(&self) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
        self.observation
            .as_ref()
            .map(ObservationService::local_addrs)
            .transpose()
    }

    pub fn observation_token_issuer(&self) -> Option<ObservationTokenIssuer> {
        self.observation_token_issuer.clone()
    }

    pub fn rendezvous_coordinator(&self) -> RendezvousCoordinator {
        self.rendezvous.clone()
    }

    pub async fn run(self) -> Result<(), ServerError> {
        let shutdown = CancellationToken::new();
        let test_shutdown_delay = internal_test_shutdown_delay()?;
        let mut runtime = Box::pin(self.run_until(shutdown.clone()));
        tokio::select! {
            result = &mut runtime => result,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                shutdown.cancel();
                runtime.await
            }
            () = async {
                match test_shutdown_delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => future::pending().await,
                }
            } => {
                shutdown.cancel();
                runtime.await
            }
        }
    }

    pub async fn run_until(mut self, shutdown: CancellationToken) -> Result<(), ServerError> {
        let runtime_root = CancellationToken::new();
        let sampler_shutdown = runtime_root.child_token();
        let projection_shutdown = runtime_root.child_token();
        let history_projection_shutdown = runtime_root.child_token();
        let history_worker_shutdown = runtime_root.child_token();
        let web_shutdown = runtime_root.child_token();
        let session_shutdown = runtime_root.child_token();
        let mut rendezvous_expiry = tokio::time::interval(Duration::from_millis(250));
        rendezvous_expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let sampler_task = self
            .observability_sink
            .clone()
            .map(|sink| tokio::spawn(run_server_sampler(sink, sampler_shutdown.child_token())));

        let mut projection_task = None;
        let mut history_projection_task = None;
        let mut history_worker_task = None;
        let mut web_task = None;
        let mut dashboard_store = None;
        let mut history_service = None;
        if let Some(dashboard) = self.dashboard.take() {
            dashboard_store = Some(dashboard.store.clone());
            history_service = Some(dashboard.history.clone());
            projection_task = Some(tokio::spawn(
                dashboard
                    .projection_worker
                    .run_until(projection_shutdown.child_token()),
            ));
            history_projection_task = Some(tokio::spawn(run_history_projection(
                dashboard.store,
                dashboard.history.clone(),
                history_projection_shutdown.child_token(),
            )));
            match dashboard.history_worker.start() {
                Ok(worker) => {
                    history_worker_task = Some(tokio::spawn(run_history_worker(
                        worker,
                        history_worker_shutdown.child_token(),
                    )));
                }
                Err(error) => {
                    tracing::warn!(
                        error = %safe_display(&error),
                        "SQLite history worker could not start; live observability remains active"
                    );
                }
            }
            web_task = Some(tokio::spawn(run_web_supervisor(
                dashboard.web_server,
                dashboard.web_restart_config,
                dashboard.web_restart_limits,
                dashboard.web_data_sources,
                web_shutdown.child_token(),
            )));
        }

        let mut observation = self
            .observation
            .map(|service| Box::pin(service.run(session_shutdown.child_token())));
        let mut sessions = JoinSet::new();
        let result = loop {
            tokio::select! {
                () = shutdown.cancelled() => break Ok(()),
                _ = rendezvous_expiry.tick() => self.rendezvous.expire_now(),
                observation_result = async {
                    match observation.as_mut() {
                        Some(service) => Some(service.await),
                        None => std::future::pending().await,
                    }
                } => {
                    observation = None;
                    break observation_result
                        .expect("the absent observation future cannot complete")
                        .map_err(ServerError::from);
                }
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
                    let observation_token_issuer = self.observation_token_issuer.clone();
                    let rendezvous = self.rendezvous.clone();
                    let context = control::ControlContext::new_with_version(
                        tls_server,
                        authenticator,
                        registry,
                        limiter,
                        control::ControlRuntime::new(
                            handshake_timeout,
                            heartbeat_timeout,
                            self.protocol_version,
                            observation_token_issuer,
                            rendezvous,
                        ),
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
                            tracing::debug!(peer = %safe_display(peer), error = %safe_display(&error), "control session ended");
                        }
                    });
                }
            }
            while sessions.try_join_next().is_some() {}
        };

        web_shutdown.cancel();
        sampler_shutdown.cancel();
        session_shutdown.cancel();
        join_task_bounded("Web server", web_task).await;
        if let Some(observation) = observation {
            match tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, observation).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    error = %safe_display(&error),
                    "observation listener degraded during shutdown"
                ),
                Err(_) => tracing::warn!(
                    "observation listener shutdown timed out; process exit will continue"
                ),
            }
        }

        if tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, async {
            while sessions.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tracing::warn!("relay session shutdown timed out; remaining sessions will be aborted");
            sessions.abort_all();
            while sessions.join_next().await.is_some() {}
        }

        join_task_bounded("server sampler", sampler_task).await;

        if let Some(store) = dashboard_store.as_ref()
            && tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, async {
                while store.snapshot().event_queue_depth != 0 {
                    tokio::time::sleep(PROJECTION_DRAIN_POLL).await;
                }
            })
            .await
            .is_err()
        {
            tracing::warn!(
                "observability projection drain timed out; final history will use the latest available snapshot"
            );
        }

        history_projection_shutdown.cancel();
        join_task_bounded("history projection", history_projection_task).await;
        if let Some(history) = history_service.as_ref() {
            match tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, history.checkpoint()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    error = %safe_display(&error),
                    "SQLite history checkpoint degraded during shutdown"
                ),
                Err(_) => tracing::warn!("SQLite history checkpoint timed out during shutdown"),
            }
        }
        if let Some(history) = history_service.as_ref() {
            history.close();
        }
        history_worker_shutdown.cancel();
        join_result_task_bounded("SQLite history worker", history_worker_task).await;
        projection_shutdown.cancel();
        join_task_bounded("observability projection", projection_task).await;
        runtime_root.cancel();
        result
    }
}

async fn run_server_sampler(sink: ObservabilitySink, shutdown: CancellationToken) {
    let mut sampler = HostSampler::new();
    let mut ticks = tokio::time::interval(SERVER_SAMPLE_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                let _ = sink.try_publish(ObservationEvent::ServerSample {
                    metrics: sampler.sample(),
                });
                return;
            },
            _ = ticks.tick() => {
                let _ = sink.try_publish(ObservationEvent::ServerSample {
                    metrics: sampler.sample(),
                });
            }
        }
    }
}

async fn run_history_projection(
    store: ObservabilityStore,
    history: HistoryService,
    shutdown: CancellationToken,
) {
    let mut projector = HistoryProjector::default();
    let mut ticks = tokio::time::interval(HISTORY_PROJECTION_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                publish_history_snapshot(&mut projector, &store, &history);
                return;
            }
            _ = ticks.tick() => publish_history_snapshot(&mut projector, &store, &history),
        }
    }
}

fn publish_history_snapshot(
    projector: &mut HistoryProjector,
    store: &ObservabilityStore,
    history: &HistoryService,
) {
    for batch in projector.project(store.snapshot()) {
        let _ = history.try_publish(batch);
    }
}

#[derive(Default)]
struct HistoryProjector {
    server_sampled_unix_millis: Option<u64>,
    clients: BTreeMap<String, ProjectedClientHistory>,
    sessions: BTreeMap<String, SessionSnapshot>,
}

#[derive(Default)]
struct ProjectedClientHistory {
    generation: u64,
    authenticated_recorded: bool,
    disconnected_unix_millis: Option<u64>,
    sampled_unix_millis: Option<u64>,
}

impl HistoryProjector {
    fn project(&mut self, snapshot: OverviewSnapshot) -> Vec<HistoryBatch> {
        let mut batches = HistoryBatchBuilder::default();
        if let Some(metrics) = snapshot.server.metrics
            && self
                .server_sampled_unix_millis
                .is_none_or(|current| metrics.sampled_unix_millis > current)
        {
            self.server_sampled_unix_millis = Some(metrics.sampled_unix_millis);
            batches.server(ServerHistorySample::from_metrics(
                metrics,
                snapshot.server.traffic,
            ));
        }

        for client in snapshot.clients {
            let Ok(identity) = AuthenticatedClientIdentity::from_server_authentication(
                client.name.as_str().to_owned(),
                client.generation,
            ) else {
                continue;
            };
            let projected = self.clients.entry(identity.name().to_owned()).or_default();
            if projected.generation != identity.generation() {
                *projected = ProjectedClientHistory {
                    generation: identity.generation(),
                    ..ProjectedClientHistory::default()
                };
            }
            if !projected.authenticated_recorded {
                projected.authenticated_recorded = true;
                batches.lifecycle(ClientLifecycleRecord {
                    client: identity.clone(),
                    kind: ClientLifecycleKind::Authenticated,
                    timestamp_unix_millis: client.authenticated_unix_millis,
                    version: Some(client.version.clone()),
                });
            }
            if let Some(disconnected_unix_millis) = client.disconnected_unix_millis
                && projected.disconnected_unix_millis != Some(disconnected_unix_millis)
            {
                projected.disconnected_unix_millis = Some(disconnected_unix_millis);
                batches.lifecycle(ClientLifecycleRecord {
                    client: identity.clone(),
                    kind: ClientLifecycleKind::Disconnected,
                    timestamp_unix_millis: disconnected_unix_millis,
                    version: None,
                });
            }
            if let Some(metrics) = client.metrics
                && projected
                    .sampled_unix_millis
                    .is_none_or(|current| metrics.sampled_unix_millis > current)
            {
                projected.sampled_unix_millis = Some(metrics.sampled_unix_millis);
                batches.client(ClientHistorySample::from_metrics(
                    identity,
                    metrics,
                    client.traffic,
                ));
            }
        }

        let mut current_sessions = BTreeMap::new();
        for session in snapshot.sessions {
            let key = format!("{}:{}", session.id.as_str(), session.opened_unix_millis);
            if self.sessions.get(&key) != Some(&session) {
                batches.session(session.clone());
            }
            current_sessions.insert(key, session);
        }
        self.sessions = current_sessions;
        batches.finish()
    }
}

const HISTORY_RECORDS_PER_PUBLISH: usize = 1_024;

#[derive(Default)]
struct HistoryBatchBuilder {
    current: HistoryBatch,
    complete: Vec<HistoryBatch>,
}

impl HistoryBatchBuilder {
    fn server(&mut self, sample: ServerHistorySample) {
        self.flush_if_full();
        self.current.server_points.push(sample);
    }

    fn client(&mut self, sample: ClientHistorySample) {
        self.flush_if_full();
        self.current.client_points.push(sample);
    }

    fn lifecycle(&mut self, record: ClientLifecycleRecord) {
        self.flush_if_full();
        self.current.client_lifecycle.push(record);
    }

    fn session(&mut self, session: SessionSnapshot) {
        self.flush_if_full();
        self.current.session_summaries.push(session);
    }

    fn flush_if_full(&mut self) {
        if self.current.record_count() >= HISTORY_RECORDS_PER_PUBLISH {
            self.complete.push(std::mem::take(&mut self.current));
        }
    }

    fn finish(mut self) -> Vec<HistoryBatch> {
        if !self.current.is_empty() {
            self.complete.push(self.current);
        }
        self.complete
    }
}

async fn run_history_worker(
    worker: HistoryWorkerHandle,
    shutdown: CancellationToken,
) -> Result<(), HistoryWorkerError> {
    let worker = worker;
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return worker.shutdown().await,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if worker.is_finished() {
                    return worker.shutdown().await;
                }
            }
        }
    }
}

async fn run_web_supervisor(
    initial: WebServer,
    config: ServerConfig,
    limits: WebRuntimeLimits,
    data_sources: DashboardDataSources,
    shutdown: CancellationToken,
) {
    let mut server = Some(initial);
    let mut backoff = WEB_RESTART_INITIAL_BACKOFF;
    loop {
        let running = server
            .take()
            .expect("Web supervisor always binds before entering the run phase");
        let started = Instant::now();
        let outcome = running.run_until(shutdown.child_token()).await;
        if shutdown.is_cancelled() {
            return;
        }
        match outcome {
            Ok(()) => tracing::warn!("Web server exited unexpectedly; it will be restarted"),
            Err(error) => tracing::warn!(
                error = %safe_display(&error),
                "Web server failed; relay remains active and Web will be restarted"
            ),
        }
        if started.elapsed() >= Duration::from_secs(30) {
            backoff = WEB_RESTART_INITIAL_BACKOFF;
        }
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            match WebServer::bind_with_data_sources(&config, limits.clone(), data_sources.clone())
                .await
            {
                Ok(restarted) => {
                    match restarted.local_addr() {
                        Ok(address) => tracing::info!(
                            address = %safe_display(address),
                            "Web server restarted"
                        ),
                        Err(error) => tracing::info!(
                            error = %safe_display(&error),
                            "Web server restarted"
                        ),
                    }
                    server = Some(restarted);
                    backoff = backoff.saturating_mul(2).min(WEB_RESTART_MAX_BACKOFF);
                    break;
                }
                Err(error) => {
                    tracing::warn!(
                        error = %safe_display(&error),
                        "Web server restart bind failed; relay remains active"
                    );
                    backoff = backoff.saturating_mul(2).min(WEB_RESTART_MAX_BACKOFF);
                }
            }
        }
    }
}

async fn join_task_bounded(name: &'static str, task: Option<JoinHandle<()>>) {
    let Some(mut task) = task else {
        return;
    };
    match tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, &mut task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(
            task = name,
            error = %safe_display(&error),
            "subordinate server task failed"
        ),
        Err(_) => {
            tracing::warn!(task = name, "subordinate server task shutdown timed out");
            task.abort();
            let _ = task.await;
        }
    }
}

async fn join_result_task_bounded(
    name: &'static str,
    task: Option<JoinHandle<Result<(), HistoryWorkerError>>>,
) {
    let Some(mut task) = task else {
        return;
    };
    match tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => tracing::warn!(
            task = name,
            error = %safe_display(&error),
            "subordinate server task degraded"
        ),
        Ok(Err(error)) => tracing::warn!(
            task = name,
            error = %safe_display(&error),
            "subordinate server task failed"
        ),
        Err(_) => {
            tracing::warn!(task = name, "subordinate server task shutdown timed out");
            task.abort();
            let _ = task.await;
        }
    }
}

fn internal_test_protocol_version() -> Result<ProtocolVersion, ServerError> {
    if std::env::var("RUSTGO_INTERNAL_TESTING").as_deref() != Ok("1") {
        return Ok(control::SERVER_VERSION);
    }
    let minor = std::env::var("RUSTGO_TEST_PROTOCOL_MINOR")
        .ok()
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| ServerError::InvalidRuntimeLimits)
        })
        .transpose()?
        .unwrap_or(control::SERVER_VERSION.minor);
    Ok(ProtocolVersion::new(control::SERVER_VERSION.major, minor))
}

fn internal_test_shutdown_delay() -> Result<Option<Duration>, ServerError> {
    if std::env::var("RUSTGO_INTERNAL_TESTING").as_deref() != Ok("1") {
        return Ok(None);
    }
    std::env::var("RUSTGO_TEST_SHUTDOWN_AFTER_MS")
        .ok()
        .map(|value| {
            let millis = value
                .parse::<u64>()
                .map_err(|_| ServerError::InvalidRuntimeLimits)?;
            if millis == 0 {
                return Err(ServerError::InvalidRuntimeLimits);
            }
            Ok(Duration::from_millis(millis))
        })
        .transpose()
}

fn load_authenticator(config: &ServerConfig) -> Result<Authenticator, ServerError> {
    Authenticator::new(&config.clients).map_err(|_| ServerError::AuthenticationSetup)
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
        if let Some(value) = parse("RUSTGO_TEST_UDP_DISCONNECT_AFTER_REPLIES")? {
            self.udp_test_disconnect_after_replies = Some(value);
        }
        if let Some(value) = parse("RUSTGO_TEST_MAX_PENDING_DATA_CHANNEL_TOKENS")? {
            self.max_pending_data_channel_tokens_per_client =
                usize::try_from(value).map_err(|_| ServerError::InvalidRuntimeLimits)?;
        }
        if let Some(value) = parse("RUSTGO_TEST_WEB_EXIT_AFTER_ACCEPTS")? {
            self.web_test_exit_after_accepts =
                Some(usize::try_from(value).map_err(|_| ServerError::InvalidRuntimeLimits)?);
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
    #[error("Web dashboard setup failed: {0}")]
    Web(#[from] WebError),
    #[error("SQLite history setup failed: {0}")]
    HistoryConfiguration(#[from] HistoryConfigError),
    #[error("invalid server runtime limits")]
    InvalidRuntimeLimits,
    #[error("invalid paired observation bind configuration")]
    InvalidObservationConfiguration,
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
    fn rendezvous_ttl_rejects_subsecond_values_that_wire_expiry_cannot_represent() {
        assert_invalid(ServerRuntimeLimits {
            rendezvous_session_ttl: std::time::Duration::from_millis(999),
            ..ServerRuntimeLimits::default()
        });
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

use std::{sync::Arc, time::Duration};

use rustgo_config::{ClientConfig, TelemetryConfig};
use rustgo_transport::{
    Backoff, BackoffClock, BackoffConfig, JitterSource, RandomJitter, SystemBackoffClock,
    safe_display,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::{
    ChildSessionSupervisor, ClientError, ControlClient, ExportRegistry, PeerGenerationHandler,
    RegisteredTunnel, SessionGeneration,
    orchestration::ProductionPeerRuntime,
    path_status::PathStatusStore,
    telemetry::{
        LogicalTraffic, TelemetryRuntime, TelemetryRuntimeHook, TrafficHandle, TrafficSnapshot,
    },
    udp::RelaySessionSupervisor,
};

const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAXIMUM_RECONNECT_DELAY: Duration = Duration::from_secs(60);
const RECONNECT_JITTER: Duration = Duration::from_millis(250);
const STABLE_CONNECTION_RESET_AFTER: Duration = Duration::from_secs(30);

pub trait ReconnectBackoff: Send + 'static {
    fn mark_connected(&mut self);
    fn mark_disconnected(&mut self) {}
    fn next_delay(&mut self) -> Duration;
}

impl<J, C> ReconnectBackoff for Backoff<J, C>
where
    J: JitterSource + Send + 'static,
    C: BackoffClock + Send + 'static,
{
    fn mark_connected(&mut self) {
        Backoff::mark_connected(self);
    }

    fn mark_disconnected(&mut self) {
        Backoff::mark_disconnected(self);
    }

    fn next_delay(&mut self) -> Duration {
        Backoff::next_delay(self)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientStatus {
    active: Option<ActiveGeneration>,
    authentication_rejected: bool,
}

impl ClientStatus {
    pub fn authentication_rejected(&self) -> bool {
        self.authentication_rejected
    }
    pub fn active(&self) -> Option<&ActiveGeneration> {
        self.active.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct ActiveGeneration {
    generation: SessionGeneration,
    registered_tunnels: Arc<[RegisteredTunnel]>,
}

impl ActiveGeneration {
    pub const fn generation(&self) -> SessionGeneration {
        self.generation
    }

    pub fn registered_tunnels(&self) -> &[RegisteredTunnel] {
        &self.registered_tunnels
    }
}

pub struct ClientApp {
    stop_on_auth_rejection: bool,
    control: ControlClient,
    backoff: Box<dyn ReconnectBackoff>,
    supervisor: Arc<dyn ChildSessionSupervisor>,
    status: watch::Sender<ClientStatus>,
    exports: ExportRegistry,
    peer_handler: Option<Arc<dyn PeerGenerationHandler>>,
    telemetry: Option<TelemetryConfig>,
    telemetry_report_interval_override: Option<Duration>,
    telemetry_hook: Option<Arc<dyn TelemetryRuntimeHook>>,
    logical_traffic: Option<Arc<LogicalTraffic>>,
    path_status_store: PathStatusStore,
    last_generation: u64,
}

impl ClientApp {
    pub fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let telemetry = config.telemetry.clone();
        let exports = ExportRegistry::new(config.exports.clone())
            .map_err(|_| ClientError::InvalidConfiguration)?;
        let control = ControlClient::from_config(config)?;
        let backoff = Backoff::<RandomJitter, SystemBackoffClock>::new(BackoffConfig {
            initial_delay: INITIAL_RECONNECT_DELAY,
            maximum_delay: MAXIMUM_RECONNECT_DELAY,
            jitter: RECONNECT_JITTER,
            stable_connection_reset_after: STABLE_CONNECTION_RESET_AFTER,
        })
        .map_err(|_| ClientError::InvalidConfiguration)?;
        let logical_traffic = telemetry
            .as_ref()
            .is_none_or(|telemetry| telemetry.enabled)
            .then(|| Arc::new(LogicalTraffic::default()));
        let supervisor = Arc::new(RelaySessionSupervisor::new(
            &control,
            logical_traffic.clone(),
        ));
        Ok(Self::with_runtime_and_exports(
            control,
            backoff,
            supervisor,
            exports,
            telemetry,
            logical_traffic,
        ))
    }

    pub fn with_runtime<B>(
        control: ControlClient,
        backoff: B,
        supervisor: Arc<dyn ChildSessionSupervisor>,
    ) -> Self
    where
        B: ReconnectBackoff,
    {
        let exports = ExportRegistry::new(control.config().exports.clone())
            .expect("validated client configuration has valid exports");
        let telemetry = control.config().telemetry.clone();
        let logical_traffic = telemetry
            .as_ref()
            .is_none_or(|telemetry| telemetry.enabled)
            .then(|| Arc::new(LogicalTraffic::default()));
        Self::with_runtime_and_exports(
            control,
            backoff,
            supervisor,
            exports,
            telemetry,
            logical_traffic,
        )
    }

    fn with_runtime_and_exports<B>(
        control: ControlClient,
        backoff: B,
        supervisor: Arc<dyn ChildSessionSupervisor>,
        exports: ExportRegistry,
        telemetry: Option<TelemetryConfig>,
        logical_traffic: Option<Arc<LogicalTraffic>>,
    ) -> Self
    where
        B: ReconnectBackoff,
    {
        let (status, _) = watch::channel(ClientStatus::default());
        Self {
            stop_on_auth_rejection: false,
            control,
            backoff: Box::new(backoff),
            supervisor,
            status,
            exports,
            peer_handler: None,
            telemetry,
            telemetry_report_interval_override: None,
            telemetry_hook: None,
            logical_traffic,
            path_status_store: PathStatusStore::new(),
            last_generation: 0,
        }
    }

    /// Return authentication rejection to a caller that can request administrator approval.
    pub fn with_approval_recovery(mut self) -> Self {
        self.stop_on_auth_rejection = true;
        self
    }

    /// Overrides the production peer owner for lifecycle integration testing.
    #[doc(hidden)]
    pub fn with_peer_handler(mut self, handler: Arc<dyn PeerGenerationHandler>) -> Self {
        self.peer_handler = Some(handler);
        self
    }

    /// Overrides telemetry scheduling and I/O only for deterministic integration tests.
    #[doc(hidden)]
    pub fn with_telemetry_test_runtime(
        mut self,
        report_interval: Duration,
        hook: Arc<dyn TelemetryRuntimeHook>,
    ) -> Result<Self, ClientError> {
        if report_interval.is_zero() {
            return Err(ClientError::InvalidConfiguration);
        }
        self.telemetry_report_interval_override = Some(report_interval);
        self.telemetry_hook = Some(hook);
        Ok(self)
    }

    pub fn subscribe(&self) -> watch::Receiver<ClientStatus> {
        self.status.subscribe()
    }

    pub fn exports(&self) -> &ExportRegistry {
        &self.exports
    }

    /// Current logical-traffic totals, or `None` when telemetry is explicitly
    /// disabled (`[telemetry] enabled = false`), which also disables recording.
    pub fn traffic_snapshot(&self) -> Option<TrafficSnapshot> {
        self.logical_traffic
            .as_ref()
            .map(|traffic| traffic.snapshot())
    }

    /// Shareable handle for polling traffic totals while the client runs;
    /// `None` when telemetry is explicitly disabled.
    pub fn traffic_handle(&self) -> Option<TrafficHandle> {
        self.logical_traffic.clone().map(TrafficHandle)
    }

    /// Path-status store for observing current P2P path selections.
    ///
    /// The GUI client polls this to display which exports are using direct
    /// paths versus relay fallback.
    pub fn path_status_store(&self) -> &PathStatusStore {
        &self.path_status_store
    }

    pub async fn run(self) -> Result<(), ClientError> {
        let shutdown = CancellationToken::new();
        let mut runtime = Box::pin(self.run_until(shutdown.clone()));
        tokio::select! {
            result = &mut runtime => result,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                shutdown.cancel();
                runtime.await
            }
        }
    }

    pub async fn run_until(mut self, shutdown: CancellationToken) -> Result<(), ClientError> {
        self.status.send_replace(ClientStatus::default());
        let mut telemetry = self.logical_traffic.clone().and_then(|traffic| {
            TelemetryRuntime::start(
                self.telemetry.take(),
                self.telemetry_report_interval_override.take(),
                self.telemetry_hook.take(),
                traffic,
            )
        });
        let peer_runtime = self.peer_handler.clone().unwrap_or_else(|| {
            Arc::new(ProductionPeerRuntime::new(
                Arc::new(self.control.config().clone()),
                self.control.keypair(),
                self.exports.clone(),
                self.logical_traffic.clone(),
                self.path_status_store.clone(),
            ))
        });
        let result = self
            .run_reconnect_loop(shutdown, peer_runtime.clone(), telemetry.as_mut())
            .await;
        let telemetry_result = match telemetry {
            Some(telemetry) => telemetry.shutdown().await,
            None => Ok(()),
        };
        let shutdown_result = peer_runtime.shutdown().await;
        telemetry_result.and(shutdown_result).and(result)
    }

    async fn run_reconnect_loop(
        &mut self,
        shutdown: CancellationToken,
        peer_runtime: Arc<dyn PeerGenerationHandler>,
        mut telemetry: Option<&mut TelemetryRuntime>,
    ) -> Result<(), ClientError> {
        loop {
            let connected = tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                connected = self.control.connect() => connected,
            };

            match connected {
                Ok(session) => {
                    let generation = SessionGeneration::next(self.last_generation)?;
                    let protocol_version = session.protocol_version();
                    let generation_telemetry = if session.supports_telemetry() {
                        telemetry.as_deref_mut().map(TelemetryRuntime::generation)
                    } else {
                        None
                    };
                    let local_protocol_version = self.control.protocol_version();
                    self.last_generation = generation.get();
                    self.backoff.mark_connected();
                    self.status.send_replace(ClientStatus {
                        authentication_rejected: false,
                        active: Some(ActiveGeneration {
                            generation,
                            registered_tunnels: session.registered_tunnels_shared(),
                        }),
                    });
                    tracing::info!(
                        client = %safe_display(&self.control.config().client.name),
                        generation = generation.get(),
                        protocol_major = protocol_version.major,
                        protocol_minor = protocol_version.minor,
                        local_protocol_minor = local_protocol_version.minor,
                        event = %"registration_ready",
                        "客户端隧道注册已就绪"
                    );
                    let status = self.status.clone();
                    let supervisor = self.supervisor.clone();
                    let backoff = &mut self.backoff;
                    let result = session
                        .run_generation_with_peer(crate::session::GenerationConfig {
                            generation,
                            telemetry: generation_telemetry,
                            shutdown: shutdown.clone(),
                            supervisor,
                            peer_handler: Some(peer_runtime.clone()),
                            on_control_ended: move || {
                                backoff.mark_disconnected();
                            },
                            on_inactive: move || {
                                status.send_replace(ClientStatus::default());
                            },
                        })
                        .await;
                    if shutdown.is_cancelled() {
                        return Ok(());
                    }
                    if matches!(
                        &result,
                        Err(ClientError::PeerGenerationFailed | ClientError::TaskJoin)
                    ) {
                        tracing::error!(
                            client = %safe_display(&self.control.config().client.name),
                            error = %safe_display(result.as_ref().expect_err("matched error")),
                            generation = generation.get(),
                            event = %"control_fail_stop",
                            "客户端控制运行时因代次所有权异常已故障停机"
                        );
                        return result;
                    }
                    if let Err(error) = result {
                        tracing::warn!(
                            client = %safe_display(&self.control.config().client.name),
                            error = %safe_display(&error),
                            generation = generation.get(),
                            event = %"control_ended",
                            "客户端控制连接代次已结束"
                        );
                    }
                }
                Err(error) => {
                    if matches!(error, ClientError::AuthenticationRejected) {
                        self.status.send_replace(ClientStatus {
                            active: None,
                            authentication_rejected: true,
                        });
                        if self.stop_on_auth_rejection {
                            return Err(error);
                        }
                    }
                    self.status.send_replace(ClientStatus::default());
                    tracing::warn!(
                        client = %safe_display(&self.control.config().client.name),
                        error = %safe_display(&error),
                        event = %"control_connect_failed",
                        "客户端控制连接失败"
                    );
                }
            }

            let delay = self.backoff.next_delay();
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }
}

impl std::fmt::Debug for ClientApp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientApp")
            .field("last_generation", &self.last_generation)
            .field("exports", &self.exports)
            .finish_non_exhaustive()
    }
}

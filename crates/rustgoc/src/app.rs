use std::{sync::Arc, time::Duration};

use rustgo_config::ClientConfig;
use rustgo_transport::{
    Backoff, BackoffClock, BackoffConfig, JitterSource, RandomJitter, SystemBackoffClock,
    safe_display,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::{
    ChildSessionSupervisor, ClientError, ControlClient, ExportRegistry, PeerGenerationHandler,
    RegisteredTunnel, SessionGeneration, orchestration::ProductionPeerRuntime,
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
}

impl ClientStatus {
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
    control: ControlClient,
    backoff: Box<dyn ReconnectBackoff>,
    supervisor: Arc<dyn ChildSessionSupervisor>,
    status: watch::Sender<ClientStatus>,
    exports: ExportRegistry,
    peer_handler: Option<Arc<dyn PeerGenerationHandler>>,
    last_generation: u64,
}

impl ClientApp {
    pub fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
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
        let supervisor = Arc::new(RelaySessionSupervisor::new(&control));
        Ok(Self::with_runtime_and_exports(
            control, backoff, supervisor, exports,
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
        Self::with_runtime_and_exports(control, backoff, supervisor, exports)
    }

    fn with_runtime_and_exports<B>(
        control: ControlClient,
        backoff: B,
        supervisor: Arc<dyn ChildSessionSupervisor>,
        exports: ExportRegistry,
    ) -> Self
    where
        B: ReconnectBackoff,
    {
        let (status, _) = watch::channel(ClientStatus::default());
        Self {
            control,
            backoff: Box::new(backoff),
            supervisor,
            status,
            exports,
            peer_handler: None,
            last_generation: 0,
        }
    }

    /// Overrides the production peer owner for lifecycle integration testing.
    #[doc(hidden)]
    pub fn with_peer_handler(mut self, handler: Arc<dyn PeerGenerationHandler>) -> Self {
        self.peer_handler = Some(handler);
        self
    }

    pub fn subscribe(&self) -> watch::Receiver<ClientStatus> {
        self.status.subscribe()
    }

    pub fn exports(&self) -> &ExportRegistry {
        &self.exports
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
                    let local_protocol_version = self.control.protocol_version();
                    self.last_generation = generation.get();
                    self.backoff.mark_connected();
                    self.status.send_replace(ClientStatus {
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
                        "client tunnel registration ready"
                    );
                    let status = self.status.clone();
                    let supervisor = self.supervisor.clone();
                    let peer_runtime = self.peer_handler.clone().unwrap_or_else(|| {
                        Arc::new(ProductionPeerRuntime::new(
                            Arc::new(self.control.config().clone()),
                            self.control.keypair(),
                            self.exports.clone(),
                        ))
                    });
                    let backoff = &mut self.backoff;
                    let result = session
                        .run_generation_with_peer(
                            generation,
                            shutdown.clone(),
                            supervisor,
                            Some(peer_runtime),
                            move || {
                                backoff.mark_disconnected();
                            },
                            move || {
                                status.send_replace(ClientStatus::default());
                            },
                        )
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
                            "client control runtime fail-stopped after generation ownership failure"
                        );
                        return result;
                    }
                    if let Err(error) = result {
                        tracing::warn!(
                            client = %safe_display(&self.control.config().client.name),
                            error = %safe_display(&error),
                            generation = generation.get(),
                            event = %"control_ended",
                            "client control generation ended"
                        );
                    }
                }
                Err(error) => {
                    self.status.send_replace(ClientStatus::default());
                    tracing::warn!(
                        client = %safe_display(&self.control.config().client.name),
                        error = %safe_display(&error),
                        event = %"control_connect_failed",
                        "client control connection failed"
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

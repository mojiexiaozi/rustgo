use std::{sync::Arc, time::Duration};

use rustgo_config::ClientConfig;
use rustgo_transport::{
    Backoff, BackoffClock, BackoffConfig, JitterSource, RandomJitter, SystemBackoffClock,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::{
    ChildSessionSupervisor, ClientError, ControlClient, RegisteredTunnel, SessionGeneration,
    tcp::TcpSessionSupervisor,
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
    last_generation: u64,
}

impl ClientApp {
    pub fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let control = ControlClient::from_config(config)?;
        let backoff = Backoff::<RandomJitter, SystemBackoffClock>::new(BackoffConfig {
            initial_delay: INITIAL_RECONNECT_DELAY,
            maximum_delay: MAXIMUM_RECONNECT_DELAY,
            jitter: RECONNECT_JITTER,
            stable_connection_reset_after: STABLE_CONNECTION_RESET_AFTER,
        })
        .map_err(|_| ClientError::InvalidConfiguration)?;
        let supervisor = Arc::new(TcpSessionSupervisor::new(&control));
        Ok(Self::with_runtime(control, backoff, supervisor))
    }

    pub fn with_runtime<B>(
        control: ControlClient,
        backoff: B,
        supervisor: Arc<dyn ChildSessionSupervisor>,
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
            last_generation: 0,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<ClientStatus> {
        self.status.subscribe()
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
                    self.last_generation = generation.get();
                    self.backoff.mark_connected();
                    self.status.send_replace(ClientStatus {
                        active: Some(ActiveGeneration {
                            generation,
                            registered_tunnels: session.registered_tunnels_shared(),
                        }),
                    });
                    tracing::info!(
                        generation = generation.get(),
                        "event=registration_ready client tunnel registration ready"
                    );
                    let status = self.status.clone();
                    let supervisor = self.supervisor.clone();
                    let backoff = &mut self.backoff;
                    let result = session
                        .run_generation(generation, shutdown.clone(), supervisor, move || {
                            backoff.mark_disconnected();
                            status.send_replace(ClientStatus::default());
                        })
                        .await;
                    if shutdown.is_cancelled() {
                        return Ok(());
                    }
                    if let Err(error) = result {
                        tracing::warn!(%error, generation = generation.get(), "client control generation ended");
                    }
                }
                Err(error) => {
                    self.status.send_replace(ClientStatus::default());
                    tracing::warn!(%error, "client control connection failed");
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
            .finish_non_exhaustive()
    }
}

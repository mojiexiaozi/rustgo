use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use rustgo_config::TelemetryConfig;
use rustgo_observability::{HostMetrics, HostSampler};
use rustgo_protocol::TelemetryReport;
use tokio::{sync::watch, task::JoinHandle, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::ClientError;

/// Internal integration seam for deterministically exercising telemetry
/// coalescing and write backpressure without depending on kernel socket sizes.
#[doc(hidden)]
pub trait TelemetryRuntimeHook: Send + Sync + 'static {
    fn after_publish(&self, _sequence: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn before_read_latest(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn before_write(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

/// Process-lifetime owner for the stateful host sampler.
pub(crate) struct TelemetryRuntime {
    samples: watch::Receiver<Option<HostMetrics>>,
    report_interval: Duration,
    hook: Option<Arc<dyn TelemetryRuntimeHook>>,
    shutdown: CancellationToken,
    owner: JoinHandle<()>,
}

impl TelemetryRuntime {
    pub(crate) fn start(
        config: Option<TelemetryConfig>,
        report_interval_override: Option<Duration>,
        hook: Option<Arc<dyn TelemetryRuntimeHook>>,
    ) -> Option<Self> {
        let config = config.filter(|config| config.enabled)?;
        let sample_interval = Duration::from_secs(config.sample_interval_secs);
        let report_interval = report_interval_override
            .unwrap_or_else(|| Duration::from_secs(config.report_interval_secs));
        let shutdown = CancellationToken::new();
        let owner_shutdown = shutdown.clone();
        let (samples, receiver) = watch::channel(None);
        let owner = tokio::spawn(async move {
            let mut sampler = HostSampler::new();
            let mut ticks = tokio::time::interval(sample_interval);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    biased;
                    () = owner_shutdown.cancelled() => return,
                    _ = ticks.tick() => {
                        samples.send_replace(Some(sampler.sample()));
                    }
                }
            }
        });

        Some(Self {
            samples: receiver,
            report_interval,
            hook,
            shutdown,
            owner,
        })
    }

    pub(crate) fn generation(&self) -> GenerationTelemetry {
        GenerationTelemetry {
            samples: self.samples.clone(),
            report_interval: self.report_interval,
            hook: self.hook.clone(),
        }
    }

    pub(crate) async fn shutdown(self) -> Result<(), ClientError> {
        self.shutdown.cancel();
        self.owner.await.map_err(|_| ClientError::TaskJoin)
    }
}

/// A generation-scoped publisher. Dropping its output queue discards every
/// report that belonged to the disconnected generation.
pub(crate) struct GenerationTelemetry {
    samples: watch::Receiver<Option<HostMetrics>>,
    report_interval: Duration,
    hook: Option<Arc<dyn TelemetryRuntimeHook>>,
}

impl GenerationTelemetry {
    pub(crate) fn hook(&self) -> Option<Arc<dyn TelemetryRuntimeHook>> {
        self.hook.clone()
    }

    pub(crate) async fn run(
        mut self,
        reports: watch::Sender<Option<TelemetryReport>>,
        shutdown: CancellationToken,
    ) {
        let first_tick = tokio::time::Instant::now() + self.report_interval;
        let mut ticks = tokio::time::interval_at(first_tick, self.report_interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sequence = 0_u64;

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = ticks.tick() => {
                    let Some(sample) = self.samples.borrow_and_update().clone() else {
                        continue;
                    };
                    let Some(next_sequence) = sequence.checked_add(1) else {
                        return;
                    };
                    sequence = next_sequence;
                    if reports.is_closed() {
                        return;
                    }
                    reports.send_replace(Some(report_from_sample(sample, sequence)));
                    if let Some(hook) = &self.hook {
                        hook.after_publish(sequence).await;
                    }
                }
            }
        }
    }
}

pub(crate) fn latest_telemetry_channel() -> (
    watch::Sender<Option<TelemetryReport>>,
    watch::Receiver<Option<TelemetryReport>>,
) {
    watch::channel(None)
}

fn report_from_sample(sample: HostMetrics, sequence: u64) -> TelemetryReport {
    let (memory_used_bytes, memory_total_bytes) =
        bounded_pair(sample.memory_used_bytes, sample.memory_total_bytes);
    let (disk_used_bytes, disk_total_bytes) =
        bounded_pair(sample.disk_used_bytes, sample.disk_total_bytes);
    TelemetryReport {
        sampled_unix_millis: sample.sampled_unix_millis,
        sequence,
        cpu_basis_points: sample.cpu_basis_points.unwrap_or_default().min(10_000),
        memory_used_bytes,
        memory_total_bytes,
        disk_used_bytes,
        disk_total_bytes,
        tx_bytes_per_sec: sample.network_tx_bytes_per_sec.unwrap_or_default(),
        rx_bytes_per_sec: sample.network_rx_bytes_per_sec.unwrap_or_default(),
    }
}

fn bounded_pair(used: Option<u64>, total: Option<u64>) -> (u64, u64) {
    match (used, total) {
        (Some(used), Some(total)) => (used.min(total), total),
        _ => (0, 0),
    }
}

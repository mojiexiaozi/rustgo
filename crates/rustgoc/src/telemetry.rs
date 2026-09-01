use std::time::Duration;

use rustgo_config::TelemetryConfig;
use rustgo_observability::{HostMetrics, HostSampler};
use rustgo_protocol::TelemetryReport;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;

use crate::ClientError;

/// Process-lifetime owner for the stateful host sampler.
pub(crate) struct TelemetryRuntime {
    samples: watch::Receiver<Option<HostMetrics>>,
    report_interval: Duration,
    shutdown: CancellationToken,
    owner: JoinHandle<()>,
}

impl TelemetryRuntime {
    pub(crate) fn start(config: Option<TelemetryConfig>) -> Option<Self> {
        let config = config.filter(|config| config.enabled)?;
        let sample_interval = Duration::from_secs(config.sample_interval_secs);
        let report_interval = Duration::from_secs(config.report_interval_secs);
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
            shutdown,
            owner,
        })
    }

    pub(crate) fn generation(&self) -> GenerationTelemetry {
        GenerationTelemetry {
            samples: self.samples.clone(),
            report_interval: self.report_interval,
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
}

impl GenerationTelemetry {
    pub(crate) async fn run(mut self, reports: LatestTelemetrySender, shutdown: CancellationToken) {
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
                    if reports
                        .try_send(report_from_sample(sample, sequence))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
}

/// A capacity-one wakeup paired with a watch value. Replacing the watch value
/// before `try_send` means a full wakeup slot still points at the newest report
/// rather than retaining an older queued payload.
pub(crate) struct LatestTelemetrySender {
    latest: watch::Sender<Option<TelemetryReport>>,
    pending: mpsc::Sender<()>,
}

impl LatestTelemetrySender {
    fn try_send(&self, report: TelemetryReport) -> Result<(), ()> {
        self.latest.send_replace(Some(report));
        match self.pending.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(()),
        }
    }
}

pub(crate) struct LatestTelemetryReceiver {
    latest: watch::Receiver<Option<TelemetryReport>>,
    pending: mpsc::Receiver<()>,
}

impl LatestTelemetryReceiver {
    pub(crate) async fn recv(&mut self) -> Option<TelemetryReport> {
        self.pending.recv().await?;
        self.latest.borrow_and_update().clone()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.pending.is_closed()
    }
}

pub(crate) fn latest_telemetry_channel() -> (LatestTelemetrySender, LatestTelemetryReceiver) {
    let (latest, receiver) = watch::channel(None);
    let (pending, notifications) = mpsc::channel(1);
    (
        LatestTelemetrySender { latest, pending },
        LatestTelemetryReceiver {
            latest: receiver,
            pending: notifications,
        },
    )
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

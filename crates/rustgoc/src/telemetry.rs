use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use rustgo_config::TelemetryConfig;
use rustgo_observability::{HostMetrics, HostSampler};
use rustgo_protocol::TelemetryReport;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    task::JoinHandle,
    time::MissedTickBehavior,
};
use tokio_util::sync::CancellationToken;

use crate::ClientError;

#[derive(Debug, Default)]
pub(crate) struct LogicalTraffic {
    active: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
}

impl LogicalTraffic {
    pub(crate) fn record_sent(&self, bytes: usize) {
        if self.active.load(Ordering::Acquire) {
            saturating_add(&self.sent, bytes as u64);
        }
    }

    pub(crate) fn record_received(&self, bytes: usize) {
        if self.active.load(Ordering::Acquire) {
            saturating_add(&self.received, bytes as u64);
        }
    }

    fn activate(self: &Arc<Self>) -> LogicalTrafficActivation {
        self.active.store(true, Ordering::Release);
        LogicalTrafficActivation(self.clone())
    }

    fn totals(&self) -> (u64, u64) {
        (
            self.sent.load(Ordering::Acquire),
            self.received.load(Ordering::Acquire),
        )
    }
}

struct LogicalTrafficActivation(Arc<LogicalTraffic>);

impl Drop for LogicalTrafficActivation {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::Release);
    }
}

fn saturating_add(counter: &AtomicU64, delta: u64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_add(delta))
    });
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TrafficDirection {
    Sent,
    Received,
}

pub(crate) struct MeteredIo<T> {
    inner: T,
    traffic: Arc<LogicalTraffic>,
    direction: TrafficDirection,
}

impl<T> MeteredIo<T> {
    pub(crate) fn new(inner: T, traffic: Arc<LogicalTraffic>, direction: TrafficDirection) -> Self {
        Self {
            inner,
            traffic,
            direction,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for MeteredIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MeteredIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                match this.direction {
                    TrafficDirection::Sent => this.traffic.record_sent(written),
                    TrafficDirection::Received => this.traffic.record_received(written),
                }
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

/// Internal AsyncWrite gate used to make the real framed control write
/// deterministically pending in process-level integration coverage.
#[doc(hidden)]
pub trait TelemetryControlWriteGate: Send + Sync + 'static {
    fn arm(&self);
    fn poll_write(&self, context: &mut Context<'_>) -> Poll<()>;
}

/// Internal integration seam for deterministically exercising telemetry
/// coalescing and write backpressure without depending on kernel socket sizes.
#[doc(hidden)]
pub trait TelemetryRuntimeHook: Send + Sync + 'static {
    /// Test-only observation that the process host sampler was lazily started.
    #[doc(hidden)]
    fn sampler_started(&self) {}

    fn after_publish(&self, _sequence: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn before_read_latest(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn control_write_gate(&self) -> Option<Arc<dyn TelemetryControlWriteGate>> {
        None
    }

    /// Test-only batch observation of the process logical-traffic totals used
    /// to derive the next wire rate. Production data paths never call hooks.
    #[doc(hidden)]
    fn after_traffic_snapshot(&self, _sent: u64, _received: u64) {}
}

/// Process-lifetime owner for the stateful host sampler.
pub(crate) struct TelemetryRuntime {
    sample_interval: Duration,
    report_interval: Duration,
    hook: Option<Arc<dyn TelemetryRuntimeHook>>,
    sampler: Option<SamplerOwner>,
    traffic: Arc<LogicalTraffic>,
}

struct SamplerOwner {
    samples: watch::Receiver<Option<HostMetrics>>,
    shutdown: CancellationToken,
    owner: JoinHandle<()>,
}

impl TelemetryRuntime {
    pub(crate) fn start(
        config: Option<TelemetryConfig>,
        report_interval_override: Option<Duration>,
        hook: Option<Arc<dyn TelemetryRuntimeHook>>,
        traffic: Arc<LogicalTraffic>,
    ) -> Option<Self> {
        let config = config.unwrap_or_default();
        if !config.enabled {
            return None;
        }
        let sample_interval = Duration::from_secs(config.sample_interval_secs);
        let report_interval = report_interval_override
            .unwrap_or_else(|| Duration::from_secs(config.report_interval_secs));

        Some(Self {
            sample_interval,
            report_interval,
            hook,
            sampler: None,
            traffic,
        })
    }

    pub(crate) fn generation(&mut self) -> GenerationTelemetry {
        if self.sampler.is_none() {
            if let Some(hook) = &self.hook {
                hook.sampler_started();
            }
            let shutdown = CancellationToken::new();
            let owner_shutdown = shutdown.clone();
            let (samples, receiver) = watch::channel(None);
            let sample_interval = self.sample_interval;
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
            self.sampler = Some(SamplerOwner {
                samples: receiver,
                shutdown,
                owner,
            });
        }
        let samples = self
            .sampler
            .as_ref()
            .expect("the sampler was initialized above")
            .samples
            .clone();
        let (last_sent, last_received) = self.traffic.totals();
        GenerationTelemetry {
            samples,
            report_interval: self.report_interval,
            hook: self.hook.clone(),
            traffic: self.traffic.clone(),
            last_sent,
            last_received,
            last_rate_sample: Instant::now(),
        }
    }

    pub(crate) async fn shutdown(self) -> Result<(), ClientError> {
        let Some(sampler) = self.sampler else {
            return Ok(());
        };
        sampler.shutdown.cancel();
        sampler.owner.await.map_err(|_| ClientError::TaskJoin)
    }
}

/// A generation-scoped publisher. Dropping its output queue discards every
/// report that belonged to the disconnected generation.
pub(crate) struct GenerationTelemetry {
    samples: watch::Receiver<Option<HostMetrics>>,
    report_interval: Duration,
    hook: Option<Arc<dyn TelemetryRuntimeHook>>,
    traffic: Arc<LogicalTraffic>,
    last_sent: u64,
    last_received: u64,
    last_rate_sample: Instant,
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
        let _activation = self.traffic.activate();
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
                    let now = Instant::now();
                    let (sent, received) = self.traffic.totals();
                    if let Some(hook) = &self.hook {
                        hook.after_traffic_snapshot(sent, received);
                    }
                    let elapsed = now.saturating_duration_since(self.last_rate_sample);
                    let tx_bytes_per_sec = rate_per_second(sent.saturating_sub(self.last_sent), elapsed);
                    let rx_bytes_per_sec = rate_per_second(received.saturating_sub(self.last_received), elapsed);
                    self.last_sent = sent;
                    self.last_received = received;
                    self.last_rate_sample = now;
                    reports.send_replace(Some(report_from_sample(
                        sample,
                        sequence,
                        tx_bytes_per_sec,
                        rx_bytes_per_sec,
                    )));
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

fn report_from_sample(
    sample: HostMetrics,
    sequence: u64,
    tx_bytes_per_sec: u64,
    rx_bytes_per_sec: u64,
) -> TelemetryReport {
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
        tx_bytes_per_sec,
        rx_bytes_per_sec,
    }
}

fn rate_per_second(bytes: u64, elapsed: Duration) -> u64 {
    let elapsed_millis = elapsed.as_millis().max(1);
    u64::try_from(u128::from(bytes).saturating_mul(1_000) / elapsed_millis).unwrap_or(u64::MAX)
}

fn bounded_pair(used: Option<u64>, total: Option<u64>) -> (u64, u64) {
    match (used, total) {
        (Some(used), Some(total)) => (used.min(total), total),
        _ => (0, 0),
    }
}

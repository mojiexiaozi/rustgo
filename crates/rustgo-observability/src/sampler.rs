use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sysinfo::{Disks, Networks, System};
use tokio::{sync::mpsc, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::HostMetrics;

const BASIS_POINTS_PER_PERCENT: f32 = 100.0;
const BASIS_POINTS_PER_HUNDRED_PERCENT: u16 = 10_000;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Stateful, cross-platform host resource sampler.
///
/// Keeping the `sysinfo` sources and network counters alive is necessary for
/// CPU and network deltas to describe the interval since the prior sample.
pub struct HostSampler {
    system: System,
    disks: Disks,
    networks: Networks,
    previous_networks: Option<BTreeMap<String, NetworkCounters>>,
    previous_sampled_at: Option<Instant>,
}

impl Default for HostSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl HostSampler {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            previous_networks: None,
            previous_sampled_at: None,
        }
    }

    /// Samples currently available host resources without failing the caller
    /// when a platform cannot expose a particular resource.
    pub fn sample(&mut self) -> HostMetrics {
        let sampled_at = Instant::now();
        let mut metrics = HostMetrics {
            sampled_unix_millis: unix_millis_now(),
            ..HostMetrics::default()
        };

        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        if sysinfo::IS_SUPPORTED_SYSTEM {
            metrics.cpu_basis_points = percent_to_basis_points(self.system.global_cpu_usage());
            let memory_total = self.system.total_memory();
            if memory_total > 0 {
                metrics.memory_total_bytes = Some(memory_total);
                metrics.memory_used_bytes = Some(self.system.used_memory().min(memory_total));
            }
        } else {
            tracing::warn!("host resource sampling is unavailable on this platform");
        }

        self.disks.refresh(true);
        let (disk_used_bytes, disk_total_bytes, disk_available) = aggregate_disks(&self.disks);
        if disk_available {
            metrics.disk_used_bytes = Some(disk_used_bytes);
            metrics.disk_total_bytes = Some(disk_total_bytes);
        }

        self.networks.refresh(true);
        let current_networks = aggregate_networks(&self.networks);
        let elapsed = self
            .previous_sampled_at
            .map(|previous| sampled_at.saturating_duration_since(previous));
        let rates = network_rates(self.previous_networks.as_ref(), &current_networks, elapsed);
        metrics.network_rx_bytes_per_sec = rates.map(|rates| rates.received_bytes);
        metrics.network_tx_bytes_per_sec = rates.map(|rates| rates.sent_bytes);

        self.previous_networks = (!current_networks.is_empty()).then_some(current_networks);
        self.previous_sampled_at = Some(sampled_at);
        metrics
    }

    /// Repeatedly samples the host until cancellation or receiver closure.
    ///
    /// A slow receiver delays the next tick rather than causing a burst of
    /// stale samples. A closed receiver is a normal lifecycle boundary.
    pub async fn run(
        &mut self,
        interval: Duration,
        sender: mpsc::Sender<HostMetrics>,
        shutdown: CancellationToken,
    ) {
        if interval.is_zero() {
            tracing::warn!("host sampler received a zero interval; stopping sampler");
            return;
        }

        let mut ticks = tokio::time::interval(interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = ticks.tick() => {
                    let sample = self.sample();
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => return,
                        result = sender.send(sample) => {
                            if result.is_err() {
                                tracing::warn!("host sampler receiver closed; stopping sampler");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct NetworkCounters {
    received_bytes: u64,
    sent_bytes: u64,
}

fn aggregate_disks(disks: &Disks) -> (u64, u64, bool) {
    let mut used_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut available = false;

    for disk in disks {
        let total = disk.total_space();
        if total == 0 {
            continue;
        }
        available = true;
        total_bytes = total_bytes.saturating_add(total);
        used_bytes = used_bytes.saturating_add(total.saturating_sub(disk.available_space()));
    }

    (used_bytes.min(total_bytes), total_bytes, available)
}

fn aggregate_networks(networks: &Networks) -> BTreeMap<String, NetworkCounters> {
    networks
        .iter()
        .filter(|(name, _)| !is_loopback_interface(name))
        .map(|(name, data)| {
            (
                name.to_string(),
                NetworkCounters {
                    received_bytes: data.total_received(),
                    sent_bytes: data.total_transmitted(),
                },
            )
        })
        .collect()
}

fn is_loopback_interface(name: &str) -> bool {
    matches!(name, "lo" | "lo0") || name.to_ascii_lowercase().contains("loopback")
}

fn network_rates(
    previous: Option<&BTreeMap<String, NetworkCounters>>,
    current: &BTreeMap<String, NetworkCounters>,
    elapsed: Option<Duration>,
) -> Option<NetworkCounters> {
    let previous = previous?;
    let elapsed = elapsed?;
    if previous.is_empty() || current.is_empty() || previous.len() != current.len() {
        return Some(NetworkCounters::default());
    }

    let mut received_delta = 0_u64;
    let mut sent_delta = 0_u64;
    for (name, current_counters) in current {
        let Some(previous_counters) = previous.get(name) else {
            return Some(NetworkCounters::default());
        };
        if current_counters.received_bytes < previous_counters.received_bytes
            || current_counters.sent_bytes < previous_counters.sent_bytes
        {
            return Some(NetworkCounters::default());
        }
        received_delta = received_delta.saturating_add(
            current_counters
                .received_bytes
                .saturating_sub(previous_counters.received_bytes),
        );
        sent_delta = sent_delta.saturating_add(
            current_counters
                .sent_bytes
                .saturating_sub(previous_counters.sent_bytes),
        );
    }

    Some(NetworkCounters {
        received_bytes: bytes_per_second(received_delta, elapsed),
        sent_bytes: bytes_per_second(sent_delta, elapsed),
    })
}

fn bytes_per_second(bytes: u64, elapsed: Duration) -> u64 {
    let elapsed_nanos = elapsed.as_nanos();
    if elapsed_nanos == 0 {
        return 0;
    }
    let per_second = u128::from(bytes)
        .saturating_mul(NANOS_PER_SECOND)
        .checked_div(elapsed_nanos)
        .unwrap_or(0);
    u64::try_from(per_second).unwrap_or(u64::MAX)
}

fn percent_to_basis_points(percent: f32) -> Option<u16> {
    percent.is_finite().then(|| {
        (percent * BASIS_POINTS_PER_PERCENT)
            .clamp(0.0, f32::from(BASIS_POINTS_PER_HUNDRED_PERCENT))
            .round() as u16
    })
}

fn unix_millis_now() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

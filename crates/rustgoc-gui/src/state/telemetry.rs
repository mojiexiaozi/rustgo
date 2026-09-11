#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

const MAX_TELEMETRY_POINTS: usize = 300;

#[derive(Clone, Debug)]
pub struct TelemetryPoint {
    pub timestamp: u64,
    pub cpu_basis_points: u64,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub tx_bytes_per_sec: u64,
    pub rx_bytes_per_sec: u64,
}

#[derive(Clone)]
pub struct TelemetryHistory {
    inner: Arc<Mutex<TelemetryHistoryInner>>,
}

struct TelemetryHistoryInner {
    points: VecDeque<TelemetryPoint>,
    last_tx_bytes: u64,
    last_rx_bytes: u64,
}

impl TelemetryHistory {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TelemetryHistoryInner {
                points: VecDeque::with_capacity(MAX_TELEMETRY_POINTS),
                last_tx_bytes: 0,
                last_rx_bytes: 0,
            })),
        }
    }

    pub fn push(&self, point: TelemetryPoint) {
        let mut inner = self.inner.lock().unwrap();
        if inner.points.len() >= MAX_TELEMETRY_POINTS {
            inner.points.pop_front();
        }
        inner.points.push_back(point);
    }

    pub fn snapshot(&self) -> Vec<TelemetryPoint> {
        let inner = self.inner.lock().unwrap();
        inner.points.iter().cloned().collect()
    }

    pub fn update_traffic_delta(&self, sent_bytes: u64, received_bytes: u64, delta_secs: f64) {
        let mut inner = self.inner.lock().unwrap();

        let tx_rate = if sent_bytes >= inner.last_tx_bytes && delta_secs > 0.0 {
            ((sent_bytes - inner.last_tx_bytes) as f64 / delta_secs) as u64
        } else {
            0
        };

        let rx_rate = if received_bytes >= inner.last_rx_bytes && delta_secs > 0.0 {
            ((received_bytes - inner.last_rx_bytes) as f64 / delta_secs) as u64
        } else {
            0
        };

        inner.last_tx_bytes = sent_bytes;
        inner.last_rx_bytes = received_bytes;

        if let Some(last_point) = inner.points.back_mut() {
            last_point.tx_bytes_per_sec = tx_rate;
            last_point.rx_bytes_per_sec = rx_rate;
        }
    }
}

impl Default for TelemetryHistory {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn sample_telemetry(
    history: TelemetryHistory,
    cancel: CancellationToken,
    interval_secs: u64,
) {
    let mut sampler = rustgo_observability::HostSampler::new();
    let mut ticker = interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = ticker.tick() => {
                let metrics = sampler.sample();

                let cpu = metrics.cpu_basis_points.unwrap_or(0);
                let memory = metrics.memory_used_bytes.unwrap_or(0);

                history.push(TelemetryPoint {
                    timestamp: metrics.sampled_unix_millis,
                    cpu_basis_points: cpu as u64,
                    memory_bytes: memory,
                    disk_bytes: metrics.disk_used_bytes.unwrap_or(0),
                    tx_bytes_per_sec: 0,
                    rx_bytes_per_sec: 0,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_capacity_and_drop_oldest() {
        let history = TelemetryHistory::new();

        for i in 0..350 {
            history.push(TelemetryPoint {
                timestamp: i,
                cpu_basis_points: i * 100,
                memory_bytes: i * 1000,
                disk_bytes: i * 2000,
                tx_bytes_per_sec: 0,
                rx_bytes_per_sec: 0,
            });
        }

        let snapshot = history.snapshot();
        assert_eq!(snapshot.len(), MAX_TELEMETRY_POINTS);
        assert_eq!(snapshot[0].timestamp, 350 - MAX_TELEMETRY_POINTS as u64);
        assert_eq!(snapshot[MAX_TELEMETRY_POINTS - 1].timestamp, 349);
    }

    #[test]
    fn test_traffic_delta_to_rate() {
        let history = TelemetryHistory::new();

        history.push(TelemetryPoint {
            timestamp: 0,
            cpu_basis_points: 500,
            memory_bytes: 1_000_000,
            disk_bytes: 2_000_000,
            tx_bytes_per_sec: 0,
            rx_bytes_per_sec: 0,
        });

        history.update_traffic_delta(10_000, 20_000, 2.0);

        let snapshot = history.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].tx_bytes_per_sec, 5_000);
        assert_eq!(snapshot[0].rx_bytes_per_sec, 10_000);

        history.update_traffic_delta(15_000, 30_000, 1.0);

        let snapshot = history.snapshot();
        assert_eq!(snapshot[0].tx_bytes_per_sec, 5_000);
        assert_eq!(snapshot[0].rx_bytes_per_sec, 10_000);
    }

    #[tokio::test]
    async fn test_sampler_cancellation() {
        let history = TelemetryHistory::new();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            sample_telemetry(history, cancel_clone, 1).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok());
    }
}

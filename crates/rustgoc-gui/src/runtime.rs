#![forbid(unsafe_code)]
#![allow(dead_code)]

use crate::state::telemetry::TelemetryHistory;
use rustgoc::{ClientApp, TrafficHandle};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

pub struct ClientRuntime {
    runtime: Option<Runtime>,
    state: Arc<Mutex<RuntimeState>>,
    telemetry_shutdown: CancellationToken,
}

struct RuntimeState {
    shutdown: Option<CancellationToken>,
    generation: u64,
    traffic_handle: Option<TrafficHandle>,
}

impl ClientRuntime {
    pub fn enroll(
        &self,
        mut config: rustgo_config::ClientConfig,
        config_path: std::path::PathBuf,
        key: String,
    ) -> std::sync::mpsc::Receiver<Result<rustgoc::EnrollmentCompletion, String>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        if let Some(runtime) = &self.runtime {
            runtime.spawn(async move {
                let result = rustgoc::enroll(&mut config, &config_path, key.trim())
                    .await
                    .map_err(|error| error.to_string());
                let _ = sender.send(result);
            });
        } else {
            let _ = sender.send(Err("注册运行时不可用".to_owned()));
        }
        receiver
    }

    pub fn recover_enrollment(
        &self,
        mut config: rustgo_config::ClientConfig,
        config_path: std::path::PathBuf,
    ) -> std::sync::mpsc::Receiver<Result<bool, String>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        if let Some(runtime) = &self.runtime {
            runtime.spawn(async move {
                let result = rustgoc::recover_pending_enrollment(&mut config, &config_path)
                    .await
                    .map_err(|error| error.to_string());
                let _ = sender.send(result);
            });
        }
        receiver
    }

    pub fn new(telemetry_history: TelemetryHistory) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let state = Arc::new(Mutex::new(RuntimeState {
            shutdown: None,
            generation: 0,
            traffic_handle: None,
        }));
        let telemetry_shutdown = CancellationToken::new();

        runtime.spawn(run_telemetry_sampling(
            telemetry_history,
            state.clone(),
            telemetry_shutdown.clone(),
        ));

        Ok(Self {
            runtime: Some(runtime),
            state,
            telemetry_shutdown,
        })
    }

    pub fn connect(&self, app: ClientApp, traffic_handle: Option<TrafficHandle>) {
        if let Some(runtime) = &self.runtime {
            let shutdown = CancellationToken::new();
            let generation = {
                let mut guard = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(previous) = guard.shutdown.replace(shutdown.clone()) {
                    previous.cancel();
                }
                guard.generation += 1;
                guard.traffic_handle = traffic_handle;
                guard.generation
            };
            let state = self.state.clone();

            // Spawn client task
            let client_shutdown = shutdown.clone();
            runtime.spawn(async move {
                let result = app.run_until(client_shutdown).await;

                let mut guard = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if guard.generation == generation {
                    guard.shutdown = None;
                    guard.traffic_handle = None;
                }

                if let Err(e) = result {
                    tracing::error!("Client error: {}", e);
                }
            });
        }
    }

    pub fn disconnect(&self) {
        let shutdown = {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.traffic_handle = None;
            guard.shutdown.take()
        };
        if let Some(token) = shutdown {
            token.cancel();
        }
    }
}

impl Drop for ClientRuntime {
    fn drop(&mut self) {
        self.disconnect();
        self.telemetry_shutdown.cancel();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(std::time::Duration::from_secs(5));
        }
    }
}

async fn run_telemetry_sampling(
    history: TelemetryHistory,
    state: Arc<Mutex<RuntimeState>>,
    cancel: CancellationToken,
) {
    const SAMPLE_INTERVAL_SECS: u64 = 2;

    let mut sampler = rustgo_observability::HostSampler::new();
    let mut ticker = interval(Duration::from_secs(SAMPLE_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = ticker.tick() => {
                let metrics = sampler.sample();
                history.push(crate::state::telemetry::TelemetryPoint {
                    timestamp: metrics.sampled_unix_millis,
                    cpu_basis_points: metrics.cpu_basis_points.unwrap_or(0) as u64,
                    memory_bytes: metrics.memory_used_bytes.unwrap_or(0),
                    disk_bytes: metrics.disk_used_bytes.unwrap_or(0),
                    tx_bytes_per_sec: 0,
                    rx_bytes_per_sec: 0,
                });

                let traffic_handle = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .traffic_handle
                    .clone();
                if let Some(traffic_handle) = traffic_handle {
                    let snapshot = traffic_handle.snapshot();
                    history.update_traffic_delta(
                        snapshot.sent_bytes(),
                        snapshot.received_bytes(),
                        SAMPLE_INTERVAL_SECS as f64,
                    );
                }
            }
        }
    }
}

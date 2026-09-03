#![forbid(unsafe_code)]
#![allow(dead_code)]

use rustgoc::ClientApp;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub struct ClientRuntime {
    runtime: Option<Runtime>,
    state: Arc<Mutex<RuntimeState>>,
}

struct RuntimeState {
    shutdown: Option<CancellationToken>,
    generation: u64,
}

impl ClientRuntime {
    pub fn new() -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let state = Arc::new(Mutex::new(RuntimeState {
            shutdown: None,
            generation: 0,
        }));

        Ok(Self {
            runtime: Some(runtime),
            state,
        })
    }

    pub fn connect(&self, app: ClientApp) {
        let state = self.state.clone();
        if let Some(runtime) = &self.runtime {
            runtime.spawn(async move {
                let shutdown = CancellationToken::new();
                let generation = {
                    let mut guard = state.lock().await;
                    guard.generation += 1;
                    guard.shutdown = Some(shutdown.clone());
                    guard.generation
                };

                let result = app.run_until(shutdown.clone()).await;

                let mut guard = state.lock().await;
                if guard.generation == generation {
                    guard.shutdown = None;
                }

                if let Err(e) = result {
                    tracing::error!("Client error: {}", e);
                }
            });
        }
    }

    pub fn disconnect(&self) {
        let state = self.state.clone();
        if let Some(runtime) = &self.runtime {
            runtime.spawn(async move {
                let shutdown = {
                    let mut guard = state.lock().await;
                    guard.shutdown.take()
                };
                if let Some(token) = shutdown {
                    token.cancel();
                }
            });
        }
    }
}

impl Drop for ClientRuntime {
    fn drop(&mut self) {
        self.disconnect();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(std::time::Duration::from_secs(5));
        }
    }
}

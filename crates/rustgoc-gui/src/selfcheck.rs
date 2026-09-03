#![forbid(unsafe_code)]

use rustgoc::ClientApp;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const SELFCHECK_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = rustgo_config::load_client(config_path)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let app = ClientApp::from_config(config)?;
        let status_rx = app.subscribe();
        let traffic_handle = app.traffic_handle();
        let path_status_store = app.path_status_store().clone();
        let shutdown = CancellationToken::new();

        let app_handle = tokio::spawn({
            let shutdown = shutdown.clone();
            async move { app.run_until(shutdown).await }
        });

        let wait_result = timeout(SELFCHECK_TIMEOUT, async {
            loop {
                if status_rx.borrow().active().is_some() {
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await;

        if wait_result.is_err() {
            shutdown.cancel();
            let _ = app_handle.await;
            anyhow::bail!("Timeout: client did not reach active status within 30 seconds");
        }

        let status = status_rx.borrow().clone();
        let active = status.active().expect("active status checked above");

        if let Some(handle) = traffic_handle {
            let snapshot = handle.snapshot();
            println!(
                "Traffic: tx={} rx={}",
                snapshot.sent_bytes(),
                snapshot.received_bytes()
            );
        }

        let paths = path_status_store.snapshot();
        if paths.is_empty() {
            println!("Path status: no active P2P paths");
        } else {
            for (export_name, path_status) in paths {
                println!(
                    "Path status: export={} kind={:?}",
                    export_name, path_status.kind
                );
            }
        }

        println!(
            "Selfcheck passed: generation={} tunnels={}",
            active.generation().get(),
            active.registered_tunnels().len()
        );

        shutdown.cancel();
        let _ = app_handle.await;

        Ok(())
    })
}

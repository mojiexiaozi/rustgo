use std::time::Duration;

use rustgo_observability::{HostMetrics, HostSampler};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn host_sampler_reports_bounded_metrics_and_cancels_cleanly() {
    let mut sampler = HostSampler::new();
    let first = sampler.sample();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let second = sampler.sample();

    assert_metrics_are_bounded(&first);
    assert_metrics_are_bounded(&second);
    assert!(second.sampled_unix_millis >= first.sampled_unix_millis);

    let (sender, mut receiver) = mpsc::channel(1);
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        HostSampler::new()
            .run(Duration::from_millis(10), sender, task_shutdown)
            .await;
    });

    let sample = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await
        .expect("sampler must produce an initial sample before cancellation")
        .expect("sampler sender must remain open before cancellation");
    assert_metrics_are_bounded(&sample);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("sampler must stop after cancellation")
        .expect("sampler task must not panic");
}

fn assert_metrics_are_bounded(metrics: &HostMetrics) {
    assert!(metrics.cpu_basis_points.is_none_or(|cpu| cpu <= 10_000));
    assert_pair_is_bounded(metrics.memory_used_bytes, metrics.memory_total_bytes);
    assert_pair_is_bounded(metrics.disk_used_bytes, metrics.disk_total_bytes);
    assert_eq!(
        metrics.network_rx_bytes_per_sec.is_some(),
        metrics.network_tx_bytes_per_sec.is_some()
    );
}

fn assert_pair_is_bounded(used: Option<u64>, total: Option<u64>) {
    assert_eq!(used.is_some(), total.is_some());
    assert!(used.zip(total).is_none_or(|(used, total)| used <= total));
}

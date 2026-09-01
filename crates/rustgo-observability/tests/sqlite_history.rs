use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use rustgo_observability::{
    AuthenticatedClientIdentity, BoundedLabel, ClientHistorySample, ClientLifecycleKind,
    ClientLifecycleRecord, HISTORY_BATCH_QUEUE_CAPACITY, HISTORY_SCHEMA_VERSION, HistoryBatch,
    HistoryConfig, HistoryMetric, HistoryPublishError, HistoryQuery, HistoryResolution,
    HistoryScope, HistoryService, HistoryWorkerHandle, HostMetrics, MAX_HISTORY_POINTS,
    MAX_HISTORY_QUEUE_BYTES, ServerHistorySample, SessionKind, SessionPath, SessionSnapshot,
    ShortSessionId, TrafficCounters,
};

const MINUTE_MILLIS: u64 = 60_000;
const FIVE_MINUTE_BUCKET_MILLIS: u64 = 5 * MINUTE_MILLIS;
const HOUR_MILLIS: u64 = 60 * MINUTE_MILLIS;
const DAY_MILLIS: u64 = 24 * HOUR_MILLIS;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rustgo-sqlite-history-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("metrics.db")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config(path: PathBuf) -> HistoryConfig {
    HistoryConfig {
        database_path: path,
        history_days: 7,
        database_max_mib: 16,
    }
}

fn host_metrics(timestamp: u64, cpu: u16) -> HostMetrics {
    HostMetrics {
        sampled_unix_millis: timestamp,
        cpu_basis_points: Some(cpu),
        process_cpu_basis_points: Some(cpu / 2),
        memory_used_bytes: Some(400),
        memory_total_bytes: Some(1_000),
        process_memory_bytes: Some(100),
        disk_used_bytes: Some(2_000),
        disk_total_bytes: Some(10_000),
        disk_read_bytes_per_sec: Some(11),
        disk_write_bytes_per_sec: Some(12),
        network_rx_bytes_per_sec: Some(13),
        network_tx_bytes_per_sec: Some(14),
    }
}

fn server_sample(timestamp: u64, cpu: u16) -> ServerHistorySample {
    ServerHistorySample {
        timestamp_unix_millis: timestamp,
        metrics: host_metrics(timestamp, cpu),
        traffic: TrafficCounters {
            received_bytes: u64::from(cpu),
            sent_bytes: u64::from(cpu) * 2,
        },
    }
}

fn client(name: &str, generation: u64) -> AuthenticatedClientIdentity {
    AuthenticatedClientIdentity::from_server_authentication(name, generation).unwrap()
}

fn query(
    scope: HistoryScope,
    metric: HistoryMetric,
    start: u64,
    end: u64,
    resolution: HistoryResolution,
) -> HistoryQuery {
    HistoryQuery {
        scope,
        metric,
        start_unix_millis: start,
        end_unix_millis: end,
        resolution,
        max_points: MAX_HISTORY_POINTS,
    }
}

async fn stop(service: HistoryService, worker: HistoryWorkerHandle) {
    service.close();
    worker.shutdown().await.unwrap();
}

fn total_database_bytes(path: &Path) -> u64 {
    [
        path.to_path_buf(),
        sidecar(path, "-wal"),
        sidecar(path, "-shm"),
    ]
    .into_iter()
    .filter_map(|candidate| fs::metadata(candidate).ok())
    .map(|metadata| metadata.len())
    .sum()
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn session_summary(sequence: u64, client_name: &str, timestamp: u64) -> SessionSnapshot {
    let long_label = BoundedLabel::try_from("s".repeat(128)).unwrap();
    SessionSnapshot {
        id: ShortSessionId::from_bytes(format!("history-session-{sequence}").as_bytes()),
        client: BoundedLabel::try_from(client_name).unwrap(),
        peer: Some(long_label.clone()),
        tunnel: Some(long_label.clone()),
        export: Some(long_label.clone()),
        kind: SessionKind::P2p,
        path: SessionPath::P2pDirect,
        traffic: TrafficCounters {
            received_bytes: sequence,
            sent_bytes: sequence.saturating_mul(2),
        },
        opened_unix_millis: timestamp,
        closed_unix_millis: Some(timestamp.saturating_add(1)),
        terminal_reason: Some(long_label),
    }
}

fn large_session_batch(seed: u64, count: usize, timestamp: u64) -> HistoryBatch {
    HistoryBatch {
        session_summaries: (0..count)
            .map(|index| {
                session_summary(
                    seed.saturating_add(index as u64),
                    &"c".repeat(128),
                    timestamp.saturating_add(index as u64),
                )
            })
            .collect(),
        ..HistoryBatch::default()
    }
}

async fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrates_to_wal_and_persists_points_across_restart() {
    let directory = TestDirectory::new("restart");
    let database = directory.database();
    {
        let connection = Connection::open(&database).unwrap();
        connection.pragma_update(None, "user_version", 0).unwrap();
    }

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let task = worker.start().unwrap();
    let persisted_client = client("restart-client", 3);
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(1_000, 2_500)],
            client_lifecycle: vec![ClientLifecycleRecord {
                client: persisted_client.clone(),
                kind: ClientLifecycleKind::Authenticated,
                timestamp_unix_millis: 900,
                version: Some(BoundedLabel::try_from("0.3.0").unwrap()),
            }],
            session_summaries: vec![SessionSnapshot {
                id: ShortSessionId::from_bytes(b"restart-session"),
                client: BoundedLabel::try_from(persisted_client.name()).unwrap(),
                peer: None,
                tunnel: Some(BoundedLabel::try_from("ssh").unwrap()),
                export: None,
                kind: SessionKind::Tcp,
                path: SessionPath::Relay,
                traffic: TrafficCounters {
                    received_bytes: 10,
                    sent_bytes: 20,
                },
                opened_unix_millis: 950,
                closed_unix_millis: Some(1_050),
                terminal_reason: Some(BoundedLabel::try_from("complete").unwrap()),
            }],
            ..HistoryBatch::default()
        })
        .unwrap();
    let first = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            2_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(first.points.len(), 1);
    assert_eq!(first.points[0].value, 2_500.0);
    stop(service, task).await;

    let connection = Connection::open(&database).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    let lifecycle_rows: usize = connection
        .query_row("SELECT COUNT(*) FROM client_lifecycle", [], |row| {
            row.get(0)
        })
        .unwrap();
    let session_rows: usize = connection
        .query_row("SELECT COUNT(*) FROM session_summaries", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, HISTORY_SCHEMA_VERSION);
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(lifecycle_rows, 1);
    assert_eq!(session_rows, 1);
    drop(connection);

    let (service, worker) = HistoryService::new(config(database)).unwrap();
    let task = worker.start().unwrap();
    let restarted = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            2_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(restarted.points, first.points);
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregation_is_idempotent_and_retention_keeps_the_expected_tiers() {
    let directory = TestDirectory::new("aggregation");
    let now = 10 * DAY_MILLIS;
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let task = worker.start().unwrap();

    let minute_bucket = now - (2 * HOUR_MILLIS);
    let five_minute_bucket = now - (2 * DAY_MILLIS);
    let expired = now - (8 * DAY_MILLIS);
    service
        .try_publish(HistoryBatch {
            server_points: vec![
                server_sample(minute_bucket + 1_000, 1_000),
                server_sample(minute_bucket + 2_000, 3_000),
                server_sample(five_minute_bucket + 1_000, 2_000),
                server_sample(five_minute_bucket + 2_000, 4_000),
                server_sample(expired, 9_000),
                server_sample(now - 1_000, 5_000),
            ],
            ..HistoryBatch::default()
        })
        .unwrap();

    service.maintain(now).await.unwrap();
    service.maintain(now).await.unwrap();

    let minute = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            minute_bucket,
            minute_bucket + MINUTE_MILLIS,
            HistoryResolution::OneMinute,
        ))
        .await
        .unwrap();
    assert_eq!(minute.points.len(), 1);
    assert_eq!(minute.points[0].value, 2_000.0);

    let five_minute = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            five_minute_bucket,
            five_minute_bucket + (5 * MINUTE_MILLIS),
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert_eq!(five_minute.points.len(), 1);
    assert_eq!(five_minute.points[0].value, 3_000.0);

    let raw = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            now,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(raw.points.len(), 1);
    assert_eq!(raw.points[0].value, 5_000.0);

    let expired = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            now - (7 * DAY_MILLIS),
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert!(expired.points.is_empty());
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_queries_observe_ordered_writes_and_point_limits_are_hard() {
    let directory = TestDirectory::new("concurrent");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let task = worker.start().unwrap();
    let writer = {
        let service = service.clone();
        tokio::spawn(async move {
            for index in 0..2_100_u64 {
                service
                    .try_publish(HistoryBatch {
                        server_points: vec![server_sample(index, (index % 10_000) as u16)],
                        ..HistoryBatch::default()
                    })
                    .unwrap();
                if index % 100 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        })
    };
    let reader =
        {
            let service = service.clone();
            tokio::spawn(async move {
                for _ in 0..20 {
                    let series = service
                        .query(query(
                            HistoryScope::Server,
                            HistoryMetric::CpuBasisPoints,
                            0,
                            3_000,
                            HistoryResolution::Raw,
                        ))
                        .await
                        .unwrap();
                    assert!(series.points.len() <= MAX_HISTORY_POINTS);
                    assert!(series.points.windows(2).all(|pair| {
                        pair[0].timestamp_unix_millis < pair[1].timestamp_unix_millis
                    }));
                }
            })
        };
    writer.await.unwrap();
    reader.await.unwrap();

    let limited = service
        .query(HistoryQuery {
            max_points: 17,
            ..query(
                HistoryScope::Server,
                HistoryMetric::CpuBasisPoints,
                0,
                3_000,
                HistoryResolution::Raw,
            )
        })
        .await
        .unwrap();
    assert_eq!(limited.points.len(), 17);
    assert!(
        service
            .query(HistoryQuery {
                max_points: MAX_HISTORY_POINTS + 1,
                ..query(
                    HistoryScope::Server,
                    HistoryMetric::CpuBasisPoints,
                    0,
                    3_000,
                    HistoryResolution::Raw,
                )
            })
            .await
            .is_err()
    );
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn size_cap_counts_database_wal_and_shm_and_prunes_oldest_history_first() {
    let directory = TestDirectory::new("cap");
    let database = directory.database();
    let mut cap_config = config(database.clone());
    cap_config.database_max_mib = 1;
    let (service, worker) = HistoryService::new(cap_config).unwrap();
    let task = worker.start().unwrap();
    let identity = client(&"x".repeat(128), 1);
    let long_reason = BoundedLabel::try_from("r".repeat(128)).unwrap();
    let now = 20 * DAY_MILLIS;

    for chunk in 0..24_u64 {
        let mut batch = HistoryBatch::default();
        for index in 0..400_u64 {
            let sequence = (chunk * 400) + index;
            let timestamp = now - (2 * DAY_MILLIS) + sequence;
            batch.server_points.push(server_sample(timestamp, 1_000));
            batch.client_lifecycle.push(ClientLifecycleRecord {
                client: identity.clone(),
                kind: ClientLifecycleKind::Disconnected,
                timestamp_unix_millis: timestamp,
                version: None,
            });
            batch.session_summaries.push(SessionSnapshot {
                id: ShortSessionId::from_bytes(format!("session-{sequence}").as_bytes()),
                client: BoundedLabel::try_from(identity.name()).unwrap(),
                peer: None,
                tunnel: Some(long_reason.clone()),
                export: None,
                kind: SessionKind::Tcp,
                path: SessionPath::Relay,
                traffic: TrafficCounters::default(),
                opened_unix_millis: timestamp,
                closed_unix_millis: Some(timestamp + 1),
                terminal_reason: Some(long_reason.clone()),
            });
        }
        service.try_publish(batch).unwrap();
    }

    service.maintain(now).await.unwrap();
    let health = service.health();
    assert_eq!(health.total_database_bytes, total_database_bytes(&database));
    assert!(
        health.total_database_bytes <= 1024 * 1024 || health.size_floor_reached,
        "database family still exceeded the cap without reaching its minimum: {health:?}"
    );
    let old_five_minute = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            now - (3 * DAY_MILLIS),
            now,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert!(old_five_minute.points.len() < 32);
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_database_is_quarantined_and_history_recovers_without_losing_live_ownership() {
    let directory = TestDirectory::new("corrupt");
    let database = directory.database();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let task = worker.start().unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(1_000, 123)],
            ..HistoryBatch::default()
        })
        .unwrap();
    service.checkpoint().await.unwrap();
    stop(service, task).await;
    assert!(sidecar(&database, ".rustgo-owner").is_file());

    fs::write(&database, b"this is not a sqlite database").unwrap();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    assert!(!service.health().history_available);
    let task = worker.start().unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let health = service.health();
            if health.history_available && health.recoveries > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(9_000, 777)],
            ..HistoryBatch::default()
        })
        .unwrap();
    let recovered = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            10_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(recovered.points[0].value, 777.0);
    assert!(fs::read_dir(&directory.0).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("metrics.db.quarantine-")
    }));
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_batch_queue_drops_the_oldest_pending_batch() {
    let directory = TestDirectory::new("queue");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    for timestamp in 0..=HISTORY_BATCH_QUEUE_CAPACITY as u64 {
        service
            .try_publish(HistoryBatch {
                server_points: vec![server_sample(timestamp, timestamp as u16)],
                ..HistoryBatch::default()
            })
            .unwrap();
    }
    assert_eq!(service.health().dropped_batches, 1);
    assert_eq!(
        service.health().pending_batches,
        HISTORY_BATCH_QUEUE_CAPACITY
    );

    let task = worker.start().unwrap();
    let series = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            HISTORY_BATCH_QUEUE_CAPACITY as u64,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(series.points.len(), HISTORY_BATCH_QUEUE_CAPACITY);
    assert_eq!(series.points[0].timestamp_unix_millis, 1);
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_history_is_scoped_to_the_authenticated_name() {
    let directory = TestDirectory::new("client-scope");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let task = worker.start().unwrap();
    service
        .try_publish(HistoryBatch {
            client_points: vec![
                ClientHistorySample {
                    client: client("alpha", 1),
                    timestamp_unix_millis: 1_000,
                    metrics: host_metrics(1_000, 111),
                    traffic: TrafficCounters::default(),
                },
                ClientHistorySample {
                    client: client("beta", 1),
                    timestamp_unix_millis: 1_000,
                    metrics: host_metrics(1_000, 222),
                    traffic: TrafficCounters::default(),
                },
            ],
            ..HistoryBatch::default()
        })
        .unwrap();
    let alpha = service
        .query(query(
            HistoryScope::Client(BoundedLabel::try_from("alpha").unwrap()),
            HistoryMetric::CpuBasisPoints,
            0,
            2_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(alpha.points.len(), 1);
    assert_eq!(alpha.points[0].value, 111.0);
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_cap_enforcement_runs_after_writes_without_manual_maintenance() {
    let directory = TestDirectory::new("automatic-cap");
    let database = directory.database();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    let now = 20 * DAY_MILLIS;

    for chunk in 0..30_u64 {
        service
            .try_publish(large_session_batch(
                chunk * 300,
                300,
                now - (2 * DAY_MILLIS) + (chunk * 300),
            ))
            .unwrap();
    }
    wait_until(
        || service.health().pending_batches == 0,
        Duration::from_secs(10),
    )
    .await;
    stop(service, worker).await;
    assert!(total_database_bytes(&database) > 1024 * 1024);

    let mut cap_config = config(database.clone());
    cap_config.database_max_mib = 1;
    let (service, worker) = HistoryService::new(cap_config).unwrap();
    let worker = worker.start().unwrap();

    wait_until(
        || {
            let health = service.health();
            health.pending_batches == 0
                && health.total_database_bytes > 0
                && (health.total_database_bytes <= 1024 * 1024 || health.size_floor_reached)
        },
        Duration::from_secs(10),
    )
    .await;
    for chunk in 30..36_u64 {
        service
            .try_publish(large_session_batch(
                chunk * 300,
                300,
                now - (2 * DAY_MILLIS) + (chunk * 300),
            ))
            .unwrap();
    }
    wait_until(
        || {
            let health = service.health();
            health.pending_batches == 0
                && (health.total_database_bytes <= 1024 * 1024 || health.size_floor_reached)
        },
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        service.health().total_database_bytes,
        total_database_bytes(&database)
    );
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_maintenance_yields_to_queries_and_shutdown_is_bounded() {
    let directory = TestDirectory::new("maintenance-yield");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let worker = worker.start().unwrap();
    let now = 40 * DAY_MILLIS;
    let identity = client("maintenance-client", 1);

    for chunk in 0..50_u64 {
        let mut lifecycle = Vec::with_capacity(1_000);
        for index in 0..1_000_u64 {
            lifecycle.push(ClientLifecycleRecord {
                client: identity.clone(),
                kind: ClientLifecycleKind::Disconnected,
                timestamp_unix_millis: chunk * 1_000 + index,
                version: None,
            });
        }
        service
            .try_publish(HistoryBatch {
                client_lifecycle: lifecycle,
                ..HistoryBatch::default()
            })
            .unwrap();
    }
    service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            now,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();

    let maintenance = {
        let service = service.clone();
        tokio::spawn(async move { service.maintain(now).await })
    };
    tokio::task::yield_now().await;
    tokio::time::timeout(
        Duration::from_secs(2),
        service.query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            now,
            HistoryResolution::Raw,
        )),
    )
    .await
    .unwrap()
    .unwrap();

    service.close();
    tokio::time::timeout(Duration::from_secs(2), worker.shutdown())
        .await
        .unwrap()
        .unwrap();
    let _ = maintenance.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_queued_maintenance_command_is_never_executed_later() {
    let directory = TestDirectory::new("cancelled-maintenance");
    let database = directory.database();
    let now = 20 * DAY_MILLIS;
    let old_timestamp = now - (2 * DAY_MILLIS);
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let cancelled = {
        let service = service.clone();
        tokio::spawn(async move { service.maintain(now).await })
    };
    tokio::task::yield_now().await;
    cancelled.abort();
    let _ = cancelled.await;

    let worker = worker.start().unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(old_timestamp, 444)],
            ..HistoryBatch::default()
        })
        .unwrap();
    let raw = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            old_timestamp,
            old_timestamp,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(raw.points.len(), 1);
    stop(service, worker).await;

    let connection = Connection::open(&database).unwrap();
    let last_maintenance: u64 = connection
        .query_row(
            "SELECT last_maintenance_ms FROM history_health WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_maintenance, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_worker_guard_signals_the_dedicated_thread_to_exit() {
    let directory = TestDirectory::new("worker-guard");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(|| service.health().worker_running, Duration::from_secs(2)).await;
    drop(worker);
    wait_until(|| !service.health().worker_running, Duration::from_secs(2)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_denied_database_stays_degraded_and_recovers_after_writes_return() {
    let directory = TestDirectory::new("write-denied");
    let database = directory.database();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER deny_history_writes
                 BEFORE UPDATE ON history_health
                 BEGIN
                     SELECT RAISE(FAIL, 'simulated read-only history database');
                 END;",
            )
            .unwrap();
    }
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(3),
    )
    .await;
    assert!(!service.health().history_available);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(service.health().history_failures <= 5);

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("DROP TRIGGER deny_history_writes", [])
            .unwrap();
    }
    wait_until(
        || service.health().history_available,
        Duration::from_secs(8),
    )
    .await;
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unowned_and_protected_files_are_never_quarantined_or_overwritten() {
    let directory = TestDirectory::new("unowned");
    let protected = directory.0.join("server.toml");
    let original = b"[server]\nbind = '127.0.0.1:7443'\n";
    fs::write(&protected, original).unwrap();
    let (service, worker) = HistoryService::new(config(protected.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    assert!(!service.health().history_available);
    stop(service, worker).await;
    assert_eq!(fs::read(&protected).unwrap(), original);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);

    let unrelated = directory.0.join("unrelated.db");
    fs::write(&unrelated, b"not owned by Rustgo").unwrap();
    let (service, worker) = HistoryService::new(config(unrelated.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;
    assert_eq!(fs::read(&unrelated).unwrap(), b"not owned by Rustgo");
    assert!(!sidecar(&unrelated, ".rustgo-owner").exists());
    assert!(!directory.0.join("unrelated.db.quarantine-0").exists());
}

#[cfg(any(unix, windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlink_database_path_is_not_followed_or_quarantined() {
    let directory = TestDirectory::new("symlink");
    let target = directory.0.join("target.db");
    let database = directory.database();
    fs::write(&target, b"unrelated target").unwrap();
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&target, &database);
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file(&target, &database);
    if linked.is_err() {
        return;
    }

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;
    assert_eq!(fs::read(&target).unwrap(), b"unrelated target");
    assert!(
        fs::symlink_metadata(&database)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantine_directory_collision_never_overwrites_existing_content() {
    let directory = TestDirectory::new("quarantine-collision");
    let database = directory.database();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;

    let occupied = directory.0.join("metrics.db.quarantine-0");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("sentinel"), b"keep me").unwrap();
    fs::write(&database, b"owned but now corrupt").unwrap();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available && service.health().recoveries > 0,
        Duration::from_secs(5),
    )
    .await;
    stop(service, worker).await;
    assert_eq!(fs::read(occupied.join("sentinel")).unwrap(), b"keep me");
    assert!(directory.0.join("metrics.db.quarantine-1").is_dir());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn marker_owned_supported_version_with_missing_table_or_column_is_recreated() {
    let directory = TestDirectory::new("schema-damage");
    let database = directory.database();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;
    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("DROP TABLE server_metric_points", [])
            .unwrap();
    }

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available && service.health().recoveries > 0,
        Duration::from_secs(5),
    )
    .await;
    stop(service, worker).await;
    let connection = Connection::open(&database).unwrap();
    let exists: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='server_metric_points'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 1);
    drop(connection);

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("ALTER TABLE history_health DROP COLUMN probe_nonce", [])
            .unwrap();
    }
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available && service.health().recoveries > 0,
        Duration::from_secs(5),
    )
    .await;
    stop(service, worker).await;
    let connection = Connection::open(&database).unwrap();
    let probe_columns: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('history_health') WHERE name='probe_nonce'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(probe_columns, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_batch_is_isolated_without_discarding_healthy_neighbors() {
    let directory = TestDirectory::new("isolated-batch-failure");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(1_000, 100)],
            ..HistoryBatch::default()
        })
        .unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(i64::MAX as u64 + 1, 200)],
            ..HistoryBatch::default()
        })
        .unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(2_000, 300)],
            ..HistoryBatch::default()
        })
        .unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available && service.health().dropped_batches == 1,
        Duration::from_secs(5),
    )
    .await;
    let series = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            0,
            3_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(series.points.len(), 2);
    assert_eq!(series.points[0].value, 100.0);
    assert_eq!(series.points[1].value, 300.0);
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_raw_replay_after_rollup_retention_never_replaces_complete_bucket() {
    let directory = TestDirectory::new("late-replay");
    let now = 10 * DAY_MILLIS;
    let bucket = now - (2 * DAY_MILLIS);
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let worker = worker.start().unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![
                server_sample(bucket + 1_000, 1_000),
                server_sample(bucket + 2_000, 3_000),
            ],
            ..HistoryBatch::default()
        })
        .unwrap();
    service.maintain(now).await.unwrap();
    let before = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            bucket,
            bucket + FIVE_MINUTE_BUCKET_MILLIS,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert_eq!(before.points[0].value, 2_000.0);

    for _ in 0..2 {
        service
            .try_publish(HistoryBatch {
                server_points: vec![server_sample(bucket + 3_000, 9_000)],
                ..HistoryBatch::default()
            })
            .unwrap();
    }
    let after = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            bucket,
            bucket + FIVE_MINUTE_BUCKET_MILLIS,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert_eq!(after.points, before.points);
    assert_eq!(service.health().dropped_late_points, 2);
    stop(service, worker).await;
}

#[test]
fn history_queue_is_bounded_by_owned_bytes_and_compacts_spare_capacity() {
    let directory = TestDirectory::new("queue-bytes");
    let mut large_config = config(directory.database());
    large_config.database_max_mib = 4096;
    let (service, _worker) = HistoryService::new(large_config).unwrap();
    for batch in 0..96_u64 {
        service
            .try_publish(large_session_batch(batch * 1_000, 1_000, batch * 1_000))
            .unwrap();
    }
    let health = service.health();
    assert!(health.pending_batches < 96);
    assert!(health.pending_batch_bytes <= MAX_HISTORY_QUEUE_BYTES);
    assert!(health.dropped_batches > 0);
    assert!(health.dropped_batch_bytes > 0);

    let other = TestDirectory::new("queue-compact");
    let (compact, _worker) = HistoryService::new(config(other.database())).unwrap();
    let mut points = Vec::with_capacity(100_000);
    points.push(server_sample(1, 1));
    compact
        .try_publish(HistoryBatch {
            server_points: points,
            ..HistoryBatch::default()
        })
        .unwrap();
    assert!(compact.health().pending_batch_bytes < 1024);

    let rejected = TestDirectory::new("queue-reject");
    let mut tiny_config = config(rejected.database());
    tiny_config.database_max_mib = 1;
    let (tiny, _worker) = HistoryService::new(tiny_config).unwrap();
    let error = tiny
        .try_publish(large_session_batch(0, 8_000, 0))
        .unwrap_err();
    assert_eq!(error, HistoryPublishError::BatchMemoryTooLarge);
    assert_eq!(tiny.health().dropped_batches, 1);
    assert!(tiny.health().dropped_batch_bytes > 1024 * 1024);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_preserves_active_session_until_it_is_closed() {
    let directory = TestDirectory::new("active-session-retention");
    let database = directory.database();
    let now = 20 * DAY_MILLIS;
    let mut active = session_summary(1, "active-client", now - (10 * DAY_MILLIS));
    active.closed_unix_millis = None;
    active.terminal_reason = None;
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    service
        .try_publish(HistoryBatch {
            session_summaries: vec![active.clone()],
            ..HistoryBatch::default()
        })
        .unwrap();
    service.maintain(now).await.unwrap();
    stop(service, worker).await;
    let connection = Connection::open(&database).unwrap();
    let active_rows: usize = connection
        .query_row("SELECT COUNT(*) FROM session_summaries", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(active_rows, 1);
    drop(connection);

    active.closed_unix_millis = Some(now);
    active.terminal_reason = Some(BoundedLabel::try_from("closed").unwrap());
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    service
        .try_publish(HistoryBatch {
            session_summaries: vec![active],
            ..HistoryBatch::default()
        })
        .unwrap();
    service.maintain(now + (8 * DAY_MILLIS)).await.unwrap();
    stop(service, worker).await;
    let connection = Connection::open(&database).unwrap();
    let remaining: usize = connection
        .query_row("SELECT COUNT(*) FROM session_summaries", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(remaining, 0);
}

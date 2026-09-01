use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
const RUSTGO_APPLICATION_ID: i64 = 0x5253_474f;

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

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn recent_base() -> u64 {
    let now = unix_millis_now();
    (now / FIVE_MINUTE_BUCKET_MILLIS) * FIVE_MINUTE_BUCKET_MILLIS
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

fn create_exact_v4_history(path: &Path, timestamp: u64) {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .unwrap();
    connection
        .execute_batch(
            "CREATE TABLE server_metric_points (
             resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
             timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
             metric TEXT NOT NULL, value REAL NOT NULL,
             sample_count INTEGER NOT NULL CHECK (sample_count > 0),
             PRIMARY KEY (resolution, timestamp_ms, metric)
         ) WITHOUT ROWID;
         CREATE TABLE client_metric_points (
             client_name TEXT NOT NULL,
             resolution INTEGER NOT NULL CHECK (resolution BETWEEN 0 AND 2),
             timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
             metric TEXT NOT NULL, value REAL NOT NULL,
             sample_count INTEGER NOT NULL CHECK (sample_count > 0),
             PRIMARY KEY (client_name, resolution, timestamp_ms, metric)
         ) WITHOUT ROWID;
         CREATE TABLE client_lifecycle (
             id INTEGER PRIMARY KEY, client_name TEXT NOT NULL,
             generation TEXT NOT NULL, event_kind TEXT NOT NULL,
             timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0), version TEXT,
             UNIQUE (client_name, generation, event_kind, timestamp_ms)
         );
         CREATE TABLE session_summaries (
             session_id TEXT NOT NULL, client_name TEXT NOT NULL, peer TEXT,
             tunnel TEXT, export_name TEXT, kind TEXT NOT NULL, path TEXT NOT NULL,
             received_bytes TEXT NOT NULL, sent_bytes TEXT NOT NULL,
             opened_ms INTEGER NOT NULL CHECK (opened_ms >= 0),
             closed_ms INTEGER CHECK (closed_ms IS NULL OR closed_ms >= 0),
             terminal_reason TEXT, PRIMARY KEY (session_id, opened_ms)
         );
         CREATE TABLE history_health (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             last_maintenance_ms INTEGER NOT NULL CHECK (last_maintenance_ms >= 0),
             probe_nonce INTEGER NOT NULL
         );
         CREATE INDEX server_metric_query
             ON server_metric_points (resolution, metric, timestamp_ms);
         CREATE INDEX client_metric_query
             ON client_metric_points (resolution, metric, timestamp_ms, client_name);
         CREATE INDEX client_metric_retention
             ON client_metric_points (resolution, timestamp_ms, client_name);
         CREATE INDEX client_lifecycle_time ON client_lifecycle (timestamp_ms, id);
         CREATE INDEX client_lifecycle_latest
             ON client_lifecycle (client_name, timestamp_ms DESC, id DESC);
         CREATE INDEX session_summaries_time
             ON session_summaries (closed_ms, opened_ms, session_id);
         INSERT INTO history_health VALUES (1, 0, 7);",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO server_metric_points VALUES (0, ?1, 'cpu_basis_points', 4321.0, 1)",
            [timestamp],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 4).unwrap();
    drop(connection);
    fs::write(
        sidecar(path, ".rustgo-owner"),
        b"rustgo-observability-history-v1\n",
    )
    .unwrap();
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
async fn bootstraps_owned_wal_schema_and_persists_points_across_restart() {
    let directory = TestDirectory::new("restart");
    let database = directory.database();
    let now = unix_millis_now();

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let task = worker.start().unwrap();
    let persisted_client = client("restart-client", 3);
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(now, 2_500)],
            client_lifecycle: vec![ClientLifecycleRecord {
                client: persisted_client.clone(),
                kind: ClientLifecycleKind::Authenticated,
                timestamp_unix_millis: now - 100,
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
                opened_unix_millis: now - 50,
                closed_unix_millis: Some(now + 50),
                terminal_reason: Some(BoundedLabel::try_from("complete").unwrap()),
            }],
            ..HistoryBatch::default()
        })
        .unwrap();
    let first = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            now - 1_000,
            now + 1_000,
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
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap();
    let auto_vacuum: i64 = connection
        .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
        .unwrap();
    let owner_nonce: String = connection
        .query_row(
            "SELECT owner_nonce FROM history_health WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(application_id, RUSTGO_APPLICATION_ID);
    assert_eq!(auto_vacuum, 2);
    assert_eq!(owner_nonce.len(), 64);
    assert!(
        String::from_utf8(fs::read(sidecar(&database, ".rustgo-owner")).unwrap())
            .unwrap()
            .contains(&format!("nonce={owner_nonce}\n"))
    );
    assert_eq!(lifecycle_rows, 1);
    assert_eq!(session_rows, 1);
    drop(connection);

    let (service, worker) = HistoryService::new(config(database)).unwrap();
    let task = worker.start().unwrap();
    let restarted = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            now - 1_000,
            now + 1_000,
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
    let now = recent_base();
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let task = worker.start().unwrap();

    let minute_bucket = now - (2 * MINUTE_MILLIS);
    let five_minute_bucket = now - (15 * MINUTE_MILLIS);
    service
        .try_publish(HistoryBatch {
            server_points: vec![
                server_sample(minute_bucket + 1_000, 1_000),
                server_sample(minute_bucket + 2_000, 3_000),
                server_sample(five_minute_bucket + 1_000, 2_000),
                server_sample(five_minute_bucket + 2_000, 4_000),
                server_sample(now + 1_000, 5_000),
            ],
            ..HistoryBatch::default()
        })
        .unwrap();

    let retention_now = now + (2 * HOUR_MILLIS);
    service.maintain(retention_now).await.unwrap();
    service.maintain(retention_now).await.unwrap();

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

    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(now + 2_000, 5_000)],
            ..HistoryBatch::default()
        })
        .unwrap();
    let raw = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            now + 2_000,
            now + 2_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(raw.points.len(), 1);
    assert_eq!(raw.points[0].value, 5_000.0);

    service.maintain(now + (8 * DAY_MILLIS)).await.unwrap();
    let expired = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            now - HOUR_MILLIS,
            now + HOUR_MILLIS,
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
    let now = unix_millis_now();
    let writer = {
        let service = service.clone();
        tokio::spawn(async move {
            for index in 0..2_100_u64 {
                service
                    .try_publish(HistoryBatch {
                        server_points: vec![server_sample(now + index, (index % 10_000) as u16)],
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
                            now,
                            now + 3_000,
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
                now,
                now + 3_000,
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
                    now,
                    now + 3_000,
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
    let now = unix_millis_now();
    let oldest = now - (30 * MINUTE_MILLIS);

    for chunk in 0..24_u64 {
        let mut batch = HistoryBatch::default();
        for index in 0..400_u64 {
            let sequence = (chunk * 400) + index;
            let timestamp = oldest + sequence;
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
            oldest - MINUTE_MILLIS,
            now,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert!(old_five_minute.points.len() < 32);
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owned_schema_corruption_is_quarantined_and_history_recovers() {
    let directory = TestDirectory::new("corrupt");
    let database = directory.database();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let task = worker.start().unwrap();
    let now = unix_millis_now();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(now, 123)],
            ..HistoryBatch::default()
        })
        .unwrap();
    service.checkpoint().await.unwrap();
    stop(service, task).await;
    assert!(sidecar(&database, ".rustgo-owner").is_file());

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("DROP TABLE server_metric_points", [])
            .unwrap();
    }
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
            server_points: vec![server_sample(now + 1_000, 777)],
            ..HistoryBatch::default()
        })
        .unwrap();
    let recovered = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            now,
            now + 2_000,
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
    let now = unix_millis_now();
    for timestamp in 0..=HISTORY_BATCH_QUEUE_CAPACITY as u64 {
        service
            .try_publish(HistoryBatch {
                server_points: vec![server_sample(now + timestamp, timestamp as u16)],
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
            now,
            now + HISTORY_BATCH_QUEUE_CAPACITY as u64,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(series.points.len(), HISTORY_BATCH_QUEUE_CAPACITY);
    assert_eq!(series.points[0].timestamp_unix_millis, now + 1);
    stop(service, task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_history_is_scoped_to_the_authenticated_name() {
    let directory = TestDirectory::new("client-scope");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let task = worker.start().unwrap();
    let now = unix_millis_now();
    service
        .try_publish(HistoryBatch {
            client_points: vec![
                ClientHistorySample {
                    client: client("alpha", 1),
                    timestamp_unix_millis: now,
                    metrics: host_metrics(now, 111),
                    traffic: TrafficCounters::default(),
                },
                ClientHistorySample {
                    client: client("beta", 1),
                    timestamp_unix_millis: now,
                    metrics: host_metrics(now, 222),
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
            now - 1_000,
            now + 1_000,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_then_query_visibility_is_preserved_while_open_cap_runs() {
    let directory = TestDirectory::new("cap-command-order");
    let database = directory.database();
    let now = unix_millis_now();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    service
        .try_publish(large_session_batch(0, 2_000, now))
        .unwrap();
    service.checkpoint().await.unwrap();
    assert!(total_database_bytes(&database) > 1024 * 1024);
    stop(service, worker).await;

    let mut cap_config = config(database);
    cap_config.database_max_mib = 1;
    let (service, worker) = HistoryService::new(cap_config).unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(now + 1_000, 7_777)],
            ..HistoryBatch::default()
        })
        .unwrap();
    let queued_query = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .query(query(
                    HistoryScope::Server,
                    HistoryMetric::CpuBasisPoints,
                    now,
                    now + 2_000,
                    HistoryResolution::Raw,
                ))
                .await
        })
    };
    tokio::task::yield_now().await;
    let worker = worker.start().unwrap();
    let visible = queued_query.await.unwrap().unwrap();
    assert_eq!(visible.points.len(), 1);
    assert_eq!(visible.points[0].value, 7_777.0);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_metric_tier_maintenance_is_index_ordered_and_shutdown_bounded() {
    let directory = TestDirectory::new("metric-maintenance-yield");
    let database = directory.database();
    let now = unix_millis_now();
    let start = now - (2 * HOUR_MILLIS);
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;

    let mut connection = Connection::open(&database).unwrap();
    let transaction = connection.transaction().unwrap();
    {
        let mut insert = transaction
            .prepare(
                "INSERT INTO client_metric_points
                 (client_name, resolution, timestamp_ms, metric, value, sample_count)
                 VALUES ('metric-maintenance-client', 0, ?1, 'cpu_basis_points', 123.0, 1)",
            )
            .unwrap();
        for offset in 0..5_000_u64 {
            insert
                .execute([i64::try_from(start + offset).unwrap()])
                .unwrap();
        }
    }
    transaction.commit().unwrap();
    for sql in [
        "EXPLAIN QUERY PLAN
         SELECT client_name, timestamp_ms FROM client_metric_points
         WHERE resolution = 0 AND timestamp_ms < ?1
         GROUP BY timestamp_ms, client_name
         ORDER BY timestamp_ms ASC, client_name ASC LIMIT 64",
        "EXPLAIN QUERY PLAN
         SELECT candidate.client_name, candidate.timestamp_ms
         FROM client_metric_points AS candidate
         WHERE candidate.resolution = 0
           AND ?1 >= 0
           AND EXISTS (
               SELECT 1 FROM client_metric_points AS newer
               WHERE newer.client_name = candidate.client_name
                 AND newer.resolution = 0
                 AND newer.timestamp_ms > candidate.timestamp_ms
           )
         GROUP BY candidate.timestamp_ms, candidate.client_name
         ORDER BY candidate.timestamp_ms ASC, candidate.client_name ASC LIMIT 39",
    ] {
        let mut statement = connection.prepare(sql).unwrap();
        let details = statement
            .query_map([now as i64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            details.iter().all(|detail| !detail.contains("TEMP B-TREE")),
            "maintenance plan used a full-tier temporary sort: {details:?}"
        );
    }
    drop(connection);

    let (service, worker) = HistoryService::new(config(database)).unwrap();
    let worker = worker.start().unwrap();
    let maintenance = {
        let service = service.clone();
        tokio::spawn(async move { service.maintain(now).await })
    };
    tokio::task::yield_now().await;
    tokio::time::timeout(
        Duration::from_secs(2),
        service.query(query(
            HistoryScope::Client(BoundedLabel::try_from("metric-maintenance-client").unwrap()),
            HistoryMetric::CpuBasisPoints,
            start,
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
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let cancelled = {
        let service = service.clone();
        tokio::spawn(async move { service.maintain(now).await })
    };
    tokio::task::yield_now().await;
    cancelled.abort();
    let _ = cancelled.await;

    let worker = worker.start().unwrap();
    service.checkpoint().await.unwrap();
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
async fn dropping_a_busy_worker_returns_promptly_and_reaper_observes_exit() {
    let directory = TestDirectory::new("busy-worker-drop");
    let database = directory.database();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;

    let blocker = Connection::open(&database).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (service, worker) = HistoryService::new(config(database)).unwrap();
    let worker = worker.start().unwrap();
    wait_until(|| service.health().worker_running, Duration::from_secs(2)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = Instant::now();
    drop(worker);
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "Drop synchronously waited for the busy SQLite worker"
    );
    blocker.execute_batch("ROLLBACK").unwrap();
    wait_until(|| !service.health().worker_running, Duration::from_secs(3)).await;
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

    let valid = directory.0.join("personal.db");
    {
        let connection = Connection::open(&valid).unwrap();
        connection
            .execute("CREATE TABLE personal_notes (body TEXT NOT NULL)", [])
            .unwrap();
        connection
            .execute("INSERT INTO personal_notes VALUES ('keep me')", [])
            .unwrap();
    }
    fs::write(
        sidecar(&valid, ".rustgo-owner"),
        b"rustgo-observability-history-v2\napplication_id=5253474f\nnonce=0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();
    let (service, worker) = HistoryService::new(config(valid.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;
    let connection = Connection::open(&valid).unwrap();
    let note: String = connection
        .query_row("SELECT body FROM personal_notes", [], |row| row.get(0))
        .unwrap();
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap();
    assert_eq!(note, "keep me");
    assert_eq!(application_id, 0);
    assert!(!directory.0.join("personal.db.quarantine-0").exists());

    let empty = directory.0.join("empty-user-version-zero.db");
    {
        let connection = Connection::open(&empty).unwrap();
        connection.pragma_update(None, "user_version", 0).unwrap();
    }
    let before = fs::read(&empty).unwrap();
    let (service, worker) = HistoryService::new(config(empty.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;
    assert_eq!(fs::read(&empty).unwrap(), before);
    assert!(!sidecar(&empty, ".rustgo-owner").exists());
    assert!(
        !directory
            .0
            .join("empty-user-version-zero.db.quarantine-0")
            .exists()
    );
}

#[cfg(any(unix, windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlink_database_path_is_not_followed_or_quarantined() {
    let directory = TestDirectory::new("symlink");
    let target = directory.0.join("target.db");
    let database = directory.database();
    fs::write(&target, b"unrelated target").unwrap();
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&target, &database);
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file(&target, &database);
    if linked.is_err() {
        return;
    }

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
    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("DROP INDEX server_metric_query", [])
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
    assert_eq!(fs::read(occupied.join("sentinel")).unwrap(), b"keep me");
    assert!(directory.0.join("metrics.db.quarantine-1").is_dir());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_quarantine_resumes_from_matching_dual_ownership() {
    let directory = TestDirectory::new("quarantine-resume");
    let database = directory.database();
    let marker = sidecar(&database, ".rustgo-owner");
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;

    let quarantine = directory.0.join("metrics.db.quarantine-0");
    fs::create_dir(&quarantine).unwrap();
    fs::hard_link(&database, quarantine.join("metrics.db")).unwrap();
    fs::hard_link(&marker, quarantine.join("metrics.db.rustgo-owner")).unwrap();
    for suffix in ["-wal", "-shm"] {
        let source = sidecar(&database, suffix);
        if source.exists() {
            fs::hard_link(&source, quarantine.join(source.file_name().unwrap())).unwrap();
        }
    }
    fs::remove_file(&database).unwrap();

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available && service.health().recoveries == 1,
        Duration::from_secs(5),
    )
    .await;
    stop(service, worker).await;
    assert!(database.is_file());
    assert!(marker.is_file());
    assert!(quarantine.join("metrics.db").is_file());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_or_spoofed_owner_marker_never_authorizes_quarantine() {
    let directory = TestDirectory::new("stale-marker");
    let database = directory.database();
    let marker = sidecar(&database, ".rustgo-owner");
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;
    let valid_marker = fs::read(&marker).unwrap();
    let mut stale_marker = valid_marker.clone();
    let last = stale_marker.len() - 2;
    stale_marker[last] = if stale_marker[last] == b'0' {
        b'1'
    } else {
        b'0'
    };
    fs::write(&marker, &stale_marker).unwrap();

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    assert!(!service.health().history_available);
    assert!(!directory.0.join("metrics.db.quarantine-0").exists());
    fs::write(&marker, valid_marker).unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(8),
    )
    .await;
    stop(service, worker).await;
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
            .execute(
                "ALTER TABLE session_summaries DROP COLUMN terminal_reason",
                [],
            )
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
            "SELECT COUNT(*) FROM pragma_table_info('session_summaries') WHERE name='terminal_reason'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(probe_columns, 1);
    drop(connection);

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "ALTER TABLE client_lifecycle RENAME TO damaged_client_lifecycle;
                 DROP TABLE damaged_client_lifecycle;
                 CREATE TABLE client_lifecycle (
                     id INTEGER PRIMARY KEY,
                     client_name TEXT NOT NULL,
                     generation TEXT NOT NULL,
                     event_kind TEXT NOT NULL,
                     timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                     version TEXT
                 );
                 CREATE INDEX client_lifecycle_time
                     ON client_lifecycle (timestamp_ms, id);
                 CREATE INDEX client_lifecycle_latest
                     ON client_lifecycle (client_name, timestamp_ms DESC, id DESC);",
            )
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
    let unique_targets: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_list('client_lifecycle') WHERE origin='u' AND \"unique\"=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unique_targets, 1);
    drop(connection);

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "DROP INDEX client_lifecycle_latest;
                 CREATE INDEX client_lifecycle_latest
                     ON client_lifecycle (client_name, timestamp_ms ASC, id ASC);",
            )
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
    let descending_keys: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_xinfo('client_lifecycle_latest')
             WHERE key=1 AND desc=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(descending_keys, 2);
    drop(connection);

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "DROP INDEX server_metric_query;
                 CREATE UNIQUE INDEX server_metric_query
                     ON server_metric_points
                        (resolution, metric COLLATE NOCASE, timestamp_ms)
                     WHERE resolution >= 0;",
            )
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
    let restored_index: (i64, String, i64) = connection
        .query_row(
            "SELECT \"unique\", origin, partial
             FROM pragma_index_list('server_metric_points')
             WHERE name='server_metric_query'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(restored_index, (0, "c".to_owned(), 0));
    drop(connection);

    {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "DROP TABLE server_metric_points;
                 CREATE TABLE server_metric_points (
                     resolution INTEGER NOT NULL,
                     timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
                     metric TEXT NOT NULL,
                     value REAL NOT NULL,
                     sample_count INTEGER NOT NULL CHECK (sample_count > 0),
                     PRIMARY KEY (resolution, timestamp_ms, metric)
                 ) WITHOUT ROWID;
                 CREATE INDEX server_metric_query
                     ON server_metric_points (resolution, metric, timestamp_ms);",
            )
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
    let server_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='server_metric_points'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(server_sql.contains("CHECK (resolution BETWEEN 0 AND 2)"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_batch_is_isolated_without_discarding_healthy_neighbors() {
    let directory = TestDirectory::new("isolated-batch-failure");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    let now = unix_millis_now();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(now, 100)],
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
            server_points: vec![server_sample(now + 1_000, 300)],
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
            now,
            now + 2_000,
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
async fn failed_coalesced_batches_remain_in_the_shared_queue_budget_during_retry() {
    let directory = TestDirectory::new("retry-budget");
    let (service, worker) = HistoryService::new(config(directory.database())).unwrap();
    for _ in 0..64 {
        service
            .try_publish(HistoryBatch {
                server_points: vec![server_sample(i64::MAX as u64 + 1, 1)],
                ..HistoryBatch::default()
            })
            .unwrap();
    }
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    let retry_health = service.health();
    assert_eq!(retry_health.pending_batches, 64);
    assert!(retry_health.pending_batch_bytes > 0);
    let blocker = Connection::open(directory.database()).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    let now = unix_millis_now();
    for offset in 0..1_000_u64 {
        service
            .try_publish(HistoryBatch {
                server_points: vec![server_sample(now + offset, 2)],
                ..HistoryBatch::default()
            })
            .unwrap();
    }
    let filled = service.health();
    assert_eq!(filled.pending_batches, HISTORY_BATCH_QUEUE_CAPACITY);
    assert!(filled.pending_batch_bytes <= MAX_HISTORY_QUEUE_BYTES);
    assert_eq!(filled.dropped_batches, 40);
    blocker.execute_batch("ROLLBACK").unwrap();
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_clock_admission_rejects_late_raw_during_concurrent_retention() {
    let directory = TestDirectory::new("late-retention-race");
    let database = directory.database();
    let now = unix_millis_now();
    let bucket =
        ((now - (2 * HOUR_MILLIS)) / FIVE_MINUTE_BUCKET_MILLIS) * FIVE_MINUTE_BUCKET_MILLIS;
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
            .execute(
                "INSERT INTO server_metric_points
                 (resolution, timestamp_ms, metric, value, sample_count)
                 VALUES (2, ?1, 'cpu_basis_points', 2000.0, 2)",
                [bucket],
            )
            .unwrap();
    }

    let (service, worker) = HistoryService::new(config(database)).unwrap();
    let worker = worker.start().unwrap();
    let maintenance = {
        let service = service.clone();
        tokio::spawn(async move { service.maintain(now).await })
    };
    for _ in 0..2 {
        service
            .try_publish(HistoryBatch {
                server_points: vec![server_sample(bucket + 3_000, 9_000)],
                ..HistoryBatch::default()
            })
            .unwrap();
    }
    let _ = maintenance.await.unwrap();
    let retained = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            bucket,
            bucket + FIVE_MINUTE_BUCKET_MILLIS,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert_eq!(retained.points.len(), 1);
    assert_eq!(retained.points[0].value, 2_000.0);
    assert_eq!(service.health().dropped_late_points, 2);
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cap_deleted_aggregate_tombstone_rejects_same_scope_replay_only() {
    let directory = TestDirectory::new("cap-late-replay");
    let database = directory.database();
    let current_bucket = recent_base();
    let bucket = current_bucket - FIVE_MINUTE_BUCKET_MILLIS;
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    let mut active = large_session_batch(0, 2_000, bucket);
    for session in &mut active.session_summaries {
        session.closed_unix_millis = None;
        session.terminal_reason = None;
    }
    active.server_points = vec![
        server_sample(bucket + 1_000, 1_000),
        server_sample(bucket + 2_000, 3_000),
        server_sample(current_bucket + 1_000, 4_000),
    ];
    service.try_publish(active).unwrap();
    let before = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            bucket,
            bucket + FIVE_MINUTE_BUCKET_MILLIS - 1,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert_eq!(before.points[0].value, 2_000.0);
    service.checkpoint().await.unwrap();
    assert!(total_database_bytes(&database) > 1024 * 1024);
    stop(service, worker).await;

    let mut cap_config = config(database.clone());
    cap_config.database_max_mib = 1;
    let (service, worker) = HistoryService::new(cap_config).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || {
            let health = service.health();
            health.total_database_bytes > 0
                && (health.total_database_bytes <= 1024 * 1024 || health.size_floor_reached)
        },
        Duration::from_secs(10),
    )
    .await;
    for _ in 0..2 {
        service
            .try_publish(HistoryBatch {
                server_points: vec![server_sample(bucket + 1_000, 9_000)],
                ..HistoryBatch::default()
            })
            .unwrap();
    }
    let other = client("other-current-scope", 1);
    service
        .try_publish(HistoryBatch {
            client_points: vec![ClientHistorySample {
                client: other.clone(),
                timestamp_unix_millis: bucket + 1_000,
                metrics: host_metrics(bucket + 1_000, 7_777),
                traffic: TrafficCounters::default(),
            }],
            ..HistoryBatch::default()
        })
        .unwrap();
    let after = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            bucket,
            bucket + FIVE_MINUTE_BUCKET_MILLIS - 1,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert!(after.points.is_empty());
    assert_eq!(service.health().dropped_late_points, 2);
    let other_scope = service
        .query(query(
            HistoryScope::Client(BoundedLabel::try_from(other.name()).unwrap()),
            HistoryMetric::CpuBasisPoints,
            bucket + 1_000,
            bucket + 1_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(other_scope.points[0].value, 7_777.0);
    stop(service, worker).await;
    let connection = Connection::open(&database).unwrap();
    let aggregate_tombstones: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM metric_deletion_tombstones
             WHERE scope=0 AND resolution=2 AND timestamp_ms=?1",
            [bucket],
            |row| row.get(0),
        )
        .unwrap();
    assert!(aggregate_tombstones > 0);
    let active_sessions: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM session_summaries WHERE closed_ms IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active_sessions, 2_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cap_prunes_older_client_buckets_before_newer_server_buckets() {
    let directory = TestDirectory::new("cap-global-oldest");
    let database = directory.database();
    let bucket = recent_base();
    let identity = client(&"x".repeat(128), 1);
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();

    let mut point_seed = 0_u64;
    while total_database_bytes(&database) < 2_050 * 1024 {
        let client_points = (0..10_u64)
            .map(|offset| {
                let timestamp = bucket + 1_000 + point_seed + offset;
                ClientHistorySample {
                    client: identity.clone(),
                    timestamp_unix_millis: timestamp,
                    metrics: host_metrics(timestamp, 111),
                    traffic: TrafficCounters::default(),
                }
            })
            .collect();
        service
            .try_publish(HistoryBatch {
                client_points,
                ..HistoryBatch::default()
            })
            .unwrap();
        service.checkpoint().await.unwrap();
        point_seed += 10;
    }
    service
        .try_publish(HistoryBatch {
            client_points: vec![ClientHistorySample {
                client: identity,
                timestamp_unix_millis: bucket + 240_000,
                metrics: host_metrics(bucket + 240_000, 222),
                traffic: TrafficCounters::default(),
            }],
            server_points: vec![
                server_sample(bucket + 120_000, 3_333),
                server_sample(bucket + 240_001, 4_444),
            ],
            ..HistoryBatch::default()
        })
        .unwrap();
    service.checkpoint().await.unwrap();
    stop(service, worker).await;

    let raw_client_before = {
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("DELETE FROM server_metric_points WHERE resolution > 0", [])
            .unwrap();
        connection
            .execute("DELETE FROM client_metric_points WHERE resolution > 0", [])
            .unwrap();
        connection
            .query_row(
                "SELECT COUNT(*) FROM client_metric_points WHERE resolution=0",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap()
    };

    let mut cap_config = config(database);
    cap_config.database_max_mib = 2;
    let (service, worker) = HistoryService::new(cap_config).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || {
            let health = service.health();
            health.total_database_bytes > 0
                && (health.total_database_bytes <= 2 * 1024 * 1024 || health.size_floor_reached)
        },
        Duration::from_secs(15),
    )
    .await;
    let server = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            bucket + 120_000,
            bucket + 120_000,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    let health = service.health();
    stop(service, worker).await;
    let connection = Connection::open(directory.database()).unwrap();
    let raw_client_after: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM client_metric_points WHERE resolution=0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let raw_server_after: usize = connection
        .query_row(
            "SELECT COUNT(DISTINCT timestamp_ms) FROM server_metric_points WHERE resolution=0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let tombstones: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM metric_deletion_tombstones",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(raw_client_after < raw_client_before);
    assert_eq!(
        server.points.len(),
        1,
        "cap ordering evidence: seed={point_seed}, client={raw_client_before}->{raw_client_after}, server_buckets={raw_server_after}, tombstones={tombstones}, health={health:?}"
    );
    assert_eq!(server.points[0].value, 3_333.0);
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
async fn exact_v4_history_and_legacy_marker_upgrade_once_to_dual_owned_v5() {
    let directory = TestDirectory::new("v4-upgrade");
    let database = directory.database();
    let timestamp = recent_base() + 1_234;
    create_exact_v4_history(&database, timestamp);

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(3),
    )
    .await;
    let series = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            timestamp,
            timestamp,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(series.points[0].value, 4_321.0);
    stop(service, worker).await;

    let connection = Connection::open(&database).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap();
    let nonce: String = connection
        .query_row(
            "SELECT owner_nonce FROM history_health WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let tombstone_table: usize = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='metric_deletion_tombstones'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(
        (version, application_id, tombstone_table),
        (HISTORY_SCHEMA_VERSION, RUSTGO_APPLICATION_ID, 1)
    );
    assert_eq!(nonce.len(), 64);
    let marker = fs::read_to_string(sidecar(&database, ".rustgo-owner")).unwrap();
    assert!(marker.contains(&format!("nonce={nonce}\n")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_clock_without_deletion_does_not_poison_admission_after_correction() {
    let directory = TestDirectory::new("clock-correction");
    let database = directory.database();
    let now = unix_millis_now();
    let timestamp = recent_base() + 2_000;
    let (service, worker) = HistoryService::new(config(database)).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    service.maintain(now + 30 * DAY_MILLIS).await.unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![server_sample(timestamp, 6_789)],
            ..HistoryBatch::default()
        })
        .unwrap();
    let series = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            timestamp,
            timestamp,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(series.points.len(), 1);
    assert_eq!(series.points[0].value, 6_789.0);
    assert_eq!(service.health().dropped_late_points, 0);
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn future_bucket_tombstone_does_not_poison_a_normal_current_bucket() {
    let directory = TestDirectory::new("future-tombstone");
    let database = directory.database();
    let current = recent_base() + 1_000;
    let future_bucket = recent_base() + 30 * DAY_MILLIS;
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "INSERT INTO metric_deletion_tombstones
         (scope, client_name, resolution, timestamp_ms, deleted_ms)
         VALUES (0, '', 2, ?1, ?2)",
            [future_bucket, unix_millis_now()],
        )
        .unwrap();
    drop(connection);

    let (service, worker) = HistoryService::new(config(database)).unwrap();
    let worker = worker.start().unwrap();
    service
        .try_publish(HistoryBatch {
            server_points: vec![
                server_sample(current, 1_234),
                server_sample(future_bucket + 1_000, 9_999),
            ],
            ..HistoryBatch::default()
        })
        .unwrap();
    let current_series = service
        .query(query(
            HistoryScope::Server,
            HistoryMetric::CpuBasisPoints,
            current,
            current,
            HistoryResolution::Raw,
        ))
        .await
        .unwrap();
    assert_eq!(current_series.points[0].value, 1_234.0);
    assert_eq!(service.health().dropped_late_points, 1);
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_quarantine_never_removes_a_replacement_database() {
    let directory = TestDirectory::new("quarantine-replacement");
    let database = directory.database();
    let marker = sidecar(&database, ".rustgo-owner");
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_available,
        Duration::from_secs(2),
    )
    .await;
    stop(service, worker).await;

    let quarantine = directory.0.join("metrics.db.quarantine-0");
    fs::create_dir(&quarantine).unwrap();
    fs::hard_link(&database, quarantine.join("metrics.db")).unwrap();
    fs::hard_link(&marker, quarantine.join("metrics.db.rustgo-owner")).unwrap();
    fs::remove_file(&database).unwrap();
    fs::write(&database, b"replacement must survive").unwrap();

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    assert!(!service.health().history_available);
    assert_eq!(fs::read(&database).unwrap(), b"replacement must survive");
    assert!(marker.is_file());
    assert!(quarantine.join("metrics.db").is_file());
    stop(service, worker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_hot_journal_is_read_only_probed_and_left_byte_identical() {
    let directory = TestDirectory::new("hot-journal");
    let database = directory.database();
    let unrelated = Connection::open(&database).unwrap();
    unrelated
        .pragma_update(None, "journal_mode", "DELETE")
        .unwrap();
    unrelated
        .execute_batch("CREATE TABLE private_data(value TEXT); BEGIN IMMEDIATE;")
        .unwrap();
    unrelated
        .execute("INSERT INTO private_data VALUES ('secret')", [])
        .unwrap();
    let journal = sidecar(&database, "-journal");
    assert!(journal.is_file());
    let before_database = fs::read(&database).unwrap();
    let before_journal = fs::read(&journal).unwrap();

    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().history_failures > 0,
        Duration::from_secs(2),
    )
    .await;
    assert!(!service.health().history_available);
    assert_eq!(fs::read(&database).unwrap(), before_database);
    assert_eq!(fs::read(&journal).unwrap(), before_journal);
    stop(service, worker).await;
    unrelated.execute_batch("ROLLBACK").unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cap_scans_at_most_one_fixed_page_when_all_client_buckets_are_protected() {
    let directory = TestDirectory::new("protected-cap-scan");
    let database = directory.database();
    let timestamp = recent_base() + 1_000;
    let (service, worker) = HistoryService::new(config(database.clone())).unwrap();
    let worker = worker.start().unwrap();
    let client_points = (0..400_u64)
        .map(|sequence| ClientHistorySample {
            client: client(&format!("protected-{sequence:04}"), 1),
            timestamp_unix_millis: timestamp,
            metrics: host_metrics(timestamp, 100),
            traffic: TrafficCounters::default(),
        })
        .collect();
    service
        .try_publish(HistoryBatch {
            client_points,
            ..HistoryBatch::default()
        })
        .unwrap();
    service
        .try_publish(large_session_batch(50_000, 2_000, timestamp))
        .unwrap();
    service.checkpoint().await.unwrap();
    stop(service, worker).await;

    let mut cap_config = config(database);
    cap_config.database_max_mib = 1;
    let (service, worker) = HistoryService::new(cap_config).unwrap();
    let worker = worker.start().unwrap();
    wait_until(
        || service.health().maximum_maintenance_scan_rows > 0,
        Duration::from_secs(5),
    )
    .await;
    assert!(service.health().maximum_maintenance_scan_rows <= 8_192);
    let started = Instant::now();
    let _ = service
        .query(query(
            HistoryScope::Client(BoundedLabel::try_from("protected-0399").unwrap()),
            HistoryMetric::CpuBasisPoints,
            timestamp,
            timestamp,
            HistoryResolution::FiveMinutes,
        ))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    stop(service, worker).await;
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

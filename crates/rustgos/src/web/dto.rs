use serde::Serialize;

#[derive(Serialize)]
pub(super) struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Serialize)]
pub(super) struct ErrorBody {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Serialize)]
pub(super) struct OverviewResponse {
    pub generated_unix_millis: u64,
    pub snapshot_stale: bool,
    pub server: ServerMetrics,
    pub clients: BoundedItems<Client>,
    pub sessions: SessionCounts,
    pub observability: ObservabilityHealth,
    pub history: HistoryHealth,
}

#[derive(Serialize)]
pub(super) struct ServerMetricsResponse {
    pub generated_unix_millis: u64,
    pub server: ServerMetrics,
    pub observability: ObservabilityHealth,
    pub history: HistoryHealth,
}

#[derive(Serialize)]
pub(super) struct ClientsResponse {
    pub generated_unix_millis: u64,
    pub search: Option<String>,
    pub sort: &'static str,
    pub order: &'static str,
    pub clients: BoundedItems<Client>,
}

#[derive(Serialize)]
pub(super) struct ClientResponse {
    pub generated_unix_millis: u64,
    pub client: Client,
    pub sessions: BoundedItems<Session>,
}

#[derive(Serialize)]
pub(super) struct SessionsResponse {
    pub generated_unix_millis: u64,
    pub sessions: BoundedItems<Session>,
}

#[derive(Serialize)]
pub(super) struct HistoryResponse {
    pub generated_unix_millis: u64,
    pub history: HistoryHealth,
    pub query: HistoryQueryMetadata,
    pub resolution: &'static str,
    pub points: Vec<HistoryPoint>,
}

#[derive(Serialize)]
pub(super) struct HistoryQueryMetadata {
    pub scope: &'static str,
    pub client: Option<String>,
    pub metric: &'static str,
    pub start_unix_millis: u64,
    pub end_unix_millis: u64,
    pub max_points: usize,
}

#[derive(Serialize)]
pub(super) struct HistoryPoint {
    pub timestamp_unix_millis: u64,
    pub value: f64,
}

#[derive(Serialize)]
pub(super) struct BoundedItems<T> {
    pub total: usize,
    pub returned: usize,
    pub truncated: bool,
    pub items: Vec<T>,
}

impl<T> BoundedItems<T> {
    pub fn new(total: usize, items: Vec<T>) -> Self {
        let returned = items.len();
        Self {
            total,
            returned,
            truncated: returned < total,
            items,
        }
    }
}

#[derive(Serialize)]
pub(super) struct ServerMetrics {
    pub metrics: Metrics,
    pub traffic: Traffic,
    pub online_clients: usize,
    pub active_sessions: SessionCounts,
}

#[derive(Serialize)]
pub(super) struct Metrics {
    pub available: bool,
    pub stale: bool,
    pub clock_skew: bool,
    pub age_millis: Option<u64>,
    pub sampled_unix_millis: Option<u64>,
    pub cpu_basis_points: Option<u16>,
    pub process_cpu_basis_points: Option<u16>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub process_memory_bytes: Option<u64>,
    pub disk_used_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub disk_read_bytes_per_second: Option<u64>,
    pub disk_write_bytes_per_second: Option<u64>,
    pub network_received_bytes_per_second: Option<u64>,
    pub network_sent_bytes_per_second: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct Traffic {
    pub received_bytes: u64,
    pub sent_bytes: u64,
}

#[derive(Serialize)]
pub(super) struct Client {
    pub name: String,
    pub online: bool,
    pub version: String,
    pub authenticated_unix_millis: u64,
    pub disconnected_unix_millis: Option<u64>,
    pub heartbeat: Freshness,
    pub telemetry: Metrics,
    pub traffic: Traffic,
    pub inventory: Inventory,
    pub sessions: SessionCounts,
    pub paths: PathCounts,
    pub active_path: &'static str,
    pub traffic_sort_bytes: String,
    pub reconnects: u64,
}

#[derive(Serialize)]
pub(super) struct Freshness {
    pub available: bool,
    pub stale: bool,
    pub clock_skew: bool,
    pub received_unix_millis: Option<u64>,
    pub age_millis: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct Inventory {
    pub tunnels: BoundedItems<String>,
    pub exports: BoundedItems<String>,
    pub forwards: BoundedItems<String>,
}

#[derive(Serialize, Default)]
pub(super) struct SessionCounts {
    pub total: usize,
    pub active: usize,
    pub tcp: usize,
    pub udp: usize,
    pub p2p: usize,
}

#[derive(Serialize, Default)]
pub(super) struct PathCounts {
    pub relay: usize,
    pub p2p_direct: usize,
    pub p2p_fallback: usize,
}

#[derive(Serialize)]
pub(super) struct Session {
    pub id: String,
    pub client: String,
    pub peer: Option<String>,
    pub tunnel: Option<String>,
    pub export: Option<String>,
    pub kind: &'static str,
    pub path: &'static str,
    pub state: &'static str,
    pub traffic: Traffic,
    pub opened_unix_millis: u64,
    pub closed_unix_millis: Option<u64>,
    pub duration_millis: u64,
    pub terminal_reason: Option<String>,
}

#[derive(Serialize)]
pub(super) struct ObservabilityHealth {
    pub event_queue_depth: usize,
    pub dropped_events: u64,
}

#[derive(Serialize)]
pub(super) struct HistoryHealth {
    pub available: bool,
    pub worker_running: bool,
    pub pending_batches: usize,
    pub pending_batch_bytes: usize,
    pub dropped_batches: u64,
    pub dropped_batch_bytes: u64,
    pub dropped_late_points: u64,
    pub failures: u64,
    pub recoveries: u64,
    pub database_bytes: u64,
    pub size_floor_reached: bool,
}

impl HistoryHealth {
    pub fn unavailable() -> Self {
        Self {
            available: false,
            worker_running: false,
            pending_batches: 0,
            pending_batch_bytes: 0,
            dropped_batches: 0,
            dropped_batch_bytes: 0,
            dropped_late_points: 0,
            failures: 0,
            recoveries: 0,
            database_bytes: 0,
            size_floor_reached: false,
        }
    }
}

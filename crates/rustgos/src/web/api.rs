use std::{
    cmp::Ordering,
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    extract::{OriginalUri, RawQuery, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::get,
};
use rustgo_config::validate_client_name;
use rustgo_observability::{
    ClientSnapshot, HistoryHealth as StoreHistoryHealth, HistoryMetric, HistoryQuery,
    HistoryQueryError, HistoryResolution, HistoryScope, HostMetrics,
    MAX_AUTHENTICATED_CLIENT_NAME_BYTES, MAX_HISTORY_POINTS, OverviewSnapshot, SessionKind,
    SessionPath, SessionSnapshot, TrafficCounters,
};
use serde::Serialize;

use super::{
    WebState,
    dto::{
        BoundedItems, Client, ClientResponse, ClientsResponse, ErrorBody, ErrorEnvelope, Freshness,
        HistoryHealth, HistoryPoint, HistoryQueryMetadata, HistoryResponse, Inventory, Metrics,
        ObservabilityHealth, OverviewResponse, PathCounts, ServerMetrics, ServerMetricsResponse,
        Session, SessionCounts, SessionsResponse, Traffic,
    },
    security::single_cookie_header,
};

pub const MAX_API_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_QUERY_BYTES: usize = 2_048;
const MAX_QUERY_PAIRS: usize = 12;
const MAX_QUERY_KEY_BYTES: usize = 64;
const MAX_QUERY_VALUE_BYTES: usize = 384;
const MAX_SEARCH_BYTES: usize = 128;
const MAX_CLIENT_ITEMS: usize = 256;
const MAX_LIST_INVENTORY_ITEMS: usize = 2;
const MAX_DETAIL_INVENTORY_ITEMS: usize = 256;
const MAX_SESSION_ITEMS: usize = 512;
const MAX_CLIENT_DETAIL_SESSIONS: usize = 256;
const MAX_HISTORY_RANGE_MILLIS: u64 = 30 * 24 * 60 * 60 * 1_000;
const SERVER_STALE_AFTER_MILLIS: u64 = 10_000;
const CLIENT_STALE_AFTER_MILLIS: u64 = 120_000;
const HEARTBEAT_STALE_AFTER_MILLIS: u64 = 120_000;

pub(super) fn routes() -> Router<Arc<WebState>> {
    Router::new()
        .route(
            "/api/v1/overview",
            get(overview).fallback(method_not_allowed),
        )
        .route(
            "/api/v1/server/metrics",
            get(server_metrics).fallback(method_not_allowed),
        )
        .route("/api/v1/clients", get(clients).fallback(method_not_allowed))
        .route(
            "/api/v1/clients/{*name}",
            get(client).fallback(method_not_allowed),
        )
        .route(
            "/api/v1/sessions",
            get(sessions).fallback(method_not_allowed),
        )
        .route("/api/v1/history", get(history).fallback(method_not_allowed))
        .route(
            "/api/v1/{*path}",
            get(api_not_found).fallback(method_not_allowed),
        )
}

async fn overview(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    let snapshot = state.observability.snapshot();
    let now = now_unix_millis();
    let total_clients = snapshot.clients.len();
    let clients = snapshot
        .clients
        .iter()
        .take(MAX_CLIENT_ITEMS)
        .map(|client| client_dto(client, &snapshot.sessions, now, MAX_LIST_INVENTORY_ITEMS))
        .collect();
    let response = OverviewResponse {
        generated_unix_millis: snapshot.generated_unix_millis,
        snapshot_stale: snapshot.generated_unix_millis == 0
            || snapshot.generated_unix_millis > now
            || now.saturating_sub(snapshot.generated_unix_millis) > CLIENT_STALE_AFTER_MILLIS,
        server: server_dto(&snapshot, now),
        clients: BoundedItems::new(total_clients, clients),
        sessions: session_counts(&snapshot.sessions),
        observability: observability_health(&snapshot),
        history: history_health(&state),
    };
    json_response(StatusCode::OK, &response)
}

async fn server_metrics(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    let snapshot = state.observability.snapshot();
    let response = ServerMetricsResponse {
        generated_unix_millis: snapshot.generated_unix_millis,
        server: server_dto(&snapshot, now_unix_millis()),
        observability: observability_health(&snapshot),
        history: history_health(&state),
    };
    json_response(StatusCode::OK, &response)
}

async fn clients(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    let snapshot = state.observability.snapshot();
    let query = match parse_query(raw_query.as_deref(), &["search", "sort", "order", "limit"]) {
        Ok(query) => query,
        Err(()) => return invalid_query(),
    };
    let search = match query.get("search") {
        Some(value) if value.len() <= MAX_SEARCH_BYTES => Some(value.clone()),
        Some(_) => return invalid_query(),
        None => None,
    };
    let sort = match query.get("sort").map(String::as_str).unwrap_or("online") {
        "online" => ClientSort::Online,
        "name" => ClientSort::Name,
        "traffic" => ClientSort::Traffic,
        "cpu" => ClientSort::Cpu,
        _ => return invalid_query(),
    };
    let default_descending = sort == ClientSort::Online;
    let descending = match query.get("order").map(String::as_str) {
        Some("asc") => false,
        Some("desc") => true,
        Some(_) => return invalid_query(),
        None => default_descending,
    };
    let limit = match bounded_limit(query.get("limit"), MAX_CLIENT_ITEMS) {
        Ok(limit) => limit,
        Err(()) => return invalid_query(),
    };
    let search_folded = search.as_ref().map(|value| value.to_lowercase());
    let mut matched: Vec<&ClientSnapshot> = snapshot
        .clients
        .iter()
        .filter(|client| {
            search_folded
                .as_ref()
                .is_none_or(|search| client.name.as_str().to_lowercase().contains(search))
        })
        .collect();
    matched.sort_by(|left, right| {
        let ordering = compare_clients(left, right, sort, descending);
        ordering.then_with(|| left.name.as_str().cmp(right.name.as_str()))
    });
    let total = matched.len();
    let now = now_unix_millis();
    let items = matched
        .into_iter()
        .take(limit)
        .map(|client| client_dto(client, &snapshot.sessions, now, MAX_LIST_INVENTORY_ITEMS))
        .collect();
    json_response(
        StatusCode::OK,
        &ClientsResponse {
            generated_unix_millis: snapshot.generated_unix_millis,
            search,
            sort: sort.as_str(),
            order: if descending { "desc" } else { "asc" },
            clients: BoundedItems::new(total, items),
        },
    )
}

async fn client(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    let snapshot = state.observability.snapshot();
    let name = match client_name_from_path(uri.path()) {
        Ok(name) => name,
        Err(()) => return invalid_client_name(),
    };
    let Some(client) = snapshot
        .clients
        .iter()
        .find(|client| client.name.as_str() == name)
    else {
        return error_response(
            StatusCode::NOT_FOUND,
            "client_not_found",
            "client was not found",
        );
    };
    let now = now_unix_millis();
    let mut client_sessions: Vec<&SessionSnapshot> = snapshot
        .sessions
        .iter()
        .filter(|session| session.client.as_str() == name)
        .collect();
    client_sessions.sort_by_key(|left| std::cmp::Reverse(session_recency(left)));
    let total = client_sessions.len();
    let sessions = client_sessions
        .into_iter()
        .take(MAX_CLIENT_DETAIL_SESSIONS)
        .map(|session| session_dto(session, now))
        .collect();
    json_response(
        StatusCode::OK,
        &ClientResponse {
            generated_unix_millis: snapshot.generated_unix_millis,
            client: client_dto(client, &snapshot.sessions, now, MAX_DETAIL_INVENTORY_ITEMS),
            sessions: BoundedItems::new(total, sessions),
        },
    )
}

async fn sessions(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    let snapshot = state.observability.snapshot();
    let query = match parse_query(
        raw_query.as_deref(),
        &["client", "kind", "path", "state", "sort", "order", "limit"],
    ) {
        Ok(query) => query,
        Err(()) => return invalid_query(),
    };
    let client_filter = match query.get("client") {
        Some(value) if validate_client_name(value).is_ok() => Some(value.as_str()),
        Some(_) => return invalid_query(),
        None => None,
    };
    let kind_filter = match query.get("kind").map(String::as_str) {
        Some("tcp") => Some(SessionKind::Tcp),
        Some("udp") => Some(SessionKind::Udp),
        Some("p2p") => Some(SessionKind::P2p),
        Some(_) => return invalid_query(),
        None => None,
    };
    let path_filter = match query.get("path").map(String::as_str) {
        Some("relay") => Some(SessionPath::Relay),
        Some("p2p-direct") => Some(SessionPath::P2pDirect),
        Some("p2p-fallback") => Some(SessionPath::P2pFallback),
        Some(_) => return invalid_query(),
        None => None,
    };
    let active_filter = match query.get("state").map(String::as_str) {
        Some("active") => Some(true),
        Some("closed") => Some(false),
        Some(_) => return invalid_query(),
        None => None,
    };
    let sort = match query.get("sort").map(String::as_str).unwrap_or("opened") {
        "opened" => SessionSort::Opened,
        "traffic" => SessionSort::Traffic,
        _ => return invalid_query(),
    };
    let descending = match query.get("order").map(String::as_str) {
        Some("asc") => false,
        Some("desc") | None => true,
        Some(_) => return invalid_query(),
    };
    let limit = match bounded_limit(query.get("limit"), MAX_SESSION_ITEMS) {
        Ok(limit) => limit,
        Err(()) => return invalid_query(),
    };
    let mut matched: Vec<&SessionSnapshot> = snapshot
        .sessions
        .iter()
        .filter(|session| client_filter.is_none_or(|client| session.client.as_str() == client))
        .filter(|session| kind_filter.is_none_or(|kind| session.kind == kind))
        .filter(|session| path_filter.is_none_or(|path| session.path == path))
        .filter(|session| {
            active_filter.is_none_or(|active| active == session.closed_unix_millis.is_none())
        })
        .collect();
    matched.sort_by(|left, right| {
        let ordering = match sort {
            SessionSort::Opened => left.opened_unix_millis.cmp(&right.opened_unix_millis),
            SessionSort::Traffic => traffic_total(left.traffic).cmp(&traffic_total(right.traffic)),
        };
        let ordering = if descending {
            ordering.reverse()
        } else {
            ordering
        };
        ordering.then_with(|| left.id.as_str().cmp(right.id.as_str()))
    });
    let total = matched.len();
    let now = now_unix_millis();
    let items = matched
        .into_iter()
        .take(limit)
        .map(|session| session_dto(session, now))
        .collect();
    json_response(
        StatusCode::OK,
        &SessionsResponse {
            generated_unix_millis: snapshot.generated_unix_millis,
            sessions: BoundedItems::new(total, items),
        },
    )
}

async fn history(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    let snapshot = state.observability.snapshot();
    let parsed = match parse_query(
        raw_query.as_deref(),
        &[
            "scope",
            "client",
            "metric",
            "start_unix_millis",
            "end_unix_millis",
            "resolution",
            "max_points",
        ],
    ) {
        Ok(query) => query,
        Err(()) => return invalid_query(),
    };
    let query = match history_query(&parsed) {
        Ok(query) => query,
        Err(()) => return invalid_query(),
    };
    let Some(service) = state.history.clone() else {
        return history_unavailable();
    };
    if !service.health().history_available {
        return history_unavailable();
    }
    let series = match service.query(query.clone()).await {
        Ok(series) => series,
        Err(HistoryQueryError::InvalidRange | HistoryQueryError::InvalidPointLimit) => {
            return invalid_query();
        }
        Err(HistoryQueryError::TimedOut) => {
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "history_timed_out",
                "history query timed out",
            );
        }
        Err(
            HistoryQueryError::Overloaded
            | HistoryQueryError::Unavailable
            | HistoryQueryError::Closed,
        ) => return history_unavailable(),
    };
    let (scope, client) = match &query.scope {
        HistoryScope::Server => ("server", None),
        HistoryScope::Client(client) => ("client", Some(client.as_str().to_owned())),
    };
    let response = HistoryResponse {
        generated_unix_millis: snapshot.generated_unix_millis,
        history: history_health(&state),
        query: HistoryQueryMetadata {
            scope,
            client,
            metric: metric_name(query.metric),
            start_unix_millis: query.start_unix_millis,
            end_unix_millis: query.end_unix_millis,
            max_points: query.max_points,
        },
        resolution: resolution_name(series.resolution),
        points: series
            .points
            .into_iter()
            .take(query.max_points)
            .map(|point| HistoryPoint {
                timestamp_unix_millis: point.timestamp_unix_millis,
                value: point.value,
            })
            .collect(),
    };
    json_response(StatusCode::OK, &response)
}

async fn method_not_allowed(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    method_not_allowed_response()
}

pub(super) fn method_not_allowed_response() -> Response {
    let mut response = error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "only GET and HEAD are allowed",
    );
    response
        .headers_mut()
        .insert("allow", "GET, HEAD".parse().expect("static Allow header"));
    response
}

async fn api_not_found(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    not_found()
}

pub(super) fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found", "resource was not found")
}

fn authenticate(state: &WebState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if state
        .authentication
        .authenticate_cookie(single_cookie_header(headers))
    {
        Ok(())
    } else {
        Err(Box::new(authentication_required()))
    }
}

pub(super) fn authentication_required() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        "authentication_required",
        "authentication required",
    )
}

fn invalid_query() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "query parameters are invalid",
    )
}

fn invalid_client_name() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_client_name",
        "client name path segment is invalid",
    )
}

fn history_unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "history_unavailable",
        "history is temporarily unavailable",
    )
}

fn error_response(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    json_response(
        status,
        &ErrorEnvelope {
            error: ErrorBody { code, message },
        },
    )
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    let bytes = match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= MAX_API_RESPONSE_BYTES => bytes,
        Ok(_) => {
            let envelope = ErrorEnvelope {
                error: ErrorBody {
                    code: "response_too_large",
                    message: "bounded response limit was exceeded",
                },
            };
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CONTENT_TYPE, "application/json; charset=utf-8")],
                serde_json::to_vec(&envelope).expect("static error envelope serializes"),
            )
                .into_response();
        }
        Err(_) => {
            let envelope = ErrorEnvelope {
                error: ErrorBody {
                    code: "serialization_failed",
                    message: "response serialization failed",
                },
            };
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CONTENT_TYPE, "application/json; charset=utf-8")],
                serde_json::to_vec(&envelope).expect("static error envelope serializes"),
            )
                .into_response();
        }
    };
    (
        status,
        [(CONTENT_TYPE, "application/json; charset=utf-8")],
        Body::from(bytes),
    )
        .into_response()
}

fn parse_query(raw: Option<&str>, allowed: &[&str]) -> Result<BTreeMap<String, String>, ()> {
    let raw = raw.unwrap_or("");
    if raw.len() > MAX_QUERY_BYTES {
        return Err(());
    }
    let mut parsed = BTreeMap::new();
    if raw.is_empty() {
        return Ok(parsed);
    }
    for (index, pair) in raw.split('&').enumerate() {
        if index >= MAX_QUERY_PAIRS || pair.is_empty() {
            return Err(());
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key, true, MAX_QUERY_KEY_BYTES)?;
        let value = percent_decode(value, true, MAX_QUERY_VALUE_BYTES)?;
        if !allowed.contains(&key.as_str()) || parsed.insert(key, value).is_some() {
            return Err(());
        }
    }
    Ok(parsed)
}

fn percent_decode(raw: &str, plus_as_space: bool, maximum_bytes: usize) -> Result<String, ()> {
    if raw.len() > maximum_bytes.saturating_mul(3) {
        return Err(());
    }
    let raw = raw.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len().min(maximum_bytes));
    let mut index = 0;
    while index < raw.len() {
        let byte = match raw[index] {
            b'%' => {
                if index + 2 >= raw.len() {
                    return Err(());
                }
                let high = hex(raw[index + 1]).ok_or(())?;
                let low = hex(raw[index + 2]).ok_or(())?;
                index += 3;
                (high << 4) | low
            }
            b'+' if plus_as_space => {
                index += 1;
                b' '
            }
            byte if byte.is_ascii() => {
                index += 1;
                byte
            }
            _ => return Err(()),
        };
        if decoded.len() >= maximum_bytes {
            return Err(());
        }
        decoded.push(byte);
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn client_name_from_path(path: &str) -> Result<String, ()> {
    let raw = path.strip_prefix("/api/v1/clients/").ok_or(())?;
    if raw.is_empty() || raw.contains('/') {
        return Err(());
    }
    let name = percent_decode(raw, false, MAX_AUTHENTICATED_CLIENT_NAME_BYTES)?;
    if validate_client_name(&name).is_ok() {
        Ok(name)
    } else {
        Err(())
    }
}

fn bounded_limit(value: Option<&String>, maximum: usize) -> Result<usize, ()> {
    match value {
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|limit| (1..=maximum).contains(limit))
            .ok_or(()),
        None => Ok(maximum),
    }
}

fn history_query(query: &BTreeMap<String, String>) -> Result<HistoryQuery, ()> {
    let scope = match query.get("scope").map(String::as_str).unwrap_or("server") {
        "server" if !query.contains_key("client") => HistoryScope::Server,
        "client" => {
            let client = query.get("client").ok_or(())?;
            if validate_client_name(client).is_err() {
                return Err(());
            }
            HistoryScope::Client(client.as_str().try_into().map_err(|_| ())?)
        }
        _ => return Err(()),
    };
    let metric = match query.get("metric").map(String::as_str) {
        Some("cpu_basis_points") => HistoryMetric::CpuBasisPoints,
        Some("process_cpu_basis_points") => HistoryMetric::ProcessCpuBasisPoints,
        Some("memory_used_bytes") => HistoryMetric::MemoryUsedBytes,
        Some("memory_total_bytes") => HistoryMetric::MemoryTotalBytes,
        Some("process_memory_bytes") => HistoryMetric::ProcessMemoryBytes,
        Some("disk_used_bytes") => HistoryMetric::DiskUsedBytes,
        Some("disk_total_bytes") => HistoryMetric::DiskTotalBytes,
        Some("disk_read_bytes_per_second") => HistoryMetric::DiskReadBytesPerSecond,
        Some("disk_write_bytes_per_second") => HistoryMetric::DiskWriteBytesPerSecond,
        Some("network_received_bytes_per_second") => HistoryMetric::NetworkRxBytesPerSecond,
        Some("network_sent_bytes_per_second") => HistoryMetric::NetworkTxBytesPerSecond,
        Some("traffic_received_bytes") => HistoryMetric::TrafficReceivedBytes,
        Some("traffic_sent_bytes") => HistoryMetric::TrafficSentBytes,
        _ => return Err(()),
    };
    let start_unix_millis = query
        .get("start_unix_millis")
        .ok_or(())?
        .parse::<u64>()
        .map_err(|_| ())?;
    let end_unix_millis = query
        .get("end_unix_millis")
        .ok_or(())?
        .parse::<u64>()
        .map_err(|_| ())?;
    if start_unix_millis > end_unix_millis
        || end_unix_millis > i64::MAX as u64
        || end_unix_millis.saturating_sub(start_unix_millis) > MAX_HISTORY_RANGE_MILLIS
    {
        return Err(());
    }
    let resolution = match query
        .get("resolution")
        .map(String::as_str)
        .unwrap_or("auto")
    {
        "auto" => HistoryResolution::Auto,
        "raw" => HistoryResolution::Raw,
        "one-minute" => HistoryResolution::OneMinute,
        "five-minutes" => HistoryResolution::FiveMinutes,
        _ => return Err(()),
    };
    let max_points = match query.get("max_points") {
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|limit| (1..=MAX_HISTORY_POINTS).contains(limit))
            .ok_or(())?,
        None => MAX_HISTORY_POINTS,
    };
    Ok(HistoryQuery {
        scope,
        metric,
        start_unix_millis,
        end_unix_millis,
        resolution,
        max_points,
    })
}

fn server_dto(snapshot: &OverviewSnapshot, now: u64) -> ServerMetrics {
    ServerMetrics {
        metrics: metrics_dto(
            snapshot.server.metrics.as_ref(),
            snapshot
                .server
                .metrics
                .as_ref()
                .map(|metrics| metrics.sampled_unix_millis),
            now,
            SERVER_STALE_AFTER_MILLIS,
        ),
        traffic: traffic_dto(snapshot.server.traffic),
        online_clients: snapshot.server.online_clients,
        active_sessions: SessionCounts {
            total: snapshot.server.active_tcp_sessions
                + snapshot.server.active_udp_sessions
                + snapshot.server.active_p2p_sessions,
            active: snapshot.server.active_tcp_sessions
                + snapshot.server.active_udp_sessions
                + snapshot.server.active_p2p_sessions,
            tcp: snapshot.server.active_tcp_sessions,
            udp: snapshot.server.active_udp_sessions,
            p2p: snapshot.server.active_p2p_sessions,
        },
    }
}

fn client_dto(
    client: &ClientSnapshot,
    sessions: &[SessionSnapshot],
    now: u64,
    inventory_limit: usize,
) -> Client {
    let owned_sessions: Vec<&SessionSnapshot> = sessions
        .iter()
        .filter(|session| session.client.as_str() == client.name.as_str())
        .collect();
    Client {
        name: client.name.as_str().to_owned(),
        online: client.online,
        version: client.version.as_str().to_owned(),
        authenticated_unix_millis: client.authenticated_unix_millis,
        disconnected_unix_millis: client.disconnected_unix_millis,
        heartbeat: freshness(
            client.last_heartbeat_unix_millis,
            now,
            HEARTBEAT_STALE_AFTER_MILLIS,
        ),
        telemetry: metrics_dto(
            client.metrics.as_ref(),
            client.telemetry_received_unix_millis,
            now,
            CLIENT_STALE_AFTER_MILLIS,
        ),
        traffic: traffic_dto(client.traffic),
        inventory: Inventory {
            tunnels: inventory(client.tunnels.as_slice(), inventory_limit),
            exports: inventory(client.exports.as_slice(), inventory_limit),
            forwards: inventory(client.forwards.as_slice(), inventory_limit),
        },
        sessions: session_counts_refs(&owned_sessions),
        paths: path_counts(&owned_sessions),
        active_path: active_path(&owned_sessions),
        traffic_sort_bytes: traffic_total(client.traffic).to_string(),
        reconnects: client.reconnects,
    }
}

fn metrics_dto(
    metrics: Option<&HostMetrics>,
    freshness_timestamp: Option<u64>,
    now: u64,
    stale_after: u64,
) -> Metrics {
    let available = metrics.is_some();
    let receipt_clock_skew = freshness_timestamp.is_some_and(|timestamp| timestamp > now);
    let sample_clock_skew = metrics.is_some_and(|metrics| metrics.sampled_unix_millis > now);
    let clock_skew = receipt_clock_skew || sample_clock_skew;
    let age = if clock_skew {
        None
    } else {
        freshness_timestamp.map(|timestamp| now - timestamp)
    };
    Metrics {
        available,
        stale: available && (clock_skew || age.is_some_and(|age| age > stale_after)),
        clock_skew,
        age_millis: age,
        sampled_unix_millis: metrics.map(|metrics| metrics.sampled_unix_millis),
        cpu_basis_points: metrics.and_then(|metrics| metrics.cpu_basis_points),
        process_cpu_basis_points: metrics.and_then(|metrics| metrics.process_cpu_basis_points),
        memory_used_bytes: metrics.and_then(|metrics| metrics.memory_used_bytes),
        memory_total_bytes: metrics.and_then(|metrics| metrics.memory_total_bytes),
        process_memory_bytes: metrics.and_then(|metrics| metrics.process_memory_bytes),
        disk_used_bytes: metrics.and_then(|metrics| metrics.disk_used_bytes),
        disk_total_bytes: metrics.and_then(|metrics| metrics.disk_total_bytes),
        disk_read_bytes_per_second: metrics.and_then(|metrics| metrics.disk_read_bytes_per_sec),
        disk_write_bytes_per_second: metrics.and_then(|metrics| metrics.disk_write_bytes_per_sec),
        network_received_bytes_per_second: metrics
            .and_then(|metrics| metrics.network_rx_bytes_per_sec),
        network_sent_bytes_per_second: metrics.and_then(|metrics| metrics.network_tx_bytes_per_sec),
    }
}

fn freshness(timestamp: Option<u64>, now: u64, stale_after: u64) -> Freshness {
    let clock_skew = timestamp.is_some_and(|timestamp| timestamp > now);
    let age = if clock_skew {
        None
    } else {
        timestamp.map(|timestamp| now - timestamp)
    };
    Freshness {
        available: timestamp.is_some(),
        stale: timestamp.is_some() && (clock_skew || age.is_some_and(|age| age > stale_after)),
        clock_skew,
        received_unix_millis: timestamp,
        age_millis: age,
    }
}

fn inventory(labels: &[rustgo_observability::BoundedLabel], limit: usize) -> BoundedItems<String> {
    let items = labels
        .iter()
        .take(limit)
        .map(|label| label.as_str().to_owned())
        .collect();
    BoundedItems::new(labels.len(), items)
}

fn session_dto(session: &SessionSnapshot, now: u64) -> Session {
    let ended = session.closed_unix_millis.unwrap_or(now);
    Session {
        id: session.id.as_str().to_owned(),
        client: session.client.as_str().to_owned(),
        peer: session.peer.as_ref().map(|peer| peer.as_str().to_owned()),
        tunnel: session
            .tunnel
            .as_ref()
            .map(|tunnel| tunnel.as_str().to_owned()),
        export: session
            .export
            .as_ref()
            .map(|export| export.as_str().to_owned()),
        kind: session_kind_name(session.kind),
        path: session_path_name(session.path),
        state: if session.closed_unix_millis.is_some() {
            "closed"
        } else {
            "active"
        },
        traffic: traffic_dto(session.traffic),
        opened_unix_millis: session.opened_unix_millis,
        closed_unix_millis: session.closed_unix_millis,
        duration_millis: ended.saturating_sub(session.opened_unix_millis),
        terminal_reason: session
            .terminal_reason
            .as_ref()
            .map(|reason| reason.as_str().to_owned()),
    }
}

fn traffic_dto(traffic: TrafficCounters) -> Traffic {
    Traffic {
        received_bytes: traffic.received_bytes,
        sent_bytes: traffic.sent_bytes,
    }
}

fn session_counts(sessions: &[SessionSnapshot]) -> SessionCounts {
    let refs = sessions.iter().collect::<Vec<_>>();
    session_counts_refs(&refs)
}

fn session_counts_refs(sessions: &[&SessionSnapshot]) -> SessionCounts {
    let mut counts = SessionCounts {
        total: sessions.len(),
        ..SessionCounts::default()
    };
    for session in sessions {
        if session.closed_unix_millis.is_none() {
            counts.active += 1;
        }
        match session.kind {
            SessionKind::Tcp => counts.tcp += 1,
            SessionKind::Udp => counts.udp += 1,
            SessionKind::P2p => counts.p2p += 1,
        }
    }
    counts
}

fn path_counts(sessions: &[&SessionSnapshot]) -> PathCounts {
    let mut counts = PathCounts::default();
    for session in sessions {
        match session.path {
            SessionPath::Relay => counts.relay += 1,
            SessionPath::P2pDirect => counts.p2p_direct += 1,
            SessionPath::P2pFallback => counts.p2p_fallback += 1,
        }
    }
    counts
}

fn active_path(sessions: &[&SessionSnapshot]) -> &'static str {
    let mut relay = false;
    let mut direct = false;
    let mut fallback = false;
    for session in sessions
        .iter()
        .copied()
        .filter(|session| session.closed_unix_millis.is_none())
    {
        match session.path {
            SessionPath::Relay => relay = true,
            SessionPath::P2pDirect => direct = true,
            SessionPath::P2pFallback => fallback = true,
        }
    }
    match (relay, direct, fallback) {
        (false, false, false) => "none",
        (true, false, false) => "relay",
        (false, true, false) => "p2p-direct",
        (false, false, true) => "p2p-fallback",
        _ => "mixed",
    }
}

fn observability_health(snapshot: &OverviewSnapshot) -> ObservabilityHealth {
    ObservabilityHealth {
        event_queue_depth: snapshot.event_queue_depth,
        dropped_events: snapshot.dropped_events,
    }
}

fn history_health(state: &WebState) -> HistoryHealth {
    state
        .history
        .as_ref()
        .map(|history| history.health())
        .map(history_health_dto)
        .unwrap_or_else(HistoryHealth::unavailable)
}

fn history_health_dto(health: StoreHistoryHealth) -> HistoryHealth {
    HistoryHealth {
        available: health.history_available,
        worker_running: health.worker_running,
        pending_batches: health.pending_batches,
        pending_batch_bytes: health.pending_batch_bytes,
        dropped_batches: health.dropped_batches,
        dropped_batch_bytes: health.dropped_batch_bytes,
        dropped_late_points: health.dropped_late_points,
        failures: health.history_failures,
        recoveries: health.recoveries,
        database_bytes: health.total_database_bytes,
        size_floor_reached: health.size_floor_reached,
    }
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn traffic_total(traffic: TrafficCounters) -> u64 {
    traffic.received_bytes.saturating_add(traffic.sent_bytes)
}

fn session_recency(session: &SessionSnapshot) -> u64 {
    session
        .closed_unix_millis
        .unwrap_or(session.opened_unix_millis)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientSort {
    Online,
    Name,
    Traffic,
    Cpu,
}

impl ClientSort {
    fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Name => "name",
            Self::Traffic => "traffic",
            Self::Cpu => "cpu",
        }
    }
}

fn compare_clients(
    left: &ClientSnapshot,
    right: &ClientSnapshot,
    sort: ClientSort,
    descending: bool,
) -> Ordering {
    if sort == ClientSort::Cpu {
        let left = left
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.cpu_basis_points);
        let right = right
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.cpu_basis_points);
        return match (left, right) {
            (Some(left), Some(right)) if descending => left.cmp(&right).reverse(),
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
    }
    let ordering = match sort {
        ClientSort::Online => left.online.cmp(&right.online),
        ClientSort::Name => left.name.as_str().cmp(right.name.as_str()),
        ClientSort::Traffic => traffic_total(left.traffic).cmp(&traffic_total(right.traffic)),
        ClientSort::Cpu => unreachable!("CPU ordering is handled above"),
    };
    if descending {
        ordering.reverse()
    } else {
        ordering
    }
}

#[derive(Clone, Copy)]
enum SessionSort {
    Opened,
    Traffic,
}

fn session_kind_name(kind: SessionKind) -> &'static str {
    match kind {
        SessionKind::Tcp => "tcp",
        SessionKind::Udp => "udp",
        SessionKind::P2p => "p2p",
    }
}

fn session_path_name(path: SessionPath) -> &'static str {
    match path {
        SessionPath::Relay => "relay",
        SessionPath::P2pDirect => "p2p-direct",
        SessionPath::P2pFallback => "p2p-fallback",
    }
}

fn metric_name(metric: HistoryMetric) -> &'static str {
    match metric {
        HistoryMetric::CpuBasisPoints => "cpu_basis_points",
        HistoryMetric::ProcessCpuBasisPoints => "process_cpu_basis_points",
        HistoryMetric::MemoryUsedBytes => "memory_used_bytes",
        HistoryMetric::MemoryTotalBytes => "memory_total_bytes",
        HistoryMetric::ProcessMemoryBytes => "process_memory_bytes",
        HistoryMetric::DiskUsedBytes => "disk_used_bytes",
        HistoryMetric::DiskTotalBytes => "disk_total_bytes",
        HistoryMetric::DiskReadBytesPerSecond => "disk_read_bytes_per_second",
        HistoryMetric::DiskWriteBytesPerSecond => "disk_write_bytes_per_second",
        HistoryMetric::NetworkRxBytesPerSecond => "network_received_bytes_per_second",
        HistoryMetric::NetworkTxBytesPerSecond => "network_sent_bytes_per_second",
        HistoryMetric::TrafficReceivedBytes => "traffic_received_bytes",
        HistoryMetric::TrafficSentBytes => "traffic_sent_bytes",
    }
}

fn resolution_name(resolution: HistoryResolution) -> &'static str {
    match resolution {
        HistoryResolution::Auto => "auto",
        HistoryResolution::Raw => "raw",
        HistoryResolution::OneMinute => "one-minute",
        HistoryResolution::FiveMinutes => "five-minutes",
    }
}

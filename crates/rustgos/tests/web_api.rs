use std::{
    collections::HashMap,
    error::Error,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustgo_config::{Limits, ServerConfig, ServerSection, WebConfig};
use rustgo_observability::{
    AuthenticatedClientIdentity, BoundedInventory, BoundedLabel, HistoryBatch, HistoryConfig,
    HistoryService, HistoryWorkerHandle, HostMetrics, ObservabilitySink, ObservabilityStore,
    ObservationEvent, ServerHistorySample, SessionPath, ShortSessionId, TrafficCounters,
};
use rustgos::web::{DashboardDataSources, MAX_API_RESPONSE_BYTES, WebRuntimeLimits, WebServer};
use serde_json::Value;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const USERNAME: &str = "admin";
const PASSWORD: &str = "correct-horse-battery-staple";
const UNICODE_CLIENT: &str = "北京-节点";
const UNICODE_CLIENT_PATH: &str = "%E5%8C%97%E4%BA%AC-%E8%8A%82%E7%82%B9";
const RAW_SESSION_ID: &[u8] = b"full-session-id-must-never-be-returned";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_routes_expose_bounded_explicit_redacted_dtos() -> Result<(), Box<dyn Error>>
{
    let mut rig = TestRig::start(true, 3).await?;
    let cookie = rig.web.login().await?;

    let anonymous = rig.web.request("GET", "/api/v1/overview", &[], "").await?;
    assert_eq!(anonymous.status, 401);
    assert_eq!(
        anonymous.json()?["error"]["code"],
        "authentication_required"
    );

    let overview = rig.web.api("GET", "/api/v1/overview", &cookie).await?;
    assert_json_response(&overview, 200)?;
    let overview_json = overview.json()?;
    assert_eq!(overview_json["clients"]["total"], 3);
    assert_eq!(overview_json["server"]["metrics"]["available"], true);
    assert_eq!(overview_json["history"]["available"], true);
    assert_eq!(overview_json["sessions"]["total"], 3);
    assert!(!overview.body.contains(std::str::from_utf8(RAW_SESSION_ID)?));
    assert!(!overview.body.contains(PASSWORD));
    assert!(!overview.body.contains("candidate"));
    assert!(!overview.body.contains("generation"));

    let server = rig
        .web
        .api("GET", "/api/v1/server/metrics", &cookie)
        .await?;
    assert_json_response(&server, 200)?;
    assert_eq!(server.json()?["server"]["traffic"]["received_bytes"], 77);

    let clients = rig
        .web
        .api(
            "GET",
            "/api/v1/clients?search=%E5%8C%97&sort=name&order=asc&limit=2",
            &cookie,
        )
        .await?;
    assert_json_response(&clients, 200)?;
    let clients_json = clients.json()?;
    assert_eq!(clients_json["clients"]["total"], 1);
    assert_eq!(clients_json["clients"]["items"][0]["name"], UNICODE_CLIENT);
    assert_eq!(
        clients_json["clients"]["items"][0]["telemetry"]["available"],
        true
    );

    let detail = rig
        .web
        .api(
            "GET",
            &format!("/api/v1/clients/{UNICODE_CLIENT_PATH}"),
            &cookie,
        )
        .await?;
    assert_json_response(&detail, 200)?;
    let detail_json = detail.json()?;
    assert_eq!(detail_json["client"]["name"], UNICODE_CLIENT);
    assert_eq!(
        detail_json["client"]["inventory"]["exports"]["items"][0],
        "files"
    );
    assert_eq!(detail_json["client"]["paths"]["p2p_direct"], 1);
    assert_eq!(
        detail_json["sessions"]["items"][0]["id"]
            .as_str()
            .ok_or("missing shortened session id")?
            .len(),
        16
    );
    assert!(!detail.body.contains(std::str::from_utf8(RAW_SESSION_ID)?));

    let sessions = rig
        .web
        .api(
            "GET",
            "/api/v1/sessions?client=%E5%8C%97%E4%BA%AC-%E8%8A%82%E7%82%B9&kind=p2p&path=p2p-direct&state=active&sort=traffic&order=desc",
            &cookie,
        )
        .await?;
    assert_json_response(&sessions, 200)?;
    let sessions_json = sessions.json()?;
    assert_eq!(sessions_json["sessions"]["total"], 1);
    assert_eq!(sessions_json["sessions"]["items"][0]["path"], "p2p-direct");

    let now = unix_millis_now();
    let history = rig
        .web
        .api(
            "GET",
            &format!(
                "/api/v1/history?scope=server&metric=cpu_basis_points&start_unix_millis={}&end_unix_millis={}&resolution=raw&max_points=2",
                now.saturating_sub(60_000),
                now.saturating_add(60_000)
            ),
            &cookie,
        )
        .await?;
    assert_json_response(&history, 200)?;
    let history_json = history.json()?;
    assert_eq!(history_json["query"]["max_points"], 2);
    assert!(
        history_json["points"]
            .as_array()
            .ok_or("points are not an array")?
            .len()
            <= 2
    );
    assert_eq!(history_json["resolution"], "raw");

    let head = rig.web.api("HEAD", "/api/v1/overview", &cookie).await?;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());

    rig.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filters_staleness_methods_and_history_failures_have_stable_bounds()
-> Result<(), Box<dyn Error>> {
    let mut rig = TestRig::start(false, 600).await?;
    let cookie = rig.web.login().await?;

    let clients = rig
        .web
        .api("GET", "/api/v1/clients?sort=cpu&order=desc", &cookie)
        .await?;
    assert_json_response(&clients, 200)?;
    let clients_json = clients.json()?;
    let items = clients_json["clients"]["items"]
        .as_array()
        .ok_or("clients are not an array")?;
    let legacy = items
        .iter()
        .find(|client| client["name"] == "legacy")
        .ok_or("missing legacy client")?;
    let stale = items
        .iter()
        .find(|client| client["name"] == "stale")
        .ok_or("missing stale client")?;
    assert_eq!(legacy["telemetry"]["available"], false);
    assert_eq!(legacy["heartbeat"]["available"], false);
    assert_eq!(stale["telemetry"]["available"], true);
    assert_eq!(stale["telemetry"]["stale"], true);
    assert_eq!(stale["heartbeat"]["stale"], true);

    let sessions = rig.web.api("GET", "/api/v1/sessions", &cookie).await?;
    assert_json_response(&sessions, 200)?;
    let sessions_json = sessions.json()?;
    assert_eq!(sessions_json["sessions"]["returned"], 512);
    assert_eq!(sessions_json["sessions"]["truncated"], true);
    assert!(sessions.body.len() <= MAX_API_RESPONSE_BYTES);

    let unavailable = rig
        .web
        .api(
            "GET",
            "/api/v1/history?metric=cpu_basis_points&start_unix_millis=1&end_unix_millis=2",
            &cookie,
        )
        .await?;
    assert_eq!(unavailable.status, 503);
    assert_eq!(unavailable.json()?["error"]["code"], "history_unavailable");

    for path in [
        "/api/v1/history?metric=cpu_basis_points&start_unix_millis=1&end_unix_millis=2&max_points=2001",
        "/api/v1/history?metric=cpu_basis_points&start_unix_millis=1&end_unix_millis=2592000002",
        "/api/v1/history?metric=cpu_basis_points&start_unix_millis=1&end_unix_millis=2&resolution=seconds",
        "/api/v1/clients?sort=secret",
        "/api/v1/clients?search=a&search=b",
    ] {
        let response = rig.web.api("GET", path, &cookie).await?;
        assert_eq!(response.status, 400, "{path}");
        assert_eq!(response.json()?["error"]["code"], "invalid_query");
    }

    let oversized_query = format!("/api/v1/clients?search={}", "a".repeat(2_100));
    assert_eq!(
        rig.web.api("GET", &oversized_query, &cookie).await?.status,
        400
    );
    let ambiguous = rig
        .web
        .api("GET", "/api/v1/clients/%252e%252e", &cookie)
        .await?;
    assert_eq!(ambiguous.status, 400);
    assert_eq!(ambiguous.json()?["error"]["code"], "invalid_client_name");

    let anonymous_post = rig.web.request("POST", "/api/v1/overview", &[], "").await?;
    assert_eq!(anonymous_post.status, 401);
    let post = rig.web.api("POST", "/api/v1/overview", &cookie).await?;
    assert_eq!(post.status, 405);
    assert_eq!(post.header("allow"), Some("GET, HEAD"));
    assert_eq!(post.json()?["error"]["code"], "method_not_allowed");
    for method in ["PUT", "PATCH", "DELETE"] {
        assert_eq!(
            rig.web
                .api(method, "/api/v1/clients", &cookie)
                .await?
                .status,
            405
        );
    }
    let missing = rig.web.api("GET", "/api/v1/unknown", &cookie).await?;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.json()?["error"]["code"], "not_found");

    rig.shutdown().await?;
    Ok(())
}

struct TestRig {
    web: RunningWebServer,
    observability_sink: Option<ObservabilitySink>,
    observability_task: JoinHandle<()>,
    history: Option<(HistoryService, HistoryWorkerHandle)>,
    _history_directory: Option<TempDir>,
}

impl TestRig {
    async fn start(history_enabled: bool, session_count: usize) -> Result<Self, Box<dyn Error>> {
        let (store, sink, worker) = ObservabilityStore::new();
        let observability_task = tokio::spawn(worker.run());
        seed_snapshot(&sink, session_count)?;
        wait_until(Duration::from_secs(2), || {
            let snapshot = store.snapshot();
            snapshot.clients.len() == 3
                && snapshot.sessions.len() == session_count
                && snapshot.event_queue_depth == 0
        })
        .await?;

        let (history, history_directory) = if history_enabled {
            let directory = tempfile::tempdir()?;
            let (service, worker) = HistoryService::new(HistoryConfig {
                database_path: directory.path().join("metrics.db"),
                history_days: 7,
                database_max_mib: 16,
            })?;
            let worker = worker.start()?;
            wait_until(Duration::from_secs(3), || {
                let health = service.health();
                health.worker_running && health.history_available
            })
            .await?;
            let now = unix_millis_now();
            service.try_publish(HistoryBatch {
                server_points: (0..5)
                    .map(|offset| {
                        ServerHistorySample::from_metrics(
                            metrics(now.saturating_sub(offset * 1_000), 1_000 + offset as u16),
                            TrafficCounters {
                                received_bytes: offset,
                                sent_bytes: offset * 2,
                            },
                        )
                    })
                    .collect(),
                ..HistoryBatch::default()
            })?;
            (Some((service, worker)), Some(directory))
        } else {
            (None, None)
        };
        let sources =
            DashboardDataSources::new(store, history.as_ref().map(|(service, _)| service.clone()));
        let web = RunningWebServer::start(sources).await?;
        Ok(Self {
            web,
            observability_sink: Some(sink),
            observability_task,
            history,
            _history_directory: history_directory,
        })
    }

    async fn shutdown(&mut self) -> Result<(), Box<dyn Error>> {
        self.web.shutdown().await?;
        if let Some((service, worker)) = self.history.take() {
            service.close();
            worker.shutdown().await?;
        }
        self.observability_sink.take();
        tokio::time::timeout(Duration::from_secs(2), &mut self.observability_task).await??;
        Ok(())
    }
}

fn seed_snapshot(sink: &ObservabilitySink, session_count: usize) -> Result<(), Box<dyn Error>> {
    let now = unix_millis_now();
    let unicode = identity(UNICODE_CLIENT, 1)?;
    let legacy = identity("legacy", 2)?;
    let stale = identity("stale", 3)?;
    sink.try_publish(ObservationEvent::ServerSample {
        metrics: metrics(now, 2_500),
    })?;
    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: unicode.clone(),
        version: label("0.3.0")?,
        authenticated_unix_millis: now.saturating_sub(10_000),
    })?;
    sink.try_publish(ObservationEvent::Heartbeat {
        client: unicode.clone(),
        received_unix_millis: now,
    })?;
    sink.try_publish(ObservationEvent::ClientTelemetryAccepted {
        client: unicode.clone(),
        sequence: 7,
        received_unix_millis: now,
        metrics: metrics(now, 1_500),
    })?;
    sink.try_publish(ObservationEvent::TunnelInventory {
        client: unicode.clone(),
        names: inventory(["ssh", "web"])?,
    })?;
    sink.try_publish(ObservationEvent::ExportInventory {
        client: unicode.clone(),
        names: inventory(["files"])?,
    })?;
    sink.try_publish(ObservationEvent::ForwardInventory {
        client: unicode.clone(),
        names: inventory(["remote-db"])?,
    })?;
    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: legacy.clone(),
        version: label("0.2.0")?,
        authenticated_unix_millis: now.saturating_sub(500_000),
    })?;
    sink.try_publish(ObservationEvent::ClientDisconnected {
        client: legacy,
        disconnected_unix_millis: now.saturating_sub(400_000),
    })?;
    sink.try_publish(ObservationEvent::ClientAuthenticated {
        client: stale.clone(),
        version: label("0.3.0")?,
        authenticated_unix_millis: now.saturating_sub(500_000),
    })?;
    sink.try_publish(ObservationEvent::Heartbeat {
        client: stale.clone(),
        received_unix_millis: now.saturating_sub(300_000),
    })?;
    sink.try_publish(ObservationEvent::ClientTelemetryAccepted {
        client: stale,
        sequence: 1,
        received_unix_millis: now.saturating_sub(300_000),
        metrics: metrics(now.saturating_sub(300_000), 500),
    })?;

    for index in 0..session_count {
        let session_id = if index == 0 {
            ShortSessionId::from_bytes(RAW_SESSION_ID)
        } else {
            ShortSessionId::from_bytes(format!("bounded-session-{index}").as_bytes())
        };
        if index == 0 {
            sink.try_publish(ObservationEvent::P2pSessionOpened {
                client: unicode.clone(),
                session_id,
                peer: label("peer-a")?,
                export: Some(label("files")?),
                path: SessionPath::P2pDirect,
                opened_unix_millis: now.saturating_sub(5_000),
            })?;
        } else {
            sink.try_publish(ObservationEvent::TcpSessionOpened {
                client: unicode.clone(),
                session_id,
                tunnel: Some(label("ssh")?),
                opened_unix_millis: now.saturating_sub(index as u64),
            })?;
        }
    }
    sink.try_publish(ObservationEvent::ByteCounterDelta {
        client: unicode,
        session_id: Some(ShortSessionId::from_bytes(RAW_SESSION_ID)),
        counters: TrafficCounters {
            received_bytes: 77,
            sent_bytes: 88,
        },
    })?;
    Ok(())
}

fn identity(name: &str, generation: u64) -> Result<AuthenticatedClientIdentity, Box<dyn Error>> {
    Ok(AuthenticatedClientIdentity::from_server_authentication(
        name, generation,
    )?)
}

fn label(value: &str) -> Result<BoundedLabel, Box<dyn Error>> {
    Ok(BoundedLabel::try_from(value)?)
}

fn inventory<const N: usize>(values: [&str; N]) -> Result<BoundedInventory, Box<dyn Error>> {
    Ok(BoundedInventory::try_from_names(values)?)
}

fn metrics(timestamp: u64, cpu: u16) -> HostMetrics {
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

async fn wait_until(
    timeout: Duration,
    mut predicate: impl FnMut() -> bool,
) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(timeout, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

struct RunningWebServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: Option<JoinHandle<Result<(), rustgos::web::WebError>>>,
}

impl RunningWebServer {
    async fn start(sources: DashboardDataSources) -> Result<Self, Box<dyn Error>> {
        let address = unused_address()?;
        let server = WebServer::bind_with_data_sources(
            &server_config(address),
            WebRuntimeLimits::default(),
            sources,
        )
        .await?;
        let address = server.local_addr()?;
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { server.run_until(task_shutdown).await });
        Ok(Self {
            address,
            shutdown,
            task: Some(task),
        })
    }

    async fn login(&self) -> Result<String, Box<dyn Error>> {
        let body = format!("username={USERNAME}&password={PASSWORD}");
        let origin = format!("http://{}", self.address);
        let response = self
            .request(
                "POST",
                "/login",
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", &origin),
                ],
                &body,
            )
            .await?;
        if response.status != 200 {
            return Err(format!("login failed with {}", response.status).into());
        }
        response
            .header("set-cookie")
            .and_then(|cookie| cookie.split(';').next())
            .map(str::to_owned)
            .ok_or_else(|| "login did not set a session cookie".into())
    }

    async fn api(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        self.request(method, path, &[("Cookie", cookie)], "").await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        let mut stream = TcpStream::connect(self.address).await?;
        let mut wire = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.address,
            body.len()
        );
        for (name, value) in headers {
            wire.push_str(name);
            wire.push_str(": ");
            wire.push_str(value);
            wire.push_str("\r\n");
        }
        wire.push_str("\r\n");
        wire.push_str(body);
        stream.write_all(wire.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        HttpResponse::parse(&response)
    }

    async fn shutdown(&mut self) -> Result<(), Box<dyn Error>> {
        self.shutdown.cancel();
        let task = self.task.take().ok_or("Web task was already joined")?;
        task.await??;
        Ok(())
    }
}

impl Drop for RunningWebServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body: String,
}

impl HttpResponse {
    fn parse(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let split = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or("HTTP response did not contain a header terminator")?;
        let head = std::str::from_utf8(&bytes[..split])?;
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or("HTTP response did not contain a status")?
            .parse()?;
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
            headers
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_owned());
        }
        Ok(Self {
            status,
            headers,
            body: String::from_utf8(bytes[split + 4..].to_vec())?,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn json(&self) -> Result<Value, Box<dyn Error>> {
        Ok(serde_json::from_str(&self.body)?)
    }
}

fn assert_json_response(response: &HttpResponse, status: u16) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status, status);
    assert_eq!(
        response.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert!(response.body.len() <= MAX_API_RESPONSE_BYTES);
    let _: Value = response.json()?;
    Ok(())
}

fn unused_address() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn server_config(web_address: SocketAddr) -> ServerConfig {
    ServerConfig {
        server: ServerSection {
            bind_addr: "127.0.0.1:7443".to_owned(),
            udp_bind_ip: None,
            p2p_observation_bind: None,
            p2p_observation_alternate_bind: None,
            certificate_file: PathBuf::from("unused-cert.pem"),
            private_key_file: PathBuf::from("unused-key.pem"),
            heartbeat_timeout_secs: 30,
        },
        limits: Limits {
            max_clients: 1_024,
            max_tunnels_per_client: 256,
            max_tcp_connections_per_tunnel: 1_024,
            max_udp_sessions_per_tunnel: 1_024,
            max_udp_payload_bytes: 65_507,
        },
        clients: Vec::new(),
        web: Some(WebConfig {
            enabled: true,
            bind: web_address.to_string(),
            external_origin: None,
            admin_username: USERNAME.to_owned(),
            admin_password: PASSWORD.to_owned(),
            cookie_secure: false,
            history_days: 7,
            database_path: PathBuf::from("unused-history.db"),
            database_max_mib: 256,
        }),
    }
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

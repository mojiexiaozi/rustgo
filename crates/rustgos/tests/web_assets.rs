use std::{
    collections::HashMap,
    error::Error,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
};

use rustgo_config::{Limits, ServerConfig, ServerSection, WebConfig};
use rustgos::web::WebServer;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const USERNAME: &str = "dashboard-admin";
const PASSWORD: &str = "dashboard-functional-password";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_assets_are_allowlisted_cacheable_and_csp_compatible() -> Result<(), Box<dyn Error>>
{
    let server = RunningWebServer::start().await?;

    let login = server.request("GET", "/login", &[], "").await?;
    assert_eq!(login.status, 200);
    assert_page_headers(&login, "text/html; charset=utf-8")?;
    assert!(login.body.contains("id=\"login-form\""));
    assert!(login.body.contains("src=\"/login.js\""));
    assert!(!login.body.contains("<script>"));

    let anonymous_dashboard = server.request("GET", "/", &[], "").await?;
    assert_eq!(anonymous_dashboard.status, 401);

    let cookie = server.login().await?;
    let dashboard = server
        .request("GET", "/", &[("Cookie", &cookie)], "")
        .await?;
    assert_eq!(dashboard.status, 200);
    assert_eq!(dashboard.header("cache-control"), Some("no-store"));
    assert_eq!(
        dashboard.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(dashboard.body.contains("id=\"client-grid\""));
    assert!(dashboard.body.contains("id=\"chart-cpu\""));
    assert!(dashboard.body.contains("id=\"sessions-table\""));
    assert!(dashboard.body.contains("src=\"/app.js\""));

    for (path, content_type, required_hook) in [
        ("/app.css", "text/css; charset=utf-8", ".client-grid"),
        (
            "/app.js",
            "text/javascript; charset=utf-8",
            "POLL_MILLIS = 2000",
        ),
        ("/login.js", "text/javascript; charset=utf-8", "login-form"),
    ] {
        let asset = server.request("GET", path, &[], "").await?;
        assert_eq!(asset.status, 200, "{path}");
        assert_asset_headers(&asset, content_type)?;
        assert!(
            asset.body.contains(required_hook),
            "{path} is missing {required_hook}"
        );
        let etag = asset.header("etag").ok_or("asset ETag missing")?.to_owned();
        let not_modified = server
            .request("GET", path, &[("If-None-Match", &etag)], "")
            .await?;
        assert_eq!(not_modified.status, 304, "{path} did not honor its ETag");
        assert_eq!(not_modified.header("etag"), Some(etag.as_str()));
        assert_eq!(
            not_modified.header("cache-control"),
            Some("public, max-age=31536000, immutable")
        );
    }

    let unknown = server
        .request("GET", "/assets/../config.toml", &[("Cookie", &cookie)], "")
        .await?;
    assert_eq!(unknown.status, 404);
    assert!(!unknown.body.contains("config"));

    server.shutdown().await?;
    Ok(())
}

#[test]
fn checked_in_dashboard_uses_only_relative_allowlisted_resources() {
    let index = include_str!("../web/index.html");
    let login = include_str!("../web/login.html");
    let script = include_str!("../web/app.js");
    let login_script = include_str!("../web/login.js");
    let assets = include_str!("../src/web/assets.rs");
    let combined = format!("{index}\n{login}\n{script}\n{login_script}");

    for path in ["/", "/login", "/app.css", "/app.js", "/login.js"] {
        assert!(
            assets.contains(&format!("\"{path}\"")) || index.contains(path) || login.contains(path)
        );
    }
    assert!(assets.contains("include_bytes!"));
    assert!(!combined.contains("https://"));
    assert!(
        !combined
            .replace("http://www.w3.org/2000/svg", "")
            .contains("http://")
    );
    assert!(!combined.contains("<script>"));
    assert!(!combined.contains("EventSource"));
    assert!(!combined.contains("WebSocket"));
    assert!(script.contains("AbortController"));
    assert!(script.contains("visibilitychange"));
    assert!(script.contains("/api/v1/overview"));
    assert!(script.contains("/api/v1/clients/"));
    assert!(script.contains("/api/v1/sessions"));
    assert!(script.contains("/api/v1/history"));
    assert_eq!(
        script.matches("/api/v1/").count(),
        4,
        "the dashboard may only issue its four documented API route families"
    );
    for forbidden in [
        PASSWORD,
        "candidate",
        "private_key",
        "full-session-id",
        "authorization",
    ] {
        assert!(
            !combined
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase())
        );
    }
}

fn assert_asset_headers(response: &HttpResponse, content_type: &str) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.header("content-type"), Some(content_type));
    assert_eq!(
        response.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert!(response.header("etag").is_some());
    assert_security_headers(response)
}

fn assert_page_headers(response: &HttpResponse, content_type: &str) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.header("content-type"), Some(content_type));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert!(response.header("etag").is_some());
    assert_security_headers(response)
}

fn assert_security_headers(response: &HttpResponse) -> Result<(), Box<dyn Error>> {
    let csp = response
        .header("content-security-policy")
        .ok_or("missing CSP")?;
    assert!(csp.contains("script-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    Ok(())
}

struct RunningWebServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: Option<JoinHandle<Result<(), rustgos::web::WebError>>>,
}

impl RunningWebServer {
    async fn start() -> Result<Self, Box<dyn Error>> {
        let address = unused_address()?;
        let server = WebServer::bind(&server_config(address)).await?;
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
        assert_eq!(response.status, 200);
        response
            .session_cookie()
            .ok_or_else(|| "login did not return a session cookie".into())
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

    async fn shutdown(mut self) -> Result<(), Box<dyn Error>> {
        self.shutdown.cancel();
        self.task
            .take()
            .ok_or("server task was already taken")?
            .await??;
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
            .ok_or("missing HTTP response terminator")?;
        let mut lines = std::str::from_utf8(&bytes[..split])?.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or("missing HTTP status")?
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
    fn session_cookie(&self) -> Option<String> {
        self.header("set-cookie")?
            .split(';')
            .next()
            .map(str::to_owned)
    }
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
            max_clients: 8,
            max_tunnels_per_client: 8,
            max_tcp_connections_per_tunnel: 8,
            max_udp_sessions_per_tunnel: 8,
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

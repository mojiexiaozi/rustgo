use std::{
    collections::HashMap,
    error::Error,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    time::Duration,
};

use rustgo_config::{Limits, ServerConfig, ServerSection, WebConfig};
use rustgos::web::{WebRuntimeLimits, WebServer};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const USERNAME: &str = "admin";
const PASSWORD: &str = "correct-horse-battery-staple";

#[tokio::test]
async fn login_uses_indistinguishable_digest_checks_and_guards_every_api_route()
-> Result<(), Box<dyn Error>> {
    let server = RunningWebServer::start(WebRuntimeLimits::default(), false).await?;

    let unknown_user = server
        .login("unknown-administrator-name", PASSWORD, None)
        .await?;
    let wrong_password = server.login(USERNAME, "definitely-wrong", None).await?;
    assert_eq!(unknown_user.status, 401);
    assert_eq!(wrong_password.status, 401);
    assert_eq!(unknown_user.body, wrong_password.body);
    assert_eq!(
        unknown_user.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(unknown_user.header("cache-control"), Some("no-store"));
    assert!(!unknown_user.body.contains(USERNAME));
    assert!(!unknown_user.body.contains(PASSWORD));

    let login = server.login(USERNAME, PASSWORD, None).await?;
    assert_eq!(login.status, 200);
    let cookie = login
        .session_cookie()
        .ok_or("login did not set a session cookie")?;
    let token = cookie
        .split_once('=')
        .map(|(_, token)| token)
        .ok_or("session cookie had no value")?;
    assert_eq!(token.len(), 43, "a 256-bit base64url token is 43 bytes");
    assert!(!cookie.contains(PASSWORD));

    let anonymous_api = server.request("GET", "/api/v1/overview", &[], "").await?;
    assert_eq!(anonymous_api.status, 401);
    let authenticated_api = server
        .request("GET", "/api/v1/overview", &[("Cookie", &cookie)], "")
        .await?;
    assert_eq!(authenticated_api.status, 404);

    Ok(())
}

#[tokio::test]
async fn sessions_expire_on_idle_and_absolute_deadlines_and_evict_at_capacity()
-> Result<(), Box<dyn Error>> {
    tokio::time::pause();
    let capacity_limits = WebRuntimeLimits {
        max_sessions: 2,
        max_login_attempts_per_peer: 16,
        max_global_login_attempts: 16,
        ..WebRuntimeLimits::default()
    };
    let capacity_server = RunningWebServer::start(capacity_limits, false).await?;
    let first = capacity_server
        .login(USERNAME, PASSWORD, None)
        .await?
        .session_cookie()
        .ok_or("first login did not set a cookie")?;
    let second = capacity_server
        .login(USERNAME, PASSWORD, None)
        .await?
        .session_cookie()
        .ok_or("second login did not set a cookie")?;
    let third = capacity_server
        .login(USERNAME, PASSWORD, None)
        .await?
        .session_cookie()
        .ok_or("third login did not set a cookie")?;
    assert_eq!(capacity_server.api(&first).await?.status, 401);
    assert_eq!(capacity_server.api(&second).await?.status, 404);
    assert_eq!(capacity_server.api(&third).await?.status, 404);

    let idle_server = RunningWebServer::start(
        WebRuntimeLimits {
            session_idle_timeout: Duration::from_millis(40),
            session_absolute_timeout: Duration::from_secs(1),
            ..WebRuntimeLimits::default()
        },
        false,
    )
    .await?;
    let idle_cookie = idle_server
        .login(USERNAME, PASSWORD, None)
        .await?
        .session_cookie()
        .ok_or("idle login did not set a cookie")?;
    tokio::time::advance(Duration::from_millis(70)).await;
    assert_eq!(idle_server.api(&idle_cookie).await?.status, 401);

    let absolute_server = RunningWebServer::start(
        WebRuntimeLimits {
            session_idle_timeout: Duration::from_millis(50),
            session_absolute_timeout: Duration::from_millis(80),
            ..WebRuntimeLimits::default()
        },
        false,
    )
    .await?;
    let absolute_cookie = absolute_server
        .login(USERNAME, PASSWORD, None)
        .await?
        .session_cookie()
        .ok_or("absolute login did not set a cookie")?;
    for _ in 0..3 {
        tokio::time::advance(Duration::from_millis(20)).await;
        assert_eq!(absolute_server.api(&absolute_cookie).await?.status, 404);
    }
    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(absolute_server.api(&absolute_cookie).await?.status, 401);

    Ok(())
}

#[tokio::test]
async fn login_rate_limits_are_bounded_per_peer_and_globally() -> Result<(), Box<dyn Error>> {
    let peer_server = RunningWebServer::start(
        WebRuntimeLimits {
            login_window: Duration::from_millis(60),
            max_login_attempts_per_peer: 2,
            max_global_login_attempts: 20,
            max_tracked_login_peers: 2,
            ..WebRuntimeLimits::default()
        },
        false,
    )
    .await?;
    let first_failure = peer_server.login(USERNAME, "wrong-one", None).await?;
    let second_failure = peer_server.login(USERNAME, "wrong-two", None).await?;
    let peer_limited = peer_server.login(USERNAME, PASSWORD, None).await?;
    assert_eq!(first_failure.status, 401);
    assert_eq!(second_failure.status, 401);
    assert_eq!(peer_limited.status, 401);
    assert_eq!(first_failure.body, peer_limited.body);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        peer_server.login(USERNAME, PASSWORD, None).await?.status,
        200
    );

    let global_server = RunningWebServer::start(
        WebRuntimeLimits {
            max_login_attempts_per_peer: 10,
            max_global_login_attempts: 2,
            ..WebRuntimeLimits::default()
        },
        false,
    )
    .await?;
    assert_eq!(
        global_server
            .login(USERNAME, "wrong-one", None)
            .await?
            .status,
        401
    );
    assert_eq!(
        global_server
            .login(USERNAME, "wrong-two", None)
            .await?
            .status,
        401
    );
    let globally_limited = global_server.login(USERNAME, PASSWORD, None).await?;
    assert_eq!(globally_limited.status, 401);
    assert_eq!(globally_limited.body, first_failure.body);

    Ok(())
}

#[tokio::test]
async fn cookies_are_strict_configurable_and_logout_revokes_the_session()
-> Result<(), Box<dyn Error>> {
    let server = RunningWebServer::start(WebRuntimeLimits::default(), false).await?;
    let login = server.login(USERNAME, PASSWORD, None).await?;
    let set_cookie = login.header("set-cookie").ok_or("missing Set-Cookie")?;
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Path=/"));
    assert!(set_cookie.contains("Max-Age=28800"));
    assert!(!set_cookie.contains("Secure"));
    let cookie = login.session_cookie().ok_or("missing session cookie")?;

    let missing_origin = server
        .request(
            "POST",
            "/logout",
            &[
                ("Cookie", &cookie),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            "",
        )
        .await?;
    assert_eq!(missing_origin.status, 400);
    assert_eq!(server.api(&cookie).await?.status, 404);

    let wrong_origin = format!("http://127.0.0.1:{}", server.address.port() + 1);
    let rejected = server
        .request(
            "POST",
            "/logout",
            &[
                ("Cookie", &cookie),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", &wrong_origin),
            ],
            "",
        )
        .await?;
    assert_eq!(rejected.status, 400);

    let origin = server.origin();
    let logout = server
        .request(
            "POST",
            "/logout",
            &[
                ("Cookie", &cookie),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", &origin),
            ],
            "",
        )
        .await?;
    assert_eq!(logout.status, 200);
    let expired = logout
        .header("set-cookie")
        .ok_or("missing expired cookie")?;
    assert!(expired.contains("Max-Age=0"));
    assert_eq!(server.api(&cookie).await?.status, 401);

    let secure_server = RunningWebServer::start(WebRuntimeLimits::default(), true).await?;
    let secure_login = secure_server
        .login(USERNAME, PASSWORD, Some("https"))
        .await?;
    assert_eq!(secure_login.status, 200);
    assert!(
        secure_login
            .header("set-cookie")
            .ok_or("missing secure Set-Cookie")?
            .contains("; Secure")
    );

    Ok(())
}

#[tokio::test]
async fn state_changes_reject_cross_origin_non_form_and_oversized_requests()
-> Result<(), Box<dyn Error>> {
    let server = RunningWebServer::start(WebRuntimeLimits::default(), false).await?;
    let form = format!("username={USERNAME}&password={PASSWORD}");
    let origin = server.origin();

    assert_eq!(
        server
            .request(
                "POST",
                "/login",
                &[("Content-Type", "application/x-www-form-urlencoded")],
                &form,
            )
            .await?
            .status,
        400
    );
    assert_eq!(
        server
            .request(
                "POST",
                "/login",
                &[("Content-Type", "application/json"), ("Origin", &origin)],
                "{\"username\":\"admin\"}",
            )
            .await?
            .status,
        400
    );
    assert_eq!(
        server
            .request_with_host(
                "POST",
                "/login",
                "localhost.invalid",
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", "http://localhost.invalid"),
                ],
                &form,
            )
            .await?
            .status,
        400
    );
    let oversized = format!("username={USERNAME}&password={}", "x".repeat(1_100));
    assert_eq!(
        server
            .request(
                "POST",
                "/login",
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", &origin),
                ],
                &oversized,
            )
            .await?
            .status,
        400
    );

    let cookie = server
        .login(USERNAME, PASSWORD, None)
        .await?
        .session_cookie()
        .ok_or("login did not set a cookie")?;
    assert_eq!(
        server
            .request(
                "POST",
                "/logout",
                &[
                    ("Cookie", &cookie),
                    ("Content-Type", "application/json"),
                    ("Origin", &origin),
                ],
                "{}",
            )
            .await?
            .status,
        400
    );
    assert_eq!(server.api(&cookie).await?.status, 404);

    Ok(())
}

#[tokio::test]
async fn every_response_has_security_headers_and_health_reveals_only_liveness()
-> Result<(), Box<dyn Error>> {
    let server = RunningWebServer::start(WebRuntimeLimits::default(), false).await?;
    let health = server.request("GET", "/healthz", &[], "").await?;
    assert_eq!(health.status, 200);
    assert_eq!(health.body, "ok\n");
    assert!(!health.body.contains(USERNAME));
    assert!(!health.body.contains(PASSWORD));
    assert!(!health.body.contains("metrics"));
    assert!(!health.body.contains("database"));
    assert_eq!(health.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(health.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(health.header("x-frame-options"), Some("DENY"));
    assert_eq!(
        health.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    let csp = health
        .header("content-security-policy")
        .ok_or("health response omitted CSP")?;
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("unsafe-inline"));

    let api = server.request("DELETE", "/api/v1/clients", &[], "").await?;
    assert_eq!(api.status, 401);
    assert_eq!(api.header("cache-control"), Some("no-store"));
    assert_eq!(api.header("x-content-type-options"), Some("nosniff"));

    Ok(())
}

#[tokio::test]
async fn binding_fails_closed_and_is_independent_from_the_relay_listener()
-> Result<(), Box<dyn Error>> {
    let invalid_address = unused_address()?;
    let mut invalid = server_config(invalid_address, false);
    invalid.web.as_mut().expect("web config exists").bind =
        format!("0.0.0.0:{}", invalid_address.port());
    let error = WebServer::bind(&invalid)
        .await
        .expect_err("a non-loopback web address must fail validation");
    let message = error.to_string();
    assert!(message.contains("loopback"));
    assert!(!message.contains(PASSWORD));
    assert!(TcpStream::connect(invalid_address).await.is_err());

    let relay_reservation = StdTcpListener::bind("127.0.0.1:0")?;
    let relay_address = relay_reservation.local_addr()?;
    let web_address = unused_address()?;
    let mut independent = server_config(web_address, false);
    independent.server.bind_addr = relay_address.to_string();
    let web = WebServer::bind(&independent).await?;
    assert_eq!(web.local_addr()?, web_address);
    drop(web);
    drop(relay_reservation);

    Ok(())
}

struct RunningWebServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), rustgos::web::WebError>>,
}

impl RunningWebServer {
    async fn start(limits: WebRuntimeLimits, cookie_secure: bool) -> Result<Self, Box<dyn Error>> {
        let address = unused_address()?;
        let server =
            WebServer::bind_with_runtime_limits(&server_config(address, cookie_secure), limits)
                .await?;
        let address = server.local_addr()?;
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { server.run_until(task_shutdown).await });
        Ok(Self {
            address,
            shutdown,
            task,
        })
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    async fn login(
        &self,
        username: &str,
        password: &str,
        scheme: Option<&str>,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        let body = format!("username={username}&password={password}");
        let origin = format!("{}://{}", scheme.unwrap_or("http"), self.address);
        self.request(
            "POST",
            "/login",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", &origin),
            ],
            &body,
        )
        .await
    }

    async fn api(&self, cookie: &str) -> Result<HttpResponse, Box<dyn Error>> {
        self.request("GET", "/api/v1/overview", &[("Cookie", cookie)], "")
            .await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        self.request_with_host(method, path, &self.address.to_string(), headers, body)
            .await
    }

    async fn request_with_host(
        &self,
        method: &str,
        path: &str,
        host: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        let mut stream = TcpStream::connect(self.address).await?;
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request.push_str(body);
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        HttpResponse::parse(&response)
    }
}

impl Drop for RunningWebServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
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

fn server_config(web_address: SocketAddr, cookie_secure: bool) -> ServerConfig {
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
            admin_username: USERNAME.to_owned(),
            admin_password: PASSWORD.to_owned(),
            cookie_secure,
            history_days: 7,
            database_path: PathBuf::from("unused-history.db"),
            database_max_mib: 256,
        }),
    }
}

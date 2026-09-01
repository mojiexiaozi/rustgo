use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    time::Duration,
};

use rustgo_config::{Limits, MAX_WEB_AUTHORITY_BYTES, ServerConfig, ServerSection, WebConfig};
use rustgos::web::{WebRuntimeLimits, WebServer};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpSocket, TcpStream},
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
            session_idle_timeout: Duration::from_millis(80),
            session_absolute_timeout: Duration::from_secs(5),
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
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(idle_server.api(&idle_cookie).await?.status, 401);

    let absolute_server = RunningWebServer::start(
        WebRuntimeLimits {
            session_idle_timeout: Duration::from_millis(300),
            session_absolute_timeout: Duration::from_millis(800),
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
    let absolute_started = std::time::Instant::now();
    let mut successful_refreshes = 0_u8;
    loop {
        let refresh_started = std::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(80)).await;
        let status = absolute_server.api(&absolute_cookie).await?.status;
        assert!(
            refresh_started.elapsed() < Duration::from_millis(300),
            "each refresh must remain inside the idle deadline"
        );
        if status == 401 {
            break;
        }
        assert_eq!(status, 404);
        successful_refreshes = successful_refreshes.saturating_add(1);
        assert!(successful_refreshes < 20, "absolute expiry did not fire");
    }
    assert!(successful_refreshes >= 5);
    assert!(absolute_started.elapsed() >= Duration::from_millis(800));

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

    let bounded_peer_server = RunningWebServer::start(
        WebRuntimeLimits {
            max_login_attempts_per_peer: 1,
            max_global_login_attempts: 20,
            max_tracked_login_peers: 2,
            ..WebRuntimeLimits::default()
        },
        false,
    )
    .await?;
    for (last_octet, password) in [(2, "wrong-two"), (3, "wrong-three"), (4, "wrong-four")] {
        assert_eq!(
            bounded_peer_server
                .login_from(Ipv4Addr::new(127, 0, 0, last_octet), USERNAME, password)
                .await?
                .status,
            401
        );
    }
    assert_eq!(
        bounded_peer_server
            .login_from(Ipv4Addr::new(127, 0, 0, 2), USERNAME, PASSWORD)
            .await?
            .status,
        401,
        "an active .2 bucket must survive the denied .4 overflow attempt"
    );

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
async fn external_https_origin_works_through_a_loopback_reverse_proxy_without_proxy_trust()
-> Result<(), Box<dyn Error>> {
    let server = RunningWebServer::start_with_origin(
        WebRuntimeLimits::default(),
        true,
        Some("HTTPS://Dashboard.Example:443".to_owned()),
    )
    .await?;
    let proxy = RunningProxy::start(server.address).await?;
    let body = format!("username={USERNAME}&password={PASSWORD}");

    let login = server
        .request_via(
            proxy.address,
            "POST",
            "/login",
            "DASHBOARD.EXAMPLE",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "https://dashboard.example:443"),
                ("Forwarded", "for=198.51.100.7;proto=http;host=evil.example"),
                ("X-Forwarded-Host", "evil.example"),
                ("X-Forwarded-Proto", "http"),
            ],
            &body,
        )
        .await?;
    assert_eq!(login.status, 200);
    assert!(
        login
            .header("set-cookie")
            .ok_or("reverse-proxy login omitted its cookie")?
            .contains("; Secure")
    );

    let internal_host = server.address.to_string();
    let forged_proxy_headers = server
        .request_via(
            proxy.address,
            "POST",
            "/login",
            &internal_host,
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "https://dashboard.example"),
                ("X-Forwarded-Host", "dashboard.example"),
                ("X-Forwarded-Proto", "https"),
            ],
            &body,
        )
        .await?;
    assert_eq!(forged_proxy_headers.status, 400);

    Ok(())
}

#[tokio::test]
async fn browser_host_canonicalization_and_authority_limit_match_runtime_requests()
-> Result<(), Box<dyn Error>> {
    let numeric = RunningWebServer::start_with_origin(
        WebRuntimeLimits::default(),
        true,
        Some("https://127.1".to_owned()),
    )
    .await?;
    let numeric_proxy = RunningProxy::start(numeric.address).await?;
    let body = format!("username={USERNAME}&password={PASSWORD}");
    assert_eq!(
        numeric
            .request_via(
                numeric_proxy.address,
                "POST",
                "/login",
                "127.0.0.1",
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", "https://0x7f000001"),
                ],
                &body,
            )
            .await?
            .status,
        200
    );

    let unicode = RunningWebServer::start_with_origin(
        WebRuntimeLimits::default(),
        true,
        Some("https://BÜCHER.Example".to_owned()),
    )
    .await?;
    let unicode_proxy = RunningProxy::start(unicode.address).await?;
    assert_eq!(
        unicode
            .request_via(
                unicode_proxy.address,
                "POST",
                "/login",
                "XN--BCHER-KVA.EXAMPLE:443",
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", "https://xn--bcher-kva.example"),
                ],
                &body,
            )
            .await?
            .status,
        200
    );

    let authority = format!("{}.{}:1", "a".repeat(63), "b".repeat(62));
    assert_eq!(authority.len(), MAX_WEB_AUTHORITY_BYTES);
    let boundary = RunningWebServer::start_with_origin(
        WebRuntimeLimits::default(),
        true,
        Some(format!("https://{authority}")),
    )
    .await?;
    let boundary_proxy = RunningProxy::start(boundary.address).await?;
    let origin = format!("https://{authority}");
    assert_eq!(
        boundary
            .request_via(
                boundary_proxy.address,
                "POST",
                "/login",
                &authority,
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", &origin),
                ],
                &body,
            )
            .await?
            .status,
        200
    );

    let too_long_but_equivalent = authority.replacen(":1", ":01", 1);
    assert_eq!(too_long_but_equivalent.len(), MAX_WEB_AUTHORITY_BYTES + 1);
    assert_eq!(
        boundary
            .request_via(
                boundary_proxy.address,
                "POST",
                "/login",
                &too_long_but_equivalent,
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", &origin),
                ],
                &body,
            )
            .await?
            .status,
        400
    );

    Ok(())
}

#[tokio::test]
async fn slow_headers_and_chunked_bodies_release_capacity_and_shutdown_is_bounded()
-> Result<(), Box<dyn Error>> {
    let constrained = WebRuntimeLimits {
        max_connections: 1,
        max_concurrent_requests: 1,
        header_read_timeout: Duration::from_millis(80),
        request_timeout: Duration::from_millis(300),
        body_read_timeout: Duration::from_millis(80),
        graceful_drain_timeout: Duration::from_millis(50),
        ..WebRuntimeLimits::default()
    };
    let header_server = RunningWebServer::start(constrained.clone(), false).await?;
    let mut incomplete_header = TcpStream::connect(header_server.address).await?;
    incomplete_header
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1")
        .await?;
    let mut queued = TcpStream::connect(header_server.address).await?;
    queued
        .write_all(
            format!(
                "GET /healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                header_server.address
            )
            .as_bytes(),
        )
        .await?;
    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(25), queued.read(&mut probe))
            .await
            .is_err(),
        "the second connection must not be serviced above the connection ceiling"
    );
    let mut queued_response = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(500),
        queued.read_to_end(&mut queued_response),
    )
    .await??;
    assert_eq!(HttpResponse::parse(&queued_response)?.status, 200);
    drop(incomplete_header);

    let body_server = RunningWebServer::start(constrained.clone(), false).await?;
    let mut incomplete_body = TcpStream::connect(body_server.address).await?;
    incomplete_body
        .write_all(
            format!(
                "POST /login HTTP/1.1\r\nHost: {0}\r\nOrigin: http://{0}\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\nusername=admin",
                body_server.address
            )
            .as_bytes(),
        )
        .await?;
    let mut queued_after_body = TcpStream::connect(body_server.address).await?;
    queued_after_body
        .write_all(
            format!(
                "GET /healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                body_server.address
            )
            .as_bytes(),
        )
        .await?;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            queued_after_body.read(&mut probe)
        )
        .await
        .is_err()
    );
    let mut body_timeout_response = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(500),
        incomplete_body.read_to_end(&mut body_timeout_response),
    )
    .await??;
    let body_timeout_response = HttpResponse::parse(&body_timeout_response)?;
    assert_eq!(body_timeout_response.status, 408);
    assert_eq!(
        body_timeout_response.header("x-content-type-options"),
        Some("nosniff")
    );
    let mut recovered_response = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(500),
        queued_after_body.read_to_end(&mut recovered_response),
    )
    .await??;
    assert_eq!(HttpResponse::parse(&recovered_response)?.status, 200);

    let shutdown_server = RunningWebServer::start(
        WebRuntimeLimits {
            header_read_timeout: Duration::from_secs(5),
            graceful_drain_timeout: Duration::from_millis(40),
            max_connections: 1,
            max_concurrent_requests: 1,
            ..WebRuntimeLimits::default()
        },
        false,
    )
    .await?;
    let mut shutdown_blocker = TcpStream::connect(shutdown_server.address).await?;
    shutdown_blocker
        .write_all(b"GET /healthz HTTP/1.1\r\nHost:")
        .await?;
    tokio::task::yield_now().await;
    tokio::time::timeout(Duration::from_millis(250), shutdown_server.shutdown()).await??;
    drop(shutdown_blocker);

    Ok(())
}

#[tokio::test]
async fn runtime_limits_reject_zero_oversized_and_incoherent_deadlines()
-> Result<(), Box<dyn Error>> {
    let base = WebRuntimeLimits::default();
    let invalid = [
        WebRuntimeLimits {
            max_connections: 0,
            ..base.clone()
        },
        WebRuntimeLimits {
            max_connections: 1,
            max_concurrent_requests: 2,
            ..base.clone()
        },
        WebRuntimeLimits {
            header_read_timeout: Duration::ZERO,
            ..base.clone()
        },
        WebRuntimeLimits {
            request_timeout: Duration::from_secs(61),
            ..base.clone()
        },
        WebRuntimeLimits {
            request_timeout: Duration::from_millis(20),
            body_read_timeout: Duration::from_millis(21),
            ..base.clone()
        },
        WebRuntimeLimits {
            graceful_drain_timeout: Duration::from_secs(31),
            ..base
        },
    ];
    let config = server_config(unused_address()?, false);
    for limits in invalid {
        let error = WebServer::bind_with_runtime_limits(&config, limits)
            .await
            .expect_err("invalid Web runtime limits must fail before binding");
        assert!(error.to_string().contains("runtime limits"));
    }
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
    task: Option<JoinHandle<Result<(), rustgos::web::WebError>>>,
}

impl RunningWebServer {
    async fn start(limits: WebRuntimeLimits, cookie_secure: bool) -> Result<Self, Box<dyn Error>> {
        Self::start_with_origin(limits, cookie_secure, None).await
    }

    async fn start_with_origin(
        limits: WebRuntimeLimits,
        cookie_secure: bool,
        external_origin: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let address = unused_address()?;
        let mut config = server_config(address, cookie_secure);
        if let Some(external_origin) = external_origin {
            config
                .web
                .as_mut()
                .expect("the Web test configuration exists")
                .external_origin = Some(external_origin);
        }
        let server = WebServer::bind_with_runtime_limits(&config, limits).await?;
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

    async fn login_from(
        &self,
        source: Ipv4Addr,
        username: &str,
        password: &str,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        let body = format!("username={username}&password={password}");
        let host = self.address.to_string();
        let origin = format!("http://{host}");
        self.request_from(
            source,
            "POST",
            "/login",
            &host,
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
        send_request(TestRequest {
            connect_to: self.address,
            source: None,
            method,
            path,
            host,
            headers,
            body,
        })
        .await
    }

    async fn request_from(
        &self,
        source: Ipv4Addr,
        method: &str,
        path: &str,
        host: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        send_request(TestRequest {
            connect_to: self.address,
            source: Some(source),
            method,
            path,
            host,
            headers,
            body,
        })
        .await
    }

    async fn request_via(
        &self,
        connect_to: SocketAddr,
        method: &str,
        path: &str,
        host: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        send_request(TestRequest {
            connect_to,
            source: None,
            method,
            path,
            host,
            headers,
            body,
        })
        .await
    }

    async fn shutdown(mut self) -> Result<(), Box<dyn Error>> {
        self.shutdown.cancel();
        let task = self
            .task
            .take()
            .ok_or("Web server task was already taken")?;
        task.await??;
        Ok(())
    }
}

struct TestRequest<'a> {
    connect_to: SocketAddr,
    source: Option<Ipv4Addr>,
    method: &'a str,
    path: &'a str,
    host: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a str,
}

async fn send_request(request: TestRequest<'_>) -> Result<HttpResponse, Box<dyn Error>> {
    let mut stream = if let Some(source) = request.source {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(IpAddr::V4(source), 0))?;
        socket.connect(request.connect_to).await?
    } else {
        TcpStream::connect(request.connect_to).await?
    };
    let mut wire = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        request.method,
        request.path,
        request.host,
        request.body.len()
    );
    for (name, value) in request.headers {
        wire.push_str(name);
        wire.push_str(": ");
        wire.push_str(value);
        wire.push_str("\r\n");
    }
    wire.push_str("\r\n");
    wire.push_str(request.body);
    stream.write_all(wire.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    HttpResponse::parse(&response)
}

impl Drop for RunningWebServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct RunningProxy {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

impl RunningProxy {
    async fn start(target: SocketAddr) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut browser, _)) = accepted else {
                    break;
                };
                tokio::spawn(async move {
                    let Ok(mut upstream) = TcpStream::connect(target).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut browser, &mut upstream).await;
                });
            }
        });
        Ok(Self {
            address,
            shutdown,
            task,
        })
    }
}

impl Drop for RunningProxy {
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
            external_origin: cookie_secure.then(|| format!("https://{web_address}")),
            admin_username: USERNAME.to_owned(),
            admin_password: PASSWORD.to_owned(),
            cookie_secure,
            history_days: 7,
            database_path: PathBuf::from("unused-history.db"),
            database_max_mib: 256,
        }),
    }
}

//! Loopback-only HTTP authentication boundary for the Rustgo dashboard.

mod auth;
mod security;

use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};

use auth::{AuthenticationState, SESSION_COOKIE_NAME};
use axum::{
    Form, Router, body,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE, SET_COOKIE},
    },
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use rustgo_config::ServerConfig;
use serde::Deserialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use self::security::{response_security_headers, same_origin, single_cookie_header};

const MAX_LOGIN_BODY_BYTES: usize = 1_024;
const MAX_LOGOUT_BODY_BYTES: usize = 64;
const MAX_USERNAME_BYTES: usize = 64;
const MAX_PASSWORD_BYTES: usize = 256;
const MAX_SESSIONS: usize = 32;
const MAX_LOGIN_ATTEMPTS_PER_PEER: usize = 1_024;
const MAX_GLOBAL_LOGIN_ATTEMPTS: usize = 4_096;
const MAX_TRACKED_LOGIN_PEERS: usize = 1_024;

#[derive(Debug, Clone)]
pub struct WebRuntimeLimits {
    pub session_idle_timeout: Duration,
    pub session_absolute_timeout: Duration,
    pub max_sessions: usize,
    pub login_window: Duration,
    pub max_login_attempts_per_peer: usize,
    pub max_global_login_attempts: usize,
    pub max_tracked_login_peers: usize,
}

impl Default for WebRuntimeLimits {
    fn default() -> Self {
        Self {
            session_idle_timeout: Duration::from_secs(30 * 60),
            session_absolute_timeout: Duration::from_secs(8 * 60 * 60),
            max_sessions: MAX_SESSIONS,
            login_window: Duration::from_secs(60),
            max_login_attempts_per_peer: 8,
            max_global_login_attempts: 64,
            max_tracked_login_peers: MAX_TRACKED_LOGIN_PEERS,
        }
    }
}

impl WebRuntimeLimits {
    fn validate(&self) -> Result<(), WebError> {
        let now = tokio::time::Instant::now();
        if self.session_idle_timeout.is_zero()
            || self.session_absolute_timeout.is_zero()
            || self.session_idle_timeout > self.session_absolute_timeout
            || self.max_sessions == 0
            || self.max_sessions > MAX_SESSIONS
            || self.login_window.is_zero()
            || self.max_login_attempts_per_peer == 0
            || self.max_login_attempts_per_peer > MAX_LOGIN_ATTEMPTS_PER_PEER
            || self.max_global_login_attempts == 0
            || self.max_global_login_attempts > MAX_GLOBAL_LOGIN_ATTEMPTS
            || self.max_tracked_login_peers == 0
            || self.max_tracked_login_peers > MAX_TRACKED_LOGIN_PEERS
            || now.checked_add(self.session_idle_timeout).is_none()
            || now.checked_add(self.session_absolute_timeout).is_none()
            || now.checked_add(self.login_window).is_none()
        {
            return Err(WebError::InvalidRuntimeLimits);
        }
        Ok(())
    }
}

pub struct WebServer {
    listener: TcpListener,
    router: Router,
}

impl WebServer {
    pub async fn bind(config: &ServerConfig) -> Result<Self, WebError> {
        Self::bind_with_runtime_limits(config, WebRuntimeLimits::default()).await
    }

    #[doc(hidden)]
    pub async fn bind_with_runtime_limits(
        config: &ServerConfig,
        limits: WebRuntimeLimits,
    ) -> Result<Self, WebError> {
        config
            .validate()
            .map_err(|error| WebError::InvalidConfiguration(error.to_string()))?;
        limits.validate()?;
        let web = config
            .web
            .as_ref()
            .filter(|web| web.enabled)
            .ok_or(WebError::Disabled)?;
        let configured_address = web
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| WebError::InvalidBindAddress)?;
        if !configured_address.ip().is_loopback() {
            return Err(WebError::NonLoopbackBind);
        }

        let authentication =
            AuthenticationState::new(&web.admin_username, &web.admin_password, &limits)
                .map_err(|_| WebError::Authentication)?;
        let listener = TcpListener::bind(configured_address).await?;
        let bound_address = listener.local_addr()?;
        if !bound_address.ip().is_loopback() {
            return Err(WebError::NonLoopbackBind);
        }

        let state = Arc::new(WebState {
            authentication,
            expected_host: bound_address.to_string(),
            cookie_secure: web.cookie_secure,
        });
        let router = build_router(state);
        Ok(Self { listener, router })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self) -> Result<(), WebError> {
        self.run_until(CancellationToken::new()).await
    }

    pub async fn run_until(self, shutdown: CancellationToken) -> Result<(), WebError> {
        axum::serve(
            self.listener,
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await?;
        Ok(())
    }
}

impl fmt::Debug for WebServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebServer")
            .field("local_addr", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

struct WebState {
    authentication: AuthenticationState,
    expected_host: String,
    cookie_secure: bool,
}

fn build_router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/login",
            post(login).layer(DefaultBodyLimit::max(MAX_LOGIN_BODY_BYTES)),
        )
        .route(
            "/logout",
            post(logout).layer(DefaultBodyLimit::max(MAX_LOGOUT_BODY_BYTES)),
        )
        .route("/api", any(api_boundary))
        .route("/api/{*path}", any(api_boundary))
        .fallback(protected_not_found)
        .with_state(state)
        .layer(middleware::from_fn(response_security_headers))
}

async fn healthz() -> Response {
    plain_response(StatusCode::OK, "ok\n")
}

async fn login(
    State(state): State<Arc<WebState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    if !same_origin(request.headers(), &state.expected_host, state.cookie_secure)
        || !is_form_request(request.headers())
        || request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_LOGIN_BODY_BYTES)
    {
        return rejected_request();
    }

    let form = match Form::<LoginForm>::from_request(request, &()).await {
        Ok(Form(form)) => form,
        Err(_) => return rejected_request(),
    };
    if !state.authentication.admit_login(peer.ip()) {
        return authentication_failed();
    }
    let lengths_valid =
        form.username.len() <= MAX_USERNAME_BYTES && form.password.len() <= MAX_PASSWORD_BYTES;
    if !state
        .authentication
        .credentials_match(&form.username, &form.password)
        || !lengths_valid
    {
        return authentication_failed();
    }

    let token = match state.authentication.issue_session() {
        Ok(token) => token,
        Err(_) => return internal_error(),
    };
    let cookie = session_cookie(&token, state.cookie_secure);
    let mut response = plain_response(StatusCode::OK, "ok\n");
    response.headers_mut().insert(SET_COOKIE, cookie);
    response
}

async fn logout(State(state): State<Arc<WebState>>, request: Request) -> Response {
    if !same_origin(request.headers(), &state.expected_host, state.cookie_secure)
        || !is_form_request(request.headers())
        || request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_LOGOUT_BODY_BYTES)
    {
        return rejected_request();
    }
    let cookie = single_cookie_header(request.headers()).map(str::to_owned);
    let Ok(logout_body) = body::to_bytes(request.into_body(), MAX_LOGOUT_BODY_BYTES).await else {
        return rejected_request();
    };
    if !logout_body.is_empty() {
        return rejected_request();
    }
    if !state.authentication.revoke_cookie(cookie.as_deref()) {
        return authentication_failed();
    }
    let mut response = plain_response(StatusCode::OK, "ok\n");
    response
        .headers_mut()
        .insert(SET_COOKIE, expired_session_cookie(state.cookie_secure));
    response
}

async fn api_boundary(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if !state
        .authentication
        .authenticate_cookie(single_cookie_header(&headers))
    {
        return authentication_failed();
    }
    plain_response(StatusCode::NOT_FOUND, "not found\n")
}

async fn protected_not_found(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if !state
        .authentication
        .authenticate_cookie(single_cookie_header(&headers))
    {
        return authentication_failed();
    }
    plain_response(StatusCode::NOT_FOUND, "not found\n")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginForm {
    username: String,
    password: String,
}

fn is_form_request(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

fn session_cookie(token: &str, secure: bool) -> HeaderValue {
    cookie_value(token, secure, "Max-Age=28800")
}

fn expired_session_cookie(secure: bool) -> HeaderValue {
    cookie_value("", secure, "Max-Age=0")
}

fn cookie_value(value: &str, secure: bool, lifetime: &str) -> HeaderValue {
    let secure_attribute = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/; {lifetime}{secure_attribute}"
    ))
    .expect("a base64url token and static cookie attributes form a valid header")
}

fn authentication_failed() -> Response {
    plain_response(StatusCode::UNAUTHORIZED, "authentication failed\n")
}

fn rejected_request() -> Response {
    plain_response(StatusCode::BAD_REQUEST, "request rejected\n")
}

fn internal_error() -> Response {
    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
}

fn plain_response(status: StatusCode, body: &'static str) -> Response {
    (status, [(CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

#[derive(Debug, Error)]
pub enum WebError {
    #[error("invalid server configuration: {0}")]
    InvalidConfiguration(String),
    #[error("the web dashboard is not enabled")]
    Disabled,
    #[error("web.bind is not a valid socket address")]
    InvalidBindAddress,
    #[error("the web dashboard must bind to a loopback address")]
    NonLoopbackBind,
    #[error("invalid Web runtime limits")]
    InvalidRuntimeLimits,
    #[error("web authentication initialization failed")]
    Authentication,
    #[error("web listener I/O failed: {0}")]
    Io(#[from] io::Error),
}

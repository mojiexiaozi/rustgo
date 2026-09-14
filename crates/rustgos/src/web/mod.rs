//! Loopback-only HTTP authentication and read-only API for the Rustgo dashboard.

mod api;
mod assets;
mod auth;
mod dto;
mod security;

pub use api::MAX_API_RESPONSE_BYTES;

use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt, io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::enrollment::DynamicClientStore;
use auth::{AuthenticationState, SESSION_COOKIE_NAME};
use axum::{
    Form, Router,
    body::{self, Body},
    extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE, SET_COOKIE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustgo_config::{ServerConfig, WebOrigin};
use rustgo_observability::{HistoryService, ObservabilityStore};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

use self::security::{
    apply_response_security_headers, response_security_headers, same_origin, single_cookie_header,
};

const CSRF_HEADER_NAME: axum::http::HeaderName =
    axum::http::HeaderName::from_static("x-rustgo-csrf-token");

const MAX_LOGIN_BODY_BYTES: usize = 1_024;
const MAX_LOGOUT_BODY_BYTES: usize = 64;
const MAX_USERNAME_BYTES: usize = 64;
const MAX_PASSWORD_BYTES: usize = 256;
const MAX_SESSIONS: usize = 32;
const MAX_LOGIN_ATTEMPTS_PER_PEER: usize = 1_024;
const MAX_GLOBAL_LOGIN_ATTEMPTS: usize = 4_096;
const MAX_TRACKED_LOGIN_PEERS: usize = 1_024;
const MAX_CONNECTIONS: usize = 1_024;
const MAX_CONCURRENT_REQUESTS: usize = 1_024;
const MAX_HTTP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_MAX_HEADERS: usize = 64;
const HTTP_MAX_BUFFER_BYTES: usize = 16 * 1_024;

#[derive(Debug, Clone)]
pub struct WebRuntimeLimits {
    pub session_idle_timeout: Duration,
    pub session_absolute_timeout: Duration,
    pub max_sessions: usize,
    pub login_window: Duration,
    pub max_login_attempts_per_peer: usize,
    pub max_global_login_attempts: usize,
    pub max_tracked_login_peers: usize,
    pub max_connections: usize,
    pub max_concurrent_requests: usize,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
    pub body_read_timeout: Duration,
    pub graceful_drain_timeout: Duration,
    #[doc(hidden)]
    pub test_exit_after_accepts: Option<usize>,
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
            max_connections: 64,
            max_concurrent_requests: 32,
            header_read_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            body_read_timeout: Duration::from_secs(3),
            graceful_drain_timeout: Duration::from_secs(5),
            test_exit_after_accepts: None,
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
            || self.max_connections == 0
            || self.max_connections > MAX_CONNECTIONS
            || self.max_concurrent_requests == 0
            || self.max_concurrent_requests > MAX_CONCURRENT_REQUESTS
            || self.max_concurrent_requests > self.max_connections
            || self.header_read_timeout.is_zero()
            || self.header_read_timeout > MAX_HTTP_TIMEOUT
            || self.request_timeout.is_zero()
            || self.request_timeout > MAX_HTTP_TIMEOUT
            || self.body_read_timeout.is_zero()
            || self.body_read_timeout > self.request_timeout
            || self.graceful_drain_timeout.is_zero()
            || self.graceful_drain_timeout > MAX_GRACEFUL_DRAIN_TIMEOUT
            || self.test_exit_after_accepts == Some(0)
            || now.checked_add(self.session_idle_timeout).is_none()
            || now.checked_add(self.session_absolute_timeout).is_none()
            || now.checked_add(self.login_window).is_none()
            || now.checked_add(self.header_read_timeout).is_none()
            || now.checked_add(self.request_timeout).is_none()
            || now.checked_add(self.body_read_timeout).is_none()
            || now.checked_add(self.graceful_drain_timeout).is_none()
        {
            return Err(WebError::InvalidRuntimeLimits);
        }
        Ok(())
    }
}

pub struct WebServer {
    listener: TcpListener,
    router: Router,
    runtime_limits: WebRuntimeLimits,
}

impl WebServer {
    pub fn validate_configuration(
        config: &ServerConfig,
        limits: &WebRuntimeLimits,
    ) -> Result<SocketAddr, WebError> {
        config
            .validate()
            .map_err(|error| WebError::InvalidConfiguration(error.to_string()))?;
        limits.validate()?;
        let web = config
            .web
            .as_ref()
            .filter(|web| web.enabled)
            .ok_or(WebError::Disabled)?;
        WebOrigin::from_config(web)
            .map_err(|error| WebError::InvalidConfiguration(error.to_string()))?;
        let configured_address = web
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| WebError::InvalidBindAddress)?;
        Ok(configured_address)
    }

    pub async fn bind(config: &ServerConfig) -> Result<Self, WebError> {
        Self::bind_with_runtime_limits(config, WebRuntimeLimits::default()).await
    }

    #[doc(hidden)]
    pub async fn bind_with_runtime_limits(
        config: &ServerConfig,
        limits: WebRuntimeLimits,
    ) -> Result<Self, WebError> {
        Self::bind_with_data_sources(config, limits, DashboardDataSources::unavailable()).await
    }

    #[doc(hidden)]
    pub async fn bind_with_data_sources(
        config: &ServerConfig,
        limits: WebRuntimeLimits,
        data_sources: DashboardDataSources,
    ) -> Result<Self, WebError> {
        let configured_address = Self::validate_configuration(config, &limits)?;
        let web = config
            .web
            .as_ref()
            .filter(|web| web.enabled)
            .ok_or(WebError::Disabled)?;
        let expected_origin = WebOrigin::from_config(web)
            .map_err(|error| WebError::InvalidConfiguration(error.to_string()))?;
        let authentication =
            AuthenticationState::new(&web.admin_username, &web.admin_password, &limits)
                .map_err(|_| WebError::Authentication)?;
        let listener = TcpListener::bind(configured_address).await?;
        let state = Arc::new(WebState {
            authentication,
            expected_origin,
            cookie_secure: web.cookie_secure,
            body_read_timeout: limits.body_read_timeout,
            observability: data_sources.observability,
            history: data_sources.history,
            enrollment: data_sources.enrollment,
            operations: OperationLedger::new(1_024),
        });
        let router = build_router(state);
        Ok(Self {
            listener,
            router,
            runtime_limits: limits,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self) -> Result<(), WebError> {
        self.run_until(CancellationToken::new()).await
    }

    pub async fn run_until(self, shutdown: CancellationToken) -> Result<(), WebError> {
        let connection_slots = Arc::new(Semaphore::new(self.runtime_limits.max_connections));
        let request_slots = Arc::new(Semaphore::new(self.runtime_limits.max_concurrent_requests));
        let connection_shutdown = CancellationToken::new();
        let mut connections = JoinSet::new();
        let mut accepted_connections = 0_usize;

        let accept_result = 'accept: loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break Ok(()),
                completed = connections.join_next(), if !connections.is_empty() => {
                    let _ = completed;
                }
                permit = connection_slots.clone().acquire_owned() => {
                    let permit = permit.expect("the Web connection semaphore remains open");
                    let accepted = tokio::select! {
                        biased;
                        () = shutdown.cancelled() => {
                            drop(permit);
                            break 'accept Ok(());
                        }
                        accepted = self.listener.accept() => accepted,
                    };
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(WebError::Io(error)),
                    };
                    accepted_connections = accepted_connections.saturating_add(1);
                    if self
                        .runtime_limits
                        .test_exit_after_accepts
                        .is_some_and(|limit| accepted_connections >= limit)
                    {
                        drop(stream);
                        drop(permit);
                        break Err(WebError::UnexpectedTestExit);
                    }
                    connections.spawn(run_connection(
                        stream,
                        peer,
                        permit,
                        ConnectionRuntime {
                            router: self.router.clone(),
                            request_slots: request_slots.clone(),
                            shutdown: connection_shutdown.child_token(),
                            header_read_timeout: self.runtime_limits.header_read_timeout,
                            request_timeout: self.runtime_limits.request_timeout,
                        },
                    ));
                }
            }
        };

        connection_shutdown.cancel();
        if tokio::time::timeout(self.runtime_limits.graceful_drain_timeout, async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
        accept_result
    }
}

#[derive(Clone)]
pub struct DashboardDataSources {
    observability: ObservabilityStore,
    history: Option<HistoryService>,
    enrollment: Option<EnrollmentManagement>,
}

#[derive(Clone)]
pub struct EnrollmentManagement {
    pub(super) store: Arc<DynamicClientStore>,
    pub(super) server_addr: String,
    pub(super) certificate_fingerprint: [u8; 32],
    pub(super) token_ttl: Duration,
    pub(super) registry: Option<crate::registry::ClientRegistry>,
}

impl EnrollmentManagement {
    pub fn new(
        store: Arc<DynamicClientStore>,
        server_addr: String,
        certificate_fingerprint: [u8; 32],
        token_ttl: Duration,
    ) -> Self {
        Self {
            store,
            server_addr,
            certificate_fingerprint,
            token_ttl,
            registry: None,
        }
    }

    pub(crate) fn with_registry(mut self, registry: crate::registry::ClientRegistry) -> Self {
        self.registry = Some(registry);
        self
    }

    pub(crate) fn store(&self) -> Arc<DynamicClientStore> {
        self.store.clone()
    }
}

impl DashboardDataSources {
    pub fn new(observability: ObservabilityStore, history: Option<HistoryService>) -> Self {
        Self {
            observability,
            history,
            enrollment: None,
        }
    }

    pub fn with_enrollment(mut self, enrollment: EnrollmentManagement) -> Self {
        self.enrollment = Some(enrollment);
        self
    }

    fn unavailable() -> Self {
        let (observability, sink, worker) = ObservabilityStore::new();
        drop(sink);
        drop(worker);
        Self::new(observability, None)
    }
}

impl fmt::Debug for DashboardDataSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DashboardDataSources")
            .field("history_configured", &self.history.is_some())
            .finish_non_exhaustive()
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
    expected_origin: WebOrigin,
    cookie_secure: bool,
    body_read_timeout: Duration,
    observability: ObservabilityStore,
    history: Option<HistoryService>,
    enrollment: Option<EnrollmentManagement>,
    operations: OperationLedger,
}

struct OperationLedger {
    records: Mutex<VecDeque<OperationRecord>>,
    capacity: usize,
}

struct OperationRecord {
    key: [u8; 32],
    request: [u8; 32],
    outcome: OperationOutcome,
}

enum OperationOutcome {
    Pending,
    Secret,
    Response { status: u16, body: Vec<u8> },
}

enum OperationAdmission {
    Started([u8; 32]),
    SecretUnavailable,
    Replay { status: u16, body: Vec<u8> },
    InFlight,
    Conflict,
    Unavailable,
}

impl OperationLedger {
    fn new(capacity: usize) -> Self {
        Self {
            records: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    fn begin(
        &self,
        session: &str,
        endpoint: &str,
        operation_id: &str,
        request: &[u8],
    ) -> OperationAdmission {
        let key: [u8; 32] = Sha256::digest(
            [
                session.as_bytes(),
                b"\0",
                endpoint.as_bytes(),
                b"\0",
                operation_id.as_bytes(),
            ]
            .concat(),
        )
        .into();
        let request: [u8; 32] = Sha256::digest(request).into();
        let Ok(mut records) = self.records.lock() else {
            return OperationAdmission::Unavailable;
        };
        if let Some(record) = records.iter().find(|record| record.key == key) {
            return if record.request != request {
                OperationAdmission::Conflict
            } else {
                match &record.outcome {
                    OperationOutcome::Pending => OperationAdmission::InFlight,
                    OperationOutcome::Secret => OperationAdmission::SecretUnavailable,
                    OperationOutcome::Response { status, body } => OperationAdmission::Replay {
                        status: *status,
                        body: body.clone(),
                    },
                }
            };
        }
        if records.len() == self.capacity {
            if let Some(index) = records
                .iter()
                .position(|record| !matches!(record.outcome, OperationOutcome::Pending))
            {
                records.remove(index);
            } else {
                return OperationAdmission::Unavailable;
            }
        }
        records.push_back(OperationRecord {
            key,
            request,
            outcome: OperationOutcome::Pending,
        });
        OperationAdmission::Started(key)
    }

    fn finish(&self, key: [u8; 32], succeeded: bool) {
        let Ok(mut records) = self.records.lock() else {
            return;
        };
        if succeeded {
            if let Some(record) = records.iter_mut().find(|record| record.key == key) {
                record.outcome = OperationOutcome::Secret;
            }
        } else if let Some(index) = records.iter().position(|record| record.key == key) {
            records.remove(index);
        }
    }

    fn finish_response(&self, key: [u8; 32], status: u16, body: Vec<u8>) {
        let Ok(mut records) = self.records.lock() else {
            return;
        };
        if let Some(record) = records.iter_mut().find(|record| record.key == key) {
            record.outcome = OperationOutcome::Response { status, body };
        }
    }
}

fn build_router(state: Arc<WebState>) -> Router {
    let api_routes = api::routes().route_layer(middleware::from_fn_with_state(
        Arc::clone(&state),
        protect_management_writes,
    ));
    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/login",
            post(login)
                .get(assets::login_page)
                .layer(DefaultBodyLimit::max(MAX_LOGIN_BODY_BYTES)),
        )
        .route(
            "/logout",
            post(logout).layer(DefaultBodyLimit::max(MAX_LOGOUT_BODY_BYTES)),
        )
        .merge(api_routes)
        .merge(assets::routes())
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
    if !same_origin(request.headers(), &state.expected_origin)
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

    let form = match tokio::time::timeout(
        state.body_read_timeout,
        Form::<LoginForm>::from_request(request, &()),
    )
    .await
    {
        Ok(Ok(Form(form))) => form,
        Ok(Err(_)) => return rejected_request(),
        Err(_) => return request_timed_out(),
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
    let csrf_cookie = format!("{SESSION_COOKIE_NAME}={token}");
    let Some(csrf) = state.authentication.csrf_for_cookie(Some(&csrf_cookie)) else {
        return internal_error();
    };
    let cookie = session_cookie(&token, state.cookie_secure);
    let mut response = plain_response(StatusCode::OK, "ok\n");
    response.headers_mut().insert(SET_COOKIE, cookie);
    response.headers_mut().insert(
        CSRF_HEADER_NAME,
        HeaderValue::from_str(&csrf).expect("base64url CSRF token is a valid header value"),
    );
    response
}

async fn protect_management_writes(
    State(state): State<Arc<WebState>>,
    request: Request,
    next: Next,
) -> Response {
    let guarded = request.method() == Method::POST
        && (request.uri().path() == "/api/v1/clients"
            || request.uri().path().starts_with("/api/v1/clients/")
            || request
                .uri()
                .path()
                .starts_with("/api/v1/registration-requests/"));
    if !guarded {
        return next.run(request).await;
    }
    let headers = request.headers();
    let cookie = single_cookie_header(headers);
    if !state.authentication.authenticate_cookie(cookie) {
        return api::authentication_required();
    }
    let mut csrf_values = headers.get_all(&CSRF_HEADER_NAME).iter();
    let csrf = csrf_values.next().and_then(|value| value.to_str().ok());
    if csrf_values.next().is_some()
        || !same_origin(headers, &state.expected_origin)
        || !is_json_request(headers)
        || !csrf.is_some_and(|csrf| state.authentication.validate_csrf(cookie, csrf))
    {
        return api::csrf_rejected();
    }
    next.run(request).await
}

async fn logout(State(state): State<Arc<WebState>>, request: Request) -> Response {
    if !same_origin(request.headers(), &state.expected_origin)
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
    let logout_body = match tokio::time::timeout(
        state.body_read_timeout,
        body::to_bytes(request.into_body(), MAX_LOGOUT_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return rejected_request(),
        Err(_) => return request_timed_out(),
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

async fn api_boundary(
    State(state): State<Arc<WebState>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if !state
        .authentication
        .authenticate_cookie(single_cookie_header(&headers))
    {
        return api::authentication_required();
    }
    if method != Method::GET && method != Method::HEAD {
        return api::method_not_allowed_response();
    }
    api::not_found()
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

fn is_json_request(headers: &HeaderMap) -> bool {
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
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
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

fn request_timed_out() -> Response {
    plain_response(StatusCode::REQUEST_TIMEOUT, "request timed out\n")
}

fn service_unavailable() -> Response {
    plain_response(StatusCode::SERVICE_UNAVAILABLE, "service unavailable\n")
}

async fn run_connection(
    stream: TcpStream,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
    runtime: ConnectionRuntime,
) {
    let ConnectionRuntime {
        router,
        request_slots,
        shutdown,
        header_read_timeout,
        request_timeout,
    } = runtime;
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        dispatch_request(
            router.clone(),
            request_slots.clone(),
            peer,
            request,
            request_timeout,
        )
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .max_headers(HTTP_MAX_HEADERS)
        .max_buf_size(HTTP_MAX_BUFFER_BYTES);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {}
        () = shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

struct ConnectionRuntime {
    router: Router,
    request_slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    header_read_timeout: Duration,
    request_timeout: Duration,
}

async fn dispatch_request(
    router: Router,
    request_slots: Arc<Semaphore>,
    peer: SocketAddr,
    request: hyper::Request<Incoming>,
    request_timeout: Duration,
) -> Result<Response, Infallible> {
    let path = request.uri().path().to_owned();
    let response = tokio::time::timeout(request_timeout, async move {
        let Ok(_permit) = request_slots.acquire_owned().await else {
            return service_unavailable();
        };
        let (parts, incoming) = request.into_parts();
        let mut request = Request::from_parts(parts, Body::new(incoming));
        request.extensions_mut().insert(ConnectInfo(peer));
        match router.oneshot(request).await {
            Ok(response) => response,
            Err(error) => match error {},
        }
    })
    .await;
    let response = match response {
        Ok(response) => response,
        Err(_) => {
            let mut response = request_timed_out();
            apply_response_security_headers(&path, &mut response);
            response
        }
    };
    Ok(response)
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
    #[doc(hidden)]
    #[error("web listener exited at the internal lifecycle test seam")]
    UnexpectedTestExit,
}

#[cfg(test)]
mod management_tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use rustgo_crypto::DeviceKeypair;
    use rustgo_protocol::{EnrollmentKeyMaterial, EnrollmentPurpose};

    #[tokio::test]
    async fn registration_review_requires_login_and_csrf_and_binds_only_on_approval() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            DynamicClientStore::open(
                directory.path().join("db"),
                crate::enrollment::EnrollmentStoreLimits {
                    max_active_clients: 4,
                    max_tokens: 4,
                },
            )
            .unwrap(),
        );
        let public = DeviceKeypair::from_secret_bytes([5; 32]).public_key();
        let _ = store.request_approval(
            "Automatic.Node",
            EnrollmentPurpose::Enroll,
            &public,
            "approval-1",
            std::time::SystemTime::now(),
        );
        let (observability, sink, worker) = ObservabilityStore::new();
        drop(sink);
        drop(worker);
        let authentication =
            AuthenticationState::new("admin", "password", &WebRuntimeLimits::default()).unwrap();
        let token = authentication.issue_session().unwrap();
        let cookie = format!("{SESSION_COOKIE_NAME}={token}");
        let csrf = authentication.csrf_for_cookie(Some(&cookie)).unwrap();
        let state = Arc::new(WebState {
            authentication,
            expected_origin: WebOrigin::parse("http://127.0.0.1:8080").unwrap(),
            cookie_secure: false,
            body_read_timeout: Duration::from_secs(1),
            observability,
            history: None,
            enrollment: Some(EnrollmentManagement::new(
                store.clone(),
                "server.example:7443".into(),
                [7; 32],
                Duration::from_secs(300),
            )),
            operations: OperationLedger::new(16),
        });
        let router = build_router(state);
        let list = HttpRequest::builder()
            .uri("/api/v1/registration-requests")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(list).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        for include_cookie in [false, true] {
            let mut request = HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/registration-requests/approval-1")
                .header("host", "127.0.0.1:8080")
                .header("origin", "http://127.0.0.1:8080")
                .header("content-type", "application/json");
            if include_cookie {
                request = request.header("cookie", &cookie);
            }
            let response = router
                .clone()
                .oneshot(request.body(Body::from(r#"{"approve":true}"#)).unwrap())
                .await
                .unwrap();
            assert!(matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ));
            assert!(store.list_clients().unwrap().is_empty());
        }
        let list = HttpRequest::builder()
            .uri("/api/v1/registration-requests")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(list).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body::to_bytes(response.into_body(), 4096).await.unwrap();
        let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list["items"][0]["client_id"], "Automatic.Node");
        for _ in 0..2 {
            let request = HttpRequest::builder()
                .method("POST")
                .uri("/api/v1/registration-requests/approval-1")
                .header("host", "127.0.0.1:8080")
                .header("origin", "http://127.0.0.1:8080")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .header("x-rustgo-csrf-token", &csrf)
                .body(Body::from(r#"{"approve":true}"#))
                .unwrap();
            assert_eq!(
                router.clone().oneshot(request).await.unwrap().status(),
                StatusCode::OK
            );
        }
        assert_eq!(store.list_clients().unwrap().len(), 1);
        assert_eq!(store.list_clients().unwrap()[0].revision(), 1);
    }

    #[tokio::test]
    async fn create_client_returns_one_time_key_without_internal_identity() {
        let directory = tempfile::tempdir().unwrap();
        let enrollment_store = Arc::new(
            DynamicClientStore::open(
                directory.path().join("enrollment.db"),
                crate::enrollment::EnrollmentStoreLimits {
                    max_active_clients: 4,
                    max_tokens: 4,
                },
            )
            .unwrap(),
        );
        let (observability, sink, worker) = ObservabilityStore::new();
        drop(sink);
        drop(worker);
        let authentication =
            AuthenticationState::new("admin", "password", &WebRuntimeLimits::default()).unwrap();
        let token = authentication.issue_session().unwrap();
        let cookie = format!("{SESSION_COOKIE_NAME}={token}");
        let csrf = authentication.csrf_for_cookie(Some(&cookie)).unwrap();
        let state = Arc::new(WebState {
            authentication,
            expected_origin: WebOrigin::parse("http://127.0.0.1:8080").unwrap(),
            cookie_secure: false,
            body_read_timeout: Duration::from_secs(1),
            observability,
            history: None,
            enrollment: Some(EnrollmentManagement::new(
                Arc::clone(&enrollment_store),
                "server.example:7443".into(),
                [7; 32],
                Duration::from_secs(300),
            )),
            operations: OperationLedger::new(16),
        });
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie.clone())
            .header("x-rustgo-csrf-token", csrf.clone())
            .body(Body::from(
                r#"{"client_id":"Node.One","operation_id":"create-1"}"#,
            ))
            .unwrap();
        let router = build_router(Arc::clone(&state));
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let body = body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["client"]["client_id"], "Node.One");
        assert_eq!(json["client"]["revision"], 1);
        assert!(json.get("internal_id").is_none());
        assert!(json.get("public_key").is_none());
        let initial_encoded = json["enrollment_key"].as_str().unwrap().to_owned();
        let key = EnrollmentKeyMaterial::decode(&initial_encoded).unwrap();
        assert_eq!(key.server_addr(), "server.example:7443");
        assert_eq!(enrollment_store.list_clients().unwrap().len(), 1);

        let list = HttpRequest::builder()
            .uri("/api/v1/clients?sort=name")
            .header("cookie", cookie.clone())
            .body(Body::empty())
            .unwrap();
        let list = router.clone().oneshot(list).await.unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let list: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(list.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(list["clients"]["items"][0]["name"], "Node.One");
        assert_eq!(list["clients"]["items"][0]["identity_source"], "dynamic");
        assert_eq!(list["clients"]["items"][0]["online"], false);
        assert!(list["clients"]["items"][0].get("internal_id").is_none());

        let detail = HttpRequest::builder()
            .uri("/api/v1/clients/Node.One")
            .header("cookie", cookie.clone())
            .body(Body::empty())
            .unwrap();
        let detail = router.clone().oneshot(detail).await.unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let detail: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(detail.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(detail["client"]["revision"], 1);
        assert_eq!(detail["sessions"]["total"], 0);

        let replay = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie.clone())
            .header("x-rustgo-csrf-token", csrf.clone())
            .body(Body::from(
                r#"{"client_id":"Node.One","operation_id":"create-1"}"#,
            ))
            .unwrap();
        let replay = router.clone().oneshot(replay).await.unwrap();
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        let body = body::to_bytes(replay.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "secret_unavailable");
        assert_eq!(enrollment_store.list_clients().unwrap().len(), 1);

        let reissue = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients/Node.One/enrollment-token")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie.clone())
            .header("x-rustgo-csrf-token", csrf.clone())
            .body(Body::from(
                r#"{"expected_revision":1,"operation_id":"reissue-1"}"#,
            ))
            .unwrap();
        let reissue = router.clone().oneshot(reissue).await.unwrap();
        assert_eq!(reissue.status(), StatusCode::OK);
        let body = body::to_bytes(reissue.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let current_encoded = json["enrollment_key"].as_str().unwrap();
        assert_eq!(
            EnrollmentKeyMaterial::decode(current_encoded)
                .unwrap()
                .purpose(),
            EnrollmentPurpose::Enroll
        );
        let public_key = DeviceKeypair::from_secret_bytes([42; 32]).public_key();
        enrollment_store
            .consume_token(
                current_encoded,
                &public_key,
                "bind-web-test",
                std::time::SystemTime::now(),
            )
            .unwrap();

        let reenroll = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients/node.one/reenrollment-token")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie.clone())
            .header("x-rustgo-csrf-token", csrf.clone())
            .body(Body::from(
                r#"{"expected_revision":2,"operation_id":"reenroll-1"}"#,
            ))
            .unwrap();
        let reenroll = router.clone().oneshot(reenroll).await.unwrap();
        assert_eq!(reenroll.status(), StatusCode::OK);
        let body = body::to_bytes(reenroll.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            EnrollmentKeyMaterial::decode(json["enrollment_key"].as_str().unwrap())
                .unwrap()
                .purpose(),
            EnrollmentPurpose::ReEnroll
        );

        let rename_body =
            r#"{"new_client_id":"Renamed.Node","expected_revision":2,"operation_id":"rename-1"}"#;
        let rename = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients/node.one/rename")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie.clone())
            .header("x-rustgo-csrf-token", csrf.clone())
            .body(Body::from(rename_body))
            .unwrap();
        let rename = router.clone().oneshot(rename).await.unwrap();
        assert_eq!(rename.status(), StatusCode::OK);
        let rename_bytes = body::to_bytes(rename.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&rename_bytes).unwrap();
        assert_eq!(json["client"]["client_id"], "Renamed.Node");
        assert_eq!(json["client"]["revision"], 3);

        let replay = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients/node.one/rename")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie.clone())
            .header("x-rustgo-csrf-token", csrf.clone())
            .body(Body::from(rename_body))
            .unwrap();
        let replay = router.clone().oneshot(replay).await.unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(
            body::to_bytes(replay.into_body(), 4096).await.unwrap(),
            rename_bytes
        );

        let disable = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients/Renamed.Node/state")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie.clone())
            .header("x-rustgo-csrf-token", csrf.clone())
            .body(Body::from(
                r#"{"enabled":false,"expected_revision":3,"operation_id":"state-1"}"#,
            ))
            .unwrap();
        let disable = router.clone().oneshot(disable).await.unwrap();
        assert_eq!(disable.status(), StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(disable.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(json["client"]["enabled"], false);
        assert_eq!(json["client"]["revision"], 4);

        let delete = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/clients/Renamed.Node/delete")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .header("x-rustgo-csrf-token", csrf)
            .body(Body::from(
                r#"{"expected_revision":4,"operation_id":"delete-1"}"#,
            ))
            .unwrap();
        let delete = router.oneshot(delete).await.unwrap();
        assert_eq!(delete.status(), StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(delete.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(json["client"]["deleted"], true);
        assert_eq!(json["client"]["revision"], 5);
        assert!(enrollment_store.list_clients().unwrap().is_empty());
    }

    #[test]
    fn operation_ledger_bounds_inflight_and_rejects_changed_replays() {
        let ledger = OperationLedger::new(1);
        let key = match ledger.begin("session-a", "/create", "op-1", b"request-a") {
            OperationAdmission::Started(key) => key,
            _ => panic!("first operation should start"),
        };
        assert!(matches!(
            ledger.begin("session-a", "/create", "op-1", b"request-a"),
            OperationAdmission::InFlight
        ));
        assert!(matches!(
            ledger.begin("session-a", "/create", "op-1", b"request-b"),
            OperationAdmission::Conflict
        ));
        assert!(matches!(
            ledger.begin("session-a", "/create", "op-2", b"request"),
            OperationAdmission::Unavailable
        ));
        ledger.finish(key, true);
        assert!(matches!(
            ledger.begin("session-a", "/create", "op-1", b"request-a"),
            OperationAdmission::SecretUnavailable
        ));
        assert!(matches!(
            ledger.begin("session-b", "/create", "op-1", b"request-a"),
            OperationAdmission::Started(_)
        ));

        let ledger = OperationLedger::new(1);
        let key = match ledger.begin("session", "/rename", "op", b"request") {
            OperationAdmission::Started(key) => key,
            _ => panic!("regular operation should start"),
        };
        ledger.finish_response(key, 200, br#"{"ok":true}"#.to_vec());
        match ledger.begin("session", "/rename", "op", b"request") {
            OperationAdmission::Replay { status, body } => {
                assert_eq!(status, 200);
                assert_eq!(body, br#"{"ok":true}"#);
            }
            _ => panic!("regular response should replay"),
        }
    }
}

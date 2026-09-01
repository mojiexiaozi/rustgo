use axum::{
    extract::Request,
    http::{
        HeaderMap, HeaderName, HeaderValue,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, ORIGIN, REFERRER_POLICY,
        },
    },
    middleware::Next,
    response::Response,
};
use rustgo_config::WebOrigin;

const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const MAX_ORIGIN_HEADER_BYTES: usize = 256;
const MAX_HOST_HEADER_BYTES: usize = 128;

pub(super) async fn response_security_headers(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    apply_response_security_headers(&path, &mut response);
    response
}

pub(super) fn apply_response_security_headers(path: &str, response: &mut Response) {
    let no_store = requires_no_store(path);
    let status = response.status();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if no_store {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if !headers.contains_key(CONTENT_TYPE) && status.as_u16() != 204 {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
}

pub(super) fn same_origin(headers: &HeaderMap, expected: &WebOrigin) -> bool {
    let Some(host) = single_header(headers, HOST, MAX_HOST_HEADER_BYTES) else {
        return false;
    };
    if !expected.matches_authority(host) {
        return false;
    }
    let Some(origin) = single_header(headers, ORIGIN, MAX_ORIGIN_HEADER_BYTES) else {
        return false;
    };
    let Ok(origin) = WebOrigin::parse(origin) else {
        return false;
    };
    &origin == expected
}

pub(super) fn single_cookie_header(headers: &HeaderMap) -> Option<&str> {
    single_header(headers, axum::http::header::COOKIE, 1_024)
}

fn single_header(headers: &HeaderMap, name: HeaderName, max_bytes: usize) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    (value.len() <= max_bytes).then_some(value)
}

fn requires_no_store(path: &str) -> bool {
    matches!(path, "/login" | "/logout" | "/api") || path.starts_with("/api/")
}

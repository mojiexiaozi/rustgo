//! Checked-in, allowlisted dashboard assets.

use std::sync::{Arc, OnceLock};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use sha2::{Digest, Sha256};

use super::{WebState, api, security::single_cookie_header};

struct Asset {
    bytes: &'static [u8],
    content_type: &'static str,
    etag: OnceLock<HeaderValue>,
}

static INDEX: Asset = Asset {
    bytes: include_bytes!("../../web/index.html"),
    content_type: "text/html; charset=utf-8",
    etag: OnceLock::new(),
};
static LOGIN: Asset = Asset {
    bytes: include_bytes!("../../web/login.html"),
    content_type: "text/html; charset=utf-8",
    etag: OnceLock::new(),
};
static STYLE: Asset = Asset {
    bytes: include_bytes!("../../web/app.css"),
    content_type: "text/css; charset=utf-8",
    etag: OnceLock::new(),
};
static APP_SCRIPT: Asset = Asset {
    bytes: include_bytes!("../../web/app.js"),
    content_type: "text/javascript; charset=utf-8",
    etag: OnceLock::new(),
};
static LOGIN_SCRIPT: Asset = Asset {
    bytes: include_bytes!("../../web/login.js"),
    content_type: "text/javascript; charset=utf-8",
    etag: OnceLock::new(),
};

pub(super) fn routes() -> Router<Arc<WebState>> {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(style))
        .route("/app.js", get(app_script))
        .route("/login.js", get(login_script))
}

pub(super) async fn login_page(headers: HeaderMap) -> Response {
    asset_response(&LOGIN, &headers, false)
}

async fn index(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if !state
        .authentication
        .authenticate_cookie(single_cookie_header(&headers))
    {
        return api::authentication_required();
    }
    asset_response(&INDEX, &headers, true)
}

async fn style(headers: HeaderMap) -> Response {
    asset_response(&STYLE, &headers, false)
}

async fn app_script(headers: HeaderMap) -> Response {
    asset_response(&APP_SCRIPT, &headers, false)
}

async fn login_script(headers: HeaderMap) -> Response {
    asset_response(&LOGIN_SCRIPT, &headers, false)
}

fn asset_response(asset: &'static Asset, request_headers: &HeaderMap, no_store: bool) -> Response {
    let etag = asset.etag.get_or_init(|| {
        HeaderValue::from_str(&format!("\"{:x}\"", Sha256::digest(asset.bytes)))
            .expect("SHA-256 ETag is a valid HTTP header value")
    });
    if request_headers
        .get(IF_NONE_MATCH)
        .is_some_and(|value| value.as_bytes() == etag.as_bytes())
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
        headers.insert(ETAG, etag.clone());
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static(cache_control(no_store)),
        );
        return response;
    }
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, asset.content_type),
            (CACHE_CONTROL, cache_control(no_store)),
            (ETAG, etag.to_str().expect("static ETag stays valid")),
        ],
        Body::from(asset.bytes),
    )
        .into_response()
}

fn cache_control(no_store: bool) -> &'static str {
    if no_store { "no-store" } else { "no-cache" }
}

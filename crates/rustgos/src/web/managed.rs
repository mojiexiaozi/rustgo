use std::sync::Arc;

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use rustgo_config::{ExportConfig, ForwardConfig, TunnelConfig};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    WebState,
    api::{authenticate, json_response},
};
use crate::managed::{ManagedError, ManagedSnapshot};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    #[serde(default, rename = "operation_id")]
    _operation_id: Option<String>,
    expected_revision: u64,
    action: String,
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    item: Option<Value>,
}

pub(super) async fn get(state: Arc<WebState>, headers: HeaderMap, name: String) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    let Some(management) = state.managed.clone() else {
        return unavailable();
    };
    let active = management.registry.active_control_session(&name);
    let online = active.is_some();
    let supported = active
        .as_ref()
        .map(|session| session.protocol_version().supports_managed_configuration());
    let result = tokio::task::spawn_blocking(move || management.snapshot(&name)).await;
    match result {
        Ok(Ok(snapshot)) => json_response(
            StatusCode::OK,
            &json!({"snapshot":snapshot,"online":online,"supported":supported}),
        ),
        Ok(Err(error)) => failure(error),
        Err(_) => unavailable(),
    }
}

pub(super) async fn write(
    state: Arc<WebState>,
    headers: HeaderMap,
    name: String,
    body: Bytes,
) -> Response {
    if let Err(response) = authenticate(&state, &headers) {
        return *response;
    }
    if rustgo_config::validate_client_name(&name).is_err() {
        return failure(ManagedError::Invalid("invalid client name".into()));
    }
    let Some(management) = state.managed.clone() else {
        return unavailable();
    };
    if management
        .registry
        .active_control_session(&name)
        .is_some_and(|session| !session.protocol_version().supports_managed_configuration())
    {
        return failure(ManagedError::Invalid("客户端需升级后才能管理隧道".into()));
    }
    let request: Mutation = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return failure(ManagedError::Invalid("invalid tunnel request".into())),
    };
    let registry = management.registry.clone();
    let client_name = name.clone();
    let result = tokio::task::spawn_blocking(move || {
        let identity = management.identity(&name)?;
        let snapshot = management.store.get_for_identity(&identity)?.ok_or(ManagedError::NotFound)?;
        let configuration = mutate(snapshot, &request)?;
        management.validate(&name, &configuration)?;
        let snapshot = management.store.replace_for_identity(&identity, &name, request.expected_revision, &configuration)?;
        let item_name = request.name.as_deref().or_else(|| request.item.as_ref().and_then(|item| item.get("name")).and_then(Value::as_str)).unwrap_or("");
        tracing::info!(actor = "web-admin", client = %rustgo_transport::safe_display(&name), item = %rustgo_transport::safe_display(item_name), kind = %rustgo_transport::safe_display(&request.kind), action = %rustgo_transport::safe_display(&request.action), revision = snapshot.revision, event = "managed_configuration_saved", "隧道配置已保存");
        Ok::<_, ManagedError>(snapshot)
    }).await;
    match result {
        Ok(Ok(snapshot)) => {
            registry.terminate_by_name(&client_name);
            json_response(
                StatusCode::OK,
                &json!({"snapshot":snapshot,"state":"pending"}),
            )
        }
        Ok(Err(error)) => {
            tracing::warn!(actor="web-admin",client=%rustgo_transport::safe_display(&client_name), error=%rustgo_transport::safe_display(&error), event="managed_configuration_rejected", "隧道配置修改失败");
            failure(error)
        }
        Err(_) => unavailable(),
    }
}

fn mutate(
    snapshot: ManagedSnapshot,
    request: &Mutation,
) -> Result<rustgo_config::ManagedConfiguration, ManagedError> {
    if snapshot.revision != request.expected_revision {
        return Err(ManagedError::Conflict);
    }
    let mut configuration = snapshot.configuration;
    if request.action == "add" && request.kind != "tunnel" && !configuration.p2p_enabled {
        return Err(ManagedError::Invalid("请先在客户端启用 P2P 并重连".into()));
    }
    let invalid = || ManagedError::Invalid("invalid tunnel operation".into());
    match (request.action.as_str(), request.kind.as_str()) {
        ("add", "tunnel") => configuration.tunnels.push(
            serde_json::from_value::<TunnelConfig>(request.item.clone().ok_or_else(invalid)?)
                .map_err(|_| invalid())?,
        ),
        ("add", "export") => configuration.exports.push(
            serde_json::from_value::<ExportConfig>(request.item.clone().ok_or_else(invalid)?)
                .map_err(|_| invalid())?,
        ),
        ("add", "forward") => configuration.forwards.push(
            serde_json::from_value::<ForwardConfig>(request.item.clone().ok_or_else(invalid)?)
                .map_err(|_| invalid())?,
        ),
        ("delete", kind) => {
            let name = request.name.as_deref().ok_or_else(invalid)?;
            let removed = match kind {
                "tunnel" => remove_named(&mut configuration.tunnels, name, |item| &item.name),
                "export" => remove_named(&mut configuration.exports, name, |item| &item.name),
                "forward" => remove_named(&mut configuration.forwards, name, |item| &item.name),
                _ => return Err(invalid()),
            };
            if !removed {
                return Err(ManagedError::NotFound);
            }
        }
        _ => return Err(invalid()),
    }
    Ok(configuration)
}

fn remove_named<T>(items: &mut Vec<T>, name: &str, item_name: impl Fn(&T) -> &str) -> bool {
    let before = items.len();
    items.retain(|item| item_name(item) != name);
    items.len() != before
}

fn unavailable() -> Response {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({"error":{"code":"managed_unavailable","message":"服务器未启用隧道管理或配置存储不可用"}}),
    )
}

fn failure(error: ManagedError) -> Response {
    let (status, code, message) = match error {
        ManagedError::Invalid(message) => (
            StatusCode::BAD_REQUEST,
            "invalid_tunnel_configuration",
            message,
        ),
        ManagedError::Conflict => (
            StatusCode::CONFLICT,
            "revision_conflict",
            "配置已更新，请刷新后重试".into(),
        ),
        ManagedError::NotFound => (
            StatusCode::NOT_FOUND,
            "tunnel_configuration_not_found",
            "客户端尚未同步隧道配置或项目不存在".into(),
        ),
        ManagedError::Storage(_) => return unavailable(),
    };
    json_response(status, &json!({"error":{"code":code,"message":message}}))
}

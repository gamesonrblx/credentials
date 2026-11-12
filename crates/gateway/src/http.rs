//! HTTP surface. Proxy injection is the only delivery mode on this listener.
//! Environment and header delivery stay on the local channel, which this
//! pre-alpha listener does not expose.

use std::sync::Arc;

use crate::b64::{b64std_decode, b64std_encode};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::{Delivery, DeliveryPolicy};
use crate::service::{CreatedSession, CreatedVersion, CreatedWorkspace, Gateway, InjectRequest};
use crate::ApiError;

#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<Gateway>,
}

pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/workspaces", post(create_workspace))
        .route("/v1/secrets", post(create_secret))
        .route("/v1/secrets/{*tail}", post(create_version))
        .route("/v1/agents", post(create_agent))
        .route("/v1/agent-sessions", post(create_session))
        .route("/v1/agent-sessions/{id}/revoke", post(revoke_session))
        .route("/v1/inject", post(inject))
        .route("/v1/audit", get(audit))
        .route("/v1/kek/rotate", post(rotate_kek))
        .route("/v1/workspaces/{id}/deletion", post(delete_workspace))
        .route("/v1/workspaces/{id}/deletion/cancel", post(cancel_deletion))
        .with_state(AppState { gateway })
}

async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(Serialize)]
struct WorkspaceResponse {
    id: Uuid,
    credential: String,
}

async fn create_workspace(
    State(state): State<AppState>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    let created: CreatedWorkspace = state.gateway.create_workspace().await?;
    Ok(Json(WorkspaceResponse {
        id: created.id,
        credential: created.credential,
    }))
}

#[derive(Deserialize)]
struct SecretBody {
    name: String,
    value: String,
    policy: PolicyBody,
}

#[derive(Deserialize)]
struct PolicyBody {
    header_name: Option<String>,
    header_format: Option<String>,
    env_name: Option<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default = "yes")]
    allow_proxy: bool,
    #[serde(default)]
    allow_header: bool,
    #[serde(default)]
    allow_env: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize)]
struct VersionResponse {
    secret_id: Uuid,
    version_id: Uuid,
    version: u32,
}

async fn create_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecretBody>,
) -> Result<Json<VersionResponse>, ApiError> {
    let credential = bearer(&headers)?;
    let value = b64std_decode(&body.value)?;
    let created: CreatedVersion = state
        .gateway
        .create_secret(
            credential,
            &body.name,
            &value,
            DeliveryPolicy {
                header_name: body.policy.header_name,
                header_format: body.policy.header_format,
                env_name: body.policy.env_name,
                hosts: body.policy.hosts,
                allow_proxy: body.policy.allow_proxy,
                allow_header: body.policy.allow_header,
                allow_env: body.policy.allow_env,
            },
        )
        .await?;
    Ok(Json(VersionResponse {
        secret_id: created.secret_id,
        version_id: created.version_id,
        version: created.version,
    }))
}

#[derive(Deserialize)]
struct VersionBody {
    value: String,
}

async fn create_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(tail): axum::extract::Path<String>,
    Json(body): Json<VersionBody>,
) -> Result<Json<VersionResponse>, ApiError> {
    let name = tail
        .strip_suffix("/versions")
        .filter(|name| !name.is_empty() && !name.ends_with('/'))
        .ok_or(ApiError::NotFound)?;
    let value = b64std_decode(&body.value)?;
    let created = state
        .gateway
        .create_version(bearer(&headers)?, name, &value)
        .await?;
    Ok(Json(VersionResponse {
        secret_id: created.secret_id,
        version_id: created.version_id,
        version: created.version,
    }))
}

#[derive(Deserialize)]
struct AgentBody {
    display_name: String,
}

#[derive(Serialize)]
struct AgentResponse {
    id: Uuid,
}

async fn create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AgentBody>,
) -> Result<Json<AgentResponse>, ApiError> {
    let id = state
        .gateway
        .create_agent(bearer(&headers)?, &body.display_name)
        .await?;
    Ok(Json(AgentResponse { id }))
}

#[derive(Deserialize)]
struct SessionBody {
    agent_id: Uuid,
    scopes: Vec<String>,
    ttl_seconds: Option<u64>,
    dpop_public_b64: String,
}

#[derive(Serialize)]
struct SessionResponse {
    session_id: Uuid,
    token: String,
    expires_at: u64,
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SessionBody>,
) -> Result<Json<SessionResponse>, ApiError> {
    let created: CreatedSession = state
        .gateway
        .create_session(
            bearer(&headers)?,
            body.agent_id,
            body.scopes,
            body.ttl_seconds,
            &body.dpop_public_b64,
        )
        .await?;
    Ok(Json(SessionResponse {
        session_id: created.session_id,
        token: created.token,
        expires_at: created.expires_at,
    }))
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.gateway.revoke_session(bearer(&headers)?, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct InjectBody {
    secret: String,
    delivery: String,
    request: Option<ProxyRequest>,
}

#[derive(Deserialize)]
struct ProxyRequest {
    method: String,
    url: String,
    #[serde(default)]
    body: String,
}

#[derive(Serialize)]
struct InjectHttpResponse {
    upstream_status: u16,
    body: String,
}

async fn inject(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<InjectBody>,
) -> Result<Json<InjectHttpResponse>, ApiError> {
    let token = bearer(&headers)?.to_owned();
    let dpop = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthenticated)?
        .to_owned();
    let delivery = Delivery::parse(&body.delivery).ok_or(ApiError::BadRequest)?;
    let request = body.request.unwrap_or(ProxyRequest {
        method: "GET".into(),
        url: String::new(),
        body: String::new(),
    });
    let htu = headers
        .get("x-dpop-htu")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https://credentials.local/v1/inject")
        .to_owned();
    let response = state
        .gateway
        .inject(InjectRequest {
            token,
            dpop,
            secret: body.secret,
            delivery,
            method: request.method,
            url: request.url,
            body: if request.body.is_empty() {
                Vec::new()
            } else {
                b64std_decode(&request.body)?
            },
            htm: "POST".into(),
            htu,
            local_channel: false,
        })
        .await?;
    Ok(Json(InjectHttpResponse {
        upstream_status: response.upstream_status,
        body: b64std_encode(&response.body),
    }))
}

#[derive(Deserialize)]
struct AuditQuery {
    agent_id: Option<Uuid>,
}

#[derive(Serialize)]
struct AuditResponse {
    events: Vec<AuditEventResponse>,
}

#[derive(Serialize)]
struct AuditEventResponse {
    seq: u64,
    agent_id: Option<Uuid>,
    event_type: String,
    hash_hex: String,
}

async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, ApiError> {
    let events = state
        .gateway
        .audit_log(bearer(&headers)?, query.agent_id)
        .await?;
    Ok(Json(AuditResponse {
        events: events
            .into_iter()
            .map(|event| AuditEventResponse {
                seq: event.seq,
                agent_id: event.agent_id,
                event_type: event.event_type,
                hash_hex: hex_encode(&event.hash),
            })
            .collect(),
    }))
}

async fn rotate_kek(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let version = state.gateway.rotate_kek(bearer(&headers)?).await?;
    Ok(Json(serde_json::json!({ "kek_version": version })))
}

async fn cancel_deletion(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.gateway.cancel_deletion(bearer(&headers)?, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state
        .gateway
        .delete_workspace(bearer(&headers)?, id)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthenticated)?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or(ApiError::Unauthenticated)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

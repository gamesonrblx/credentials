//! HTTP surface. The public listener serves proxy injection only.
//! Environment and header delivery require the local Unix socket, which
//! builds this router with `local_channel` set.

use std::sync::Arc;

use crate::b64::{b64std_decode, b64std_encode};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::{Delivery, DeliveryPolicy};
use crate::service::{
    CreatedSession, CreatedVersion, CreatedWorkspace, E2eSubmission, Gateway, InjectRequest,
};
use crate::store::RecipientRow;
use crate::ApiError;

#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<Gateway>,
    /// When set, `POST /v1/workspaces` requires this bearer. Loopback dev leaves it empty.
    pub operator_token: Option<String>,
    /// True only on the local Unix socket. The public listener leaves this false.
    pub local_channel: bool,
}

pub fn router(gateway: Arc<Gateway>) -> Router {
    router_with_bootstrap(gateway, None)
}

pub fn router_with_bootstrap(gateway: Arc<Gateway>, operator_token: Option<String>) -> Router {
    routes().with_state(AppState {
        gateway,
        operator_token,
        local_channel: false,
    })
}

/// Same routes as the public listener, with env and header delivery enabled.
pub fn router_local(gateway: Arc<Gateway>) -> Router {
    routes().with_state(AppState {
        gateway,
        operator_token: None,
        local_channel: true,
    })
}

fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/workspaces", post(create_workspace))
        .route("/v1/secrets", post(create_secret))
        .route("/v1/secrets/{*tail}", post(secret_action))
        .route("/v1/agents", post(create_agent))
        .route(
            "/v1/agent-sessions",
            post(create_session).get(list_sessions),
        )
        .route("/v1/agent-sessions/{id}/revoke", post(revoke_session))
        .route("/v1/inject", post(inject))
        .route("/v1/audit", get(audit))
        .route("/v1/kek/rotate", post(rotate_kek))
        .route("/v1/workspaces/{id}/deletion", post(delete_workspace))
        .route("/v1/workspaces/{id}/deletion/cancel", post(cancel_deletion))
        .route(
            "/v1/workspace-keys",
            post(register_workspace_key).get(get_workspace_key),
        )
        .route(
            "/v1/recovery-recipients",
            post(add_recipient).get(list_recipients),
        )
        .route(
            "/v1/recovery-recipients/{id}/revoke",
            post(revoke_recipient),
        )
        .route("/v1/e2e-secrets", post(store_e2e_secret))
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
    headers: HeaderMap,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    if let Some(expected) = &state.operator_token {
        let presented = bearer(&headers).unwrap_or("");
        if presented.len() != expected.len()
            || !bool::from(subtle::ConstantTimeEq::ct_eq(
                presented.as_bytes(),
                expected.as_bytes(),
            ))
        {
            return Err(ApiError::Unauthenticated);
        }
    }
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

async fn secret_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(tail): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, ApiError> {
    if let Some(name) = tail
        .strip_suffix("/disable")
        .filter(|name| !name.is_empty() && !name.ends_with('/'))
    {
        state
            .gateway
            .disable_secret(bearer(&headers)?, name)
            .await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let name = tail
        .strip_suffix("/versions")
        .filter(|name| !name.is_empty() && !name.ends_with('/'))
        .ok_or(ApiError::NotFound)?;
    let encoded = body
        .get("value")
        .and_then(|value| value.as_str())
        .ok_or(ApiError::BadRequest)?;
    let value = b64std_decode(encoded)?;
    let created = state
        .gateway
        .create_version(bearer(&headers)?, name, &value)
        .await?;
    Ok(Json(VersionResponse {
        secret_id: created.secret_id,
        version_id: created.version_id,
        version: created.version,
    })
    .into_response())
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

#[derive(Serialize)]
struct SessionListResponse {
    sessions: Vec<SessionListItem>,
}

#[derive(Serialize)]
struct SessionListItem {
    session_id: Uuid,
    agent_id: Uuid,
    expires_at: u64,
    revoked_at: Option<u64>,
    scopes: Vec<String>,
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionListResponse>, ApiError> {
    let sessions = state.gateway.list_sessions(bearer(&headers)?).await?;
    Ok(Json(SessionListResponse {
        sessions: sessions
            .into_iter()
            .map(|session| SessionListItem {
                session_id: session.id,
                agent_id: session.agent_id,
                expires_at: session.expires_at,
                revoked_at: session.revoked_at,
                scopes: session.scopes,
            })
            .collect(),
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
            local_channel: state.local_channel,
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
    checkpoint: Option<AuditCheckpointResponse>,
}

#[derive(Serialize)]
struct AuditEventResponse {
    seq: u64,
    agent_id: Option<Uuid>,
    event_type: String,
    hash_hex: String,
    prev_hash_hex: String,
}

#[derive(Serialize)]
struct AuditCheckpointResponse {
    seq: u64,
    kid: String,
    signature_hex: String,
}

async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, ApiError> {
    let credential = bearer(&headers)?;
    let checkpoint = state.gateway.latest_checkpoint(credential).await?;
    let events = state.gateway.audit_log(credential, query.agent_id).await?;
    Ok(Json(AuditResponse {
        events: events
            .into_iter()
            .map(|event| AuditEventResponse {
                seq: event.seq,
                agent_id: event.agent_id,
                event_type: event.event_type,
                hash_hex: hex_encode(&event.hash),
                prev_hash_hex: hex_encode(&event.prev_hash),
            })
            .collect(),
        checkpoint: checkpoint.map(|row| AuditCheckpointResponse {
            seq: row.seq,
            kid: row.kid,
            signature_hex: hex_encode(&row.signature),
        }),
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

#[derive(Deserialize)]
struct WorkspaceKeyBody {
    encapsulation_key: String,
}

#[derive(Serialize)]
struct WorkspaceKeyResponse {
    id: Uuid,
    encapsulation_key: String,
}

async fn register_workspace_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WorkspaceKeyBody>,
) -> Result<Json<WorkspaceKeyResponse>, ApiError> {
    let key = b64std_decode(&body.encapsulation_key)?;
    let id = state
        .gateway
        .register_workspace_key(bearer(&headers)?, &key)
        .await?;
    Ok(Json(WorkspaceKeyResponse {
        id,
        encapsulation_key: body.encapsulation_key,
    }))
}

async fn get_workspace_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WorkspaceKeyResponse>, ApiError> {
    let key = state.gateway.registered_key(bearer(&headers)?).await?;
    Ok(Json(WorkspaceKeyResponse {
        id: key.id,
        encapsulation_key: b64std_encode(&key.encapsulation_key),
    }))
}

#[derive(Deserialize)]
struct RecipientBody {
    id: Uuid,
    kind: String,
    encapsulation_key: Option<String>,
    encapsulation: Option<String>,
    prf_salt: Option<String>,
    kdf_params: Option<String>,
    wrap_nonce: String,
    wrapped_key: String,
}

#[derive(Serialize)]
struct RecipientResponse {
    id: Uuid,
    kind: String,
    revoked_at: Option<u64>,
}

async fn add_recipient(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RecipientBody>,
) -> Result<StatusCode, ApiError> {
    let credential = bearer(&headers)?;
    let row = recipient_row(credential, &state, body).await?;
    state.gateway.add_recipient(credential, row).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn recipient_row(
    credential: &str,
    state: &AppState,
    body: RecipientBody,
) -> Result<RecipientRow, ApiError> {
    let workspace_id = state.gateway.workspace_id_for(credential).await?;
    Ok(RecipientRow {
        id: body.id,
        workspace_id,
        kind: body.kind,
        encapsulation_key: optional_b64(body.encapsulation_key)?,
        encapsulation: optional_b64(body.encapsulation)?,
        prf_salt: optional_b64(body.prf_salt)?,
        kdf_params: body.kdf_params,
        wrap_nonce: b64std_decode(&body.wrap_nonce)?,
        wrapped_key: b64std_decode(&body.wrapped_key)?,
        revoked_at: None,
    })
}

fn optional_b64(value: Option<String>) -> Result<Option<Vec<u8>>, ApiError> {
    value.map(|text| b64std_decode(&text)).transpose()
}

async fn list_recipients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RecipientResponse>>, ApiError> {
    let rows = state.gateway.list_recipients(bearer(&headers)?).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| RecipientResponse {
                id: row.id,
                kind: row.kind,
                revoked_at: row.revoked_at,
            })
            .collect(),
    ))
}

async fn revoke_recipient(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state
        .gateway
        .revoke_recipient(bearer(&headers)?, id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct E2eBody {
    name: String,
    value: Option<String>,
    secret_id: Uuid,
    version_id: Uuid,
    workspace_key_id: Uuid,
    payload_nonce: String,
    payload_ciphertext: String,
    dek_wrap_nonce: String,
    dek_wrapped: String,
    e2e_encapsulation: String,
    plaintext_len: usize,
    policy: PolicyBody,
}

async fn store_e2e_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<E2eBody>,
) -> Result<Json<VersionResponse>, ApiError> {
    if body.value.is_some() {
        return Err(ApiError::BadRequest);
    }
    let created = state
        .gateway
        .store_e2e_secret(
            bearer(&headers)?,
            &body.name,
            DeliveryPolicy {
                header_name: body.policy.header_name,
                header_format: body.policy.header_format,
                env_name: body.policy.env_name,
                hosts: body.policy.hosts,
                allow_proxy: body.policy.allow_proxy,
                allow_header: body.policy.allow_header,
                allow_env: body.policy.allow_env,
            },
            E2eSubmission {
                secret_id: body.secret_id,
                version_id: body.version_id,
                workspace_key_id: body.workspace_key_id,
                payload_nonce: arr12(b64std_decode(&body.payload_nonce)?)?,
                payload_ciphertext: b64std_decode(&body.payload_ciphertext)?,
                dek_wrap_nonce: arr12(b64std_decode(&body.dek_wrap_nonce)?)?,
                dek_wrapped: b64std_decode(&body.dek_wrapped)?,
                encapsulation: b64std_decode(&body.e2e_encapsulation)?,
                plaintext_len: body.plaintext_len,
            },
        )
        .await?;
    Ok(Json(VersionResponse {
        secret_id: created.secret_id,
        version_id: created.version_id,
        version: created.version,
    }))
}

fn arr12(bytes: Vec<u8>) -> Result<[u8; 12], ApiError> {
    bytes.try_into().map_err(|_| ApiError::BadRequest)
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

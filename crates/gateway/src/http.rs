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

use crate::login::{self, SharedLogin};
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
    /// True when this router is behind the TLS listener. DPoP `htu` uses it.
    pub tls: bool,
    /// Human dashboard login. Absent on the local inject socket.
    pub login: Option<SharedLogin>,
}

pub fn router(gateway: Arc<Gateway>) -> Router {
    router_with_bootstrap(gateway, None)
}

pub fn router_with_bootstrap(gateway: Arc<Gateway>, operator_token: Option<String>) -> Router {
    routes().with_state(AppState {
        gateway,
        operator_token,
        local_channel: false,
        tls: false,
        login: None,
    })
}

pub fn router_with_login(
    gateway: Arc<Gateway>,
    operator_token: Option<String>,
    login: SharedLogin,
) -> Router {
    routes().with_state(AppState {
        gateway,
        operator_token,
        local_channel: false,
        tls: false,
        login: Some(login),
    })
}

/// Public routes behind the TLS listener. DPoP `htu` uses `https`. Pass
/// `login` to serve the OIDC dashboard login on this listener.
pub fn router_tls(
    gateway: Arc<Gateway>,
    operator_token: Option<String>,
    login: Option<SharedLogin>,
) -> Router {
    routes().with_state(AppState {
        gateway,
        operator_token,
        local_channel: false,
        tls: true,
        login,
    })
}

/// Same routes as the public listener, with env and header delivery enabled.
pub fn router_local(gateway: Arc<Gateway>) -> Router {
    routes().with_state(AppState {
        gateway,
        operator_token: None,
        local_channel: true,
        tls: false,
        login: None,
    })
}

fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/keys", get(signing_keys))
        .route("/v1/workspaces", post(create_workspace))
        .route(
            "/v1/workspaces/{id}/credential/rotate",
            post(rotate_credential),
        )
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
        .route("/v1/login", get(login::begin))
        .route("/v1/login/callback", get(login::callback))
        .route("/v1/session", get(login::session))
        .route("/dashboard", get(login::dashboard))
}

async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(Serialize)]
struct KeysResponse {
    keys: Vec<KeyItem>,
}

#[derive(Serialize)]
struct KeyItem {
    kid: String,
    alg: &'static str,
    public_key: String,
}

/// Unauthenticated. The injector operator pins this key to verify grants.
async fn signing_keys(State(state): State<AppState>) -> Json<KeysResponse> {
    let (kid, public_key) = state.gateway.signing_key();
    Json(KeysResponse {
        keys: vec![KeyItem {
            kid: kid.to_owned(),
            alg: "EdDSA",
            public_key: b64std_encode(&public_key),
        }],
    })
}

async fn rotate_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    let credential = bearer(&headers)?;
    if state.gateway.workspace_id_for(credential).await? != id {
        return Err(ApiError::NotFound);
    }
    let fresh = state
        .gateway
        .rotate_workspace_credential(credential)
        .await?;
    Ok(Json(WorkspaceResponse {
        id,
        credential: fresh,
    }))
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
        let presented_hash = sha256(presented.as_bytes());
        let expected_hash = sha256(expected.as_bytes());
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            presented_hash.as_slice(),
            expected_hash.as_slice(),
        )) {
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
    /// Content-Type of the proxied body. `request.content_type` is accepted
    /// too; when both are present they must match.
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Deserialize)]
struct ProxyRequest {
    method: String,
    url: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    content_type: Option<String>,
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
        content_type: None,
    });
    let content_type = match (body.content_type, request.content_type) {
        (Some(outer), Some(inner)) if outer != inner => return Err(ApiError::BadRequest),
        (outer, inner) => inner.or(outer).filter(|value| !value.is_empty()),
    };
    let htu = request_htu(&headers, state.tls, state.gateway.public_origin())?;
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
            content_type,
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
    /// Return events with `seq` greater than this. Default 0.
    #[serde(default)]
    after_seq: u64,
    /// Page size. Default 500, capped at 1000.
    limit: Option<u32>,
}

#[derive(Serialize)]
struct AuditResponse {
    events: Vec<AuditEventResponse>,
    checkpoint: Option<AuditCheckpointResponse>,
    /// Pass as `after_seq` for the next page. Null on the last page.
    next_after_seq: Option<u64>,
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
    let page = state
        .gateway
        .audit_page(credential, query.agent_id, query.after_seq, query.limit)
        .await?;
    Ok(Json(AuditResponse {
        next_after_seq: page.next_after_seq,
        events: page
            .events
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

/// DPoP `htu` for `/v1/inject`. With a configured public origin it is that
/// origin plus the path and the Host header is ignored. Otherwise it is built
/// from the Host header the server received. A client-supplied `x-dpop-htu`
/// header is never consulted.
fn request_htu(
    headers: &HeaderMap,
    tls: bool,
    public_origin: Option<&str>,
) -> Result<String, ApiError> {
    if let Some(origin) = public_origin {
        return Ok(format!("{origin}/v1/inject"));
    }
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::BadRequest)?;
    if host.is_empty()
        || host.len() > 253
        || host
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\' || ch == '@' || ch == '?')
    {
        return Err(ApiError::BadRequest);
    }
    let scheme = if tls { "https" } else { "http" };
    Ok(format!("{scheme}://{host}/v1/inject"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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

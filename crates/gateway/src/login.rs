//! Human login for the dashboard.
//!
//! The session cookie names a subject. It is not a decryption key and it is
//! not accepted by inject routes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use credentials_edge::{finish_browser_login, start_browser_login, OidcClient};
use serde::Deserialize;
use serde_json::json;

use crate::http::AppState;

pub struct LoginHub {
    client: OidcClient,
    secret: Option<String>,
    pending: Mutex<HashMap<String, String>>,
    sessions: Mutex<HashMap<String, String>>,
}

impl LoginHub {
    pub fn new(
        issuer: String,
        client_id: String,
        redirect_uri: String,
        secret: Option<String>,
    ) -> Self {
        Self {
            client: OidcClient {
                issuer,
                client_id,
                redirect_uri,
            },
            secret,
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

pub async fn begin(State(state): State<AppState>) -> Response {
    let Some(login) = &state.login else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let client = login.client.clone();
    let started = match tokio::task::spawn_blocking(move || start_browser_login(&client)).await {
        Ok(Ok(started)) => started,
        _ => return StatusCode::BAD_GATEWAY.into_response(),
    };
    login
        .pending
        .lock()
        .expect("login")
        .insert(started.state.clone(), started.verifier);
    let cookie = format!(
        "credentials_login={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=300",
        started.state
    );
    (
        [(header::SET_COOKIE, cookie)],
        Redirect::temporary(&started.url),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: String,
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(login) = &state.login else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let cookie_state = cookie(&headers, "credentials_login");
    if cookie_state.as_deref() != Some(query.state.as_str()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let verifier = login.pending.lock().expect("login").remove(&query.state);
    let Some(verifier) = verifier else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let client = login.client.clone();
    let secret = login.secret.clone();
    let code = query.code.clone();
    let subject = match tokio::task::spawn_blocking(move || {
        finish_browser_login(&client, secret.as_deref(), &code, &verifier)
    })
    .await
    {
        Ok(Ok(session)) => session.subject,
        _ => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("os random");
    let session_id = hex(&raw);
    login
        .sessions
        .lock()
        .expect("login")
        .insert(session_id.clone(), subject);
    let cookie =
        format!("credentials_session={session_id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600");
    (
        [(header::SET_COOKIE, cookie)],
        Redirect::temporary("/dashboard"),
    )
        .into_response()
}

pub async fn session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(login) = &state.login else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(id) = cookie(&headers, "credentials_session") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let subject = login.sessions.lock().expect("login").get(&id).cloned();
    let Some(subject) = subject else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    Json(json!({"subject": subject, "decrypts": false})).into_response()
}

pub async fn dashboard() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../../dashboard/index.html"),
    )
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get(header::COOKIE)?.to_str().ok()?;
    header.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub type SharedLogin = Arc<LoginHub>;

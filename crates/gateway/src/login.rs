//! Human login for the dashboard.
//!
//! The session cookie names a subject. It is not a decryption key and it is
//! not accepted by inject routes.
//!
//! Pending logins and sessions expire and are capped. `/v1/login` is
//! unauthenticated, so at most [`MAX_IDP_CALLS`] calls to the identity
//! provider run at once; further requests get 503 instead of queueing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use credentials_edge::{finish_browser_login, start_browser_login, OidcClient};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;

use crate::http::AppState;

/// Time a browser has to come back from the identity provider.
pub const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// Dashboard session lifetime. The cookie carries the same Max-Age.
pub const SESSION_TTL: Duration = Duration::from_secs(60 * 60);
/// Most logins waiting for a callback.
pub const MAX_PENDING: usize = 10_000;
/// Most live dashboard sessions.
pub const MAX_SESSIONS: usize = 100_000;
/// Most identity-provider round trips in flight.
pub const MAX_IDP_CALLS: usize = 16;

struct Expiring {
    value: String,
    expires: Instant,
}

pub struct LoginHub {
    client: OidcClient,
    secret: Option<String>,
    pending: Mutex<HashMap<String, Expiring>>,
    sessions: Mutex<HashMap<String, Expiring>>,
    idp_calls: Semaphore,
}

/// A poisoned lock still holds a usable map, so recover it instead of panicking.
fn locked(map: &Mutex<HashMap<String, Expiring>>) -> MutexGuard<'_, HashMap<String, Expiring>> {
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Drop expired entries, then insert unless the map is at `cap`.
fn insert_bounded(
    map: &mut HashMap<String, Expiring>,
    key: String,
    value: String,
    ttl: Duration,
    cap: usize,
    now: Instant,
) -> bool {
    map.retain(|_, entry| entry.expires > now);
    if map.len() >= cap {
        return false;
    }
    map.insert(
        key,
        Expiring {
            value,
            expires: now + ttl,
        },
    );
    true
}

/// Remove and return a live entry.
fn take_live(map: &mut HashMap<String, Expiring>, key: &str, now: Instant) -> Option<String> {
    let entry = map.remove(key)?;
    (entry.expires > now).then_some(entry.value)
}

/// Return a live entry, dropping it if it has expired.
fn get_live(map: &mut HashMap<String, Expiring>, key: &str, now: Instant) -> Option<String> {
    let live = map.get(key).map(|entry| entry.expires > now)?;
    if !live {
        map.remove(key);
        return None;
    }
    map.get(key).map(|entry| entry.value.clone())
}

/// Cookie attributes. `Secure` is set when the browser reached us over HTTPS.
fn cookie_attrs(secure: bool, max_age: Duration) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "HttpOnly; SameSite=Lax; Path=/; Max-Age={}{secure}",
        max_age.as_secs()
    )
}

fn served_over_https(state: &AppState) -> bool {
    state.tls
        || state
            .gateway
            .public_origin()
            .is_some_and(|origin| origin.starts_with("https://"))
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
            idp_calls: Semaphore::new(MAX_IDP_CALLS),
        }
    }
}

pub async fn begin(State(state): State<AppState>) -> Response {
    let Some(login) = &state.login else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Refuse before calling the identity provider when the table is full.
    {
        let mut pending = locked(&login.pending);
        let now = Instant::now();
        pending.retain(|_, entry| entry.expires > now);
        if pending.len() >= MAX_PENDING {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    let Ok(_call) = login.idp_calls.try_acquire() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let client = login.client.clone();
    let started = match tokio::task::spawn_blocking(move || start_browser_login(&client)).await {
        Ok(Ok(started)) => started,
        _ => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let inserted = insert_bounded(
        &mut locked(&login.pending),
        started.state.clone(),
        started.verifier,
        PENDING_TTL,
        MAX_PENDING,
        Instant::now(),
    );
    if !inserted {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let cookie = format!(
        "credentials_login={}; {}",
        started.state,
        cookie_attrs(served_over_https(&state), PENDING_TTL)
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
    let verifier = take_live(&mut locked(&login.pending), &query.state, Instant::now());
    let Some(verifier) = verifier else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(_call) = login.idp_calls.try_acquire() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
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
    if getrandom::fill(&mut raw).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let session_id = hex(&raw);
    let inserted = insert_bounded(
        &mut locked(&login.sessions),
        session_id.clone(),
        subject,
        SESSION_TTL,
        MAX_SESSIONS,
        Instant::now(),
    );
    if !inserted {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let cookie = format!(
        "credentials_session={session_id}; {}",
        cookie_attrs(served_over_https(&state), SESSION_TTL)
    );
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
    let subject = get_live(&mut locked(&login.sessions), &id, Instant::now());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_entries_are_pruned_and_not_returned() {
        let start = Instant::now();
        let mut map = HashMap::new();
        assert!(insert_bounded(
            &mut map,
            "a".into(),
            "va".into(),
            Duration::from_secs(10),
            4,
            start
        ));
        let later = start + Duration::from_secs(11);
        assert_eq!(get_live(&mut map, "a", later), None);
        assert!(map.is_empty());

        assert!(insert_bounded(
            &mut map,
            "b".into(),
            "vb".into(),
            Duration::from_secs(10),
            4,
            start
        ));
        assert_eq!(take_live(&mut map, "b", later), None);
        assert!(map.is_empty());
    }

    #[test]
    fn a_full_table_refuses_new_entries_until_they_expire() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut map = HashMap::new();
        assert!(insert_bounded(
            &mut map,
            "a".into(),
            "1".into(),
            ttl,
            2,
            start
        ));
        assert!(insert_bounded(
            &mut map,
            "b".into(),
            "2".into(),
            ttl,
            2,
            start
        ));
        assert!(!insert_bounded(
            &mut map,
            "c".into(),
            "3".into(),
            ttl,
            2,
            start
        ));
        assert_eq!(map.len(), 2);
        let later = start + Duration::from_secs(11);
        assert!(insert_bounded(
            &mut map,
            "c".into(),
            "3".into(),
            ttl,
            2,
            later
        ));
        assert_eq!(map.len(), 1);
        assert_eq!(get_live(&mut map, "c", later), Some("3".into()));
    }

    #[test]
    fn cookies_are_http_only_lax_and_secure_over_https() {
        let plain = cookie_attrs(false, SESSION_TTL);
        assert!(plain.contains("HttpOnly"));
        assert!(plain.contains("SameSite=Lax"));
        assert!(plain.contains("Path=/"));
        assert!(plain.contains("Max-Age=3600"));
        assert!(!plain.contains("Secure"));
        assert!(cookie_attrs(true, PENDING_TTL).ends_with("; Secure"));
    }
}

//! Credentials gateway.
//!
//! This crate is the pre-alpha server.
//! It issues short Ed25519 tokens.
//! It checks scope.
//! The dev path opens `wrap_mode=gateway` rows.
//! The production path does not open `wrap_mode=e2e` rows.
//! SQLite and Postgres implement [`Store`].
//! TLS 1.3 can negotiate group 4588.

#![forbid(unsafe_code)]

mod anchor;
mod audit;
mod b64;
mod dpop;
mod error;
mod http;
#[cfg(unix)]
mod local;
#[cfg(test)]
mod log_canary;
mod login;
mod names;
mod policy;
mod redact;
mod service;
mod sql_store;
mod store;
mod tls;
mod token;
mod upstream;

pub use anchor::{checkpoint_message, AuditAnchor, DevFileAnchor, FileAnchor, MemoryAnchor};
pub use audit::{verify_chain, AuditRecord};
pub use error::ApiError;
pub use http::{router, router_local, router_tls, router_with_bootstrap, router_with_login};
#[cfg(unix)]
pub use local::{peer_uid_allowed, serve_local};
pub use login::LoginHub;
pub use policy::{Delivery, DeliveryPolicy};
pub use redact::redact_field;
pub use service::{
    generate_dpop, Clock, CreatedSession, E2eSubmission, Gateway, InjectRequest, InjectResponse,
    ManualClock, Now, ISSUER,
};
pub use sql_store::SqlStore;
pub use store::{MemoryStore, RecipientRow, Store, WrapMode};
pub use tls::{
    group_code, hybrid_provider, is_hybrid, serve_tls, server_config, tls_classical_kex_total,
    HYBRID_GROUP,
};
pub use token::DevSigner;
pub use upstream::{HttpUpstream, Outbound, RecordingUpstream, UnconfiguredUpstream, Upstream};

use std::net::SocketAddr;
use std::sync::Arc;

/// Bind the dev server. The listener address defaults to loopback.
pub async fn serve(gateway: Arc<Gateway>, addr: SocketAddr) -> std::io::Result<()> {
    serve_with(gateway, addr, None).await
}

pub async fn serve_with(
    gateway: Arc<Gateway>,
    addr: SocketAddr,
    operator_token: Option<String>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "credentials gateway listening");
    axum::serve(listener, router_with_bootstrap(gateway, operator_token)).await
}

/// Bind an ephemeral loopback port and serve in the background.
pub async fn spawn_ephemeral(gateway: Arc<Gateway>) -> std::io::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(gateway)).await;
    });
    Ok(addr)
}

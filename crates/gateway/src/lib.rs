//! Credentials gateway.
//!
//! This crate is the pre-alpha server: short-lived Ed25519 tokens, a scope
//! check, envelope decryption, proxy injection, and a hash-chained audit log.
//! The root-key provider is the dev implementation from `credentials-crypto`.
//! It refuses to start when `CREDENTIALS_ENV=production`.
//!
//! Not implemented yet: a cloud KMS, TLS termination with `X25519MLKEM768`,
//! the end-to-end mode, and external secret backends. SQLite and Postgres
//! implement [`Store`]. `wrap_mode = e2e` is stored as a column and rejected
//! on write until that mode exists.

#![forbid(unsafe_code)]

mod anchor;
mod audit;
mod b64;
mod dpop;
mod error;
mod http;
mod names;
mod policy;
mod redact;
mod service;
mod sql_store;
mod store;
mod token;
mod upstream;

pub use anchor::{checkpoint_message, AuditAnchor, DevFileAnchor, MemoryAnchor};
pub use audit::{verify_chain, AuditRecord};
pub use error::ApiError;
pub use http::{router, router_with_bootstrap};
pub use policy::{Delivery, DeliveryPolicy};
pub use redact::redact_field;
pub use service::{
    generate_dpop, Clock, CreatedSession, Gateway, InjectRequest, InjectResponse, ManualClock, Now,
    ISSUER,
};
pub use sql_store::SqlStore;
pub use store::{MemoryStore, Store, WrapMode};
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

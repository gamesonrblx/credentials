//! Credentials gateway.
//!
//! This crate is the pre-alpha server: short-lived Ed25519 tokens, a scope
//! check, envelope decryption, proxy injection, and a hash-chained audit log.
//! The root-key provider is the dev implementation from `credentials-crypto`.
//! It refuses to start when `CREDENTIALS_ENV=production`.
//!
//! Not implemented yet: a cloud KMS, TLS termination with `X25519MLKEM768`,
//! the end-to-end mode, external secret backends, and a durable database.

#![forbid(unsafe_code)]

mod audit;
mod b64;
mod dpop;
mod error;
mod http;
mod names;
mod policy;
mod redact;
mod service;
mod store;
mod token;
mod upstream;

pub use audit::{verify_chain, AuditRecord};
pub use error::ApiError;
pub use http::router;
pub use policy::{Delivery, DeliveryPolicy};
pub use redact::redact_field;
pub use service::{
    generate_dpop, Clock, CreatedSession, Gateway, InjectRequest, InjectResponse, ManualClock, Now,
    ISSUER,
};
pub use store::MemoryStore;
pub use upstream::{RecordingUpstream, UnconfiguredUpstream, Upstream};

use std::net::SocketAddr;
use std::sync::Arc;

/// Bind the dev server. The listener address defaults to loopback.
pub async fn serve(gateway: Arc<Gateway>, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "credentials gateway listening");
    axum::serve(listener, router(gateway)).await
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

//! TLS 1.3 listener. The hybrid group `X25519MLKEM768` is RFC 10024 group 4588.
//!
//! `require_hybrid` offers only that group. A classical-only client cannot
//! finish the handshake. Hosted mode turns this on.

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::kx_group;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig;
use rustls::version::TLS13;
use rustls::NamedGroup;

use crate::ApiError;

pub const HYBRID_GROUP: u16 = 4588;

pub fn hybrid_provider(require_hybrid: bool) -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = if require_hybrid {
        vec![kx_group::X25519MLKEM768]
    } else {
        vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
        ]
    };
    provider
}

pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    require_hybrid: bool,
) -> Result<ServerConfig, ApiError> {
    let provider = Arc::new(hybrid_provider(require_hybrid));
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| ApiError::BadRequest)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|_| ApiError::BadRequest)
}

pub fn group_code(group: NamedGroup) -> u16 {
    u16::from(group)
}

pub fn is_hybrid(group: NamedGroup) -> bool {
    group_code(group) == HYBRID_GROUP
}

static CLASSICAL_KEX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn tls_classical_kex_total() -> u64 {
    CLASSICAL_KEX.load(std::sync::atomic::Ordering::Relaxed)
}

/// Serve the public router on TLS 1.3.
pub async fn serve_tls(
    gateway: Arc<crate::service::Gateway>,
    addr: std::net::SocketAddr,
    operator_token: Option<String>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    require_hybrid: bool,
) -> std::io::Result<()> {
    let config = server_config(cert, key, require_hybrid).map_err(std::io::Error::other)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = crate::http::router_tls(gateway, operator_token);
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            if let Some(group) = tls.get_ref().1.negotiated_key_exchange_group() {
                if !is_hybrid(group.name()) {
                    CLASSICAL_KEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            let io = hyper_util::rt::TokioIo::new(tls);
            let service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    let (parts, body) = request.into_parts();
                    let request =
                        axum::extract::Request::from_parts(parts, axum::body::Body::new(body));
                    tower::ServiceExt::oneshot(app.clone(), request)
                },
            );
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

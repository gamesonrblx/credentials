//! TLS 1.3 listener. The hybrid group `X25519MLKEM768` is RFC 10024 group 4588.
//!
//! `require_hybrid` offers only that group. A classical-only client cannot
//! finish the handshake. Hosted mode turns this on.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::aws_lc_rs::kx_group;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig;
use rustls::version::TLS13;
use rustls::NamedGroup;
use tokio::sync::Semaphore;

use crate::login::SharedLogin;
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

/// Build the TLS 1.3 server config. `certs` is the leaf first, then any
/// intermediates, in the order a PEM chain file lists them.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    require_hybrid: bool,
) -> Result<ServerConfig, ApiError> {
    if certs.is_empty() {
        return Err(ApiError::BadRequest);
    }
    let provider = Arc::new(hybrid_provider(require_hybrid));
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| ApiError::BadRequest)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| ApiError::BadRequest)
}

/// Time allowed for a client to finish the TLS handshake.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for a client to send a complete set of request headers.
pub const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Most connections served at once. Further clients wait in the accept queue.
pub const MAX_TLS_CONNECTIONS: usize = 4096;
/// Pause after an accept error such as EMFILE before trying again.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

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
///
/// One failed accept is logged and retried. Handshakes and request headers
/// have deadlines, and at most [`MAX_TLS_CONNECTIONS`] connections run at once.
/// `login` enables the dashboard OIDC routes on this listener.
pub async fn serve_tls(
    gateway: Arc<crate::service::Gateway>,
    addr: std::net::SocketAddr,
    operator_token: Option<String>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    require_hybrid: bool,
    login: Option<SharedLogin>,
) -> std::io::Result<()> {
    let config = server_config(certs, key, require_hybrid).map_err(std::io::Error::other)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "credentials gateway listening on tls");
    let app = crate::http::router_tls(gateway, operator_token, login);
    let slots = Arc::new(Semaphore::new(MAX_TLS_CONNECTIONS));
    loop {
        let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
            return Err(std::io::Error::other("connection limiter closed"));
        };
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(err) => {
                tracing::warn!(error = %err, "tls accept failed");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) =
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
            else {
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
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HTTP_HEADER_READ_TIMEOUT)
                .serve_connection(io, service)
                .await;
        });
    }
}

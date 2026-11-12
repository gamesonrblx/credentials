//! Dev gateway process.
//!
//! Binds to `127.0.0.1:8080` unless `CREDENTIALS_LISTEN` is set. Root keys go
//! in `CREDENTIALS_DEV_KEYS` (default `.credentials-dev-keys.json`). The dev
//! signer seed goes in `CREDENTIALS_DEV_SIGNER` (default
//! `.credentials-dev-signer.json`). Rows go in `CREDENTIALS_DATABASE_URL`
//! (default a SQLite file beside the process). Those files hold raw key
//! material and are not a production KMS. `CREDENTIALS_ENV=production`
//! starts the control plane instead: no dev key file, no dev signer, and
//! no dev audit anchor. That process cannot unwrap secrets.
//!
//! Workspace creation on this listener is unauthenticated so a local process
//! can bootstrap. Do not expose the port beyond loopback.

use std::net::SocketAddr;
use std::sync::Arc;

use credentials_crypto::{DevFileRootKeys, DevPolicy};
use credentials_gateway::{
    serve_with, Clock, DevFileAnchor, DevSigner, FileAnchor, Gateway, HttpUpstream, SqlStore,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let policy = DevPolicy::from_env();
    let mut gateway = if policy.allow_dev {
        build_dev(policy).await
    } else {
        build_production(policy).await
    };
    if let Ok(issuer) = std::env::var("CREDENTIALS_ISSUER") {
        gateway.set_issuer(issuer);
    }
    if let Ok(audience) = std::env::var("CREDENTIALS_AUDIENCE") {
        gateway.set_audience(audience);
    }
    let gateway = Arc::new(gateway);

    let addr: SocketAddr = std::env::var("CREDENTIALS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("CREDENTIALS_LISTEN is not a socket address");
            std::process::exit(1);
        });
    let operator_token = std::env::var("CREDENTIALS_OPERATOR_TOKEN").ok();
    if !addr.ip().is_loopback() && operator_token.is_none() {
        eprintln!("CREDENTIALS_OPERATOR_TOKEN is required when the listener is not loopback");
        std::process::exit(1);
    }

    let poller = Arc::clone(&gateway);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(err) = poller.publish_checkpoints().await {
                tracing::error!(error = %err, "audit checkpoint failed");
            }
            if let Err(err) = poller.poll_shreds().await {
                tracing::error!(error = %err, "shred poller failed");
            }
            if let Err(err) = poller.resume_rewrap_jobs().await {
                tracing::error!(error = %err, "rewrap job failed");
            }
            if let Err(err) = poller.purge_dpop().await {
                tracing::error!(error = %err, "dpop purge failed");
            }
        }
    });

    if let Ok(directory) = std::env::var("CREDENTIALS_LOCAL_DIR") {
        #[cfg(unix)]
        {
            let local = Arc::clone(&gateway);
            tokio::spawn(async move {
                if let Err(err) = credentials_gateway::serve_local(local, directory.into()).await {
                    tracing::error!(error = %err, "local channel stopped");
                }
            });
        }
        #[cfg(not(unix))]
        {
            let _ = directory;
            eprintln!("CREDENTIALS_LOCAL_DIR is only supported on unix");
            std::process::exit(1);
        }
    }

    let require_hybrid = match std::env::var("TLS_REQUIRE_HYBRID") {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "TRUE"),
        Err(_) => !policy.allow_dev,
    };
    let cert_path = std::env::var("CREDENTIALS_TLS_CERT").ok();
    let key_path = std::env::var("CREDENTIALS_TLS_KEY").ok();
    if require_hybrid && (cert_path.is_none() || key_path.is_none()) {
        eprintln!("TLS_REQUIRE_HYBRID is on. Set CREDENTIALS_TLS_CERT and CREDENTIALS_TLS_KEY");
        std::process::exit(1);
    }
    if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        let certs = match load_certs(&cert_path) {
            Ok(certs) => certs,
            Err(err) => {
                eprintln!("tls cert: {err}");
                std::process::exit(1);
            }
        };
        let key = match load_key(&key_path) {
            Ok(key) => key,
            Err(err) => {
                eprintln!("tls key: {err}");
                std::process::exit(1);
            }
        };
        let Some(cert) = certs.into_iter().next() else {
            eprintln!("tls cert file is empty");
            std::process::exit(1);
        };
        if let Err(err) =
            credentials_gateway::serve_tls(gateway, addr, operator_token, cert, key, require_hybrid)
                .await
        {
            eprintln!("tls server: {err}");
            std::process::exit(1);
        }
        return;
    }

    if let Some(login) = oidc_login(addr) {
        let app = credentials_gateway::router_with_login(gateway, operator_token, login);
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("server: {err}");
                std::process::exit(1);
            }
        };
        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("server: {err}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(err) = serve_with(gateway, addr, operator_token).await {
        eprintln!("server: {err}");
        std::process::exit(1);
    }
}

fn oidc_login(addr: std::net::SocketAddr) -> Option<std::sync::Arc<credentials_gateway::LoginHub>> {
    let issuer = std::env::var("CREDENTIALS_OIDC_ISSUER").ok()?;
    let client_id =
        std::env::var("CREDENTIALS_OIDC_CLIENT_ID").unwrap_or_else(|_| "credentials".into());
    let secret = std::env::var("CREDENTIALS_OIDC_CLIENT_SECRET").ok();
    let redirect = std::env::var("CREDENTIALS_OIDC_REDIRECT")
        .unwrap_or_else(|_| format!("http://{addr}/v1/login/callback"));
    Some(std::sync::Arc::new(credentials_gateway::LoginHub::new(
        issuer, client_id, redirect, secret,
    )))
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let bytes = std::fs::read(path).map_err(|err| err.to_string())?;
    let ders = pem_ders(&bytes, "CERTIFICATE")?;
    if ders.is_empty() {
        return Err("no certificate".into());
    }
    Ok(ders
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect())
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let bytes = std::fs::read(path).map_err(|err| err.to_string())?;
    if let Ok(der) = pem_ders(&bytes, "PRIVATE KEY") {
        if let Some(der) = der.into_iter().next() {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(der),
            ));
        }
    }
    let der = pem_ders(&bytes, "EC PRIVATE KEY")?
        .into_iter()
        .next()
        .ok_or_else(|| "no private key".to_string())?;
    Ok(rustls::pki_types::PrivateKeyDer::Sec1(
        rustls::pki_types::PrivateSec1KeyDer::from(der),
    ))
}

fn pem_ders(bytes: &[u8], label: &str) -> Result<Vec<Vec<u8>>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "pem is not utf-8".to_string())?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        rest = &rest[start + begin.len()..];
        let Some(stop) = rest.find(&end) else {
            return Err("pem block is not closed".into());
        };
        let body: String = rest[..stop]
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        out.push(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                .map_err(|_| "pem is not base64".to_string())?,
        );
        rest = &rest[stop + end.len()..];
    }
    Ok(out)
}

async fn build_dev(policy: DevPolicy) -> Gateway {
    let key_path = std::env::var("CREDENTIALS_DEV_KEYS")
        .unwrap_or_else(|_| ".credentials-dev-keys.json".into());
    let kms = match DevFileRootKeys::open(&key_path, policy) {
        Ok(kms) => Arc::new(kms),
        Err(err) => {
            eprintln!("dev key file: {err}");
            std::process::exit(1);
        }
    };
    let signer_path = std::env::var("CREDENTIALS_DEV_SIGNER")
        .unwrap_or_else(|_| ".credentials-dev-signer.json".into());
    let signer = match DevSigner::load_or_create(std::path::Path::new(&signer_path), policy) {
        Ok(signer) => signer,
        Err(err) => {
            eprintln!("dev signer: {err}");
            std::process::exit(1);
        }
    };
    let database_url = std::env::var("CREDENTIALS_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://.credentials-dev.sqlite".into());
    let anchor_path = std::env::var("CREDENTIALS_DEV_ANCHOR")
        .unwrap_or_else(|_| ".credentials-dev-anchor.log".into());
    let anchor = match DevFileAnchor::open(&anchor_path, policy) {
        Ok(anchor) => Arc::new(anchor) as Arc<dyn credentials_gateway::AuditAnchor>,
        Err(err) => {
            eprintln!("dev audit anchor: {err}");
            std::process::exit(1);
        }
    };
    match Gateway::with_anchor(
        connect_store(&database_url).await,
        kms,
        upstream(),
        Arc::new(Clock),
        signer,
        anchor,
    ) {
        Ok(gateway) => gateway,
        Err(err) => {
            eprintln!("gateway: {err}");
            std::process::exit(1);
        }
    }
}

async fn build_production(policy: DevPolicy) -> Gateway {
    if std::env::var("CREDENTIALS_DEV_KEYS").is_ok()
        || std::env::var("CREDENTIALS_DEV_SIGNER").is_ok()
        || std::env::var("CREDENTIALS_DEV_ANCHOR").is_ok()
    {
        eprintln!("production refuses the dev key file, the dev signer, and the dev audit anchor");
        std::process::exit(1);
    }
    let Some(signer_path) = std::env::var("CREDENTIALS_SIGNING_KEY").ok() else {
        eprintln!("CREDENTIALS_SIGNING_KEY is required in production");
        std::process::exit(1);
    };
    let Some(anchor_path) = std::env::var("CREDENTIALS_AUDIT_ANCHOR").ok() else {
        eprintln!("CREDENTIALS_AUDIT_ANCHOR is required in production");
        std::process::exit(1);
    };
    let Some(database_url) = std::env::var("CREDENTIALS_DATABASE_URL").ok() else {
        eprintln!("CREDENTIALS_DATABASE_URL is required in production");
        std::process::exit(1);
    };
    let signer = match DevSigner::load_production(std::path::Path::new(&signer_path), policy) {
        Ok(signer) => signer,
        Err(err) => {
            eprintln!("signing key: {err}");
            std::process::exit(1);
        }
    };
    let anchor = match FileAnchor::open(&anchor_path) {
        Ok(anchor) => Arc::new(anchor) as Arc<dyn credentials_gateway::AuditAnchor>,
        Err(err) => {
            eprintln!("audit anchor: {err}");
            std::process::exit(1);
        }
    };
    match Gateway::control_plane(
        connect_store(&database_url).await,
        upstream(),
        Arc::new(Clock),
        signer,
        anchor,
        policy,
    ) {
        Ok(gateway) => gateway,
        Err(err) => {
            eprintln!("gateway: {err}");
            std::process::exit(1);
        }
    }
}

async fn connect_store(database_url: &str) -> Arc<SqlStore> {
    match SqlStore::connect(database_url).await {
        Ok(store) => {
            tracing::info!(engine = store.engine_name(), "durable store ready");
            Arc::new(store)
        }
        Err(err) => {
            eprintln!("store: {err}");
            std::process::exit(1);
        }
    }
}

fn upstream() -> Arc<HttpUpstream> {
    Arc::new(HttpUpstream::new().unwrap_or_else(|err| {
        eprintln!("upstream client: {err}");
        std::process::exit(1);
    }))
}

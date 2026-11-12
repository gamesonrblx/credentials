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
//! Production also requires `CREDENTIALS_PUBLIC_URL` (the https origin DPoP
//! proofs are bound to) and a Postgres URL that enforces TLS unless
//! `CREDENTIALS_ALLOW_PLAINTEXT_DB=1`. A non-loopback listener needs an
//! operator token of at least 16 characters.
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
        .fmt_fields(credentials_gateway::redacting_fields())
        .init();

    let policy = DevPolicy::from_env().unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
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
    match std::env::var("CREDENTIALS_PUBLIC_URL") {
        Ok(raw) => match public_origin(&raw, policy.allow_dev) {
            Ok(origin) => gateway.set_public_origin(Some(origin)),
            Err(err) => {
                eprintln!("CREDENTIALS_PUBLIC_URL: {err}");
                std::process::exit(1);
            }
        },
        Err(_) if !policy.allow_dev => {
            eprintln!(
                "CREDENTIALS_PUBLIC_URL is required in production (for example \
                 https://secrets.example.com). DPoP proofs are bound to it instead of the \
                 client-supplied Host header"
            );
            std::process::exit(1);
        }
        Err(_) => {}
    }
    let public_url = gateway.public_origin().map(str::to_owned);
    let gateway = Arc::new(gateway);

    let addr: SocketAddr = std::env::var("CREDENTIALS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("CREDENTIALS_LISTEN is not a socket address");
            std::process::exit(1);
        });
    let operator_token = std::env::var("CREDENTIALS_OPERATOR_TOKEN").ok();
    if !addr.ip().is_loopback() {
        if let Err(err) = check_operator_token(operator_token.as_deref()) {
            eprintln!("{err}");
            std::process::exit(1);
        }
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
    let tls = cert_path.is_some() && key_path.is_some();
    let login = oidc_login(addr, tls, public_url.as_deref());
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
        // The whole chain is served: leaf first, then intermediates.
        if let Err(err) = credentials_gateway::serve_tls(
            gateway,
            addr,
            operator_token,
            certs,
            key,
            require_hybrid,
            login,
        )
        .await
        {
            eprintln!("tls server: {err}");
            std::process::exit(1);
        }
        return;
    }

    if let Some(login) = login {
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

/// Dashboard login, when `CREDENTIALS_OIDC_ISSUER` is set. The default
/// redirect uses the public URL, or the listener address and scheme.
fn oidc_login(
    addr: std::net::SocketAddr,
    tls: bool,
    public_url: Option<&str>,
) -> Option<std::sync::Arc<credentials_gateway::LoginHub>> {
    let issuer = std::env::var("CREDENTIALS_OIDC_ISSUER").ok()?;
    let client_id =
        std::env::var("CREDENTIALS_OIDC_CLIENT_ID").unwrap_or_else(|_| "credentials".into());
    let secret = std::env::var("CREDENTIALS_OIDC_CLIENT_SECRET").ok();
    let redirect =
        std::env::var("CREDENTIALS_OIDC_REDIRECT").unwrap_or_else(|_| match public_url {
            Some(origin) => format!("{origin}/v1/login/callback"),
            None => {
                let scheme = if tls { "https" } else { "http" };
                format!("{scheme}://{addr}/v1/login/callback")
            }
        });
    Some(std::sync::Arc::new(credentials_gateway::LoginHub::new(
        issuer, client_id, redirect, secret,
    )))
}

/// Normalise `CREDENTIALS_PUBLIC_URL` to an origin such as
/// `https://secrets.example.com`. Plain `http` is accepted only in dev.
fn public_origin(raw: &str, allow_http: bool) -> Result<String, String> {
    let url = url::Url::parse(raw.trim()).map_err(|_| "not a valid URL".to_string())?;
    match url.scheme() {
        "https" => {}
        "http" if allow_http => {}
        "http" => return Err("must use https outside dev".into()),
        _ => return Err("scheme must be https".into()),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("a host is required".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials".into());
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("must be an origin with no path, query or fragment".into());
    }
    Ok(url.origin().ascii_serialization())
}

/// A non-loopback listener needs a real operator token.
fn check_operator_token(token: Option<&str>) -> Result<(), &'static str> {
    match token {
        None => Err("CREDENTIALS_OPERATOR_TOKEN is required when the listener is not loopback"),
        Some("change-me") => Err("CREDENTIALS_OPERATOR_TOKEN is still the example value change-me"),
        Some(token) if token.chars().count() < MIN_OPERATOR_TOKEN_CHARS => Err(
            "CREDENTIALS_OPERATOR_TOKEN must be at least 16 characters when the listener is not loopback",
        ),
        Some(_) => Ok(()),
    }
}

const MIN_OPERATOR_TOKEN_CHARS: usize = 16;

/// True for a `postgres://` or `postgresql://` URL.
fn is_postgres_url(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("postgres://") || lower.starts_with("postgresql://")
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
    if is_postgres_url(&database_url)
        && !SqlStore::postgres_url_enforces_tls(&database_url)
        && std::env::var("CREDENTIALS_ALLOW_PLAINTEXT_DB").as_deref() != Ok("1")
    {
        eprintln!(
            "CREDENTIALS_DATABASE_URL does not enforce TLS (set sslmode=require, verify-ca or \
             verify-full). Ciphertext, audit rows and tokens would cross the network in clear. \
             Set CREDENTIALS_ALLOW_PLAINTEXT_DB=1 only for a database on a private host network"
        );
        std::process::exit(1);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_url_is_normalised_to_an_origin() {
        assert_eq!(
            public_origin("https://Secrets.Example.com/", false).unwrap(),
            "https://secrets.example.com"
        );
        assert_eq!(
            public_origin("https://secrets.example.com:8443", false).unwrap(),
            "https://secrets.example.com:8443"
        );
        assert_eq!(
            public_origin("https://secrets.example.com:443", false).unwrap(),
            "https://secrets.example.com"
        );
        assert_eq!(
            public_origin("http://127.0.0.1:8080", true).unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn public_url_rejects_http_in_production_and_extra_parts() {
        assert!(public_origin("http://secrets.example.com", false).is_err());
        assert!(public_origin("ftp://secrets.example.com", true).is_err());
        assert!(public_origin("https://secrets.example.com/v1", false).is_err());
        assert!(public_origin("https://secrets.example.com/?a=b", false).is_err());
        assert!(public_origin("https://secrets.example.com/#x", false).is_err());
        assert!(public_origin("https://user:pw@secrets.example.com", false).is_err());
        assert!(public_origin("secrets.example.com", false).is_err());
    }

    #[test]
    fn weak_operator_tokens_are_refused() {
        assert!(check_operator_token(None).is_err());
        assert!(check_operator_token(Some("change-me")).is_err());
        assert!(check_operator_token(Some("short-token")).is_err());
        assert!(check_operator_token(Some("a-long-random-operator-token")).is_ok());
    }

    #[test]
    fn postgres_urls_are_recognised() {
        assert!(is_postgres_url("postgres://u:p@db/x"));
        assert!(is_postgres_url("postgresql://u:p@db/x"));
        assert!(!is_postgres_url("sqlite://file.db"));
    }
}

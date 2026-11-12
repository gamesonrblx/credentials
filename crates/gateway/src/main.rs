//! Dev gateway process.
//!
//! Binds to `127.0.0.1:8080` unless `CREDENTIALS_LISTEN` is set. Root keys go
//! in `CREDENTIALS_DEV_KEYS` (default `.credentials-dev-keys.json`). The dev
//! signer seed goes in `CREDENTIALS_DEV_SIGNER` (default
//! `.credentials-dev-signer.json`). Rows go in `CREDENTIALS_DATABASE_URL`
//! (default a SQLite file beside the process). Those files hold raw key
//! material and are not a production KMS. The process exits if
//! `CREDENTIALS_ENV=production`.
//!
//! Workspace creation on this listener is unauthenticated so a local process
//! can bootstrap. Do not expose the port beyond loopback.

use std::net::SocketAddr;
use std::sync::Arc;

use credentials_crypto::{DevFileRootKeys, DevPolicy};
use credentials_gateway::{serve, Clock, DevSigner, Gateway, SqlStore, UnconfiguredUpstream};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let policy = DevPolicy::from_env();
    if !policy.allow_dev {
        eprintln!(
            "CREDENTIALS_ENV=production, but this build only includes the dev root-key provider"
        );
        std::process::exit(1);
    }

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
    let store = match SqlStore::connect(&database_url).await {
        Ok(store) => {
            tracing::info!(engine = store.engine_name(), "durable store ready");
            Arc::new(store)
        }
        Err(err) => {
            eprintln!("store: {err}");
            std::process::exit(1);
        }
    };
    let gateway = match Gateway::with_signer(
        store,
        kms,
        Arc::new(UnconfiguredUpstream),
        Arc::new(Clock),
        signer,
    ) {
        Ok(gateway) => Arc::new(gateway),
        Err(err) => {
            eprintln!("gateway: {err}");
            std::process::exit(1);
        }
    };

    let addr: SocketAddr = std::env::var("CREDENTIALS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("CREDENTIALS_LISTEN is not a socket address");
            std::process::exit(1);
        });

    let poller = Arc::clone(&gateway);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(err) = poller.poll_shreds().await {
                tracing::error!(error = %err, "shred poller failed");
            }
        }
    });

    if let Err(err) = serve(gateway, addr).await {
        eprintln!("server: {err}");
        std::process::exit(1);
    }
}

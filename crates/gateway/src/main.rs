//! Dev gateway process.
//!
//! Binds to `127.0.0.1:8080` unless `CREDENTIALS_LISTEN` is set. Root keys go
//! in `CREDENTIALS_DEV_KEYS` (default `.credentials-dev-keys.json`). That file
//! holds raw keys and is not a production KMS. The process exits if
//! `CREDENTIALS_ENV=production`.
//!
//! Workspace creation on this listener is unauthenticated so a local process
//! can bootstrap. Do not expose the port beyond loopback.

use std::net::SocketAddr;
use std::sync::Arc;

use credentials_crypto::{DevFileRootKeys, DevPolicy};
use credentials_gateway::{serve, Clock, Gateway, MemoryStore, UnconfiguredUpstream};

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
    let gateway = match Gateway::new(
        Arc::new(MemoryStore::new()),
        kms,
        Arc::new(UnconfiguredUpstream),
        Arc::new(Clock),
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

    if let Err(err) = serve(gateway, addr).await {
        eprintln!("server: {err}");
        std::process::exit(1);
    }
}

//! A sealed secret survives a process restart, on SQLite and on Postgres.

use std::sync::Arc;

use credentials_crypto::{DevFileRootKeys, DevPolicy};
use credentials_gateway::{
    generate_dpop, verify_chain, Clock, Delivery, DeliveryPolicy, DevSigner, Gateway,
    InjectRequest, Now, SqlStore,
};
use uuid::Uuid;

fn policy() -> DeliveryPolicy {
    DeliveryPolicy {
        header_name: Some("Authorization".into()),
        header_format: Some("Bearer {value}".into()),
        env_name: None,
        hosts: vec!["api.openai.com".into()],
        allow_proxy: true,
        allow_header: false,
        allow_env: false,
    }
}

struct Paths {
    dir: std::path::PathBuf,
}

impl Drop for Paths {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn round_trip(database_url: &str, dir: &std::path::Path) {
    let keys = dir.join("keys.json");
    let signer_path = dir.join("signer.json");
    let plaintext = b"sk-restart-value";
    let kms = Arc::new(DevFileRootKeys::open(&keys, DevPolicy { allow_dev: true }).unwrap());
    let signer = DevSigner::load_or_create(&signer_path, DevPolicy { allow_dev: true }).unwrap();
    let upstream = Arc::new(credentials_gateway::RecordingUpstream::new());
    let clock = Arc::new(Clock);
    let store = Arc::new(SqlStore::connect(database_url).await.unwrap());
    let gateway =
        Gateway::with_signer(store, kms.clone(), upstream.clone(), clock.clone(), signer).unwrap();
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            plaintext,
            policy(),
        )
        .await
        .unwrap();
    let dpop = generate_dpop().unwrap();
    let agent = gateway
        .create_agent(&created.credential, "runner")
        .await
        .unwrap();
    let session = gateway
        .create_session(
            &created.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(300),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    drop(gateway);

    let signer = DevSigner::load_or_create(&signer_path, DevPolicy { allow_dev: true }).unwrap();
    let store = Arc::new(SqlStore::connect(database_url).await.unwrap());
    let gateway =
        Gateway::with_signer(store, kms, upstream.clone(), clock.clone(), signer).unwrap();
    let htu = "https://credentials.local/v1/inject";
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        clock.unix_secs(),
        "proof-restart",
    );
    let response = gateway
        .inject(InjectRequest {
            token: session.token,
            dpop: proof,
            secret: "prod/openai/api_key".into(),
            delivery: Delivery::Proxy,
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat/completions".into(),
            body: Vec::new(),
            htm: "POST".into(),
            htu: htu.into(),
            local_channel: false,
        })
        .await
        .unwrap();
    assert_eq!(response.upstream_status, 200);
    assert_eq!(
        upstream.last_value().as_deref(),
        Some("Bearer sk-restart-value")
    );
    let log = gateway.audit_log(&created.credential, None).await.unwrap();
    assert!(verify_chain(&log));
    assert!(log.iter().any(|event| event.event_type == "secret.write"));
    assert!(log
        .iter()
        .any(|event| event.event_type == "secret.access.delivered"));
}

#[tokio::test]
async fn sqlite_restart_keeps_the_secret_and_omits_plaintext() {
    let dir = std::env::temp_dir().join(format!("credentials-sql-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let _guard = Paths { dir: dir.clone() };
    let db = dir.join("cred.sqlite");
    let url = format!("sqlite://{}", db.display());
    round_trip(&url, &dir).await;
    let bytes = std::fs::read(&db).unwrap();
    assert!(!bytes
        .windows(b"sk-restart-value".len())
        .any(|window| window == b"sk-restart-value"));
    assert!(DevSigner::load_or_create(
        dir.join("signer.json").as_path(),
        DevPolicy { allow_dev: false }
    )
    .is_err());
}

#[tokio::test]
async fn postgres_restart_keeps_the_secret() {
    let Some(admin) = std::env::var("CREDENTIALS_TEST_POSTGRES").ok() else {
        return;
    };
    let name = format!("cred_{}", Uuid::now_v7().simple());
    let admin_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin_pool)
        .await
        .unwrap();
    let mut url = url::Url::parse(&admin).unwrap();
    url.set_path(&name);
    let dir = std::env::temp_dir().join(format!("credentials-pg-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let _guard = Paths { dir: dir.clone() };
    round_trip(url.as_str(), &dir).await;
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&admin_pool)
        .await
        .unwrap();
}

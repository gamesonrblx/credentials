//! Token revocation and DPoP replay stay in the database.

use std::sync::Arc;

use credentials_crypto::{DevPolicy, MemoryRootKeys};
use credentials_gateway::{
    generate_dpop, Delivery, DeliveryPolicy, Gateway, InjectRequest, ManualClock, MemoryStore, Now,
    RecordingUpstream, SqlStore, Store,
};

fn inject_request(token: &str, proof: &str) -> InjectRequest {
    InjectRequest {
        token: token.into(),
        dpop: proof.into(),
        secret: "prod/openai/api_key".into(),
        delivery: Delivery::Proxy,
        method: "POST".into(),
        url: "https://api.openai.com/v1/chat/completions".into(),
        body: Vec::new(),
        htm: "POST".into(),
        htu: "https://credentials.local/v1/inject".into(),
        local_channel: false,
        content_type: None,
    }
}

#[tokio::test]
async fn revoked_jti_blocks_inject_after_restart() {
    let dir = std::env::temp_dir().join(format!("credentials-jti-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}/dev.sqlite", dir.display());
    let store = Arc::new(SqlStore::connect(&url).await.unwrap());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = make_gateway(store.clone(), clock.clone());
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            b"sk-jti",
            DeliveryPolicy {
                header_name: Some("Authorization".into()),
                header_format: Some("Bearer {value}".into()),
                env_name: None,
                hosts: vec!["api.openai.com".into()],
                allow_proxy: true,
                allow_header: false,
                allow_env: false,
            },
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
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    gateway
        .revoke_session(&created.credential, session.session_id)
        .await
        .unwrap();
    drop(gateway);
    let store = Arc::new(SqlStore::connect(&url).await.unwrap());
    let gateway = make_gateway(store, clock.clone());
    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "after-restart",
    );
    let err = gateway
        .inject(inject_request(&session.token, &proof))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unauthenticated");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn dpop_replay_is_durable() {
    let store = Arc::new(MemoryStore::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = make_gateway(store.clone(), clock.clone());
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            b"sk-replay",
            DeliveryPolicy {
                header_name: Some("Authorization".into()),
                header_format: Some("Bearer {value}".into()),
                env_name: None,
                hosts: vec!["api.openai.com".into()],
                allow_proxy: true,
                allow_header: false,
                allow_env: false,
            },
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
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "replay-jti",
    );
    gateway
        .inject(inject_request(&session.token, &proof))
        .await
        .unwrap();
    let again = gateway
        .inject(inject_request(&session.token, &proof))
        .await
        .unwrap_err();
    assert_eq!(again.code(), "unauthenticated");
    let _ = store;
}

fn make_gateway(store: Arc<dyn Store>, clock: Arc<ManualClock>) -> Gateway {
    Gateway::new(
        store,
        Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
        Arc::new(RecordingUpstream::new()),
        clock,
    )
    .unwrap()
}

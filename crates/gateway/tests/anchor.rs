//! Checkpoints are signed and a lagged anchor stops decrypt.

use std::sync::Arc;

use credentials_crypto::{CountingProvider, DevPolicy, MemoryRootKeys};
use credentials_gateway::{
    checkpoint_message, generate_dpop, AuditAnchor, Delivery, DeliveryPolicy, DevFileAnchor,
    DevSigner, Gateway, InjectRequest, ManualClock, MemoryAnchor, MemoryStore, Now,
    RecordingUpstream,
};

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

fn inject(token: &str, proof: &str) -> InjectRequest {
    InjectRequest {
        token: token.to_owned(),
        dpop: proof.to_owned(),
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
async fn dev_anchor_checkpoint_verifies_and_production_is_refused() {
    let dir = std::env::temp_dir().join(format!("credentials-anchor-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer_path = dir.join("signer.json");
    let anchor_path = dir.join("anchor.log");
    assert!(DevFileAnchor::open(&anchor_path, DevPolicy { allow_dev: false }).is_err());
    let signer = DevSigner::load_or_create(&signer_path, DevPolicy { allow_dev: true }).unwrap();
    let anchor =
        Arc::new(DevFileAnchor::open(&anchor_path, DevPolicy { allow_dev: true }).unwrap());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = Gateway::with_anchor(
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
        Arc::new(RecordingUpstream::new()),
        clock.clone(),
        signer,
        anchor.clone(),
    )
    .unwrap();
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            b"anchor-value",
            policy(),
        )
        .await
        .unwrap();
    assert_eq!(gateway.publish_checkpoints().await.unwrap(), 0);
    clock.set(clock.unix_secs() + 61);
    assert_eq!(gateway.publish_checkpoints().await.unwrap(), 1);
    let tip = anchor.latest(created.id).await.unwrap().unwrap();
    let reloaded = DevSigner::load_or_create(&signer_path, DevPolicy { allow_dev: true }).unwrap();
    let message = checkpoint_message(created.id, tip.seq, &tip.tip_hash);
    assert!(reloaded.verify_message(&message, &tip.signature));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn lagged_anchor_stops_decrypt() {
    let store = Arc::new(MemoryStore::new());
    let kms = Arc::new(CountingProvider::new(
        MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap(),
    ));
    let anchor = Arc::new(MemoryAnchor::new());
    anchor.set_fail(true);
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let upstream = Arc::new(RecordingUpstream::new());
    let gateway = Gateway::with_anchor(
        store,
        kms.clone(),
        upstream.clone(),
        clock.clone(),
        DevSigner::generate("dev-1").unwrap(),
        anchor,
    )
    .unwrap();
    gateway.set_anchor_max_lag(30);
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            b"lag-value",
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
    clock.set(clock.unix_secs() + 61);
    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "proof-lag-1",
    );
    gateway
        .inject(inject(&session.token, &proof))
        .await
        .unwrap();
    let decrypts = kms.decrypts();
    clock.set(clock.unix_secs() + 31);
    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "proof-lag-2",
    );
    let err = gateway
        .inject(inject(&session.token, &proof))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "audit_anchor_unavailable");
    assert_eq!(kms.decrypts(), decrypts);
    assert!(upstream.last_value().is_some());
}

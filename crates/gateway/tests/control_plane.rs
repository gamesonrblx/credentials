//! Production control plane: no dev unwrap path.

use std::sync::Arc;

use credentials_crypto::{generate_hybrid_keypair, seal_e2e, DevPolicy, VersionIds};
use credentials_gateway::{
    generate_dpop, Clock, Delivery, DeliveryPolicy, DevFileAnchor, DevSigner, E2eSubmission,
    FileAnchor, Gateway, InjectRequest, MemoryAnchor, MemoryStore, Now, RecordingUpstream,
};

#[tokio::test]
async fn production_releases_e2e_and_refuses_to_seal_plaintext() {
    let policy = DevPolicy { allow_dev: false };
    let dir = std::env::temp_dir().join(format!("credentials-prod-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(DevSigner::load_or_create(&dir.join("dev-signer.json"), policy).is_err());
    assert!(DevFileAnchor::open(dir.join("dev-anchor.log"), policy).is_err());
    let signer = DevSigner::load_production(&dir.join("signing.json"), policy).unwrap();
    let anchor = FileAnchor::open(dir.join("anchor.log")).unwrap();
    let gateway = Gateway::control_plane(
        Arc::new(MemoryStore::new()),
        Arc::new(RecordingUpstream::new()),
        Arc::new(Clock),
        signer,
        Arc::new(anchor),
        policy,
    )
    .unwrap();
    assert!(Gateway::control_plane(
        Arc::new(MemoryStore::new()),
        Arc::new(RecordingUpstream::new()),
        Arc::new(Clock),
        DevSigner::generate("sign-1").unwrap(),
        Arc::new(MemoryAnchor::new()),
        DevPolicy { allow_dev: true },
    )
    .is_err());

    let created = gateway.create_workspace().await.unwrap();
    let err = gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            b"sk-plaintext",
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
        .await;
    assert!(err.is_err());

    let pair = generate_hybrid_keypair().unwrap();
    let key_id = gateway
        .register_workspace_key(&created.credential, &pair.encapsulation_key)
        .await
        .unwrap();
    let ids = VersionIds {
        workspace_id: created.id,
        secret_id: uuid::Uuid::now_v7(),
        version_id: uuid::Uuid::now_v7(),
    };
    let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, b"sk-prod", 1024).unwrap();
    gateway
        .store_e2e_secret(
            &created.credential,
            "prod/openai/api_key",
            DeliveryPolicy {
                header_name: Some("Authorization".into()),
                header_format: Some("Bearer {value}".into()),
                env_name: None,
                hosts: vec!["api.openai.com".into()],
                allow_proxy: true,
                allow_header: false,
                allow_env: false,
            },
            E2eSubmission {
                secret_id: ids.secret_id,
                version_id: ids.version_id,
                workspace_key_id: key_id,
                payload_nonce: sealed.payload_nonce,
                payload_ciphertext: sealed.payload_ciphertext,
                dek_wrap_nonce: sealed.dek_wrap_nonce,
                dek_wrapped: sealed.dek_wrapped,
                encapsulation: sealed.encapsulation,
                plaintext_len: sealed.plaintext_len,
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
        Clock.unix_secs(),
        "prod-e2e",
    );
    let released = gateway
        .inject(InjectRequest {
            token: session.token,
            dpop: proof,
            secret: "prod/openai/api_key".into(),
            delivery: Delivery::Proxy,
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat/completions".into(),
            body: Vec::new(),
            htm: "POST".into(),
            htu: "https://credentials.local/v1/inject".into(),
            local_channel: false,
        })
        .await
        .unwrap();
    assert!(!released
        .body
        .windows(b"sk-prod".len())
        .any(|w| w == b"sk-prod"));
    let _ = std::fs::remove_dir_all(&dir);
}

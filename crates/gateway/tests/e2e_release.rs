//! The control plane stores and releases end-to-end ciphertext. It does not open it.

use std::sync::Arc;

use credentials_crypto::{
    generate_hybrid_keypair, open_e2e, seal_e2e, seal_to_device, CountingProvider, DevPolicy,
    E2eSealed, MemoryRootKeys, VersionIds,
};
use credentials_gateway::{
    generate_dpop, Clock, Delivery, DeliveryPolicy, E2eSubmission, Gateway, InjectRequest,
    ManualClock, MemoryStore, Now, RecipientRow, RecordingUpstream, SqlStore,
};

fn submission(sealed: &E2eSealed, ids: VersionIds) -> E2eSubmission {
    E2eSubmission {
        secret_id: ids.secret_id,
        version_id: ids.version_id,
        workspace_key_id: sealed.workspace_key_id,
        payload_nonce: sealed.payload_nonce,
        payload_ciphertext: sealed.payload_ciphertext.clone(),
        dek_wrap_nonce: sealed.dek_wrap_nonce,
        dek_wrapped: sealed.dek_wrapped.clone(),
        encapsulation: sealed.encapsulation.clone(),
        plaintext_len: sealed.plaintext_len,
    }
}

#[tokio::test]
async fn control_plane_releases_ciphertext_and_does_not_unwrap() {
    let kms = Arc::new(CountingProvider::new(
        MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap(),
    ));
    let store = Arc::new(MemoryStore::new());
    let upstream = Arc::new(RecordingUpstream::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway =
        Gateway::new(store.clone(), kms.clone(), upstream.clone(), clock.clone()).unwrap();
    let created = gateway.create_workspace().await.unwrap();
    let pair = generate_hybrid_keypair().unwrap();
    let key_id = gateway
        .register_workspace_key(&created.credential, &pair.encapsulation_key)
        .await
        .unwrap();
    let ids = VersionIds {
        workspace_id: gateway.workspace_id_for(&created.credential).await.unwrap(),
        secret_id: uuid::Uuid::now_v7(),
        version_id: uuid::Uuid::now_v7(),
    };
    let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, b"sk-e2e-canary", 1024).unwrap();
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
            submission(&sealed, ids),
        )
        .await
        .unwrap();
    let device = generate_hybrid_keypair().unwrap();
    let wrapped = seal_to_device(
        &device.encapsulation_key,
        ids.workspace_id,
        pair.decapsulation_key(),
    )
    .unwrap();
    gateway
        .add_recipient(
            &created.credential,
            RecipientRow {
                id: uuid::Uuid::now_v7(),
                workspace_id: ids.workspace_id,
                kind: "device".into(),
                encapsulation_key: Some(device.encapsulation_key.clone()),
                encapsulation: Some(wrapped.encapsulation),
                prf_salt: None,
                kdf_params: None,
                wrap_nonce: wrapped.nonce.to_vec(),
                wrapped_key: wrapped.ciphertext,
                revoked_at: None,
            },
        )
        .await
        .unwrap();
    let rejected = gateway
        .add_recipient(
            &created.credential,
            RecipientRow {
                id: uuid::Uuid::now_v7(),
                workspace_id: ids.workspace_id,
                kind: "operator".into(),
                encapsulation_key: None,
                encapsulation: None,
                prf_salt: None,
                kdf_params: None,
                wrap_nonce: vec![0; 12],
                wrapped_key: vec![1],
                revoked_at: None,
            },
        )
        .await;
    assert!(rejected.is_err());

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
        "e2e-release",
    );
    let released = gateway
        .inject(InjectRequest {
            token: session.token.clone(),
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
    assert_eq!(kms.decrypts(), 0);
    assert!(upstream.last_value().is_none());
    assert!(!released
        .body
        .windows(b"sk-e2e-canary".len())
        .any(|w| w == b"sk-e2e-canary"));
    let grant: serde_json::Value = serde_json::from_slice(&released.body).unwrap();
    assert_eq!(grant["wrap_mode"], "e2e");
    let opened = open_e2e(pair.decapsulation_key(), &sealed, ids).unwrap();
    assert_eq!(opened.as_slice(), b"sk-e2e-canary");

    gateway
        .revoke_session(&created.credential, session.session_id)
        .await
        .unwrap();
    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "e2e-revoked",
    );
    let denied = gateway
        .inject(InjectRequest {
            token: session.token.clone(),
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
        .await;
    assert!(denied.is_err());

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
    store.set_fail_appends(true);
    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "e2e-audit-fail",
    );
    let blocked = gateway
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
        .await;
    assert!(blocked.is_err());
    assert_eq!(kms.decrypts(), 0);
    let _ = Clock;
}

#[tokio::test]
async fn sqlite_keeps_an_e2e_row_the_gateway_cannot_open() {
    let dir = std::env::temp_dir().join(format!("credentials-e2e-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(
        SqlStore::connect(&format!("sqlite://{}/dev.sqlite", dir.display()))
            .await
            .unwrap(),
    );
    let gateway = Gateway::new(
        store,
        Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
        Arc::new(RecordingUpstream::new()),
        Arc::new(Clock),
    )
    .unwrap();
    let created = gateway.create_workspace().await.unwrap();
    let pair = generate_hybrid_keypair().unwrap();
    let key_id = gateway
        .register_workspace_key(&created.credential, &pair.encapsulation_key)
        .await
        .unwrap();
    let ids = VersionIds {
        workspace_id: gateway.workspace_id_for(&created.credential).await.unwrap(),
        secret_id: uuid::Uuid::now_v7(),
        version_id: uuid::Uuid::now_v7(),
    };
    let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, b"sk-sqlite", 1024).unwrap();
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
            submission(&sealed, ids),
        )
        .await
        .unwrap();
    let file = std::fs::read(dir.join("dev.sqlite")).unwrap();
    assert!(!file.windows(b"sk-sqlite".len()).any(|w| w == b"sk-sqlite"));
    let _ = std::fs::remove_dir_all(&dir);
}

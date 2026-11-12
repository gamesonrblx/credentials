use std::sync::Arc;

use base64::Engine;

use credentials_client::{CredentialsClient, DpopKey};
use credentials_crypto::{DevPolicy, MemoryRootKeys};
use credentials_gateway::{spawn_ephemeral, Clock, Gateway, MemoryStore, RecordingUpstream};

#[tokio::test]
async fn http_inject_round_trip() {
    let gateway = Arc::new(
        Gateway::new(
            Arc::new(MemoryStore::new()),
            Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
            Arc::new(RecordingUpstream::new()),
            Arc::new(Clock),
        )
        .unwrap(),
    );
    let addr = spawn_ephemeral(gateway).await.unwrap();

    let base = format!("http://{addr}");
    let htu = format!("{base}/v1/inject");
    let client = CredentialsClient::new(&base);
    let workspace = client.create_workspace().await.unwrap();
    let client = client.with_credential(&workspace.credential);
    client
        .create_secret("prod/openai/api_key", b"sk-http", &["api.openai.com"])
        .await
        .unwrap();
    let second = client
        .create_version("prod/openai/api_key", b"sk-http-v2")
        .await
        .unwrap();
    assert_eq!(second.version, 2);
    let sessions = client.list_sessions().await.unwrap();
    let _ = sessions;
    let audit = client.audit(None).await.unwrap();
    assert!(audit
        .events
        .iter()
        .any(|event| event.event_type == "secret.write"));
    let agent = client.create_agent("http-runner").await.unwrap();
    let dpop = DpopKey::generate();
    let session = client
        .create_session(
            agent.id,
            &["secret:inject:prod/openai/api_key"],
            dpop.public_b64(),
        )
        .await
        .unwrap();
    let proof = dpop.proof("POST", &htu, &session.token);
    let injected = client
        .inject(
            &session.token,
            &proof,
            "prod/openai/api_key",
            "https://api.openai.com/v1/chat/completions",
            Some("application/json"),
        )
        .await
        .unwrap();
    assert_eq!(injected.upstream_status, 200);
    assert_eq!(
        injected.body,
        base64::engine::general_purpose::STANDARD.encode(b"upstream-ok")
    );
}

#[tokio::test]
async fn http_e2e_key_and_ciphertext_upload() {
    use credentials_client::{DeliveryPolicy, E2eSecretUpload};
    use credentials_crypto::{generate_hybrid_keypair, seal_e2e, VersionIds};

    let gateway = Arc::new(
        Gateway::new(
            Arc::new(MemoryStore::new()),
            Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
            Arc::new(RecordingUpstream::new()),
            Arc::new(Clock),
        )
        .unwrap(),
    );
    let addr = spawn_ephemeral(gateway).await.unwrap();
    let client = CredentialsClient::new(format!("http://{addr}"));
    let workspace = client.create_workspace().await.unwrap();
    let client = client.with_credential(&workspace.credential);

    let pair = generate_hybrid_keypair().unwrap();
    let registered = client
        .register_workspace_key(&pair.encapsulation_key)
        .await
        .unwrap();
    let fetched = client.workspace_key().await.unwrap();
    assert_eq!(fetched.id, registered.id);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&fetched.encapsulation_key)
            .unwrap(),
        pair.encapsulation_key
    );

    let ids = VersionIds {
        workspace_id: workspace.id,
        secret_id: uuid::Uuid::now_v7(),
        version_id: uuid::Uuid::now_v7(),
    };
    let sealed = seal_e2e(
        &pair.encapsulation_key,
        registered.id,
        ids,
        b"sk-e2e-http",
        1024,
    )
    .unwrap();
    let policy = DeliveryPolicy {
        header_name: Some("Authorization".into()),
        header_format: Some("Bearer {value}".into()),
        hosts: vec!["api.openai.com".into()],
        allow_proxy: true,
        ..DeliveryPolicy::default()
    };
    let created = client
        .store_e2e_secret(&E2eSecretUpload {
            name: "prod/openai/api_key",
            secret_id: ids.secret_id,
            version_id: ids.version_id,
            workspace_key_id: registered.id,
            payload_nonce: sealed.payload_nonce,
            payload_ciphertext: &sealed.payload_ciphertext,
            dek_wrap_nonce: sealed.dek_wrap_nonce,
            dek_wrapped: &sealed.dek_wrapped,
            encapsulation: &sealed.encapsulation,
            plaintext_len: sealed.plaintext_len,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(created.secret_id, ids.secret_id);
    assert_eq!(created.version_id, ids.version_id);
}

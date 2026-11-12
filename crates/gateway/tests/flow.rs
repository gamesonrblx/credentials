//! End-to-end checks against the in-memory store and dev KMS.

use std::sync::Arc;

use credentials_crypto::{CountingProvider, DevPolicy, MemoryRootKeys};
use credentials_gateway::{
    generate_dpop, verify_chain, Delivery, DeliveryPolicy, Gateway, InjectRequest, ManualClock,
    MemoryStore, Now, RecordingUpstream, Store,
};

struct Env {
    gateway: Gateway,
    store: Arc<MemoryStore>,
    kms: Arc<CountingProvider<MemoryRootKeys>>,
    upstream: Arc<RecordingUpstream>,
    clock: Arc<ManualClock>,
    credential: String,
    workspace: uuid::Uuid,
}

async fn setup() -> Env {
    let store = Arc::new(MemoryStore::new());
    let kms = Arc::new(CountingProvider::new(
        MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap(),
    ));
    let upstream = Arc::new(RecordingUpstream::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway =
        Gateway::new(store.clone(), kms.clone(), upstream.clone(), clock.clone()).unwrap();
    let created = gateway.create_workspace().await.unwrap();
    Env {
        gateway,
        store,
        kms,
        upstream,
        clock,
        credential: created.credential,
        workspace: created.id,
    }
}

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

fn request(token: &str, proof: &str, htu: &str) -> InjectRequest {
    InjectRequest {
        token: token.to_owned(),
        dpop: proof.to_owned(),
        secret: "prod/openai/api_key".into(),
        delivery: Delivery::Proxy,
        method: "POST".into(),
        url: "https://api.openai.com/v1/chat/completions".into(),
        body: Vec::new(),
        htm: "POST".into(),
        htu: htu.into(),
        local_channel: false,
        content_type: None,
    }
}

#[tokio::test]
async fn proxy_inject_happy_path_writes_the_audit_chain() {
    let env = setup().await;
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .await
        .unwrap();
    let dpop = generate_dpop().unwrap();
    let agent = env
        .gateway
        .create_agent(&env.credential, "runner")
        .await
        .unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/*".into()],
            Some(300),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    let htu = "https://credentials.local/v1/inject";
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        env.clock.unix_secs(),
        "proof-1",
    );
    let before = env.kms.decrypts();
    let response = env
        .gateway
        .inject(request_with_body(&session.token, &proof, htu))
        .await
        .unwrap();
    assert_eq!(response.body, b"upstream-ok");
    assert_eq!(
        env.upstream.last_value().as_deref(),
        Some("Bearer sk-test-value")
    );
    // The KEK unwrapped while storing the secret may still be in the 60s cache.
    assert!(env.kms.decrypts() >= before);
    assert!(before >= 1);
    let log = env
        .gateway
        .audit_log(&env.credential, Some(agent))
        .await
        .unwrap();
    assert!(log
        .iter()
        .any(|event| event.event_type == "secret.access.delivered"));
    let full = env.gateway.audit_log(&env.credential, None).await.unwrap();
    assert!(verify_chain(&full));
}

#[tokio::test]
async fn a_new_version_does_not_replace_the_previous_ciphertext() {
    let env = setup().await;
    let first = env
        .gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"version-one",
            policy(),
        )
        .await
        .unwrap();
    let second = env
        .gateway
        .create_version(&env.credential, "prod/openai/api_key", b"version-two")
        .await
        .unwrap();
    assert_eq!(second.secret_id, first.secret_id);
    assert_eq!(second.version, 2);
    let latest = Store::latest_version(env.store.as_ref(), first.secret_id)
        .await
        .unwrap();
    let rows = Store::versions_for_kek(env.store.as_ref(), latest.kek_id)
        .await
        .unwrap();
    let mut ours: Vec<_> = rows
        .into_iter()
        .filter(|row| row.secret_id == first.secret_id)
        .collect();
    ours.sort_by_key(|row| row.version);
    assert_eq!(ours.len(), 2);
    assert_ne!(
        ours[0].sealed.payload_ciphertext,
        ours[1].sealed.payload_ciphertext
    );
    let dpop = generate_dpop().unwrap();
    let agent = env
        .gateway
        .create_agent(&env.credential, "runner")
        .await
        .unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    let htu = "https://credentials.local/v1/inject";
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        env.clock.unix_secs(),
        "proof-v2",
    );
    let response = env
        .gateway
        .inject(request(&session.token, &proof, htu))
        .await
        .unwrap();
    assert_eq!(response.body, b"upstream-ok");
    assert_eq!(
        env.upstream.last_value().as_deref(),
        Some("Bearer version-two")
    );
}

#[tokio::test]
async fn a_disabled_secret_does_not_unwrap() {
    let env = setup().await;
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .await
        .unwrap();
    env.gateway
        .disable_secret(&env.credential, "prod/openai/api_key")
        .await
        .unwrap();
    let decrypts = env.kms.decrypts();
    let dpop = generate_dpop().unwrap();
    let agent = env
        .gateway
        .create_agent(&env.credential, "runner")
        .await
        .unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    let listed = env.gateway.list_sessions(&env.credential).await.unwrap();
    assert_eq!(listed.len(), 1);
    let htu = "https://credentials.local/v1/inject";
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        env.clock.unix_secs(),
        "proof-off",
    );
    let err = env
        .gateway
        .inject(request(&session.token, &proof, htu))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "forbidden");
    assert_eq!(env.kms.decrypts(), decrypts);
}

#[tokio::test]
async fn revoked_and_expired_tokens_do_not_unwrap() {
    let env = setup().await;
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .await
        .unwrap();
    let decrypts_after_write = env.kms.decrypts();

    let dpop = generate_dpop().unwrap();
    let agent = env
        .gateway
        .create_agent(&env.credential, "runner")
        .await
        .unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    env.gateway
        .revoke_session(&env.credential, session.session_id)
        .await
        .unwrap();
    let htu = "https://credentials.local/v1/inject";
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        env.clock.unix_secs(),
        "proof-revoked",
    );
    let err = env
        .gateway
        .inject(request(&session.token, &proof, htu))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unauthenticated");
    assert_eq!(env.kms.decrypts(), decrypts_after_write);

    let dpop = generate_dpop().unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    env.clock.set(env.clock.unix_secs() + 10_000);
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        env.clock.unix_secs(),
        "proof-expired",
    );
    let err = env
        .gateway
        .inject(request(&session.token, &proof, htu))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unauthenticated");
    assert_eq!(env.kms.decrypts(), decrypts_after_write);
}

#[tokio::test]
async fn audit_failure_does_not_decrypt() {
    let env = setup().await;
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .await
        .unwrap();
    let decrypts_after_write = env.kms.decrypts();
    let dpop = generate_dpop().unwrap();
    let agent = env
        .gateway
        .create_agent(&env.credential, "runner")
        .await
        .unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    env.store.set_fail_appends(true);
    let htu = "https://credentials.local/v1/inject";
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        env.clock.unix_secs(),
        "proof-audit",
    );
    let err = env
        .gateway
        .inject(request(&session.token, &proof, htu))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "audit_failed");
    assert_eq!(env.kms.decrypts(), decrypts_after_write);
    assert!(env.upstream.last_value().is_none());
}

#[tokio::test]
async fn rotation_and_deletion() {
    let env = setup().await;
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .await
        .unwrap();
    assert_eq!(env.gateway.rotate_kek(&env.credential).await.unwrap(), 2);
    assert_eq!(
        env.gateway
            .rewrap_outstanding(&env.credential)
            .await
            .unwrap(),
        0
    );
    assert_eq!(env.gateway.rotate_kek(&env.credential).await.unwrap(), 3);
    assert_eq!(
        env.gateway
            .rewrap_outstanding(&env.credential)
            .await
            .unwrap(),
        0
    );

    let dpop = generate_dpop().unwrap();
    let agent = env
        .gateway
        .create_agent(&env.credential, "runner")
        .await
        .unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap();
    let decrypts = env.kms.decrypts();
    env.gateway
        .delete_workspace(&env.credential, env.workspace)
        .await
        .unwrap();
    let htu = "https://credentials.local/v1/inject";
    let proof = dpop.proof(
        "POST",
        htu,
        &session.token,
        env.clock.unix_secs(),
        "proof-delete",
    );
    let err = env
        .gateway
        .inject(request(&session.token, &proof, htu))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "workspace_deleting");
    assert_eq!(env.kms.decrypts(), decrypts);
}

#[tokio::test]
async fn cancel_restores_a_workspace_and_shred_is_terminal() {
    let env = setup().await;
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"before-delete",
            policy(),
        )
        .await
        .unwrap();
    env.gateway
        .delete_workspace(&env.credential, env.workspace)
        .await
        .unwrap();
    assert_eq!(env.gateway.poll_shreds().await.unwrap(), 0);
    env.gateway
        .cancel_deletion(&env.credential, env.workspace)
        .await
        .unwrap();
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"after-cancel",
            policy(),
        )
        .await
        .unwrap();
    env.gateway
        .delete_workspace(&env.credential, env.workspace)
        .await
        .unwrap();
    let decrypts = env.kms.decrypts();
    env.clock.set(env.clock.unix_secs() + 8 * 24 * 3600);
    assert_eq!(env.gateway.poll_shreds().await.unwrap(), 1);
    let err = env
        .gateway
        .cancel_deletion(&env.credential, env.workspace)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unauthenticated");
    assert_eq!(env.kms.decrypts(), decrypts);
    let events = Store::audit_for_workspace(env.store.as_ref(), env.workspace)
        .await
        .unwrap();
    assert!(verify_chain(&events));
    assert!(events
        .iter()
        .any(|event| event.event_type == "tenant.delete.cancelled"));
    assert!(events
        .iter()
        .any(|event| event.event_type == "tenant.shredded"));
}

fn request_with_body(token: &str, proof: &str, htu: &str) -> InjectRequest {
    let mut request = request(token, proof, htu);
    request.body = b"{}".to_vec();
    request
}

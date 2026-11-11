//! End-to-end checks against the in-memory store and dev KMS.

use std::sync::Arc;

use credentials_crypto::{CountingProvider, DevPolicy, MemoryRootKeys};
use credentials_gateway::{
    generate_dpop, verify_chain, Delivery, DeliveryPolicy, Gateway, InjectRequest, ManualClock,
    MemoryStore, Now, RecordingUpstream,
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

fn setup() -> Env {
    let store = Arc::new(MemoryStore::new());
    let kms = Arc::new(CountingProvider::new(
        MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap(),
    ));
    let upstream = Arc::new(RecordingUpstream::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway =
        Gateway::new(store.clone(), kms.clone(), upstream.clone(), clock.clone()).unwrap();
    let created = gateway.create_workspace().unwrap();
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
    }
}

#[tokio::test]
async fn proxy_inject_happy_path_writes_the_audit_chain() {
    let env = setup();
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .unwrap();
    let dpop = generate_dpop().unwrap();
    let agent = env.gateway.create_agent(&env.credential, "runner").unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/*".into()],
            Some(300),
            dpop.public_b64(),
        )
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
    let log = env.gateway.audit_log(&env.credential, Some(agent)).unwrap();
    assert!(log
        .iter()
        .any(|event| event.event_type == "secret.access.delivered"));
    let full = env.gateway.audit_log(&env.credential, None).unwrap();
    assert!(verify_chain(&full));
}

#[tokio::test]
async fn revoked_and_expired_tokens_do_not_unwrap() {
    let env = setup();
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .unwrap();
    let decrypts_after_write = env.kms.decrypts();

    let dpop = generate_dpop().unwrap();
    let agent = env.gateway.create_agent(&env.credential, "runner").unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .unwrap();
    env.gateway
        .revoke_session(&env.credential, session.session_id)
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
    let env = setup();
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .unwrap();
    let decrypts_after_write = env.kms.decrypts();
    let dpop = generate_dpop().unwrap();
    let agent = env.gateway.create_agent(&env.credential, "runner").unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
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
    let env = setup();
    env.gateway
        .create_secret(
            &env.credential,
            "prod/openai/api_key",
            b"sk-test-value",
            policy(),
        )
        .unwrap();
    assert_eq!(env.gateway.rotate_kek(&env.credential).unwrap(), 2);
    assert_eq!(env.gateway.rotate_kek(&env.credential).unwrap(), 3);

    let dpop = generate_dpop().unwrap();
    let agent = env.gateway.create_agent(&env.credential, "runner").unwrap();
    let session = env
        .gateway
        .create_session(
            &env.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .unwrap();
    let decrypts = env.kms.decrypts();
    env.gateway
        .delete_workspace(&env.credential, env.workspace)
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

fn request_with_body(token: &str, proof: &str, htu: &str) -> InjectRequest {
    let mut request = request(token, proof, htu);
    request.body = b"{}".to_vec();
    request
}

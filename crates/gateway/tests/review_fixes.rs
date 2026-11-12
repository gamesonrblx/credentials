//! Deletion without a root key, inject denials, reflection, audit paging,
//! the anchor read-back, credential rotation, and the public DPoP origin.

use std::sync::Arc;

use credentials_crypto::{
    generate_hybrid_keypair, seal_e2e, DevPolicy, MemoryRootKeys, VersionIds,
};
use credentials_gateway::{
    checkpoint_message, generate_dpop, ApiError, AuditAnchor, AuditRecord, Delivery,
    DeliveryPolicy, DevSigner, E2eSubmission, Gateway, Inbound, InjectRequest, ManualClock,
    MemoryAnchor, MemoryStore, Now, Outbound, RecordingUpstream, SqlStore, Store, Upstream,
    DELETION_RETENTION_SECS,
};
use uuid::Uuid;

const HTU: &str = "https://credentials.local/v1/inject";
const SECRET: &str = "prod/openai/api_key";

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

fn request(token: &str, proof: &str, secret: &str, method: &str) -> InjectRequest {
    InjectRequest {
        token: token.into(),
        dpop: proof.into(),
        secret: secret.into(),
        delivery: Delivery::Proxy,
        method: method.into(),
        url: "https://api.openai.com/v1/chat/completions".into(),
        body: Vec::new(),
        htm: "POST".into(),
        htu: HTU.into(),
        local_channel: false,
        content_type: None,
    }
}

fn denied_with(events: &[AuditRecord], reason: &str) -> bool {
    let needle = format!("\"{reason}\"");
    events.iter().any(|event| {
        event.event_type == "secret.access.denied"
            && format!("{:?}", event.fields).contains(&needle)
    })
}

fn control_plane(store: Arc<dyn Store>, clock: Arc<ManualClock>) -> Gateway {
    Gateway::control_plane(
        store,
        Arc::new(RecordingUpstream::new()),
        clock,
        DevSigner::generate("sign-1").unwrap(),
        Arc::new(MemoryAnchor::new()),
        DevPolicy { allow_dev: false },
    )
    .unwrap()
}

fn dev(store: Arc<dyn Store>, upstream: Arc<dyn Upstream>, clock: Arc<ManualClock>) -> Gateway {
    Gateway::new(
        store,
        Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
        upstream,
        clock,
    )
    .unwrap()
}

/// Store an end-to-end secret and return its id.
async fn store_e2e(gateway: &Gateway, credential: &str, workspace: Uuid) -> Uuid {
    let pair = generate_hybrid_keypair().unwrap();
    let key_id = gateway
        .register_workspace_key(credential, &pair.encapsulation_key)
        .await
        .unwrap();
    let ids = VersionIds {
        workspace_id: workspace,
        secret_id: Uuid::now_v7(),
        version_id: Uuid::now_v7(),
    };
    let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, b"sk-e2e-delete", 1024).unwrap();
    gateway
        .store_e2e_secret(
            credential,
            SECRET,
            policy(),
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
    ids.secret_id
}

async fn control_plane_delete_cancel_and_shred(store: Arc<dyn Store>) {
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = control_plane(store.clone(), clock.clone());
    let created = gateway.create_workspace().await.unwrap();
    let secret_id = store_e2e(&gateway, &created.credential, created.id).await;

    gateway
        .delete_workspace(&created.credential, created.id)
        .await
        .unwrap();
    let row = store.workspace(created.id).await.unwrap();
    assert_eq!(row.status, "deleting");
    assert_eq!(
        row.delete_after,
        Some(1_700_000_000 + DELETION_RETENTION_SECS)
    );
    // Ciphertext stays until the deadline.
    assert!(store.latest_version(secret_id).await.is_ok());
    assert_eq!(gateway.poll_shreds().await.unwrap(), 0);

    gateway
        .cancel_deletion(&created.credential, created.id)
        .await
        .unwrap();
    let row = store.workspace(created.id).await.unwrap();
    assert_eq!(row.status, "active");
    assert_eq!(row.delete_after, None);
    assert!(store.latest_version(secret_id).await.is_ok());

    gateway
        .delete_workspace(&created.credential, created.id)
        .await
        .unwrap();
    clock.set(1_700_000_000 + DELETION_RETENTION_SECS - 1);
    assert_eq!(gateway.poll_shreds().await.unwrap(), 0);
    clock.set(1_700_000_000 + DELETION_RETENTION_SECS + 1);
    let late = gateway
        .cancel_deletion(&created.credential, created.id)
        .await
        .unwrap_err();
    assert_eq!(late.code(), "bad_request");
    assert_eq!(gateway.poll_shreds().await.unwrap(), 1);
    assert_eq!(
        store.workspace(created.id).await.unwrap().status,
        "shredded"
    );
    assert_eq!(
        store.latest_version(secret_id).await.unwrap_err().code(),
        "not_found"
    );
    assert_eq!(
        gateway
            .workspace_id_for(&created.credential)
            .await
            .unwrap_err()
            .code(),
        "unauthenticated"
    );
    let events = store.audit_for_workspace(created.id).await.unwrap();
    for kind in [
        "tenant.delete.scheduled",
        "tenant.delete.cancelled",
        "tenant.shredded",
    ] {
        assert!(
            events.iter().any(|event| event.event_type == kind),
            "{kind}"
        );
    }
}

#[tokio::test]
async fn control_plane_deletion_works_without_a_root_key() {
    control_plane_delete_cancel_and_shred(Arc::new(MemoryStore::new())).await;
}

#[tokio::test]
async fn control_plane_deletion_works_on_sqlite() {
    let dir = std::env::temp_dir().join(format!("credentials-delete-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(
        SqlStore::connect(&format!("sqlite://{}/dev.sqlite", dir.display()))
            .await
            .unwrap(),
    );
    control_plane_delete_cancel_and_shred(store).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn one_failing_workspace_does_not_block_the_next_shred() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let upstream: Arc<dyn Upstream> = Arc::new(RecordingUpstream::new());
    // Two dev gateways with different root-key providers share one store, so
    // each sees a workspace whose root key it cannot find.
    let first = dev(store.clone(), upstream.clone(), clock.clone());
    let second = dev(store.clone(), upstream, clock.clone());
    let a = first.create_workspace().await.unwrap();
    let b = second.create_workspace().await.unwrap();
    first.delete_workspace(&a.credential, a.id).await.unwrap();
    second.delete_workspace(&b.credential, b.id).await.unwrap();
    clock.set(1_700_000_000 + DELETION_RETENTION_SECS + 1);
    assert_eq!(second.poll_shreds().await.unwrap(), 1);
    assert_eq!(store.workspace(b.id).await.unwrap().status, "shredded");
    assert_eq!(store.workspace(a.id).await.unwrap().status, "deleting");
    assert_eq!(first.poll_shreds().await.unwrap(), 1);
    assert_eq!(store.workspace(a.id).await.unwrap().status, "shredded");
}

struct Env {
    gateway: Gateway,
    store: Arc<MemoryStore>,
    clock: Arc<ManualClock>,
    credential: String,
    workspace: Uuid,
    agent: Uuid,
}

async fn env_with(upstream: Arc<dyn Upstream>, value: &[u8]) -> Env {
    let store = Arc::new(MemoryStore::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = dev(store.clone(), upstream, clock.clone());
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(&created.credential, SECRET, value, policy())
        .await
        .unwrap();
    let agent = gateway
        .create_agent(&created.credential, "runner")
        .await
        .unwrap();
    Env {
        gateway,
        store,
        clock,
        credential: created.credential,
        workspace: created.id,
        agent,
    }
}

impl Env {
    async fn session(&self, dpop_public_b64: &str) -> String {
        self.gateway
            .create_session(
                &self.credential,
                self.agent,
                vec!["secret:inject:prod/openai/api_key".into()],
                Some(300),
                dpop_public_b64,
            )
            .await
            .unwrap()
            .token
    }

    async fn events(&self) -> Vec<AuditRecord> {
        self.store
            .audit_for_workspace(self.workspace)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn inject_denials_are_audited() {
    let env = env_with(Arc::new(RecordingUpstream::new()), b"sk-denials").await;
    let dpop = generate_dpop().unwrap();
    let token = env.session(dpop.public_b64()).await;
    let now = env.clock.unix_secs();

    // A proof for another URL fails DPoP and is audited.
    let wrong = dpop.proof("POST", "https://elsewhere/v1/inject", &token, now, "d-1");
    let err = env
        .gateway
        .inject(request(&token, &wrong, SECRET, "POST"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unauthenticated");
    assert!(denied_with(&env.events().await, "dpop"));

    // A replayed jti is audited the same way.
    let proof = dpop.proof("POST", HTU, &token, now, "d-2");
    env.gateway
        .inject(request(&token, &proof, SECRET, "POST"))
        .await
        .unwrap();
    let before = env.events().await.len();
    let err = env
        .gateway
        .inject(request(&token, &proof, SECRET, "POST"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unauthenticated");
    let after = env.events().await;
    assert_eq!(after.len(), before + 1);
    assert!(denied_with(&after[before..], "dpop"));

    // A method outside the allow list is denied before release.
    let proof = dpop.proof("POST", HTU, &token, now, "d-3");
    let err = env
        .gateway
        .inject(request(&token, &proof, SECRET, "TRACE"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "forbidden");
    assert!(denied_with(&env.events().await, "method"));

    // A malformed name is not written to the log.
    let proof = dpop.proof("POST", HTU, &token, now, "d-4");
    let err = env
        .gateway
        .inject(request(&token, &proof, "../Etc/Passwd", "POST"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "not_found");
    let events = env.events().await;
    assert!(denied_with(&events, "invalid_name"));
    assert!(!format!("{:?}", events).contains("Passwd"));

    // A well-formed missing name is still recorded.
    let proof = dpop.proof("POST", HTU, &token, now, "d-5");
    env.gateway
        .inject(request(&token, &proof, "prod/missing", "POST"))
        .await
        .unwrap_err();
    let events = env.events().await;
    assert!(denied_with(&events, "not_found"));
    assert!(format!("{:?}", events).contains("prod/missing"));
}

/// Echoes the injected header back in the response body.
struct EchoUpstream;

#[async_trait::async_trait]
impl Upstream for EchoUpstream {
    async fn forward(&self, request: Outbound) -> Result<Inbound, ApiError> {
        Ok(Inbound {
            status: 200,
            body: format!("debug: {}", request.header_value).into_bytes(),
        })
    }
}

#[tokio::test]
async fn a_reflected_secret_is_not_returned() {
    let env = env_with(Arc::new(EchoUpstream), b"sk-reflected-value").await;
    let dpop = generate_dpop().unwrap();
    let token = env.session(dpop.public_b64()).await;
    let proof = dpop.proof("POST", HTU, &token, env.clock.unix_secs(), "r-1");
    let err = env
        .gateway
        .inject(request(&token, &proof, SECRET, "POST"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "upstream_failed");
    let events = env.events().await;
    assert!(events
        .iter()
        .any(|event| event.event_type == "secret.access.failed"
            && format!("{:?}", event.fields).contains("\"reflected\"")));
    assert!(!events
        .iter()
        .any(|event| event.event_type == "secret.access.delivered"));
}

#[tokio::test]
async fn a_short_secret_is_caught_through_its_header_value() {
    let env = env_with(Arc::new(EchoUpstream), b"abc").await;
    let dpop = generate_dpop().unwrap();
    let token = env.session(dpop.public_b64()).await;
    let proof = dpop.proof("POST", HTU, &token, env.clock.unix_secs(), "r-2");
    let err = env
        .gateway
        .inject(request(&token, &proof, SECRET, "POST"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "upstream_failed");
}

#[tokio::test]
async fn a_session_key_must_be_an_ed25519_point() {
    let env = env_with(Arc::new(RecordingUpstream::new()), b"sk-key-check").await;
    for bad in [
        "",
        "not-a-key",
        "AAAA",
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let err = env
            .gateway
            .create_session(
                &env.credential,
                env.agent,
                vec!["secret:inject:prod/openai/api_key".into()],
                Some(60),
                bad,
            )
            .await
            .err()
            .unwrap();
        assert_eq!(err.code(), "bad_request", "{bad}");
    }
}

#[tokio::test]
async fn audit_pages_follow_the_cursor() {
    let env = env_with(Arc::new(RecordingUpstream::new()), b"sk-pages").await;
    let dpop = generate_dpop().unwrap();
    let token = env.session(dpop.public_b64()).await;
    for n in 0..3 {
        let proof = dpop.proof(
            "POST",
            HTU,
            &token,
            env.clock.unix_secs(),
            &format!("p-{n}"),
        );
        env.gateway
            .inject(request(&token, &proof, SECRET, "POST"))
            .await
            .unwrap();
    }
    let total = env.events().await.len() as u64;
    assert!(total > 4);

    let mut seen = Vec::new();
    let mut after = 0;
    loop {
        let page = env
            .gateway
            .audit_page(&env.credential, None, after, Some(2))
            .await
            .unwrap();
        assert!(page.events.len() <= 2);
        seen.extend(page.events.iter().map(|event| event.seq));
        match page.next_after_seq {
            Some(next) => after = next,
            None => break,
        }
    }
    assert_eq!(seen, (1..=total).collect::<Vec<_>>());

    let agent_page = env
        .gateway
        .audit_page(&env.credential, Some(env.agent), 0, None)
        .await
        .unwrap();
    assert!(!agent_page.events.is_empty());
    assert!(agent_page
        .events
        .iter()
        .all(|event| event.agent_id == Some(env.agent)));
    let tail = env
        .gateway
        .audit_page(&env.credential, Some(env.agent), 3, Some(1000))
        .await
        .unwrap();
    assert!(tail.events.iter().all(|event| event.seq > 3));
    assert_eq!(
        env.gateway
            .audit_page(&env.credential, None, 0, Some(0))
            .await
            .err()
            .unwrap()
            .code(),
        "bad_request"
    );
    let capped = env
        .gateway
        .audit_page(&env.credential, None, 0, Some(50_000))
        .await
        .unwrap();
    assert_eq!(capped.events.len() as u64, total);
}

#[tokio::test]
async fn a_rewritten_anchor_tip_stops_inject() {
    let dir = std::env::temp_dir().join(format!("credentials-tip-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer_path = dir.join("signer.json");
    let load = || DevSigner::load_or_create(&signer_path, DevPolicy { allow_dev: true }).unwrap();
    let store = Arc::new(MemoryStore::new());
    let anchor = Arc::new(MemoryAnchor::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway_for = |signer: DevSigner| {
        Gateway::with_anchor(
            store.clone(),
            Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
            Arc::new(RecordingUpstream::new()),
            clock.clone(),
            signer,
            anchor.clone(),
        )
        .unwrap()
    };
    let gateway = gateway_for(load());
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(&created.credential, SECRET, b"sk-anchor-tip", policy())
        .await
        .unwrap();
    clock.set(clock.unix_secs() + 61);
    assert_eq!(gateway.publish_checkpoints().await.unwrap(), 1);

    // A fresh process trusts a matching anchored tip.
    let restarted = gateway_for(load());
    assert_eq!(restarted.shutdown().await.unwrap(), 0);

    // An anchored tip whose hash is not in the store is refused, even when
    // the signature is valid.
    let tip = anchor.latest(created.id).await.unwrap().unwrap();
    let forged = [9u8; 32];
    let signature = load().sign_message(&checkpoint_message(created.id, tip.seq, &forged));
    anchor
        .put(created.id, tip.seq, &forged, &signature)
        .await
        .unwrap();
    let checked = gateway_for(load());
    let agent = checked
        .create_agent(&created.credential, "runner")
        .await
        .unwrap();
    let dpop = generate_dpop().unwrap();
    let token = checked
        .create_session(
            &created.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap()
        .token;
    let proof = dpop.proof("POST", HTU, &token, clock.unix_secs(), "tip-1");
    let err = checked
        .inject(request(&token, &proof, SECRET, "POST"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "audit_anchor_unavailable");
    assert!(
        checked
            .metrics_integrity
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    let events = store.audit_for_workspace(created.id).await.unwrap();
    assert!(events
        .iter()
        .any(|event| event.event_type == "audit.anchor.mismatch"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_rotated_credential_replaces_the_old_one() {
    let env = env_with(Arc::new(RecordingUpstream::new()), b"sk-rotate").await;
    let fresh = env
        .gateway
        .rotate_workspace_credential(&env.credential)
        .await
        .unwrap();
    assert_ne!(fresh, env.credential);
    assert_eq!(
        env.gateway
            .workspace_id_for(&env.credential)
            .await
            .unwrap_err()
            .code(),
        "unauthenticated"
    );
    assert_eq!(
        env.gateway.workspace_id_for(&fresh).await.unwrap(),
        env.workspace
    );
    assert!(env
        .events()
        .await
        .iter()
        .any(|event| event.event_type == "workspace.credential.rotated"));
    assert!(env
        .gateway
        .rotate_workspace_credential(&env.credential)
        .await
        .is_err());
}

#[tokio::test]
async fn dpop_replay_is_scoped_to_the_workspace() {
    let dir = std::env::temp_dir().join(format!("credentials-replay-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let sql: Arc<dyn Store> = Arc::new(
        SqlStore::connect(&format!("sqlite://{}/dev.sqlite", dir.display()))
            .await
            .unwrap(),
    );
    let memory: Arc<dyn Store> = Arc::new(MemoryStore::new());
    for store in [memory, sql] {
        let (one, two) = (Uuid::now_v7(), Uuid::now_v7());
        store.claim_dpop_jti("same-jti", one, 2_000).await.unwrap();
        store.claim_dpop_jti("same-jti", two, 2_000).await.unwrap();
        assert_eq!(
            store
                .claim_dpop_jti("same-jti", one, 2_000)
                .await
                .unwrap_err()
                .code(),
            "unauthenticated"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn sqlite_rotates_a_credential_and_pages_the_audit_log() {
    let dir = std::env::temp_dir().join(format!("credentials-rot-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: Arc<dyn Store> = Arc::new(
        SqlStore::connect(&format!("sqlite://{}/dev.sqlite", dir.display()))
            .await
            .unwrap(),
    );
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = dev(store, Arc::new(RecordingUpstream::new()), clock);
    let created = gateway.create_workspace().await.unwrap();
    for name in ["prod/a", "prod/b", "prod/c"] {
        gateway
            .create_secret(&created.credential, name, b"sk-sqlite-page", policy())
            .await
            .unwrap();
    }
    let fresh = gateway
        .rotate_workspace_credential(&created.credential)
        .await
        .unwrap();
    assert!(gateway.workspace_id_for(&created.credential).await.is_err());
    let first = gateway.audit_page(&fresh, None, 0, Some(2)).await.unwrap();
    assert_eq!(
        first.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let rest = gateway
        .audit_page(&fresh, None, first.next_after_seq.unwrap(), Some(2))
        .await
        .unwrap();
    assert_eq!(
        rest.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert_eq!(rest.events[1].event_type, "workspace.credential.rotated");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_public_origin_replaces_the_host_header_in_htu() {
    use tower::ServiceExt;

    let store = Arc::new(MemoryStore::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let mut gateway = dev(store, Arc::new(RecordingUpstream::new()), clock.clone());
    gateway.set_public_origin(Some("https://gw.example.com/".into()));
    assert_eq!(gateway.public_origin(), Some("https://gw.example.com"));
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(&created.credential, SECRET, b"sk-origin", policy())
        .await
        .unwrap();
    let agent = gateway
        .create_agent(&created.credential, "runner")
        .await
        .unwrap();
    let dpop = generate_dpop().unwrap();
    let token = gateway
        .create_session(
            &created.credential,
            agent,
            vec!["secret:inject:prod/openai/api_key".into()],
            Some(60),
            dpop.public_b64(),
        )
        .await
        .unwrap()
        .token;
    let router = credentials_gateway::router(Arc::new(gateway));
    let body = serde_json::json!({
        "secret": SECRET,
        "delivery": "proxy",
        "request": { "method": "POST", "url": "https://api.openai.com/v1/x", "body": "" },
        "content_type": "application/json",
    });
    let send = |proof: String| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/inject")
            .header("host", "attacker.example")
            .header("authorization", format!("Bearer {token}"))
            .header("dpop", proof)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    };
    let now = clock.unix_secs();
    let spoofed = dpop.proof(
        "POST",
        "http://attacker.example/v1/inject",
        &token,
        now,
        "o-1",
    );
    let response = router.clone().oneshot(send(spoofed)).await.unwrap();
    assert_eq!(response.status(), 401);
    let pinned = dpop.proof(
        "POST",
        "https://gw.example.com/v1/inject",
        &token,
        now,
        "o-2",
    );
    let response = router.oneshot(send(pinned)).await.unwrap();
    assert_eq!(response.status(), 200);
}

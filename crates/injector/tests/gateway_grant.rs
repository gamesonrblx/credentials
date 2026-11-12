//! The real control plane signs a grant and the real injector accepts it.
//!
//! The gateway and the injector each implement the grant format on their own.
//! This test links both so a change on one side fails here.

use std::sync::{Arc, Mutex};

use credentials_crypto::{generate_hybrid_keypair, seal_e2e, DevPolicy, VersionIds};
use credentials_gateway::{
    generate_dpop, Delivery, DeliveryPolicy, DevSigner, E2eSubmission, Gateway, InjectRequest,
    ManualClock, MemoryAnchor, MemoryStore, Now, RecordingUpstream,
};
use credentials_injector::{
    deliver, verify_grant, Delivered, InjectorError, Outbound, Transport, UpstreamResponse,
};

const NOW: u64 = 1_700_000_000;
const SECRET: &[u8] = b"sk-cross-crate-canary";

/// Records the one request and answers with a fixed body.
struct Recorder {
    seen: Mutex<Vec<Outbound>>,
    reply: Vec<u8>,
}

impl Recorder {
    fn new(reply: &[u8]) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            reply: reply.to_vec(),
        }
    }
}

impl Transport for Recorder {
    async fn send(&self, request: Outbound) -> Result<UpstreamResponse, InjectorError> {
        self.seen.lock().unwrap().push(request);
        Ok(UpstreamResponse {
            status: 200,
            body: self.reply.clone(),
        })
    }
}

struct Released {
    grant: Vec<u8>,
    control_plane_key: [u8; 32],
    decapsulation_key: [u8; 32],
    body: Vec<u8>,
}

/// Store one end-to-end secret in a production control plane and inject it.
async fn release(delivery: Delivery, local_channel: bool) -> Released {
    let dir = std::env::temp_dir().join(format!("credentials-xcrate-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = DevPolicy { allow_dev: false };
    let clock = Arc::new(ManualClock::new(NOW));
    let gateway = Gateway::control_plane(
        Arc::new(MemoryStore::new()),
        Arc::new(RecordingUpstream::new()),
        clock.clone(),
        DevSigner::load_production(&dir.join("signing.json"), policy).unwrap(),
        Arc::new(MemoryAnchor::new()),
        policy,
    )
    .unwrap();
    let created = gateway.create_workspace().await.unwrap();
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
    let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, SECRET, 1024).unwrap();
    gateway
        .store_e2e_secret(
            &created.credential,
            "prod/openai/api_key",
            DeliveryPolicy {
                header_name: Some("Authorization".into()),
                header_format: Some("Bearer {value}".into()),
                env_name: Some("OPENAI_API_KEY".into()),
                hosts: vec!["api.openai.com".into()],
                allow_proxy: true,
                allow_header: true,
                allow_env: true,
            },
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
    let htu = "https://credentials.local/v1/inject";
    let proxy = matches!(delivery, Delivery::Proxy);
    let body = if proxy {
        br#"{"model":"x"}"#.to_vec()
    } else {
        Vec::new()
    };
    let released = gateway
        .inject(InjectRequest {
            token: session.token.clone(),
            dpop: dpop.proof("POST", htu, &session.token, clock.unix_secs(), "xcrate-1"),
            secret: "prod/openai/api_key".into(),
            delivery,
            method: if proxy { "POST".into() } else { String::new() },
            url: if proxy {
                "https://api.openai.com/v1/chat/completions".into()
            } else {
                String::new()
            },
            body: body.clone(),
            htm: "POST".into(),
            htu: htu.into(),
            local_channel,
            content_type: proxy.then(|| "application/json".to_owned()),
        })
        .await
        .unwrap();
    let (_, control_plane_key) = gateway.signing_key();
    Released {
        grant: released.body,
        control_plane_key,
        decapsulation_key: *pair.decapsulation_key(),
        body,
    }
}

#[tokio::test]
async fn the_injector_delivers_a_proxy_grant_from_the_control_plane() {
    let released = release(Delivery::Proxy, false).await;
    let grant = verify_grant(&released.control_plane_key, &released.grant, NOW).unwrap();

    let recorder = Recorder::new(b"upstream-ok");
    let delivered = deliver(
        &grant,
        &released.decapsulation_key,
        &released.body,
        &recorder,
    )
    .await
    .unwrap();
    let Delivered::Proxy(response) = delivered else {
        panic!("a proxy grant must end in a proxy response");
    };
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"upstream-ok");

    let seen = recorder.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(
        request.url.as_str(),
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(request.header_name, "Authorization");
    assert_eq!(
        request.header_value.as_str(),
        "Bearer sk-cross-crate-canary"
    );
    assert_eq!(request.content_type.as_deref(), Some("application/json"));
    assert_eq!(request.body, released.body);
}

#[tokio::test]
async fn the_injector_refuses_a_changed_body_a_wrong_key_and_a_late_grant() {
    let released = release(Delivery::Proxy, false).await;
    let grant = verify_grant(&released.control_plane_key, &released.grant, NOW).unwrap();

    let recorder = Recorder::new(b"upstream-ok");
    let changed = deliver(
        &grant,
        &released.decapsulation_key,
        br#"{"model":"y"}"#,
        &recorder,
    )
    .await;
    assert!(matches!(changed, Err(InjectorError::BodyMismatch)));
    assert!(recorder.seen.lock().unwrap().is_empty());

    // A response that echoes the secret never reaches the caller.
    let echo = Recorder::new(b"you sent Bearer sk-cross-crate-canary");
    let reflected = deliver(&grant, &released.decapsulation_key, &released.body, &echo).await;
    assert!(matches!(reflected, Err(InjectorError::Reflected)));

    let other_key = [7u8; 32];
    assert!(verify_grant(&other_key, &released.grant, NOW).is_err());
    assert!(matches!(
        verify_grant(&released.control_plane_key, &released.grant, NOW + 61),
        Err(InjectorError::Expired)
    ));
}

#[tokio::test]
async fn the_injector_hands_off_an_env_grant_from_the_control_plane() {
    let released = release(Delivery::Env, true).await;
    let grant = verify_grant(&released.control_plane_key, &released.grant, NOW).unwrap();
    let recorder = Recorder::new(b"unused");
    let delivered = deliver(&grant, &released.decapsulation_key, &[], &recorder)
        .await
        .unwrap();
    let Delivered::Env(handoff) = delivered else {
        panic!("an env grant must end in an env hand-off");
    };
    assert_eq!(handoff.env_name, "OPENAI_API_KEY");
    assert_eq!(handoff.value.as_str(), "sk-cross-crate-canary");
    assert!(recorder.seen.lock().unwrap().is_empty());
}

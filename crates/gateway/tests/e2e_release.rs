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
            content_type: None,
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
            content_type: None,
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
            content_type: None,
        })
        .await;
    assert!(blocked.is_err());
    assert_eq!(kms.decrypts(), 0);
    let _ = Clock;
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

#[tokio::test]
async fn control_plane_signs_a_grant_the_published_key_verifies() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use tower::ServiceExt;

    let dir = std::env::temp_dir().join(format!("credentials-grant-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = DevPolicy { allow_dev: false };
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = Gateway::control_plane(
        Arc::new(MemoryStore::new()),
        Arc::new(RecordingUpstream::new()),
        clock.clone(),
        credentials_gateway::DevSigner::load_production(&dir.join("signing.json"), policy).unwrap(),
        Arc::new(credentials_gateway::MemoryAnchor::new()),
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
    let sealed = seal_e2e(
        &pair.encapsulation_key,
        key_id,
        ids,
        b"sk-grant-value",
        1024,
    )
    .unwrap();
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
    let body = br#"{"model":"x"}"#.to_vec();
    let released = gateway
        .inject(InjectRequest {
            token: session.token.clone(),
            dpop: dpop.proof("POST", htu, &session.token, clock.unix_secs(), "grant-1"),
            secret: "prod/openai/api_key".into(),
            delivery: Delivery::Proxy,
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat/completions".into(),
            body: body.clone(),
            htm: "POST".into(),
            htu: htu.into(),
            local_channel: false,
            content_type: Some("application/json".into()),
        })
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&released.body).unwrap();
    assert_eq!(response["wrap_mode"], "e2e");
    assert!(response["payload_ciphertext"].is_string());

    let gateway = Arc::new(gateway);
    let keys = credentials_gateway::router(gateway.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/keys")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(keys.status(), 200);
    let keys: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(keys.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    let published = &keys["keys"][0];
    assert_eq!(published["alg"], "EdDSA");
    assert_eq!(published["kid"], response["grant_kid"]);
    let public: [u8; 32] = STANDARD
        .decode(published["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verifying = VerifyingKey::from_bytes(&public).unwrap();

    let grant_bytes = STANDARD
        .decode(response["grant"].as_str().unwrap())
        .unwrap();
    let signature: [u8; 64] = STANDARD
        .decode(response["grant_signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut message = credentials_gateway::GRANT_PREFIX.to_vec();
    message.extend_from_slice(&grant_bytes);
    verifying
        .verify(&message, &Signature::from_bytes(&signature))
        .unwrap();
    assert!(verifying
        .verify(&grant_bytes, &Signature::from_bytes(&signature))
        .is_err());

    let grant: serde_json::Value = serde_json::from_slice(&grant_bytes).unwrap();
    assert_eq!(grant["v"], 1);
    assert_eq!(grant["iss"], gateway.issuer());
    assert_eq!(grant["kid"], response["grant_kid"]);
    assert_eq!(grant["workspace_id"], created.id.to_string());
    assert_eq!(grant["secret_id"], ids.secret_id.to_string());
    assert_eq!(grant["version_id"], ids.version_id.to_string());
    assert_eq!(grant["workspace_key_id"], key_id.to_string());
    assert_eq!(grant["agent_id"], agent.to_string());
    assert_eq!(grant["secret_name"], "prod/openai/api_key");
    assert_eq!(grant["delivery"], "proxy");
    assert_eq!(grant["iat"], 1_700_000_000u64);
    assert_eq!(grant["exp"], 1_700_000_060u64);
    assert_eq!(
        grant["ciphertext_sha256"],
        sha256_hex(&sealed.payload_ciphertext)
    );
    assert_eq!(grant["method"], "POST");
    assert_eq!(grant["url"], "https://api.openai.com/v1/chat/completions");
    assert_eq!(grant["host"], "api.openai.com");
    assert_eq!(grant["body_sha256"], sha256_hex(&body));
    assert_eq!(grant["content_type"], "application/json");
    assert_eq!(grant["header_name"], "Authorization");
    assert_eq!(grant["header_format"], "Bearer {value}");
    assert!(grant.get("env_name").is_none());
    injector_would_accept(&grant, &response["grant_kid"]);

    // An empty content type is signed as null, never as "".
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
    let released = gateway
        .inject(InjectRequest {
            token: session.token.clone(),
            dpop: dpop.proof("POST", htu, &session.token, clock.unix_secs(), "grant-2"),
            secret: "prod/openai/api_key".into(),
            delivery: Delivery::Proxy,
            method: "GET".into(),
            url: "https://API.openai.com/v1/models?x=1".into(),
            body: Vec::new(),
            htm: "POST".into(),
            htu: htu.into(),
            local_channel: false,
            content_type: Some(String::new()),
        })
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&released.body).unwrap();
    let grant: serde_json::Value = serde_json::from_slice(
        &STANDARD
            .decode(response["grant"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(grant["content_type"].is_null());
    assert_eq!(grant["body_sha256"], sha256_hex(b""));
    injector_would_accept(&grant, &response["grant_kid"]);

    // A written port or userinfo is refused before release, since the
    // injector would refuse the grant.
    for url in [
        "https://api.openai.com:443/v1/models",
        "https://user@api.openai.com/v1/models",
    ] {
        let err = gateway
            .inject(InjectRequest {
                token: session.token.clone(),
                dpop: dpop.proof("POST", htu, &session.token, clock.unix_secs(), url),
                secret: "prod/openai/api_key".into(),
                delivery: Delivery::Proxy,
                method: "GET".into(),
                url: url.into(),
                body: Vec::new(),
                htm: "POST".into(),
                htu: htu.into(),
                local_channel: false,
                content_type: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), "forbidden", "{url}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The checks the customer injector applies to a grant. If the gateway drifts
/// from them, this fails here instead of at delivery time.
fn injector_would_accept(grant: &serde_json::Value, grant_kid: &serde_json::Value) {
    fn hex64(value: &serde_json::Value) -> bool {
        value.as_str().is_some_and(|text| {
            text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
    }
    assert_eq!(&grant["kid"], grant_kid);
    assert!(grant["iss"].as_str().is_some_and(|iss| !iss.is_empty()));
    for field in ["v", "iat", "exp"] {
        assert!(grant[field].is_u64(), "{field} must be an integer");
    }
    let lifetime = grant["exp"].as_u64().unwrap() - grant["iat"].as_u64().unwrap();
    assert!(lifetime > 0 && lifetime <= 300);
    assert!(
        grant["agent_id"].is_null()
            || grant["agent_id"]
                .as_str()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
    );
    for field in [
        "workspace_id",
        "secret_id",
        "version_id",
        "workspace_key_id",
    ] {
        assert!(uuid::Uuid::parse_str(grant[field].as_str().unwrap()).is_ok());
    }
    assert!(hex64(&grant["ciphertext_sha256"]));
    let header_ok = |grant: &serde_json::Value| {
        let name = grant["header_name"].as_str().unwrap();
        assert!(!name.is_empty() && name.len() <= 128);
        assert!(name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)));
        assert!(![
            "host",
            "content-length",
            "content-type",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
        ]
        .contains(&name.to_ascii_lowercase().as_str()));
        let format = grant["header_format"].as_str().unwrap();
        assert_eq!(format.matches("{value}").count(), 1);
        assert!(!format.chars().any(|c| c.is_control() && c != '\t'));
    };
    match grant["delivery"].as_str().unwrap() {
        "proxy" => {
            assert!(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
                .contains(&grant["method"].as_str().unwrap()));
            let url = url::Url::parse(grant["url"].as_str().unwrap()).unwrap();
            assert_eq!(url.scheme(), "https");
            assert!(url.username().is_empty() && url.password().is_none());
            let raw = grant["url"].as_str().unwrap();
            let authority = raw["https://".len()..]
                .split(['/', '?', '#'])
                .next()
                .unwrap();
            assert!(!authority.contains(':'));
            assert!(url
                .host_str()
                .unwrap()
                .eq_ignore_ascii_case(grant["host"].as_str().unwrap()));
            assert!(hex64(&grant["body_sha256"]));
            assert!(
                grant["content_type"].is_null()
                    || grant["content_type"]
                        .as_str()
                        .is_some_and(|ct| !ct.is_empty())
            );
            header_ok(grant);
        }
        "header" => header_ok(grant),
        "env" => {
            let name = grant["env_name"].as_str().unwrap();
            let mut bytes = name.bytes();
            assert!(bytes
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_'));
            assert!(bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        }
        other => panic!("unknown delivery {other}"),
    }
}

#[tokio::test]
async fn a_new_e2e_version_must_keep_the_stored_policy() {
    let gateway = Gateway::new(
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
        Arc::new(RecordingUpstream::new()),
        Arc::new(ManualClock::new(1_700_000_000)),
    )
    .unwrap();
    let created = gateway.create_workspace().await.unwrap();
    let pair = generate_hybrid_keypair().unwrap();
    let key_id = gateway
        .register_workspace_key(&created.credential, &pair.encapsulation_key)
        .await
        .unwrap();
    let secret_id = uuid::Uuid::now_v7();
    let policy = DeliveryPolicy {
        header_name: Some("Authorization".into()),
        header_format: Some("Bearer {value}".into()),
        env_name: None,
        hosts: vec!["api.openai.com".into()],
        allow_proxy: true,
        allow_header: false,
        allow_env: false,
    };
    let sealed_for = |value: &[u8]| {
        let ids = VersionIds {
            workspace_id: created.id,
            secret_id,
            version_id: uuid::Uuid::now_v7(),
        };
        let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, value, 1024).unwrap();
        submission(&sealed, ids)
    };
    gateway
        .store_e2e_secret(
            &created.credential,
            "prod/a",
            policy.clone(),
            sealed_for(b"v1"),
        )
        .await
        .unwrap();
    let mut widened = policy.clone();
    widened.hosts.push("evil.example".into());
    let err = gateway
        .store_e2e_secret(&created.credential, "prod/a", widened, sealed_for(b"v2"))
        .await
        .err()
        .unwrap();
    assert_eq!(err.code(), "invalid_policy");
    let second = gateway
        .store_e2e_secret(&created.credential, "prod/a", policy, sealed_for(b"v2"))
        .await
        .unwrap();
    assert_eq!(second.version, 2);
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

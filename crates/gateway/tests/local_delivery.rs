//! Env and header delivery return the spec objects and do not call upstream.

use std::sync::Arc;

use credentials_crypto::{DevPolicy, MemoryRootKeys};
use credentials_gateway::{
    generate_dpop, Delivery, DeliveryPolicy, Gateway, InjectRequest, ManualClock, MemoryStore, Now,
    RecordingUpstream,
};

fn request(token: &str, proof: &str, delivery: Delivery) -> InjectRequest {
    InjectRequest {
        token: token.into(),
        dpop: proof.into(),
        secret: "prod/openai/api_key".into(),
        delivery,
        method: "POST".into(),
        url: String::new(),
        body: Vec::new(),
        htm: "POST".into(),
        htu: "https://credentials.local/v1/inject".into(),
        local_channel: true,
        content_type: None,
    }
}

#[tokio::test]
async fn local_env_and_header_do_not_call_upstream() {
    let upstream = Arc::new(RecordingUpstream::new());
    let clock = Arc::new(ManualClock::new(1_700_000_000));
    let gateway = Gateway::new(
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
        upstream.clone(),
        clock.clone(),
    )
    .unwrap();
    let created = gateway.create_workspace().await.unwrap();
    gateway
        .create_secret(
            &created.credential,
            "prod/openai/api_key",
            b"sk-local",
            DeliveryPolicy {
                header_name: Some("Authorization".into()),
                header_format: Some("Bearer {value}".into()),
                env_name: Some("OPENAI_API_KEY".into()),
                hosts: vec!["api.openai.com".into()],
                allow_proxy: false,
                allow_header: true,
                allow_env: true,
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
        "local-env",
    );
    let env = gateway
        .inject(request(&session.token, &proof, Delivery::Env))
        .await
        .unwrap();
    let env_body: serde_json::Value = serde_json::from_slice(&env.body).unwrap();
    assert_eq!(env_body["env_name"], "OPENAI_API_KEY");
    assert_eq!(env_body["value"], "sk-local");
    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "local-header",
    );
    let header = gateway
        .inject(request(&session.token, &proof, Delivery::Header))
        .await
        .unwrap();
    let header_body: serde_json::Value = serde_json::from_slice(&header.body).unwrap();
    assert_eq!(header_body["header_name"], "Authorization");
    assert_eq!(header_body["value"], "Bearer sk-local");
    assert!(upstream.last_value().is_none());

    let proof = dpop.proof(
        "POST",
        "https://credentials.local/v1/inject",
        &session.token,
        clock.unix_secs(),
        "public-env",
    );
    let mut public = request(&session.token, &proof, Delivery::Env);
    public.local_channel = false;
    let err = gateway.inject(public).await.unwrap_err();
    assert_eq!(err.code(), "forbidden");
}

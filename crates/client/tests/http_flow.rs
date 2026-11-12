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
            &htu,
        )
        .await
        .unwrap();
    assert_eq!(injected.upstream_status, 200);
    assert_eq!(
        injected.body,
        base64::engine::general_purpose::STANDARD.encode(b"upstream-ok")
    );
}

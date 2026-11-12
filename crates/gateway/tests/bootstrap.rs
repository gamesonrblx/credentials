//! Non-loopback bootstrap requires an operator token. Loopback dev does not.

use std::sync::Arc;

use credentials_crypto::{DevPolicy, MemoryRootKeys};
use credentials_gateway::{router_with_bootstrap, Clock, Gateway, MemoryStore, RecordingUpstream};

#[tokio::test]
async fn operator_token_gates_workspace_create() {
    let gateway = Arc::new(
        Gateway::new(
            Arc::new(MemoryStore::new()),
            Arc::new(MemoryRootKeys::new(DevPolicy { allow_dev: true }).unwrap()),
            Arc::new(RecordingUpstream::new()),
            Arc::new(Clock),
        )
        .unwrap(),
    );
    let app = router_with_bootstrap(gateway, Some("op-token".into()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let client = reqwest::Client::new();
    let denied = client
        .post(format!("http://{addr}/v1/workspaces"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    let allowed = client
        .post(format!("http://{addr}/v1/workspaces"))
        .bearer_auth("op-token")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);
}

//! Two hosted workspaces do not share rows. The control plane cannot unwrap.

use std::sync::Arc;

use credentials_crypto::DevPolicy;
use credentials_gateway::{Clock, DevSigner, FileAnchor, Gateway, MemoryStore, RecordingUpstream};

#[tokio::test]
async fn two_workspaces_do_not_share_secrets() {
    let dir = std::env::temp_dir().join(format!("credentials-hosted-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let gateway = Gateway::control_plane(
        Arc::new(MemoryStore::new()),
        Arc::new(RecordingUpstream::new()),
        Arc::new(Clock),
        DevSigner::load_production(&dir.join("signing.json"), DevPolicy { allow_dev: false })
            .unwrap(),
        Arc::new(FileAnchor::open(dir.join("anchor.log")).unwrap()),
        DevPolicy { allow_dev: false },
    )
    .unwrap();
    let first = gateway.create_workspace().await.unwrap();
    let second = gateway.create_workspace().await.unwrap();
    assert_ne!(first.id, second.id);
    let public_key = vec![0u8; 1216];
    assert!(gateway
        .register_workspace_key(&second.credential, &public_key)
        .await
        .is_ok());
    assert!(gateway.registered_key(&first.credential).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

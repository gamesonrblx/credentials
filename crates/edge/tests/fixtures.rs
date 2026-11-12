//! Recorded response shapes from the public Infisical, Doppler, and 1Password APIs.

use axum::routing::get;
use axum::{Json, Router};
use credentials_edge::{read_doppler, read_infisical, read_onepassword};

#[test]
fn infisical_doppler_and_onepassword_match_public_shapes() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let app = Router::new()
                .route(
                    "/api/v3/secrets/raw",
                    get(|| async {
                        Json(serde_json::json!({
                            "secrets": [{
                                "secretKey": "OPENAI_API_KEY",
                                "secretValue": "sk-infisical"
                            }]
                        }))
                    }),
                )
                .route(
                    "/v3/configs/config/secrets",
                    get(|| async {
                        Json(serde_json::json!({
                            "secrets": {
                                "OPENAI_API_KEY": { "computed": "sk-doppler" }
                            }
                        }))
                    }),
                )
                .route(
                    "/v1/vaults/vault-1/items",
                    get(|| async {
                        Json(serde_json::json!([{ "id": "item-1", "title": "OpenAI" }]))
                    }),
                )
                .route(
                    "/v1/vaults/vault-1/items/item-1",
                    get(|| async {
                        Json(serde_json::json!({
                            "title": "OpenAI",
                            "fields": [{
                                "id": "password",
                                "purpose": "PASSWORD",
                                "value": "sk-onepassword"
                            }]
                        }))
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    let addr = rx.recv().unwrap();
    let base = format!("http://{addr}");
    let infisical = read_infisical(&base, "token", "ws", "prod").unwrap();
    assert_eq!(infisical[0].name, "OPENAI_API_KEY");
    assert_eq!(infisical[0].value, "sk-infisical");
    let doppler = read_doppler(&base, "token", "proj", "prd").unwrap();
    assert_eq!(doppler[0].value, "sk-doppler");
    let one = read_onepassword(&base, "token", "vault-1").unwrap();
    assert_eq!(one[0].name, "OpenAI");
    assert_eq!(one[0].value, "sk-onepassword");
}

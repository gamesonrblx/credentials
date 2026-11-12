use crate::oidc::{authorize_url, challenge_from, role_for_group, OidcClient};
use crate::webauthn::{
    authenticate, register, relying_party, stored_passkey_hides_prf, Authenticator,
};
use uuid::Uuid;

#[test]
fn webauthn_prf_stays_off_the_relying_party() {
    let origin = "https://credentials.example";
    let party = relying_party("credentials.example", origin).unwrap();
    let auth = Authenticator::generate();
    let (passkey, _) = register(&auth, &party, Uuid::now_v7(), origin).unwrap();
    authenticate(&auth, &party, &passkey, origin).unwrap();
    let prf = auth.prf(b"credentials-prf-salt-32-bytes!!!!");
    assert!(stored_passkey_hides_prf(&passkey, &prf));
    assert_ne!(prf, [0u8; 32]);
}

#[test]
fn pkce_challenge_is_s256() {
    let challenge = challenge_from("verifier-value");
    assert!(challenge.len() > 20);
    let client = OidcClient {
        issuer: "http://idp.example".into(),
        client_id: "credentials".into(),
        redirect_uri: "http://localhost/cb".into(),
    };
    let url = authorize_url(&client, &challenge, "state");
    assert!(url.contains("code_challenge_method=S256"));
    assert_eq!(role_for_group("credentials-admin"), Some("admin"));
    assert_eq!(role_for_group("inject"), None);
}

#[test]
fn password_login_reads_the_email_and_drops_the_token() {
    let saved = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let app = axum::Router::new()
        .route(
            "/issuer/authorize",
            axum::routing::get({
                let saved = saved.clone();
                move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let saved = saved.clone();
                    async move {
                        *saved.lock().unwrap() = query.get("state").cloned().unwrap_or_default();
                        axum::response::Redirect::temporary("/issuer/login")
                    }
                }
            }),
        )
        .route(
            "/issuer/login",
            axum::routing::get(|| async { "sign in" }).post({
                let saved = saved.clone();
                move || {
                    let saved = saved.clone();
                    async move {
                        let state = saved.lock().unwrap().clone();
                        axum::response::Redirect::temporary(&format!(
                            "http://127.0.0.1:9/callback?code=abc&state={state}"
                        ))
                    }
                }
            }),
        )
        .route(
            "/issuer/token",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({"access_token": "tok", "token_type": "bearer"}))
            }),
        )
        .route(
            "/issuer/userinfo",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"email": "admin@example.com"}))
            }),
        )
        .route(
            "/issuer/.well-known/openid-configuration",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                let host = headers.get("host").unwrap().to_str().unwrap();
                let origin = format!("http://{host}/issuer");
                axum::Json(serde_json::json!({
                    "authorization_endpoint": format!("{origin}/authorize"),
                    "token_endpoint": format!("{origin}/token"),
                    "userinfo_endpoint": format!("{origin}/userinfo"),
                }))
            }),
        );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    let addr = rx.recv().unwrap();
    let client = OidcClient {
        issuer: format!("http://{addr}/issuer"),
        client_id: "credentials".into(),
        redirect_uri: "http://127.0.0.1:9/callback".into(),
    };
    let session =
        crate::oidc::login_with_password(&client, None, "admin@example.com", "password").unwrap();
    assert_eq!(session.subject, "admin@example.com");
    assert!(!format!("{session:?}").contains("tok"));
}

use crate::oidc::{
    authorization_request, authorize_url, challenge_from, check_id_token, form_encode, nonce_from,
    parse_discovery, role_for_group, subject_from, OidcClient, OidcError,
};
use crate::webauthn::{
    authenticate, register, relying_party, start_registration, stored_passkey_hides_prf,
    Authenticator,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use uuid::Uuid;

#[test]
fn webauthn_prf_stays_off_the_relying_party() {
    let origin = "https://credentials.example";
    let party = relying_party("credentials.example", origin).unwrap();
    let auth = Authenticator::generate().unwrap();
    let (passkey, _) = register(
        &auth,
        &party,
        Uuid::now_v7(),
        "grace",
        "Grace Hopper",
        origin,
    )
    .unwrap();
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
fn webauthn_registration_needs_a_user_name_and_display_name() {
    let origin = "https://credentials.example";
    let party = relying_party("credentials.example", origin).unwrap();
    assert!(start_registration(&party, Uuid::now_v7(), "", "Grace").is_err());
    assert!(start_registration(&party, Uuid::now_v7(), "grace", " ").is_err());
    let (options, _) = start_registration(&party, Uuid::now_v7(), "grace", "Grace Hopper").unwrap();
    assert_eq!(options.public_key.user.name, "grace");
    assert_eq!(options.public_key.user.display_name, "Grace Hopper");
}

fn client(issuer: &str) -> OidcClient {
    OidcClient {
        issuer: issuer.into(),
        client_id: "credentials".into(),
        redirect_uri: "http://127.0.0.1:9/callback".into(),
    }
}

#[test]
fn form_values_are_percent_encoded() {
    let body = form_encode(&[("code", "a b&c=d+e/é"), ("client_id", "id&admin=1")]);
    assert_eq!(
        body.as_str(),
        "code=a%20b%26c%3Dd%2Be%2F%C3%A9&client_id=id%26admin%3D1"
    );
    let mut evil = client("https://idp.example");
    evil.client_id = "credentials&prompt=none".into();
    let url = authorization_request(
        "https://idp.example/auth?tenant=1",
        &evil,
        "chal",
        "st&x=1",
        Some("n0nce"),
    );
    assert!(url.starts_with("https://idp.example/auth?tenant=1&response_type=code&"));
    assert!(url.contains("client_id=credentials%26prompt%3Dnone&"));
    assert!(url.contains("state=st%26x%3D1&"));
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcallback&"));
    assert!(url.contains("scope=openid%20email&nonce=n0nce"));
    assert!(!url.contains("prompt=none"));
}

#[test]
fn nonce_is_bound_to_the_verifier_but_not_the_challenge() {
    assert_eq!(nonce_from("v1"), nonce_from("v1"));
    assert_ne!(nonce_from("v1"), nonce_from("v2"));
    assert_ne!(nonce_from("v1"), challenge_from("v1"));
}

#[test]
fn discovery_must_name_the_issuer_and_use_https() {
    let issuer = "https://idp.example/realms/a";
    let doc = |issuer: &str, token: &str| {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": "https://idp.example/realms/a/auth",
            "token_endpoint": token,
            "userinfo_endpoint": "https://idp.example/realms/a/userinfo",
        })
    };
    let ok = parse_discovery(&doc(issuer, "https://idp.example/realms/a/token"), issuer).unwrap();
    assert_eq!(ok.token, "https://idp.example/realms/a/token");
    assert_eq!(
        parse_discovery(
            &doc("https://evil.example", "https://idp.example/t"),
            issuer
        )
        .unwrap_err(),
        OidcError::IssuerMismatch
    );
    assert_eq!(
        parse_discovery(
            &doc("https://idp.example/realms/a/", "https://idp.example/t"),
            issuer
        )
        .unwrap_err(),
        OidcError::IssuerMismatch
    );
    assert_eq!(
        parse_discovery(&doc(issuer, "http://idp.example/token"), issuer).unwrap_err(),
        OidcError::InsecureEndpoint
    );
    let loopback = "http://127.0.0.1:5556/dex";
    assert!(parse_discovery(
        &serde_json::json!({
            "issuer": loopback,
            "authorization_endpoint": "http://127.0.0.1:5556/dex/auth",
            "token_endpoint": "http://[::1]:5556/dex/token",
            "userinfo_endpoint": "http://localhost:5556/dex/userinfo",
        }),
        loopback
    )
    .is_ok());
    let mut missing = doc(issuer, "https://idp.example/t");
    missing.as_object_mut().unwrap().remove("issuer");
    assert_eq!(
        parse_discovery(&missing, issuer).unwrap_err(),
        OidcError::Discovery
    );
}

fn id_token(claims: serde_json::Value) -> String {
    let encode = |value: &serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
    format!(
        "{}.{}.sig",
        encode(&serde_json::json!({"alg": "RS256"})),
        encode(&claims)
    )
}

#[test]
fn id_token_claims_are_checked() {
    let client = client("https://idp.example");
    let now = 1_800_000_000u64;
    let good = serde_json::json!({
        "iss": "https://idp.example",
        "aud": "credentials",
        "exp": now + 300,
        "nonce": "n1",
        "sub": "user-1",
    });
    let check =
        |claims: &serde_json::Value| check_id_token(&id_token(claims.clone()), &client, "n1", now);
    assert_eq!(check(&good).unwrap(), "user-1");
    let with = |key: &str, value: serde_json::Value| {
        let mut claims = good.clone();
        claims[key] = value;
        claims
    };
    for bad in [
        with("iss", "https://evil.example".into()),
        with("aud", "someone-else".into()),
        with("aud", serde_json::json!(["credentials", "other"])),
        with("azp", "other".into()),
        with("exp", (now - CLOCK_SKEW_SECS_FOR_TEST - 1).into()),
        with("nonce", "n2".into()),
        with("sub", "".into()),
    ] {
        assert_eq!(check(&bad).unwrap_err(), OidcError::IdToken, "{bad}");
    }
    let mut multi = with("aud", serde_json::json!(["other", "credentials"]));
    multi["azp"] = "credentials".into();
    assert!(check(&multi).is_ok());
    assert!(check(&with("exp", (now - 10).into())).is_ok());
    let mut no_nonce = good.clone();
    no_nonce.as_object_mut().unwrap().remove("nonce");
    assert!(check(&no_nonce).is_err());
    assert!(check_id_token("not-a-jwt", &client, "n1", now).is_err());
}

const CLOCK_SKEW_SECS_FOR_TEST: u64 = 60;

#[test]
fn subject_is_a_verified_email_or_the_sub() {
    let pick = |value: serde_json::Value| subject_from(&value);
    assert_eq!(
        pick(serde_json::json!({"sub": "u1", "email": "a@example.com", "email_verified": true}))
            .unwrap(),
        "a@example.com"
    );
    assert_eq!(
        pick(serde_json::json!({"sub": "u1", "email": "a@example.com", "email_verified": "true"}))
            .unwrap(),
        "a@example.com"
    );
    assert_eq!(
        pick(serde_json::json!({"sub": "u1", "email": "a@example.com", "email_verified": false}))
            .unwrap(),
        "u1"
    );
    assert_eq!(
        pick(serde_json::json!({"sub": "u1", "email": "a@example.com"})).unwrap(),
        "u1"
    );
    assert_eq!(
        pick(serde_json::json!({"email": "a@example.com"})).unwrap_err(),
        OidcError::NoSubject
    );
    assert_eq!(
        pick(serde_json::json!({"sub": "", "email_verified": true})).unwrap_err(),
        OidcError::NoSubject
    );
}

#[derive(Default)]
struct IdpState {
    state: String,
    nonce: String,
    token_body: String,
}

#[test]
fn password_login_reads_the_email_and_drops_the_token() {
    let saved = std::sync::Arc::new(std::sync::Mutex::new(IdpState::default()));
    let app = axum::Router::new()
        .route(
            "/issuer/authorize",
            axum::routing::get({
                let saved = saved.clone();
                move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                    let saved = saved.clone();
                    async move {
                        let mut saved = saved.lock().unwrap();
                        saved.state = query.get("state").cloned().unwrap_or_default();
                        saved.nonce = query.get("nonce").cloned().unwrap_or_default();
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
                        let state = saved.lock().unwrap().state.clone();
                        // A code with reserved characters must survive the round trip.
                        axum::response::Redirect::temporary(&format!(
                            "http://127.0.0.1:9/callback?code=a%26b%3Dc&state={state}"
                        ))
                    }
                }
            }),
        )
        .route(
            "/issuer/token",
            axum::routing::post({
                let saved = saved.clone();
                move |headers: axum::http::HeaderMap, body: String| {
                    let saved = saved.clone();
                    async move {
                        let host = headers.get("host").unwrap().to_str().unwrap().to_owned();
                        let mut saved = saved.lock().unwrap();
                        saved.token_body = body;
                        let exp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            + 300;
                        let token = id_token(serde_json::json!({
                            "iss": format!("http://{host}/issuer"),
                            "aud": "credentials",
                            "exp": exp,
                            "nonce": saved.nonce,
                            "sub": "user-1",
                        }));
                        axum::Json(serde_json::json!({
                            "access_token": "tok",
                            "token_type": "bearer",
                            "id_token": token,
                        }))
                    }
                }
            }),
        )
        .route(
            "/issuer/userinfo",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "sub": "user-1",
                    "email": "admin@example.com",
                    "email_verified": true,
                }))
            }),
        )
        .route(
            "/issuer/.well-known/openid-configuration",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                let host = headers.get("host").unwrap().to_str().unwrap();
                let origin = format!("http://{host}/issuer");
                axum::Json(serde_json::json!({
                    "issuer": origin,
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
    let client = client(&format!("http://{addr}/issuer"));
    let session =
        crate::oidc::login_with_password(&client, Some("s&cret="), "admin@example.com", "password")
            .unwrap();
    assert_eq!(session.subject, "admin@example.com");
    assert!(!format!("{session:?}").contains("tok"));
    let body = saved.lock().unwrap().token_body.clone();
    assert!(body.contains("code=a%26b%3Dc&"), "{body}");
    assert!(body.contains("client_secret=s%26cret%3D"), "{body}");
    assert!(body.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcallback&"));

    // The same IdP under a different configured issuer is refused at discovery.
    let mut wrong = client.clone();
    wrong.issuer = format!("http://{addr}/issuer/");
    assert_eq!(
        crate::oidc::start_browser_login(&wrong).err(),
        Some(OidcError::IssuerMismatch)
    );
}

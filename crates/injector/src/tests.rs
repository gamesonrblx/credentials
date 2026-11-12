//! Grant verification and delivery tests.

use std::future::Future;
use std::sync::Mutex;

use credentials_crypto::{generate_hybrid_keypair, seal_e2e, HybridKeyPair, VersionIds};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::json::{b64_decode, b64_encode, sha256_hex};
use crate::{
    deliver, grant_from_inject_response, verify_grant, Delivered, GrantDelivery, InjectorError,
    Outbound, Transport, UpstreamResponse, VerifiedGrant, GRANT_SIGNING_PREFIX, MAX_RESPONSE_BYTES,
};

const NOW: u64 = 1_800_000_000;
const SECRET: &[u8] = b"sk-injector";
const BODY: &[u8] = b"{\"model\":\"x\"}";

struct Fixture {
    pair: HybridKeyPair,
    signing: SigningKey,
    outer: Value,
    auth: Value,
}

impl Fixture {
    fn new() -> Self {
        Self::with_secret(SECRET)
    }

    fn with_secret(secret: &[u8]) -> Self {
        let pair = generate_hybrid_keypair().unwrap();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let ids = VersionIds {
            workspace_id: Uuid::now_v7(),
            secret_id: Uuid::now_v7(),
            version_id: Uuid::now_v7(),
        };
        let key_id = Uuid::now_v7();
        let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, secret, 1024).unwrap();
        let outer = json!({
            "wrap_mode": "e2e",
            "workspace_id": ids.workspace_id.to_string(),
            "secret_id": ids.secret_id.to_string(),
            "version_id": ids.version_id.to_string(),
            "workspace_key_id": key_id.to_string(),
            "payload_nonce": b64_encode(&sealed.payload_nonce),
            "payload_ciphertext": b64_encode(&sealed.payload_ciphertext),
            "dek_wrap_nonce": b64_encode(&sealed.dek_wrap_nonce),
            "dek_wrapped": b64_encode(&sealed.dek_wrapped),
            "e2e_encapsulation": b64_encode(&sealed.encapsulation),
            "plaintext_len": sealed.plaintext_len,
        });
        let auth = json!({
            "v": 1,
            "iss": "https://control.example",
            "kid": "cp-1",
            "workspace_id": ids.workspace_id.to_string(),
            "secret_id": ids.secret_id.to_string(),
            "version_id": ids.version_id.to_string(),
            "workspace_key_id": key_id.to_string(),
            "agent_id": Uuid::now_v7().to_string(),
            "secret_name": "prod/openai/api_key",
            "delivery": "proxy",
            "iat": NOW,
            "exp": NOW + 60,
            "ciphertext_sha256": sha256_hex(&sealed.payload_ciphertext),
            "method": "POST",
            "url": "https://api.openai.com/v1/chat/completions",
            "host": "api.openai.com",
            "body_sha256": sha256_hex(BODY),
            "content_type": "application/json",
            "header_name": "Authorization",
            "header_format": "Bearer {value}",
        });
        Self {
            pair,
            signing,
            outer,
            auth,
        }
    }

    fn header(mut self) -> Self {
        self.auth["delivery"] = json!("header");
        self
    }

    fn env(mut self) -> Self {
        self.auth["delivery"] = json!("env");
        self.auth["env_name"] = json!("OPENAI_API_KEY");
        self
    }

    fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn key(&self) -> &[u8; 32] {
        self.pair.decapsulation_key()
    }

    fn signed_outer(&self, signer: &SigningKey) -> Value {
        let grant = serde_json::to_vec(&self.auth).unwrap();
        let mut message = GRANT_SIGNING_PREFIX.to_vec();
        message.extend_from_slice(&grant);
        let signature = signer.sign(&message);
        let mut outer = self.outer.clone();
        outer["grant"] = json!(b64_encode(&grant));
        outer["grant_signature"] = json!(b64_encode(&signature.to_bytes()));
        outer["grant_kid"] = json!("cp-1");
        outer
    }

    fn grant(&self) -> Vec<u8> {
        serde_json::to_vec(&self.signed_outer(&self.signing)).unwrap()
    }

    fn verify(&self) -> Result<VerifiedGrant, InjectorError> {
        verify_grant(&self.public(), &self.grant(), NOW)
    }
}

#[derive(Default)]
struct Recorder {
    response: Vec<u8>,
    seen: Mutex<Option<Seen>>,
}

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    url: String,
    header_name: String,
    header_value: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Recorder {
    fn replying(body: &[u8]) -> Self {
        Self {
            response: body.to_vec(),
            seen: Mutex::new(None),
        }
    }

    fn seen(&self) -> Option<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Transport for Recorder {
    fn send(
        &self,
        request: Outbound,
    ) -> impl Future<Output = Result<UpstreamResponse, InjectorError>> + Send {
        *self.seen.lock().unwrap() = Some(Seen {
            method: request.method.as_str().to_owned(),
            url: request.url.to_string(),
            header_name: request.header_name.clone(),
            header_value: request.header_value.as_str().to_owned(),
            content_type: request.content_type.clone(),
            body: request.body.clone(),
        });
        let body = self.response.clone();
        async move { Ok(UpstreamResponse { status: 201, body }) }
    }
}

#[tokio::test]
async fn proxy_sends_one_header_and_returns_only_the_upstream_body() {
    let fixture = Fixture::new();
    let grant = fixture.verify().unwrap();
    assert_eq!(grant.secret_name, "prod/openai/api_key");
    let recorder = Recorder::replying(b"upstream-ok");
    let delivered = deliver(&grant, fixture.key(), BODY, &recorder)
        .await
        .unwrap();
    let Delivered::Proxy(response) = delivered else {
        panic!("expected proxy");
    };
    assert_eq!(response.status, 201);
    assert_eq!(response.body, b"upstream-ok");
    let seen = recorder.seen().unwrap();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(seen.header_name, "Authorization");
    assert_eq!(seen.header_value, "Bearer sk-injector");
    assert_eq!(seen.content_type.as_deref(), Some("application/json"));
    assert_eq!(seen.body, BODY);
}

#[tokio::test]
async fn a_grant_opens_only_with_the_customer_key() {
    let fixture = Fixture::new();
    let grant = fixture.verify().unwrap();
    let recorder = Recorder::default();
    let err = deliver(&grant, &[9u8; 32], BODY, &recorder)
        .await
        .unwrap_err();
    assert_eq!(err, InjectorError::Open);
    assert!(recorder.seen().is_none());
}

#[test]
fn a_signature_from_another_key_is_rejected() {
    let fixture = Fixture::new();
    let other = SigningKey::from_bytes(&[8u8; 32]);
    let grant = serde_json::to_vec(&fixture.signed_outer(&other)).unwrap();
    assert_eq!(
        verify_grant(&fixture.public(), &grant, NOW).unwrap_err(),
        InjectorError::Signature
    );

    let mut outer = fixture.signed_outer(&fixture.signing);
    let mut signature = b64_decode(outer["grant_signature"].as_str().unwrap()).unwrap();
    signature[0] ^= 1;
    outer["grant_signature"] = json!(b64_encode(&signature));
    let grant = serde_json::to_vec(&outer).unwrap();
    assert_eq!(
        verify_grant(&fixture.public(), &grant, NOW).unwrap_err(),
        InjectorError::Signature
    );
}

#[test]
fn a_tampered_host_breaks_the_signature() {
    let fixture = Fixture::new();
    let mut outer = fixture.signed_outer(&fixture.signing);
    let mut auth: Value =
        serde_json::from_slice(&b64_decode(outer["grant"].as_str().unwrap()).unwrap()).unwrap();
    auth["host"] = json!("evil.example");
    auth["url"] = json!("https://evil.example/collect");
    outer["grant"] = json!(b64_encode(&serde_json::to_vec(&auth).unwrap()));
    let grant = serde_json::to_vec(&outer).unwrap();
    assert_eq!(
        verify_grant(&fixture.public(), &grant, NOW).unwrap_err(),
        InjectorError::Signature
    );
}

#[test]
fn a_signed_url_must_match_the_signed_host() {
    let mut fixture = Fixture::new();
    fixture.auth["url"] = json!("https://evil.example/collect");
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::Url);
}

#[test]
fn proxy_urls_must_be_bare_https() {
    for url in [
        "http://api.openai.com/v1",
        "https://user:pw@api.openai.com/v1",
        "https://api.openai.com@evil.example/v1",
        "https://api.openai.com:443/v1",
        "https://api.openai.com:8443/v1",
        "ftp://api.openai.com/v1",
        "not a url",
    ] {
        let mut fixture = Fixture::new();
        fixture.auth["url"] = json!(url);
        assert_eq!(fixture.verify().unwrap_err(), InjectorError::Url, "{url}");
    }
    let mut fixture = Fixture::new();
    fixture.auth["url"] = json!("https://API.OpenAI.com/v1");
    assert!(fixture.verify().is_ok());
}

#[test]
fn expired_future_and_long_lived_grants_are_rejected() {
    let fixture = Fixture::new();
    let grant = fixture.grant();
    let public = fixture.public();
    assert!(verify_grant(&public, &grant, NOW + 59).is_ok());
    assert_eq!(
        verify_grant(&public, &grant, NOW + 60).unwrap_err(),
        InjectorError::Expired
    );
    assert!(verify_grant(&public, &grant, NOW - 30).is_ok());
    assert_eq!(
        verify_grant(&public, &grant, NOW - 31).unwrap_err(),
        InjectorError::Expired
    );

    let mut long = Fixture::new();
    long.auth["exp"] = json!(NOW + 301);
    assert_eq!(long.verify().unwrap_err(), InjectorError::Expired);

    let mut inverted = Fixture::new();
    inverted.auth["exp"] = json!(NOW - 1);
    assert_eq!(inverted.verify().unwrap_err(), InjectorError::Expired);
}

#[test]
fn a_legacy_unsigned_grant_is_rejected() {
    let fixture = Fixture::new();
    let grant = serde_json::to_vec(&fixture.outer).unwrap();
    assert_eq!(
        verify_grant(&fixture.public(), &grant, NOW).unwrap_err(),
        InjectorError::Unsigned
    );
}

#[test]
fn ids_version_and_ciphertext_hash_must_match() {
    let mut fixture = Fixture::new();
    fixture.auth["secret_id"] = json!(Uuid::now_v7().to_string());
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::Policy);

    let mut fixture = Fixture::new();
    fixture.auth["v"] = json!(2);
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::Grant);

    let mut fixture = Fixture::new();
    fixture.auth["ciphertext_sha256"] = json!(sha256_hex(b"other"));
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::Policy);

    let fixture = Fixture::new();
    let mut outer = fixture.signed_outer(&fixture.signing);
    outer["payload_ciphertext"] = json!(b64_encode(b"swapped ciphertext"));
    let grant = serde_json::to_vec(&outer).unwrap();
    assert_eq!(
        verify_grant(&fixture.public(), &grant, NOW).unwrap_err(),
        InjectorError::Policy
    );
}

#[test]
fn only_the_six_methods_are_allowed() {
    for method in ["TRACE", "CONNECT", "OPTIONS", "get", ""] {
        let mut fixture = Fixture::new();
        fixture.auth["method"] = json!(method);
        assert_eq!(
            fixture.verify().unwrap_err(),
            InjectorError::Method,
            "{method}"
        );
    }
}

#[test]
fn header_names_and_formats_are_checked() {
    let mut fixture = Fixture::new();
    fixture.auth["header_format"] = json!("Bearer {value} {value}");
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::HeaderValue);

    let mut fixture = Fixture::new();
    fixture.auth["header_format"] = json!("Bearer {value}\r\nX-Evil: 1");
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::HeaderValue);

    let mut fixture = Fixture::new();
    fixture.auth["header_name"] = json!("Host");
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::HeaderValue);

    let mut fixture = Fixture::new();
    fixture.auth["header_name"] = json!("X Bad");
    assert_eq!(fixture.verify().unwrap_err(), InjectorError::HeaderValue);
}

#[tokio::test]
async fn a_body_that_does_not_match_the_hash_is_rejected() {
    let fixture = Fixture::new();
    let grant = fixture.verify().unwrap();
    let recorder = Recorder::default();
    let err = deliver(&grant, fixture.key(), b"{\"model\":\"y\"}", &recorder)
        .await
        .unwrap_err();
    assert_eq!(err, InjectorError::BodyMismatch);
    assert!(recorder.seen().is_none());
}

#[tokio::test]
async fn an_empty_body_hashes_the_empty_string() {
    let mut fixture = Fixture::new();
    fixture.auth["method"] = json!("GET");
    fixture.auth["body_sha256"] =
        json!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    fixture.auth["content_type"] = Value::Null;
    let grant = fixture.verify().unwrap();
    let recorder = Recorder::replying(b"ok");
    deliver(&grant, fixture.key(), b"", &recorder)
        .await
        .unwrap();
    let seen = recorder.seen().unwrap();
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.content_type, None);
}

#[tokio::test]
async fn a_response_that_reflects_the_secret_is_withheld() {
    let fixture = Fixture::new();
    let grant = fixture.verify().unwrap();
    for body in [
        b"echo: sk-injector".to_vec(),
        b"{\"auth\":\"Bearer sk-injector\"}".to_vec(),
    ] {
        let recorder = Recorder::replying(&body);
        let err = deliver(&grant, fixture.key(), BODY, &recorder)
            .await
            .unwrap_err();
        assert_eq!(err, InjectorError::Reflected);
    }
}

#[tokio::test]
async fn an_oversized_response_is_rejected() {
    let fixture = Fixture::new();
    let grant = fixture.verify().unwrap();
    let recorder = Recorder::replying(&vec![b'a'; MAX_RESPONSE_BYTES + 1]);
    let err = deliver(&grant, fixture.key(), BODY, &recorder)
        .await
        .unwrap_err();
    assert_eq!(err, InjectorError::ResponseTooLarge);
}

#[tokio::test]
async fn a_secret_with_a_line_break_never_reaches_a_header() {
    let fixture = Fixture::with_secret(b"sk-1\r\nX-Evil: 1");
    let grant = fixture.verify().unwrap();
    let recorder = Recorder::default();
    let err = deliver(&grant, fixture.key(), BODY, &recorder)
        .await
        .unwrap_err();
    assert_eq!(err, InjectorError::HeaderValue);
    assert!(recorder.seen().is_none());
}

#[tokio::test]
async fn header_delivery_hands_off_the_formatted_header() {
    let fixture = Fixture::new().header();
    let grant = fixture.verify().unwrap();
    assert!(matches!(grant.delivery, GrantDelivery::Header { .. }));
    let recorder = Recorder::default();
    let Delivered::Header(handoff) = deliver(&grant, fixture.key(), b"", &recorder)
        .await
        .unwrap()
    else {
        panic!("expected header");
    };
    assert_eq!(handoff.header_name, "Authorization");
    assert_eq!(handoff.value.as_str(), "Bearer sk-injector");
    assert!(!format!("{handoff:?}").contains("sk-injector"));
    let json: Value = serde_json::from_str(&handoff.to_json()).unwrap();
    assert_eq!(json["value"], "Bearer sk-injector");
    assert!(recorder.seen().is_none());

    let err = deliver(&grant, fixture.key(), b"x", &recorder)
        .await
        .unwrap_err();
    assert_eq!(err, InjectorError::Policy);
}

#[tokio::test]
async fn env_delivery_hands_off_the_variable() {
    let fixture = Fixture::new().env();
    let grant = fixture.verify().unwrap();
    let recorder = Recorder::default();
    let Delivered::Env(handoff) = deliver(&grant, fixture.key(), b"", &recorder)
        .await
        .unwrap()
    else {
        panic!("expected env");
    };
    assert_eq!(handoff.env_name, "OPENAI_API_KEY");
    assert_eq!(handoff.value.as_str(), "sk-injector");
    assert!(!format!("{handoff:?}").contains("sk-injector"));
    let json: Value = serde_json::from_str(&handoff.to_json()).unwrap();
    assert_eq!(json["env_name"], "OPENAI_API_KEY");
    assert_eq!(json["value"], "sk-injector");

    let mut bad = Fixture::new().env();
    bad.auth["env_name"] = json!("1BAD");
    assert_eq!(bad.verify().unwrap_err(), InjectorError::Policy);
}

#[test]
fn the_http_envelope_is_unwrapped() {
    let fixture = Fixture::new();
    let grant = fixture.grant();
    let envelope = serde_json::to_vec(&json!({
        "upstream_status": 200,
        "body": b64_encode(&grant),
    }))
    .unwrap();
    assert_eq!(grant_from_inject_response(&envelope).unwrap(), grant);
    assert_eq!(grant_from_inject_response(&grant).unwrap(), grant);
}

use crate::oidc::{authorize_url, challenge_from, role_for_group, OidcClient};
use crate::webauthn::{authenticate, register, Authenticator};

#[test]
fn webauthn_prf_stays_off_the_relying_party() {
    let auth = Authenticator::generate();
    let challenge = b"challenge-bytes-16b";
    let party = register(
        &auth,
        challenge,
        "credentials.local",
        "https://credentials.local",
    )
    .unwrap();
    authenticate(&party, &auth, challenge).unwrap();
    let prf = auth.prf(&party.salt);
    let stored = format!("{:?}", party.public_key);
    assert!(!stored.contains(&hex(&prf)));
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

//! Seal values from a `.env` file into `POST /v1/e2e-secrets` submissions.

use std::collections::HashSet;

use credentials_crypto::{seal_e2e, E2eSealed, VersionIds, DEFAULT_MAX_SECRET_BYTES};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::grant::valid_env_name;
use crate::json::b64_encode;
use crate::InjectorError;

/// One sealed import. The source plaintext is not a field.
#[derive(Debug)]
pub struct Imported {
    /// The variable name as written in the source, such as `OPENAI_API_KEY`.
    pub env_name: String,
    /// The gateway secret name derived from `env_name`, such as `prod/openai_api_key`.
    pub name: String,
    pub sealed: E2eSealed,
    pub ids: VersionIds,
}

/// Delivery policy written into each submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionPolicy {
    pub hosts: Vec<String>,
    pub header_name: Option<String>,
    pub header_format: Option<String>,
    pub allow_proxy: bool,
    pub allow_header: bool,
    pub allow_env: bool,
}

impl SubmissionPolicy {
    /// The same checks the gateway applies to a delivery policy.
    pub fn validate(&self) -> Result<(), InjectorError> {
        if !(self.allow_proxy || self.allow_header || self.allow_env) {
            return Err(InjectorError::Policy);
        }
        if self.allow_proxy || self.allow_header {
            if self.hosts.is_empty() {
                return Err(InjectorError::Policy);
            }
            let format = self.header_format.as_deref().unwrap_or("");
            if format.matches("{value}").count() != 1 || format.matches('{').count() != 1 {
                return Err(InjectorError::Policy);
            }
            if self.header_name.as_deref().unwrap_or("").is_empty() {
                return Err(InjectorError::Policy);
            }
        }
        let bare = |host: &String| {
            !host.is_empty()
                && !host.contains(':')
                && !host.contains('/')
                && !host.chars().any(char::is_whitespace)
        };
        if !self.hosts.iter().all(bare) {
            return Err(InjectorError::Policy);
        }
        Ok(())
    }
}

/// Parse `.env` text into `(env_name, value)` pairs.
///
/// Blank lines and `#` comments are skipped. A leading `export ` is removed.
/// A value wrapped in matching single or double quotes loses the quotes; no
/// escape sequences are interpreted. An unterminated quote is an error.
pub fn parse_dotenv(source: &str) -> Result<Vec<(String, Zeroizing<String>)>, InjectorError> {
    let mut pairs = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = strip_export(line);
        let (name, value) = line.split_once('=').ok_or(InjectorError::Import)?;
        let name = name.trim();
        if !valid_env_name(name) {
            return Err(InjectorError::Name);
        }
        let value = unquote(value.trim())?;
        if value.is_empty() {
            return Err(InjectorError::Import);
        }
        pairs.push((name.to_owned(), Zeroizing::new(value.to_owned())));
    }
    Ok(pairs)
}

fn strip_export(line: &str) -> &str {
    match line.strip_prefix("export") {
        Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
        _ => line,
    }
}

fn unquote(value: &str) -> Result<&str, InjectorError> {
    for quote in ['"', '\''] {
        if value.starts_with(quote) {
            if value.len() >= 2 && value.ends_with(quote) {
                return Ok(&value[1..value.len() - 1]);
            }
            return Err(InjectorError::Import);
        }
    }
    Ok(value)
}

/// Map an environment name to a gateway secret name: lowercase ASCII,
/// optionally behind `prefix` (for example `prod/`). The result must pass the
/// gateway's secret-name grammar.
pub fn secret_name_for(env_name: &str, prefix: Option<&str>) -> Result<String, InjectorError> {
    let name = format!("{}{}", prefix.unwrap_or(""), env_name.to_ascii_lowercase());
    if valid_secret_name(&name) {
        Ok(name)
    } else {
        Err(InjectorError::Name)
    }
}

/// Mirror of the gateway grammar: lowercase ASCII letters, digits, `_ . / -`,
/// first character a letter or digit, at most 256 bytes, and no empty, `.`,
/// or `..` path segment.
fn valid_secret_name(name: &str) -> bool {
    let Some(first) = name.chars().next() else {
        return false;
    };
    name.len() <= 256
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '/' | '-')
        })
        && name
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Seal each `(env_name, value)` pair and return only ciphertext.
/// This does not call Infisical, Doppler, 1Password, Vault, or a `.env` file
/// at inject time.
pub fn import_pairs(
    pairs: &[(String, Zeroizing<String>)],
    prefix: Option<&str>,
    encapsulation_key: &[u8],
    workspace_id: Uuid,
    workspace_key_id: Uuid,
) -> Result<Vec<Imported>, InjectorError> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(pairs.len());
    for (env_name, value) in pairs {
        if value.is_empty() {
            return Err(InjectorError::Import);
        }
        let name = secret_name_for(env_name, prefix)?;
        if !seen.insert(name.clone()) {
            return Err(InjectorError::Name);
        }
        let ids = VersionIds {
            workspace_id,
            secret_id: Uuid::now_v7(),
            version_id: Uuid::now_v7(),
        };
        let sealed = seal_e2e(
            encapsulation_key,
            workspace_key_id,
            ids,
            value.as_bytes(),
            DEFAULT_MAX_SECRET_BYTES,
        )
        .map_err(|_| InjectorError::Seal)?;
        out.push(Imported {
            env_name: env_name.clone(),
            name,
            sealed,
            ids,
        });
    }
    Ok(out)
}

/// Parse `.env` text and seal every value. See [`parse_dotenv`].
pub fn import_dotenv(
    source: &str,
    prefix: Option<&str>,
    encapsulation_key: &[u8],
    workspace_id: Uuid,
    workspace_key_id: Uuid,
) -> Result<Vec<Imported>, InjectorError> {
    let pairs = parse_dotenv(source)?;
    import_pairs(
        &pairs,
        prefix,
        encapsulation_key,
        workspace_id,
        workspace_key_id,
    )
}

/// The JSON body `POST /v1/e2e-secrets` accepts for one import. Ciphertext
/// only. With env delivery allowed, `env_name` is the source variable name.
pub fn submission_json(
    imported: &Imported,
    policy: &SubmissionPolicy,
) -> Result<Value, InjectorError> {
    policy.validate()?;
    let sealed = &imported.sealed;
    let env_name = if policy.allow_env {
        Some(imported.env_name.as_str())
    } else {
        None
    };
    Ok(serde_json::json!({
        "name": imported.name,
        "secret_id": imported.ids.secret_id.to_string(),
        "version_id": imported.ids.version_id.to_string(),
        "workspace_key_id": sealed.workspace_key_id.to_string(),
        "payload_nonce": b64_encode(&sealed.payload_nonce),
        "payload_ciphertext": b64_encode(&sealed.payload_ciphertext),
        "dek_wrap_nonce": b64_encode(&sealed.dek_wrap_nonce),
        "dek_wrapped": b64_encode(&sealed.dek_wrapped),
        "e2e_encapsulation": b64_encode(&sealed.encapsulation),
        "plaintext_len": sealed.plaintext_len,
        "policy": {
            "header_name": policy.header_name,
            "header_format": policy.header_format,
            "env_name": env_name,
            "hosts": policy.hosts,
            "allow_proxy": policy.allow_proxy,
            "allow_header": policy.allow_header,
            "allow_env": policy.allow_env,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use credentials_crypto::{generate_hybrid_keypair, open_e2e};

    #[test]
    fn dotenv_import_seals_and_drops_the_source_value() {
        let pair = generate_hybrid_keypair().unwrap();
        let workspace_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();
        let source = "# comment\nOPENAI_API_KEY=sk-import-canary\n\n";
        let imported =
            import_dotenv(source, None, &pair.encapsulation_key, workspace_id, key_id).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].env_name, "OPENAI_API_KEY");
        assert_eq!(imported[0].name, "openai_api_key");
        let blob = &imported[0].sealed.payload_ciphertext;
        assert!(!blob
            .windows(b"sk-import-canary".len())
            .any(|w| w == b"sk-import-canary"));
        let opened = open_e2e(
            pair.decapsulation_key(),
            &imported[0].sealed,
            imported[0].ids,
        )
        .unwrap();
        assert_eq!(opened.as_slice(), b"sk-import-canary");
    }

    #[test]
    fn quotes_and_export_are_stripped() {
        let source =
            "export A_KEY=\"two words\"\nexport\tB_KEY='single'\nC_KEY=  plain  \nD_KEY=\"\"x\"\n";
        let pairs = parse_dotenv(source).unwrap();
        let values: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            values,
            vec![
                ("A_KEY", "two words"),
                ("B_KEY", "single"),
                ("C_KEY", "plain"),
                ("D_KEY", "\"x"),
            ]
        );
    }

    #[test]
    fn unterminated_quotes_and_empty_values_are_rejected() {
        assert_eq!(
            parse_dotenv("A=\"open\n").unwrap_err(),
            InjectorError::Import
        );
        assert_eq!(parse_dotenv("A='\n").unwrap_err(), InjectorError::Import);
        assert_eq!(parse_dotenv("A=\"\"\n").unwrap_err(), InjectorError::Import);
        assert_eq!(
            parse_dotenv("NO_EQUALS\n").unwrap_err(),
            InjectorError::Import
        );
        assert_eq!(
            parse_dotenv("BAD-NAME=x\n").unwrap_err(),
            InjectorError::Name
        );
    }

    #[test]
    fn names_map_to_valid_secret_names() {
        assert_eq!(
            secret_name_for("OPENAI_API_KEY", Some("prod/")).unwrap(),
            "prod/openai_api_key"
        );
        assert_eq!(secret_name_for("Db_Url2", None).unwrap(), "db_url2");
        assert_eq!(
            secret_name_for("_HIDDEN", Some("prod/")).unwrap(),
            "prod/_hidden"
        );
        assert_eq!(
            secret_name_for("_HIDDEN", None).unwrap_err(),
            InjectorError::Name
        );
        assert_eq!(
            secret_name_for("KEY", Some("/prod/")).unwrap_err(),
            InjectorError::Name
        );
        assert_eq!(
            secret_name_for("KEY", Some("../")).unwrap_err(),
            InjectorError::Name
        );
        assert_eq!(
            secret_name_for("KEY", Some("Prod/")).unwrap_err(),
            InjectorError::Name
        );
    }

    #[test]
    fn names_that_collide_after_lowercasing_are_rejected() {
        let pair = generate_hybrid_keypair().unwrap();
        let err = import_dotenv(
            "API_KEY=one\napi_key=two\n",
            None,
            &pair.encapsulation_key,
            Uuid::now_v7(),
            Uuid::now_v7(),
        )
        .unwrap_err();
        assert_eq!(err, InjectorError::Name);
    }

    #[test]
    fn submission_has_the_e2e_secrets_shape() {
        let pair = generate_hybrid_keypair().unwrap();
        let key_id = Uuid::now_v7();
        let imported = import_dotenv(
            "export OPENAI_API_KEY='sk-shape'\n",
            Some("prod/"),
            &pair.encapsulation_key,
            Uuid::now_v7(),
            key_id,
        )
        .unwrap();
        let policy = SubmissionPolicy {
            hosts: vec!["api.openai.com".into()],
            header_name: Some("Authorization".into()),
            header_format: Some("Bearer {value}".into()),
            allow_proxy: true,
            allow_header: false,
            allow_env: true,
        };
        let body = submission_json(&imported[0], &policy).unwrap();
        assert_eq!(body["name"], "prod/openai_api_key");
        assert_eq!(body["workspace_key_id"], key_id.to_string());
        assert_eq!(body["policy"]["env_name"], "OPENAI_API_KEY");
        assert_eq!(body["policy"]["hosts"][0], "api.openai.com");
        assert!(body.get("value").is_none());
        for field in [
            "secret_id",
            "version_id",
            "payload_nonce",
            "payload_ciphertext",
            "dek_wrap_nonce",
            "dek_wrapped",
            "e2e_encapsulation",
        ] {
            assert!(body[field].is_string(), "{field}");
        }
        assert_eq!(body["plaintext_len"], 8);
        assert!(!body.to_string().contains("sk-shape"));

        let mut bad = policy.clone();
        bad.hosts.clear();
        assert_eq!(
            submission_json(&imported[0], &bad).unwrap_err(),
            InjectorError::Policy
        );
    }
}

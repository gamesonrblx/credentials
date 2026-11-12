//! Live reads from source secret stores.
//!
//! Each function returns name/value pairs in memory. The caller seals them
//! in the injector and drops the pairs. These functions do not write a file.
//!
//! `base` must be https unless its host is loopback, because each request
//! carries a bearer token. Every caller-supplied identifier is
//! percent-encoded into the URL. The gateway does not call these yet.

use crate::net::{component, path};
use serde::Deserialize;
use zeroize::Zeroizing;

/// One imported secret. `Debug` prints the name only, and the value is
/// zeroized on drop.
#[derive(Clone)]
pub struct SourceSecret {
    pub name: String,
    pub value: Zeroizing<String>,
}

impl std::fmt::Debug for SourceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceSecret")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

fn secret(name: String, value: &str) -> SourceSecret {
    SourceSecret {
        name,
        value: Zeroizing::new(value.to_owned()),
    }
}

fn bearer(token: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("Bearer {token}"))
}

fn base_url(base: &str) -> Result<&str, String> {
    if crate::net::is_secure_url(base) {
        Ok(base.trim_end_matches('/'))
    } else {
        Err("source URL must be https unless it is loopback".to_owned())
    }
}

pub fn read_infisical(
    base: &str,
    token: &str,
    workspace: &str,
    environment: &str,
) -> Result<Vec<SourceSecret>, String> {
    let url = format!(
        "{}/api/v3/secrets/raw?workspaceId={}&environment={}",
        base_url(base)?,
        component(workspace),
        component(environment)
    );
    let value = get_json(&url, &[("Authorization", &bearer(token))])?;
    let secrets = value
        .get("secrets")
        .and_then(|v| v.as_array())
        .ok_or("secrets")?;
    secrets
        .iter()
        .map(|item| {
            Ok(secret(
                item.get("secretKey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                item.get("secretValue")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            ))
        })
        .collect()
}

pub fn read_doppler(
    base: &str,
    token: &str,
    project: &str,
    config: &str,
) -> Result<Vec<SourceSecret>, String> {
    let url = format!(
        "{}/v3/configs/config/secrets?project={}&config={}",
        base_url(base)?,
        component(project),
        component(config)
    );
    let value = get_json(&url, &[("Authorization", &bearer(token))])?;
    let map = value
        .get("secrets")
        .and_then(|v| v.as_object())
        .ok_or("secrets")?;
    Ok(map
        .iter()
        .filter_map(|(name, item)| {
            item.get("computed")
                .and_then(|v| v.as_str())
                .map(|value| secret(name.clone(), value))
        })
        .collect())
}

pub fn read_onepassword(base: &str, token: &str, vault: &str) -> Result<Vec<SourceSecret>, String> {
    let base = base_url(base)?;
    let vault = component(vault);
    let url = format!("{base}/v1/vaults/{vault}/items");
    let auth = bearer(token);
    let value = get_json(&url, &[("Authorization", &auth)])?;
    let items = value.as_array().ok_or("items")?;
    let mut out = Vec::new();
    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).ok_or("id")?;
        let detail = get_json(
            &format!("{base}/v1/vaults/{vault}/items/{}", component(id)),
            &[("Authorization", &auth)],
        )?;
        let title = detail.get("title").and_then(|v| v.as_str()).unwrap_or(id);
        if let Some(fields) = detail.get("fields").and_then(|v| v.as_array()) {
            for field in fields {
                if field.get("purpose").and_then(|v| v.as_str()) == Some("PASSWORD")
                    || field.get("id").and_then(|v| v.as_str()) == Some("password")
                {
                    if let Some(value) = field.get("value").and_then(|v| v.as_str()) {
                        out.push(secret(title.to_owned(), value));
                    }
                }
            }
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct VaultKv {
    data: VaultData,
}

#[derive(Deserialize)]
struct VaultData {
    data: serde_json::Map<String, serde_json::Value>,
}

pub fn read_vault_kv(
    base: &str,
    token: &str,
    mount: &str,
    path_in_mount: &str,
) -> Result<Vec<SourceSecret>, String> {
    let url = format!(
        "{}/v1/{}/data/{}",
        base_url(base)?,
        path(mount).ok_or("invalid mount")?,
        path(path_in_mount).ok_or("invalid path")?
    );
    let bytes = get_bytes(&url, &[("X-Vault-Token", token)])?;
    // serde errors can quote input, so they are not passed on.
    let parsed: VaultKv =
        serde_json::from_slice(&bytes).map_err(|_| "source returned invalid JSON".to_owned())?;
    Ok(parsed
        .data
        .data
        .into_iter()
        .filter_map(|(name, value)| value.as_str().map(|text| secret(name, text)))
        .collect())
}

fn get_json(url: &str, headers: &[(&str, &str)]) -> Result<serde_json::Value, String> {
    let bytes = get_bytes(url, headers)?;
    serde_json::from_slice(&bytes).map_err(|_| "source returned invalid JSON".to_owned())
}

/// GET with a timeout. Errors name the status only, never the URL or a header.
fn get_bytes(url: &str, headers: &[(&str, &str)]) -> Result<Zeroizing<Vec<u8>>, String> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| "import runtime failed".to_owned())?
                    .block_on(async {
                        let client = crate::net::http_client().ok_or("import client failed")?;
                        let mut request = client.get(url);
                        for (name, value) in headers {
                            request = request.header(*name, *value);
                        }
                        let response = request
                            .send()
                            .await
                            .map_err(|_| "source request failed".to_owned())?;
                        if !response.status().is_success() {
                            return Err(format!("source returned {}", response.status()));
                        }
                        response
                            .bytes()
                            .await
                            .map(|b| Zeroizing::new(b.to_vec()))
                            .map_err(|_| "source response failed".to_owned())
                    })
            })
            .join()
            .unwrap_or_else(|_| Err("import thread failed".to_owned()))
    })
}

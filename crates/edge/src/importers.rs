//! Live reads from source secret stores.
//!
//! Each function returns name/value pairs in memory. The caller seals them
//! in the injector and drops the pairs. These functions do not write a file.

use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct SourceSecret {
    pub name: String,
    pub value: String,
}

pub fn read_infisical(
    base: &str,
    token: &str,
    workspace: &str,
    environment: &str,
) -> Result<Vec<SourceSecret>, String> {
    let url =
        format!("{base}/api/v3/secrets/raw?workspaceId={workspace}&environment={environment}");
    let value = get_json(&url, &[("Authorization", &format!("Bearer {token}"))])?;
    let secrets = value
        .get("secrets")
        .and_then(|v| v.as_array())
        .ok_or("secrets")?;
    secrets
        .iter()
        .map(|item| {
            Ok(SourceSecret {
                name: item
                    .get("secretKey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                value: item
                    .get("secretValue")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
            })
        })
        .collect()
}

pub fn read_doppler(
    base: &str,
    token: &str,
    project: &str,
    config: &str,
) -> Result<Vec<SourceSecret>, String> {
    let url = format!("{base}/v3/configs/config/secrets?project={project}&config={config}");
    let value = get_json(&url, &[("Authorization", &format!("Bearer {token}"))])?;
    let map = value
        .get("secrets")
        .and_then(|v| v.as_object())
        .ok_or("secrets")?;
    Ok(map
        .iter()
        .filter_map(|(name, item)| {
            item.get("computed")
                .and_then(|v| v.as_str())
                .map(|value| SourceSecret {
                    name: name.clone(),
                    value: value.to_owned(),
                })
        })
        .collect())
}

pub fn read_onepassword(base: &str, token: &str, vault: &str) -> Result<Vec<SourceSecret>, String> {
    let url = format!("{base}/v1/vaults/{vault}/items");
    let value = get_json(&url, &[("Authorization", &format!("Bearer {token}"))])?;
    let items = value.as_array().ok_or("items")?;
    let mut out = Vec::new();
    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).ok_or("id")?;
        let detail = get_json(
            &format!("{base}/v1/vaults/{vault}/items/{id}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )?;
        let title = detail.get("title").and_then(|v| v.as_str()).unwrap_or(id);
        if let Some(fields) = detail.get("fields").and_then(|v| v.as_array()) {
            for field in fields {
                if field.get("purpose").and_then(|v| v.as_str()) == Some("PASSWORD")
                    || field.get("id").and_then(|v| v.as_str()) == Some("password")
                {
                    if let Some(value) = field.get("value").and_then(|v| v.as_str()) {
                        out.push(SourceSecret {
                            name: title.to_owned(),
                            value: value.to_owned(),
                        });
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
    path: &str,
) -> Result<Vec<SourceSecret>, String> {
    let url = format!("{base}/v1/{mount}/data/{path}");
    let bytes = get_bytes(&url, &[("X-Vault-Token", token)])?;
    let parsed: VaultKv = serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;
    Ok(parsed
        .data
        .data
        .into_iter()
        .filter_map(|(name, value)| {
            value.as_str().map(|text| SourceSecret {
                name,
                value: text.to_owned(),
            })
        })
        .collect())
}

fn get_json(url: &str, headers: &[(&str, &str)]) -> Result<serde_json::Value, String> {
    let bytes = get_bytes(url, headers)?;
    serde_json::from_slice(&bytes).map_err(|err| err.to_string())
}

fn get_bytes(url: &str, headers: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    let url = url.to_owned();
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("import runtime")
                    .block_on(async move {
                        let client = reqwest::Client::new();
                        let mut request = client.get(url);
                        for (name, value) in headers {
                            request = request.header(name, value);
                        }
                        let response = request.send().await.map_err(|err| err.to_string())?;
                        if !response.status().is_success() {
                            return Err(format!("source returned {}", response.status()));
                        }
                        response
                            .bytes()
                            .await
                            .map(|b| b.to_vec())
                            .map_err(|err| err.to_string())
                    })
            })
            .join()
            .expect("import thread")
    })
}

//! End-to-end checks against free local containers.
//!
//! The integration CI job sets `CREDENTIALS_INTEGRATION=1` and the service
//! URLs. A normal `cargo test` skips these when that variable is absent.

use credentials_crypto::{KekContext, RootKeyProvider};
use credentials_edge::{read_vault_kv, AwsKms, VaultTransit};
use uuid::Uuid;

fn required(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(_) => {
            if std::env::var("CREDENTIALS_INTEGRATION").is_ok() {
                panic!("{name} is required in the integration job");
            }
            None
        }
    }
}

#[test]
fn localstack_kms_round_trip() {
    let Some(endpoint) = required("CREDENTIALS_TEST_KMS") else {
        return;
    };
    let kms = AwsKms::new(endpoint, "us-east-1", "test", "test");
    let workspace = Uuid::now_v7();
    let key = kms.create_tenant_root(workspace).expect("create key");
    let context = KekContext {
        workspace_id: workspace,
        kek_id: Uuid::now_v7(),
        kek_version: 1,
    };
    let blob = kms.encrypt(&key, b"kms-canary", &context).expect("encrypt");
    let plain = kms.decrypt(&key, &blob, &context).expect("decrypt");
    assert_eq!(plain.as_slice(), b"kms-canary");
}

#[test]
fn minio_object_lock_accepts_compliance_put() {
    let Some(endpoint) = required("CREDENTIALS_TEST_MINIO") else {
        return;
    };
    let bucket = format!("lock-{}", &Uuid::now_v7().simple().to_string()[..8]);
    create_locked_bucket(&endpoint, &bucket);
    let object = credentials_edge::put_locked(
        &endpoint,
        &bucket,
        "workspace/1",
        b"checkpoint",
        "2030-01-01T00:00:00Z",
        "minioadmin",
        "minioadmin",
    )
    .expect("put");
    assert_eq!(object.key, "workspace/1");
}

#[test]
fn vault_transit_and_kv_round_trip() {
    let Some(endpoint) = required("CREDENTIALS_TEST_VAULT") else {
        return;
    };
    enable_transit(&endpoint);
    let transit = VaultTransit::new(&endpoint, "root");
    let workspace = Uuid::now_v7();
    let key = transit.create_tenant_root(workspace).expect("transit key");
    let context = KekContext {
        workspace_id: workspace,
        kek_id: Uuid::now_v7(),
        kek_version: 1,
    };
    let blob = transit
        .encrypt(&key, b"vault-canary", &context)
        .expect("encrypt");
    let plain = transit.decrypt(&key, &blob, &context).expect("decrypt");
    assert_eq!(plain.as_slice(), b"vault-canary");
    write_kv(&endpoint);
    let rows = read_vault_kv(&endpoint, "root", "secret", "imports").expect("kv");
    assert_eq!(rows[0].name, "OPENAI_API_KEY");
    assert_eq!(rows[0].value, "sk-vault");
}

fn create_locked_bucket(endpoint: &str, bucket: &str) {
    let url = format!("{endpoint}/{bucket}");
    let (date, stamp) = credentials_edge::amz_now();
    let auth = credentials_edge::authorization(
        "PUT",
        &url,
        b"",
        "us-east-1",
        "s3",
        "minioadmin",
        "minioadmin",
        &date,
        &stamp,
    );
    let status = std::thread::scope(|scope| {
        let date = date.clone();
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        reqwest::Client::new()
                            .put(url)
                            .header("Authorization", auth)
                            .header("x-amz-date", date)
                            .header("x-amz-bucket-object-lock-enabled", "true")
                            .send()
                            .await
                            .unwrap()
                            .status()
                    })
            })
            .join()
            .unwrap()
    });
    assert!(status.is_success(), "create bucket {status}");
}

fn enable_transit(endpoint: &str) {
    let endpoint = endpoint.to_owned();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let _ = reqwest::Client::new()
                        .post(format!("{endpoint}/v1/sys/mounts/transit"))
                        .header("X-Vault-Token", "root")
                        .json(&serde_json::json!({"type": "transit"}))
                        .send()
                        .await;
                })
        });
    });
}

fn write_kv(endpoint: &str) {
    let endpoint = endpoint.to_owned();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    reqwest::Client::new()
                        .post(format!("{endpoint}/v1/secret/data/imports"))
                        .header("X-Vault-Token", "root")
                        .json(&serde_json::json!({"data": {"OPENAI_API_KEY": "sk-vault"}}))
                        .send()
                        .await
                        .unwrap()
                        .error_for_status()
                        .unwrap();
                })
        });
    });
}

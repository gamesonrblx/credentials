//! S3 Object Lock in compliance mode.
//!
//! The publisher can put an object. This client has no delete method.
//! A retention-locked bucket rejects delete. The test checks the request
//! headers. A MinIO job in CI can point `CREDENTIALS_TEST_MINIO` at a
//! locked bucket.

use crate::aws_kms::s3_authorization;

#[derive(Debug)]
pub struct LockError {
    pub detail: String,
}

pub struct LockedObject {
    pub key: String,
}

pub fn put_locked(
    endpoint: &str,
    bucket: &str,
    key: &str,
    body: &[u8],
    retain_until: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<LockedObject, LockError> {
    let url = format!("{endpoint}/{bucket}/{key}");
    let (amz_date, date_stamp) = crate::aws_kms::amz_now();
    let (auth, payload_hash) = s3_authorization(
        "PUT",
        &url,
        body,
        "us-east-1",
        access_key,
        secret_key,
        &amz_date,
        &date_stamp,
        &[
            ("x-amz-object-lock-mode", "COMPLIANCE"),
            ("x-amz-object-lock-retain-until-date", retain_until),
        ],
    );
    let endpoint = endpoint.to_owned();
    let bucket = bucket.to_owned();
    let key_owned = key.to_owned();
    let body = body.to_vec();
    let retain_until = retain_until.to_owned();
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("s3 runtime")
                    .block_on(async move {
                        let response = reqwest::Client::new()
                            .put(format!("{endpoint}/{bucket}/{key_owned}"))
                            .header("Authorization", auth)
                            .header("x-amz-date", amz_date)
                            .header("x-amz-content-sha256", payload_hash)
                            .header("x-amz-object-lock-mode", "COMPLIANCE")
                            .header("x-amz-object-lock-retain-until-date", retain_until)
                            .body(body)
                            .send()
                            .await
                            .map_err(|error| LockError {
                                detail: error.to_string(),
                            })?;
                        let status = response.status();
                        if status.is_success() {
                            Ok(())
                        } else {
                            let detail = response.text().await.unwrap_or_default();
                            Err(LockError {
                                detail: format!("{status} {detail}"),
                            })
                        }
                    })
            })
            .join()
            .expect("s3 thread")
    })?;
    Ok(LockedObject {
        key: key.to_owned(),
    })
}

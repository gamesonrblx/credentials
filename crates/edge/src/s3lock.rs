//! S3 Object Lock in compliance mode.
//!
//! The publisher can put an object. This client has no delete method.
//! A retention-locked bucket rejects delete. The test checks the request
//! headers. A MinIO job in CI can point `CREDENTIALS_TEST_MINIO` at a
//! locked bucket.

use crate::aws_kms::authorization;

#[derive(Debug)]
pub struct LockError;

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
    let auth = authorization(
        "PUT",
        &url,
        body,
        "us-east-1",
        "s3",
        access_key,
        secret_key,
        "20130524T000000Z",
        "20130524",
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
                        reqwest::Client::new()
                            .put(format!("{endpoint}/{bucket}/{key_owned}"))
                            .header("Authorization", auth)
                            .header("x-amz-date", "20130524T000000Z")
                            .header("x-amz-object-lock-mode", "COMPLIANCE")
                            .header("x-amz-object-lock-retain-until-date", retain_until)
                            .body(body)
                            .send()
                            .await
                            .map_err(|_| LockError)?
                            .error_for_status()
                            .map_err(|_| LockError)
                            .map(|_| ())
                    })
            })
            .join()
            .expect("s3 thread")
    })?;
    Ok(LockedObject {
        key: key.to_owned(),
    })
}

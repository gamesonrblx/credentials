//! S3 Object Lock in compliance mode.
//!
//! The publisher can put an object. This client has no delete method.
//! A retention-locked bucket rejects delete. The test checks the request
//! headers. A MinIO job in CI can point `CREDENTIALS_TEST_MINIO` at a
//! locked bucket.
//!
//! The endpoint must be https unless its host is loopback. The bucket and
//! each key segment are percent-encoded. Temporary credentials (a session
//! token) are not supported here yet. The gateway does not call this module.

use crate::aws_kms::s3_authorization;
use crate::net::{component, path};

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
    let fail = |detail: &str| LockError {
        detail: detail.to_owned(),
    };
    if !crate::net::is_secure_url(endpoint) {
        return Err(fail("endpoint must be https unless it is loopback"));
    }
    let encoded_key = path(key).ok_or_else(|| fail("invalid object key"))?;
    let url = format!(
        "{}/{}/{encoded_key}",
        endpoint.trim_end_matches('/'),
        component(bucket)
    );
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
    let body = body.to_vec();
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| fail("s3 runtime failed"))?
                    .block_on(async move {
                        let http = crate::net::http_client().ok_or_else(|| fail("s3 client"))?;
                        let response = http
                            .put(url)
                            .header("Authorization", auth)
                            .header("x-amz-date", amz_date)
                            .header("x-amz-content-sha256", payload_hash)
                            .header("x-amz-object-lock-mode", "COMPLIANCE")
                            .header("x-amz-object-lock-retain-until-date", retain_until)
                            .body(body)
                            .send()
                            .await
                            .map_err(|_| fail("s3 request failed"))?;
                        let status = response.status();
                        if status.is_success() {
                            Ok(())
                        } else {
                            // Keep the S3 error code only; the body can echo the request.
                            let text = response.text().await.unwrap_or_default();
                            let code = text
                                .split_once("<Code>")
                                .and_then(|(_, rest)| rest.split_once("</Code>"))
                                .map(|(code, _)| code)
                                .unwrap_or("");
                            Err(LockError {
                                detail: format!("{status} {code}"),
                            })
                        }
                    })
            })
            .join()
            .unwrap_or_else(|_| Err(fail("s3 thread failed")))
    })?;
    Ok(LockedObject {
        key: key.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_endpoints_and_escaping_keys_are_refused_before_any_request() {
        let put = |endpoint: &str, key: &str| {
            put_locked(
                endpoint,
                "bucket",
                key,
                b"x",
                "2030-01-01T00:00:00Z",
                "ak",
                "sk",
            )
        };
        let error = put("http://s3.example", "a").err().unwrap();
        assert!(error.detail.contains("https"));
        assert!(!error.detail.contains("sk"));
        assert_eq!(
            put("http://127.0.0.1:9", "a/../b").err().unwrap().detail,
            "invalid object key"
        );
    }
}

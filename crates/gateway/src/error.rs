use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// API failures. Messages stay generic so a response never carries key material
/// or a secret value.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("authentication failed")]
    Unauthenticated,
    #[error("the request is outside the token scope")]
    Forbidden,
    #[error("the secret was not found")]
    NotFound,
    #[error("the delivery policy is invalid")]
    InvalidPolicy,
    #[error("the secret is larger than the configured maximum")]
    PayloadTooLarge,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("the upstream call failed")]
    UpstreamFailed,
    #[error("the root-key provider is unavailable")]
    KmsUnavailable,
    #[error("the audit log could not be appended")]
    AuditFailed,
    #[error("the audit anchor is unavailable")]
    AuditAnchorUnavailable,
    #[error("the store is unavailable")]
    StoreUnavailable,
    #[error("the workspace is being deleted")]
    WorkspaceDeleting,
    #[error("the request is invalid")]
    BadRequest,
}

impl ApiError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::InvalidPolicy => "invalid_policy",
            Self::PayloadTooLarge => "payload_too_large",
            Self::DecryptFailed => "decrypt_failed",
            Self::UpstreamFailed => "upstream_failed",
            Self::KmsUnavailable => "kms_unavailable",
            Self::AuditFailed => "audit_failed",
            Self::AuditAnchorUnavailable => "audit_anchor_unavailable",
            Self::StoreUnavailable => "store_unavailable",
            Self::WorkspaceDeleting => "workspace_deleting",
            Self::BadRequest => "bad_request",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidPolicy => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::DecryptFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UpstreamFailed => StatusCode::BAD_GATEWAY,
            Self::KmsUnavailable
            | Self::AuditFailed
            | Self::StoreUnavailable
            | Self::AuditAnchorUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::WorkspaceDeleting => StatusCode::CONFLICT,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorInner<'a>,
}

#[derive(Serialize)]
struct ErrorInner<'a> {
    code: &'a str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody {
            error: ErrorInner {
                code: self.code(),
                message: self.to_string(),
            },
        };
        (status, Json(body)).into_response()
    }
}

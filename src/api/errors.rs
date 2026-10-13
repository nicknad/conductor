//! HTTP error mapping.
//!
//! Every rejection carries a stable machine-readable `code` plus the
//! underlying message. Signature failures map to `401 Unauthorized`
//! (the request is unauthenticated) except malformed envelopes, which are
//! `400`; semantic validation failures are `422`; oversized bodies are
//! `413`. The signature `VerificationFailed` message stays generic by
//! construction, so the mapping adds no verification oracle.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::application::validate_package::ValidationError;
use crate::packages::signature::SignatureError;

/// Machine-readable error body. `code` is stable for matching; `message`
/// carries the typed-error display string.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

/// HTTP-mapped failures for the upload API.
#[derive(Debug)]
pub enum ApiError {
    /// Malformed request: missing fields, bad base64, bad envelope shape.
    BadRequest(&'static str, String),
    /// Authentication failure: unknown key, disallowed algorithm, or a
    /// signature that does not verify.
    Unauthorized(&'static str, String),
    /// Well-formed but semantically invalid package.
    Unprocessable(&'static str, String),
    /// Body exceeds the policy byte bound while streaming.
    PayloadTooLarge(String),
    /// Validation timed out.
    Timeout,
    /// Unexpected server failure (I/O around quarantine, task join).
    Internal(String),
}

impl ApiError {
    fn status_and_body(&self) -> (StatusCode, ErrorBody) {
        match self {
            Self::BadRequest(code, message) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    code,
                    message: message.clone(),
                },
            ),
            Self::Unauthorized(code, message) => (
                StatusCode::UNAUTHORIZED,
                ErrorBody {
                    code,
                    message: message.clone(),
                },
            ),
            Self::Unprocessable(code, message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorBody {
                    code,
                    message: message.clone(),
                },
            ),
            Self::PayloadTooLarge(message) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorBody {
                    code: "payload_too_large",
                    message: message.clone(),
                },
            ),
            Self::Timeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorBody {
                    code: "validation_timeout",
                    message: "package validation timed out".to_owned(),
                },
            ),
            Self::Internal(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    code: "internal",
                    message: message.clone(),
                },
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = self.status_and_body();
        tracing::warn!(code = body.code, message = %body.message, "upload rejected");
        let mut response = (status, Json(body)).into_response();
        // RFC 9110: a 401 response must carry WWW-Authenticate. These
        // uploads authenticate with a detached package signature, not an
        // HTTP auth scheme, so the challenge names that mechanism.
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Signature realm=\"package-upload\""),
            );
        }
        response
    }
}

impl From<ValidationError> for ApiError {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::Signature(SignatureError::InvalidEnvelope(message)) => {
                Self::BadRequest("invalid_signature_envelope", message)
            }
            ValidationError::Signature(inner) => {
                let code = match inner {
                    SignatureError::UnknownKey(_) => "unknown_signing_key",
                    SignatureError::UnsupportedAlgorithm => "unsupported_signature_algorithm",
                    SignatureError::VerificationFailed => "signature_verification_failed",
                    SignatureError::InvalidEnvelope(_) => "invalid_signature_envelope",
                };
                Self::Unauthorized(code, inner.to_string())
            }
            ValidationError::Policy(inner) => {
                Self::Unprocessable("policy_rejected", inner.to_string())
            }
            ValidationError::Archive(inner) => {
                Self::Unprocessable("archive_rejected", inner.to_string())
            }
            ValidationError::Digest(inner) => {
                Self::Unprocessable("digest_failed", inner.to_string())
            }
            ValidationError::Manifest(inner) => {
                Self::Unprocessable("manifest_rejected", inner.to_string())
            }
            ValidationError::Inventory(inner) => {
                Self::Unprocessable("inventory_mismatch", inner.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_failures_are_unauthorized_except_envelope() {
        let err = ApiError::from(ValidationError::Signature(
            SignatureError::VerificationFailed,
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.code, "signature_verification_failed");

        let err = ApiError::from(ValidationError::Signature(SignatureError::InvalidEnvelope(
            "bad".to_owned(),
        )));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.code, "invalid_signature_envelope");
    }

    #[test]
    fn semantic_failures_are_unprocessable() {
        let err = ApiError::from(ValidationError::Inventory(
            crate::packages::inventory::InventoryError::MissingFile("x".to_owned()),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, "inventory_mismatch");
    }
}

//! HTTP error mapping.
//!
//! Every rejection carries a stable machine-readable `code` plus the
//! underlying message. Signature failures map to `401 Unauthorized`
//! (the request is unauthenticated) except malformed envelopes, which are
//! `400`; semantic validation failures are `422`; oversized bodies are
//! `413`. All key-lookup and cryptographic failures (`UnknownKey`,
//! `UnsupportedAlgorithm`, `VerificationFailed`) map to one generic
//! `signature_verification_failed` body so the response cannot be used to
//! enumerate trusted key ids. Internal detail is logged server-side at
//! conversion time, never echoed to the caller.

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
    /// Authentication failure. The `challenge` names the HTTP auth scheme
    /// so the `WWW-Authenticate` response header matches the mechanism
    /// that rejected the request (`Bearer` for transport auth, `Signature`
    /// for package authentication).
    Unauthorized {
        code: &'static str,
        message: String,
        challenge: &'static str,
    },
    /// Well-formed but semantically invalid package.
    Unprocessable(&'static str, String),
    /// The request conflicts with existing state (e.g. a module version
    /// already registered with a different digest).
    Conflict(&'static str, String),
    /// Body exceeds the policy byte bound while streaming.
    PayloadTooLarge(String),
    /// Request headers exceed the fixed count or byte caps.
    HeadersTooLarge(String),
    /// Body upload fell below the minimum speed floor.
    SlowUpload(String),
    /// Server is at its concurrent-upload bound.
    Overloaded(String),
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
            Self::Unauthorized {
                code,
                message,
                challenge: _,
            } => (
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
            Self::Conflict(code, message) => (
                StatusCode::CONFLICT,
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
            Self::HeadersTooLarge(message) => (
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                ErrorBody {
                    code: "headers_too_large",
                    message: message.clone(),
                },
            ),
            Self::SlowUpload(message) => (
                StatusCode::REQUEST_TIMEOUT,
                ErrorBody {
                    code: "slow_upload",
                    message: message.clone(),
                },
            ),
            Self::Overloaded(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorBody {
                    code: "server_busy",
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
        // RFC 9110: a 401 response must carry WWW-Authenticate naming the
        // scheme that rejected the request.
        if let Self::Unauthorized { challenge, .. } = &self {
            if let Ok(value) = axum::http::HeaderValue::from_str(challenge) {
                response
                    .headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
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
                // Unify the external body: distinguishing unknown keys from
                // bad signatures would let any bearer-token holder probe
                // for valid key ids. Log the internal variant for
                // operators, return a generic body to callers.
                tracing::warn!(internal = %inner, "package signature rejected");
                Self::Unauthorized {
                    code: "signature_verification_failed",
                    message: "package signature verification failed".to_owned(),
                    challenge: "Signature realm=\"package-upload\"",
                }
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
        // Unknown keys, disallowed algorithms, and bad signatures are
        // externally indistinguishable: one status, one code, one message.
        for inner in [
            SignatureError::VerificationFailed,
            SignatureError::UnknownKey("k9".to_owned()),
            SignatureError::UnsupportedAlgorithm,
        ] {
            let err = ApiError::from(ValidationError::Signature(inner));
            let (status, body) = err.status_and_body();
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body.code, "signature_verification_failed");
            assert_eq!(body.message, "package signature verification failed");
        }

        let err = ApiError::from(ValidationError::Signature(SignatureError::InvalidEnvelope(
            "bad".to_owned(),
        )));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.code, "invalid_signature_envelope");
    }

    #[test]
    fn transport_limits_map_to_431_408_and_503() {
        let (status, body) = ApiError::HeadersTooLarge("too many".to_owned()).status_and_body();
        assert_eq!(status, StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        assert_eq!(body.code, "headers_too_large");

        let (status, body) = ApiError::SlowUpload("too slow".to_owned()).status_and_body();
        assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
        assert_eq!(body.code, "slow_upload");

        let (status, body) = ApiError::Overloaded("busy".to_owned()).status_and_body();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.code, "server_busy");
    }

    #[test]
    fn semantic_failures_are_unprocessable() {
        let err = ApiError::from(ValidationError::Inventory(
            crate::packages::inventory::InventoryError::MissingFile("x".to_owned()),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.code, "inventory_mismatch");

        let (status, body) =
            ApiError::Conflict("version_conflict", "taken".to_owned()).status_and_body();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.code, "version_conflict");
    }
}

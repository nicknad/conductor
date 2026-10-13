//! HTTP error mapping.
//!
//! Every rejection carries a stable machine-readable `code` plus the
//! underlying message. Signature failures map to `401 Unauthorized`
//! (the request is unauthenticated) except malformed envelopes, which are
//! `400`; semantic validation failures are `422`; oversized bodies are
//! `413`. All key-lookup and cryptographic failures (`UnknownKey`,
//! `UnsupportedAlgorithm`, `VerificationFailed`) map to one generic
//! `signature_verification_failed` body so the response cannot be used to
//! enumerate trusted key ids. Internal detail is recorded server-side as a
//! structured rejection event (see `crate::api::rejection`), never echoed
//! to the caller. The stable `code` values double as the audit taxonomy.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::application::validate_package::ValidationError;
use crate::audit::event::RejectionStage;
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
    /// HTTP status for this rejection.
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(..) => StatusCode::BAD_REQUEST,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Unprocessable(..) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict(..) => StatusCode::CONFLICT,
            Self::PayloadTooLarge(..) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::HeadersTooLarge(..) => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::SlowUpload(..) => StatusCode::REQUEST_TIMEOUT,
            Self::Overloaded(..) | Self::Timeout => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(..) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable machine-readable code: part of the response contract and the
    /// audit event taxonomy.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(code, _)
            | Self::Unauthorized { code, .. }
            | Self::Unprocessable(code, _)
            | Self::Conflict(code, _) => code,
            Self::PayloadTooLarge(..) => "payload_too_large",
            Self::HeadersTooLarge(..) => "headers_too_large",
            Self::SlowUpload(..) => "slow_upload",
            Self::Overloaded(..) => "server_busy",
            Self::Timeout => "validation_timeout",
            Self::Internal(..) => "internal",
        }
    }

    /// Caller-facing message. Internal audit detail may be more specific
    /// (see [`crate::api::rejection::Rejection`]).
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::BadRequest(_, message)
            | Self::Unprocessable(_, message)
            | Self::Conflict(_, message)
            | Self::PayloadTooLarge(message)
            | Self::HeadersTooLarge(message)
            | Self::SlowUpload(message)
            | Self::Overloaded(message)
            | Self::Internal(message) => message,
            Self::Unauthorized { message, .. } => message,
            Self::Timeout => "package validation timed out",
        }
    }

    /// Audit classification. Codes are the stable contract, so variants only
    /// constructed by [`From`]`<ValidationError>` are classified by code;
    /// the production path classifies by error variant instead
    /// ([`crate::api::rejection::Rejection::from_validation`]).
    pub(crate) fn stage(&self) -> RejectionStage {
        match self {
            Self::BadRequest(..) if self.code() == "invalid_signature_envelope" => {
                RejectionStage::Signature
            }
            Self::BadRequest(..) => RejectionStage::Multipart,
            Self::Unauthorized { challenge, .. } if challenge.starts_with("Signature") => {
                RejectionStage::Signature
            }
            Self::Unauthorized { .. } => RejectionStage::Transport,
            Self::Unprocessable(..) => match self.code() {
                "policy_rejected" => RejectionStage::Policy,
                "archive_rejected" => RejectionStage::Archive,
                "digest_failed" => RejectionStage::Digest,
                "manifest_rejected" => RejectionStage::Manifest,
                "inventory_mismatch" => RejectionStage::Inventory,
                _ => RejectionStage::Internal,
            },
            Self::Conflict(..) => RejectionStage::Registration,
            Self::PayloadTooLarge(..) | Self::SlowUpload(..) => RejectionStage::Streaming,
            Self::HeadersTooLarge(..) | Self::Overloaded(..) | Self::Timeout => {
                RejectionStage::Transport
            }
            Self::Internal(..) => RejectionStage::Internal,
        }
    }

    fn status_and_body(&self) -> (StatusCode, ErrorBody) {
        (
            self.status(),
            ErrorBody {
                code: self.code(),
                message: self.message().to_owned(),
            },
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = self.status_and_body();
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
            ValidationError::Signature(_) => {
                // Unify the external body: distinguishing unknown keys from
                // bad signatures would let any bearer-token holder probe
                // for valid key ids. The internal variant is preserved for
                // the audit record by `Rejection::from_validation`; the
                // caller gets one generic body.
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

    #[test]
    fn audit_stages_classify_transport_and_validation_failures() {
        for (api, stage) in [
            (
                ApiError::HeadersTooLarge("big".to_owned()),
                RejectionStage::Transport,
            ),
            (ApiError::Timeout, RejectionStage::Transport),
            (
                ApiError::PayloadTooLarge("big".to_owned()),
                RejectionStage::Streaming,
            ),
            (
                ApiError::SlowUpload("slow".to_owned()),
                RejectionStage::Streaming,
            ),
            (
                ApiError::Conflict("version_conflict", "taken".to_owned()),
                RejectionStage::Registration,
            ),
            (
                ApiError::Internal("io".to_owned()),
                RejectionStage::Internal,
            ),
        ] {
            assert_eq!(api.stage(), stage, "unexpected stage for {api:?}");
        }
        // Variants constructed only by `From<ValidationError>` classify by
        // their stable code.
        for (code, stage) in [
            ("policy_rejected", RejectionStage::Policy),
            ("archive_rejected", RejectionStage::Archive),
            ("digest_failed", RejectionStage::Digest),
            ("manifest_rejected", RejectionStage::Manifest),
            ("inventory_mismatch", RejectionStage::Inventory),
        ] {
            assert_eq!(
                ApiError::Unprocessable(code, String::new()).stage(),
                stage,
                "unexpected stage for {code}"
            );
        }
    }
}

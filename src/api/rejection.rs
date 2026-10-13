//! Upload rejections: the caller-facing error plus the audit evidence.
//!
//! [`Rejection`] couples the [`ApiError`] the caller sees with the internal
//! reason and attribution fields the audit record keeps. Exactly one event
//! is recorded per refused upload: typed paths convert through
//! [`Rejection::into_recorded_response`], which marks the response so the
//! transport fallback middleware (`audit_unhandled_rejections`) knows not
//! to record it again. The fallback covers responses produced by transport
//! layers (timeouts, body limits, panics) that never reached an error this
//! module could see.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::api::errors::ApiError;
use crate::control_plane::validate_package::ValidationError;
use crate::audit::event::{RejectionEvent, RejectionStage};
use crate::audit::recorder::RejectionRecorder;
use crate::packages::artifact::ValidatedArtifact;

/// Response extension marking that a rejection event for this response was
/// already recorded.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RejectionRecorded;

/// Audit-only fields beyond the response contract. Boxed so
/// `Result<_, Rejection>` stays small on hot paths.
#[derive(Debug)]
struct RejectionContext {
    stage: RejectionStage,
    detail: String,
    key_id: Option<String>,
    module_id: Option<String>,
    version: Option<String>,
    digest: Option<String>,
    byte_count: Option<u64>,
}

impl RejectionContext {
    fn new(stage: RejectionStage, detail: String) -> Self {
        Self {
            stage,
            detail,
            key_id: None,
            module_id: None,
            version: None,
            digest: None,
            byte_count: None,
        }
    }
}

/// One rejected upload. Constructed at the rejection site via
/// [`From`]`<ApiError>` / [`From`]`<ValidationError>`, enriched with
/// attribution where available, and converted once into a response plus
/// one recorded event.
#[derive(Debug)]
pub(crate) struct Rejection {
    api: ApiError,
    context: Box<RejectionContext>,
}

impl Rejection {
    /// From an error that is already response-shaped. The internal detail
    /// defaults to the caller message: nothing more specific exists for
    /// these paths.
    #[must_use]
    pub(crate) fn from_api(api: ApiError) -> Self {
        let stage = api.stage();
        let detail = api.message().to_owned();
        Self {
            api,
            context: Box::new(RejectionContext::new(stage, detail)),
        }
    }

    /// From a validation failure, preserving the internal variant (for
    /// example `UnknownKey("k9")`) while the response body stays unified.
    #[must_use]
    pub(crate) fn from_validation(err: ValidationError) -> Self {
        let stage = validation_stage(&err);
        let detail = err.to_string();
        Self {
            api: ApiError::from(err),
            context: Box::new(RejectionContext::new(stage, detail)),
        }
    }

    /// Attaches signer attribution and received byte count. Called once the
    /// signature envelope is parsed and streaming is complete.
    #[must_use]
    pub(crate) fn with_upload(mut self, key_id: Option<&str>, byte_count: Option<u64>) -> Self {
        self.context.key_id = key_id.map(str::to_owned);
        self.context.byte_count = byte_count;
        self
    }

    /// Attaches the module identity and digest from a validated artifact.
    #[must_use]
    pub(crate) fn with_artifact(mut self, artifact: &ValidatedArtifact) -> Self {
        self.context.module_id = Some(artifact.module_id().to_owned());
        self.context.version = Some(artifact.version().to_owned());
        self.context.digest = Some(artifact.digest().to_hex());
        self
    }

    /// Splits into the response contract and the audit event.
    #[must_use]
    pub(crate) fn into_parts(self, request_id: Option<String>) -> (ApiError, RejectionEvent) {
        let Self { api, context } = self;
        let RejectionContext {
            stage,
            detail,
            key_id,
            module_id,
            version,
            digest,
            byte_count,
        } = *context;
        let event = RejectionEvent::new(stage, api.code(), detail)
            .with_request_id(request_id)
            .with_key_id(key_id)
            .with_module_id(module_id)
            .with_version(version)
            .with_digest(digest)
            .with_byte_count(byte_count);
        (api, event)
    }

    /// Records exactly one rejection event and returns the caller-facing
    /// response, marked so the transport fallback does not record again.
    pub(crate) fn into_recorded_response(
        self,
        recorder: &RejectionRecorder,
        request_id: Option<String>,
    ) -> Response {
        let (api, event) = self.into_parts(request_id);
        recorder.record(&event);
        let mut response = api.into_response();
        response.extensions_mut().insert(RejectionRecorded);
        response
    }
}

impl From<ApiError> for Rejection {
    fn from(api: ApiError) -> Self {
        Self::from_api(api)
    }
}

impl From<ValidationError> for Rejection {
    fn from(err: ValidationError) -> Self {
        Self::from_validation(err)
    }
}

fn validation_stage(err: &ValidationError) -> RejectionStage {
    match err {
        ValidationError::Policy(_) => RejectionStage::Policy,
        ValidationError::Archive(_) => RejectionStage::Archive,
        ValidationError::Digest(_) => RejectionStage::Digest,
        ValidationError::Signature(_) => RejectionStage::Signature,
        ValidationError::Manifest(_) => RejectionStage::Manifest,
        ValidationError::Inventory(_) => RejectionStage::Inventory,
    }
}

/// Server-issued request id (`x-request-id`), for incident correlation.
/// Absent only before the request-id layer has run.
#[must_use]
pub(crate) fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Fallback decision for responses that carry no typed rejection. Only the
/// package-upload path's own 4xx/5xx responses are package rejections;
/// successes, health probes, unknown routes, and already-recorded
/// responses are ignored.
#[must_use]
pub(crate) fn fallback_event(
    path: &str,
    status: StatusCode,
    already_recorded: bool,
) -> Option<RejectionEvent> {
    let rejected = status.is_client_error() || status.is_server_error();
    if !rejected || already_recorded || path != crate::api::PACKAGE_UPLOAD_PATH {
        return None;
    }
    Some(RejectionEvent::new(
        RejectionStage::Transport,
        "unclassified_rejection",
        format!(
            "upload rejected with status {} before a typed rejection was recorded",
            status.as_u16()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::signature::SignatureError;

    #[test]
    fn recorded_response_keeps_the_contract_and_carries_the_marker() {
        let rejection = Rejection::from_api(ApiError::Overloaded("busy".to_owned()));
        let response = rejection.into_recorded_response(&RejectionRecorder::new(), None);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.extensions().get::<RejectionRecorded>().is_some(),
            "typed rejections must be marked recorded"
        );
    }

    #[test]
    fn signature_event_keeps_the_internal_reason_while_the_body_stays_uniform() {
        let rejection = Rejection::from_validation(ValidationError::Signature(
            SignatureError::UnknownKey("k9".to_owned()),
        ));
        let (api, event) = rejection.into_parts(Some("req-1".to_owned()));
        assert_eq!(api.code(), "signature_verification_failed");
        assert_eq!(api.message(), "package signature verification failed");
        assert_eq!(event.stage, RejectionStage::Signature);
        assert!(
            event.detail.contains("k9"),
            "internal key detail must survive: {}",
            event.detail
        );
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn direct_errors_classify_into_pipeline_stages() {
        for (api, stage) in [
            (
                ApiError::Overloaded("busy".to_owned()),
                RejectionStage::Transport,
            ),
            (
                ApiError::PayloadTooLarge("big".to_owned()),
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
            (
                ApiError::BadRequest("invalid_signature_envelope", "shape".to_owned()),
                RejectionStage::Signature,
            ),
        ] {
            let (_, event) = Rejection::from_api(api).into_parts(None);
            assert_eq!(event.stage, stage);
        }
    }

    #[test]
    fn fallback_only_covers_unmarked_upload_failures() {
        assert!(
            fallback_event(
                crate::api::PACKAGE_UPLOAD_PATH,
                StatusCode::SERVICE_UNAVAILABLE,
                false
            )
            .is_some(),
            "an unmarked 503 on the upload route must fall back"
        );
        assert!(fallback_event(
            crate::api::PACKAGE_UPLOAD_PATH,
            StatusCode::SERVICE_UNAVAILABLE,
            true
        )
        .is_none());
        assert!(fallback_event("/healthz", StatusCode::SERVICE_UNAVAILABLE, false).is_none());
        assert!(
            fallback_event(crate::api::PACKAGE_UPLOAD_PATH, StatusCode::CREATED, false).is_none()
        );
    }

    #[test]
    fn artifact_attribution_fills_module_version_and_digest() {
        let artifact = ValidatedArtifact::new(
            crate::packages::artifact::ArtifactDigest::new([7u8; 32]),
            "reporting-service".to_owned(),
            "1.2.0".to_owned(),
        );
        let (_, event) = Rejection::from_api(ApiError::Internal("promotion failed".to_owned()))
            .with_upload(Some("k1"), Some(9))
            .with_artifact(&artifact)
            .into_parts(None);
        assert_eq!(event.module_id.as_deref(), Some("reporting-service"));
        assert_eq!(event.version.as_deref(), Some("1.2.0"));
        assert_eq!(event.digest.as_deref().expect("digest").len(), 64);
        assert_eq!(event.key_id.as_deref(), Some("k1"));
        assert_eq!(event.byte_count, Some(9));
    }
}

//! Activation and execution HTTP surface.
//!
//! Both routes are bearer-authenticated and JSON-only:
//!
//! - `POST /v1/modules/{module_id}/activate` persists the active version and
//!   returns the registered identity (`module_id`, `version`, `digest`,
//!   `signer_key_id`).
//! - `POST /v1/modules/{module_id}/executions` runs one function of the
//!   active version (or an explicitly pinned one) through the shared
//!   [`ExecutionService`]. The response includes the stable lowercase
//!   outcome name and bounded stdout/stderr.
//!
//! Refusals are mapped once to stable codes and generic external messages:
//! missing module/version/active pointer is `404`; policy, integrity,
//! manifest, archive, and runtime refusals are `422`; a malformed request or
//! an over-maximum deadline is `400`; capacity exhaustion is `503`; a missing
//! or unreadable registered artifact and other storage/host failures are
//! `500` with no path or OS detail. The rejection audit
//! keeps only a stable sanitized reason plus safe attribution
//! (module/version); raw typed-error displays and client-supplied identity
//! strings never reach a row, and the request's configuration is never
//! recorded.

use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::errors::ApiError;
use crate::api::uploads::{request_id, AppState};
use crate::audit::event::{RejectionEvent, RejectionStage};
use crate::control_plane::activate_module::{ActivatedModule, ActivationError};
use crate::control_plane::execute_module::{ExecutionError, ExecutionReceipt};
use crate::executions::executor::{ExecutionError as ExecutorError, ExecutionOutcome, TargetError};
use crate::executions::protocol::MAX_FIELD_BYTES;
use crate::modules::activation::ActiveError;
use crate::storage::staging::StagingError;

/// Deadline applied when the caller omits `deadline_secs`, clamped down to
/// the host maximum when that maximum is lower.
const DEFAULT_EXECUTION_DEADLINE_SECS: u64 = 30;

/// Request body for activation. Only the registered version is selectable.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    pub version: String,
}

/// `200` body after the active pointer is persisted.
#[derive(Debug, Serialize)]
pub struct ActivateResponse {
    pub module_id: String,
    pub version: String,
    /// Lowercase hex SHA-256 over the registered artifact bytes.
    pub digest: String,
    pub signer_key_id: String,
}

/// Request body for one execution. `version` pins a registered version;
/// omitting it uses the active pointer. `configuration` is passed to the
/// worker and deliberately never logged or recorded.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    #[serde(default)]
    pub version: Option<String>,
    pub function: String,
    #[serde(default)]
    pub configuration: Option<serde_json::Value>,
    #[serde(default)]
    pub deadline_secs: Option<u64>,
}

/// `200` body for a completed execution. `outcome` is one of the stable
/// lowercase names from [`outcome_name`]; stdout carries the bounded raw
/// protocol response line.
#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub execution_id: String,
    pub module_id: String,
    pub version: String,
    pub digest: String,
    pub outcome: &'static str,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Stable wire names for [`ExecutionOutcome`]. These are part of the API
/// contract; changing one is a breaking change.
#[must_use]
pub fn outcome_name(outcome: &ExecutionOutcome) -> &'static str {
    match outcome {
        ExecutionOutcome::Succeeded { .. } => "succeeded",
        ExecutionOutcome::Failed { .. } => "failed",
        ExecutionOutcome::TimedOut { .. } => "timed_out",
        ExecutionOutcome::Cancelled { .. } => "cancelled",
        ExecutionOutcome::WorkerError { .. } => "worker_error",
        ExecutionOutcome::ProtocolViolation { .. } => "protocol_violation",
    }
}

/// Activates and persists a registered module version.
#[tracing::instrument(name = "activate_module", skip(state, headers, payload))]
pub async fn post_activate(
    State(state): State<AppState>,
    Path(module_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ActivateRequest>, JsonRejection>,
) -> Response {
    let id = request_id(&headers);
    let request = match payload {
        Ok(Json(request)) => request,
        Err(rejection) => {
            let api = json_rejection_error(rejection);
            return refuse(
                &state,
                id,
                RejectionStage::Request,
                api,
                "activation request body was rejected".to_owned(),
                attributable(&module_id),
                None,
            );
        }
    };
    if let Err(api) = validate_identity("module_id", &module_id) {
        return refuse(
            &state,
            id,
            RejectionStage::Activation,
            api,
            "activation module id is invalid".to_owned(),
            None,
            None,
        );
    }
    let version = request.version.as_str();
    if let Err(api) = validate_identity("version", version) {
        return refuse(
            &state,
            id,
            RejectionStage::Activation,
            api,
            "activation version is invalid".to_owned(),
            attributable(&module_id),
            None,
        );
    }

    match state.execution_service.activate(&module_id, version).await {
        Ok(activated) => Json(ActivateResponse::from(activated)).into_response(),
        Err(error) => {
            let api = activation_error(&error);
            let detail = execution_audit_detail(&error).to_owned();
            refuse(
                &state,
                id,
                RejectionStage::Activation,
                api,
                detail,
                Some(module_id),
                Some(version.to_owned()),
            )
        }
    }
}

/// Executes one function of the active (or pinned) module version.
#[tracing::instrument(
    name = "execute_module",
    skip(state, headers, payload),
    fields(deadline_secs = tracing::field::Empty)
)]
pub async fn post_execute(
    State(state): State<AppState>,
    Path(module_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ExecuteRequest>, JsonRejection>,
) -> Response {
    let id = request_id(&headers);
    let request = match payload {
        Ok(Json(request)) => request,
        Err(rejection) => {
            let api = json_rejection_error(rejection);
            return refuse(
                &state,
                id,
                RejectionStage::Request,
                api,
                "execution request body was rejected".to_owned(),
                attributable(&module_id),
                None,
            );
        }
    };
    if let Err(api) = validate_identity("module_id", &module_id) {
        return refuse(
            &state,
            id,
            RejectionStage::Execution,
            api,
            "execution module id is invalid".to_owned(),
            None,
            None,
        );
    }
    let function = request.function.as_str();
    if let Err(api) = validate_identity("function", function) {
        return refuse(
            &state,
            id,
            RejectionStage::Execution,
            api,
            "execution function is invalid".to_owned(),
            attributable(&module_id),
            None,
        );
    }
    let pinned = match request.version.as_deref() {
        None => None,
        Some(version) => {
            if let Err(api) = validate_identity("version", version) {
                return refuse(
                    &state,
                    id,
                    RejectionStage::Execution,
                    api,
                    "execution version is invalid".to_owned(),
                    attributable(&module_id),
                    None,
                );
            }
            Some(version.to_owned())
        }
    };
    let maximum_deadline = state.execution_service.max_deadline();
    let deadline_secs = match request.deadline_secs {
        Some(secs) => secs,
        // The documented default is 30 seconds, but never more than the host
        // ceiling: a low configured maximum must remain usable when the
        // caller omits the field.
        None => maximum_deadline
            .as_secs()
            .min(DEFAULT_EXECUTION_DEADLINE_SECS),
    };
    if deadline_secs == 0 {
        return refuse(
            &state,
            id,
            RejectionStage::Execution,
            ApiError::BadRequest(
                "invalid_deadline",
                "deadline_secs must be greater than zero".to_owned(),
            ),
            "execution deadline must be positive".to_owned(),
            attributable(&module_id),
            pinned,
        );
    }
    if Duration::from_secs(deadline_secs) > maximum_deadline {
        return refuse(
            &state,
            id,
            RejectionStage::Execution,
            ApiError::BadRequest(
                "deadline_exceeded",
                "requested deadline exceeds the host maximum".to_owned(),
            ),
            "requested deadline exceeds the host maximum".to_owned(),
            attributable(&module_id),
            pinned,
        );
    }
    tracing::Span::current().record("deadline_secs", deadline_secs);
    let configuration = request.configuration.unwrap_or(serde_json::Value::Null);
    if !configuration.is_object() && !configuration.is_null() {
        return refuse(
            &state,
            id,
            RejectionStage::Execution,
            ApiError::BadRequest(
                "invalid_configuration",
                "configuration must be a JSON object".to_owned(),
            ),
            "execution configuration is not an object".to_owned(),
            attributable(&module_id),
            pinned,
        );
    }

    let audit_version = pinned.clone();
    match state
        .execution_service
        .execute(
            &module_id,
            pinned.as_deref(),
            function,
            configuration,
            Duration::from_secs(deadline_secs),
        )
        .await
    {
        Ok(receipt) => Json(ExecuteResponse::from(receipt)).into_response(),
        Err(error) => {
            let api = execution_error(&error);
            let detail = execution_audit_detail(&error).to_owned();
            refuse(
                &state,
                id,
                RejectionStage::Execution,
                api,
                detail,
                Some(module_id),
                audit_version,
            )
        }
    }
}

impl From<ActivatedModule> for ActivateResponse {
    fn from(activated: ActivatedModule) -> Self {
        Self {
            module_id: activated.module_id,
            version: activated.version,
            digest: activated.digest.to_hex(),
            signer_key_id: activated.signer_key_id,
        }
    }
}

impl From<ExecutionReceipt> for ExecuteResponse {
    fn from(receipt: ExecutionReceipt) -> Self {
        Self {
            execution_id: receipt.execution_id,
            module_id: receipt.module_id,
            version: receipt.version,
            digest: receipt.digest.to_hex(),
            outcome: outcome_name(&receipt.outcome),
            stdout: receipt.stdout.text_lossy().into_owned(),
            stderr: receipt.stderr.text_lossy().into_owned(),
            duration_ms: u64::try_from(receipt.duration.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// Rejects empty, over-bound, or unsafe identity fields before any registry
/// or filesystem work. Allowed characters are the portable path-safe set
/// used for registered module identities: `[A-Za-z0-9._+-]`, with no
/// leading/trailing dot. This excludes path separators, whitespace, control
/// characters, and ANSI escape bytes.
fn validate_identity(field: &'static str, value: &str) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(ApiError::BadRequest(
            "invalid_identity",
            format!("{field} must not be empty"),
        ));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(ApiError::BadRequest(
            "invalid_identity",
            format!("{field} must be at most {MAX_FIELD_BYTES} bytes"),
        ));
    }
    if !is_safe_identity(value) {
        return Err(ApiError::BadRequest(
            "invalid_identity",
            format!("{field} must be a path-safe identity component"),
        ));
    }
    Ok(())
}

/// True for the same portable identity shape the manifest layer requires of
/// `module_id`/`version`, applied to API path/body identities before use.
fn is_safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FIELD_BYTES
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

/// Attribution is persisted only for identities that passed the safe-charset
/// validation. A malformed client string never reaches an audit row.
fn attributable(value: &str) -> Option<String> {
    is_safe_identity(value).then(|| value.to_owned())
}

/// Maps a JSON extractor refusal to the API contract. Body-limit rejections
/// stay `413`; every other malformed or unsupported body is `400`.
fn json_rejection_error(rejection: JsonRejection) -> ApiError {
    if rejection.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge("request body exceeds the allowed size".to_owned())
    } else {
        ApiError::BadRequest(
            "invalid_request_body",
            "request body must be valid JSON matching the documented schema".to_owned(),
        )
    }
}

/// Records one refusal and returns the caller-facing response. `detail` is
/// the internal typed reason for audit; it is never placed in the body.
fn refuse(
    state: &AppState,
    request_id: Option<String>,
    stage: RejectionStage,
    api: ApiError,
    detail: String,
    module_id: Option<String>,
    version: Option<String>,
) -> Response {
    let code = api.code();
    state.recorder.record(
        &RejectionEvent::new(stage, code, detail)
            .with_request_id(request_id)
            .with_module_id(module_id)
            .with_version(version),
    );
    api.into_response()
}

/// Activation failure mapping. The external message is fixed, so registry
/// paths and storage errors cannot reach the caller.
fn activation_error(error: &ExecutionError) -> ApiError {
    match error {
        ExecutionError::Activation(inner) => activation_policy_error(inner),
        ExecutionError::PersistActive(inner) => active_error(inner),
        ExecutionError::Registry(_) => internal(),
        ExecutionError::EmptySignerAllowlist
        | ExecutionError::InvalidConcurrency { .. }
        | ExecutionError::InvalidStorageDirectory { .. }
        | ExecutionError::BlockingTask(_)
        | ExecutionError::ArtifactDirectory { .. } => internal(),
        ExecutionError::DeadlineExceeded { .. } => deadline_exceeded(),
        ExecutionError::Overloaded { .. } => overloaded(),
        ExecutionError::LegacyManifest { .. } => ApiError::Unprocessable(
            "legacy_manifest",
            "execution requires manifest v2 with per-file integrity".to_owned(),
        ),
        ExecutionError::SignerNotAllowed { .. } => not_permitted(),
        ExecutionError::ArtifactPathEscape { .. }
        | ExecutionError::ArtifactPathNotCanonical { .. }
        | ExecutionError::ArtifactTooLarge { .. }
        | ExecutionError::ArtifactSizeMismatch { .. }
        | ExecutionError::ArtifactDigestMismatch { .. }
        | ExecutionError::RecordDigestMismatch { .. } => artifact_integrity(),
        ExecutionError::ArtifactMissing { .. } | ExecutionError::ArtifactUnreadable { .. } => {
            internal()
        }
        ExecutionError::Manifest(_)
        | ExecutionError::ManifestIdentityMismatch { .. }
        | ExecutionError::ArchiveManifestMismatch { .. } => ApiError::Unprocessable(
            "manifest_invalid",
            "stored manifest is not usable for execution".to_owned(),
        ),
        ExecutionError::Archive(_) => ApiError::Unprocessable(
            "archive_invalid",
            "registered artifact archive is not usable".to_owned(),
        ),
        ExecutionError::Staging(inner) => staging_error(inner),
        ExecutionError::Target(inner) => target_error(inner),
        ExecutionError::Executor(inner) => executor_error(inner),
    }
}

/// Execution failure mapping, including activation errors raised while
/// resolving the active or pinned version.
fn execution_error(error: &ExecutionError) -> ApiError {
    activation_error(error)
}

fn activation_policy_error(error: &ActivationError) -> ApiError {
    match error {
        ActivationError::EmptyRuntimeAllowlist => internal(),
        ActivationError::NotRegistered { .. } => ApiError::NotFound(
            "module_not_found",
            "module version is not registered".to_owned(),
        ),
        ActivationError::NoActiveVersion { .. } => ApiError::NotFound(
            "module_not_active",
            "module has no active version".to_owned(),
        ),
        ActivationError::Integrity { .. } => ApiError::Unprocessable(
            "artifact_not_intact",
            "module artifact is not intact".to_owned(),
        ),
        ActivationError::RuntimeNotAllowed { .. } => ApiError::Unprocessable(
            "runtime_not_allowed",
            "module runtime is not allowed to execute".to_owned(),
        ),
        ActivationError::Storage(_) => internal(),
    }
}

fn active_error(error: &ActiveError) -> ApiError {
    match error {
        ActiveError::NotRegistered { .. } => ApiError::NotFound(
            "module_not_found",
            "module version is not registered".to_owned(),
        ),
        ActiveError::Integrity { .. } => ApiError::Unprocessable(
            "artifact_not_intact",
            "module artifact is not intact".to_owned(),
        ),
        ActiveError::Storage(_) => internal(),
    }
}

fn executor_error(error: &ExecutorError) -> ApiError {
    match error {
        ExecutorError::InvalidRequest(_) => ApiError::BadRequest(
            "invalid_execution_request",
            "execution request is not valid".to_owned(),
        ),
        ExecutorError::TargetVerification(inner) => target_error(inner),
        ExecutorError::Spawn(_) => internal(),
    }
}

/// Staging refusals split content failures (`422`) from host I/O (`500`).
/// The caller-facing message is fixed either way, so a filesystem path or
/// OS error never reaches the response body.
fn staging_error(error: &StagingError) -> ApiError {
    match error {
        StagingError::Io(_) => internal(),
        StagingError::SourceChanged | StagingError::Digest(_) | StagingError::Archive(_) => {
            ApiError::Unprocessable(
                "package_invalid",
                "registered package could not be staged for execution".to_owned(),
            )
        }
    }
}

/// Staged-target refusals split host I/O/executable-bit failures (`500`) from
/// content/integrity failures (`422`).
fn target_error(error: &TargetError) -> ApiError {
    match error {
        TargetError::StagedFileUnreadable { .. } | TargetError::EntrypointNotExecutable(_) => {
            internal()
        }
        TargetError::StagedFileChanged { .. }
        | TargetError::EntrypointRejected(_)
        | TargetError::EntrypointMissing => ApiError::Unprocessable(
            "package_invalid",
            "staged package failed verification".to_owned(),
        ),
    }
}

/// Stable, sanitized audit reason for an activation/execution refusal.
/// It deliberately never includes an error `Display` string: those carry
/// artifact relpaths and OS messages. Safe attribution travels in the event's
/// `module_id`/`version` fields instead.
fn execution_audit_detail(error: &ExecutionError) -> &'static str {
    match error {
        ExecutionError::Activation(inner) => activation_audit_detail(inner),
        ExecutionError::PersistActive(_) => "failed to persist the active version",
        ExecutionError::Registry(_) => "registry storage failure",
        ExecutionError::DeadlineExceeded { .. } => "requested deadline exceeds the host maximum",
        ExecutionError::Overloaded { .. } => "activation or execution capacity exhausted",
        ExecutionError::EmptySignerAllowlist => "execution signer allowlist is empty",
        ExecutionError::InvalidConcurrency { .. } => {
            "execution concurrency is outside the supported range"
        }
        ExecutionError::InvalidStorageDirectory { .. } => {
            "execution storage directory is unavailable"
        }
        ExecutionError::LegacyManifest { .. } => "execution requires manifest v2",
        ExecutionError::BlockingTask(_) => "blocking activation or execution task failed",
        ExecutionError::SignerNotAllowed { .. } => "signer is not allowed to execute",
        ExecutionError::ArtifactDirectory { .. } => "artifact directory is unavailable",
        ExecutionError::ArtifactPathEscape { .. } => "artifact path escapes the artifact directory",
        ExecutionError::ArtifactPathNotCanonical { .. } => "artifact path is not canonical",
        ExecutionError::ArtifactMissing { .. } => "registered artifact is missing",
        ExecutionError::ArtifactUnreadable { .. } => "registered artifact is unreadable",
        ExecutionError::ArtifactTooLarge { .. } => "registered artifact exceeds the size bound",
        ExecutionError::ArtifactSizeMismatch { .. } => "registered artifact size mismatch",
        ExecutionError::ArtifactDigestMismatch { .. } => "registered artifact digest mismatch",
        ExecutionError::RecordDigestMismatch { .. } => "registry record digest mismatch",
        ExecutionError::Manifest(_) => "stored manifest is invalid",
        ExecutionError::ManifestIdentityMismatch { .. } => "stored manifest identity mismatch",
        ExecutionError::ArchiveManifestMismatch { .. } => "archive manifest mismatch",
        ExecutionError::Archive(_) => "registered archive is invalid",
        ExecutionError::Staging(inner) => staging_audit_detail(inner),
        ExecutionError::Target(inner) => target_audit_detail(inner),
        ExecutionError::Executor(inner) => executor_audit_detail(inner),
    }
}

fn activation_audit_detail(error: &ActivationError) -> &'static str {
    match error {
        ActivationError::EmptyRuntimeAllowlist => "activation runtime allowlist is empty",
        ActivationError::NotRegistered { .. } => "module version is not registered",
        ActivationError::NoActiveVersion { .. } => "module has no active version",
        ActivationError::Integrity { .. } => "module artifact is not intact",
        ActivationError::RuntimeNotAllowed { .. } => "module runtime is not allowed",
        ActivationError::Storage(_) => "registry lookup failed",
    }
}

fn staging_audit_detail(error: &StagingError) -> &'static str {
    match error {
        StagingError::Io(_) => "staging host I/O failed",
        StagingError::SourceChanged | StagingError::Digest(_) | StagingError::Archive(_) => {
            "package staging refused the bytes"
        }
    }
}

fn target_audit_detail(error: &TargetError) -> &'static str {
    match error {
        TargetError::StagedFileUnreadable { .. } | TargetError::EntrypointNotExecutable(_) => {
            "staged target host I/O failed"
        }
        TargetError::StagedFileChanged { .. }
        | TargetError::EntrypointRejected(_)
        | TargetError::EntrypointMissing => "staged target failed verification",
    }
}

fn executor_audit_detail(error: &ExecutorError) -> &'static str {
    match error {
        ExecutorError::InvalidRequest(_) => "execution request is invalid",
        ExecutorError::TargetVerification(inner) => target_audit_detail(inner),
        ExecutorError::Spawn(_) => "worker spawn failed",
    }
}

fn internal() -> ApiError {
    ApiError::Internal("execution host failure".to_owned())
}

fn deadline_exceeded() -> ApiError {
    ApiError::BadRequest(
        "deadline_exceeded",
        "requested deadline exceeds the host maximum".to_owned(),
    )
}

fn overloaded() -> ApiError {
    ApiError::Overloaded("server is at its execution bound; retry later".to_owned())
}

fn not_permitted() -> ApiError {
    ApiError::Unprocessable(
        "execution_not_permitted",
        "module version is not permitted to execute".to_owned(),
    )
}

fn artifact_integrity() -> ApiError {
    ApiError::Unprocessable(
        "artifact_integrity_failed",
        "registered artifact failed integrity verification".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_names_are_stable_lowercase() {
        assert_eq!(
            outcome_name(&ExecutionOutcome::Succeeded {
                result: serde_json::Value::Null
            }),
            "succeeded"
        );
        assert_eq!(
            outcome_name(&ExecutionOutcome::Failed {
                message: "nope".to_owned()
            }),
            "failed"
        );
        assert_eq!(
            outcome_name(&ExecutionOutcome::TimedOut {
                deadline: Duration::from_secs(1)
            }),
            "timed_out"
        );
        assert_eq!(
            outcome_name(&ExecutionOutcome::Cancelled {
                reason: "stop".to_owned()
            }),
            "cancelled"
        );
        assert_eq!(
            outcome_name(&ExecutionOutcome::WorkerError {
                detail: "exit".to_owned()
            }),
            "worker_error"
        );
        assert_eq!(
            outcome_name(&ExecutionOutcome::ProtocolViolation {
                detail: "bad".to_owned()
            }),
            "protocol_violation"
        );
    }

    #[test]
    fn execution_errors_never_expose_paths_or_manifest_text() {
        let errors = [
            ExecutionError::ArtifactMissing {
                relpath: "reporting/1.2.0/secret.zip".to_owned(),
            },
            ExecutionError::ArtifactUnreadable {
                relpath: "reporting/1.2.0/secret.zip".to_owned(),
                detail: "Permission denied (os error 13)".to_owned(),
            },
            ExecutionError::ManifestIdentityMismatch {
                module_id: "reporting".to_owned(),
                version: "1.2.0".to_owned(),
                field: "module_id",
                expected: "reporting".to_owned(),
                actual: "other".to_owned(),
            },
            ExecutionError::LegacyManifest {
                module_id: "reporting".to_owned(),
                version: "1.2.0".to_owned(),
                manifest_version: 1,
            },
            ExecutionError::ArtifactDigestMismatch {
                relpath: "reporting/1.2.0/secret.zip".to_owned(),
            },
        ];
        for error in errors {
            let api = execution_error(&error);
            let (_, body) = api.status_and_body();
            assert!(!body.message.contains("secret.zip"), "{}", body.message);
            assert!(!body.message.contains('/'), "{}", body.message);
            assert!(!body.message.contains("os error"), "{}", body.message);
            let detail = execution_audit_detail(&error);
            assert!(!detail.contains("secret.zip"), "{detail}");
            assert!(!detail.contains('/'), "{detail}");
            assert!(!detail.contains("os error"), "{detail}");
        }
    }

    #[test]
    fn host_io_failures_map_to_generic_internal_errors() {
        let errors = [
            ExecutionError::ArtifactMissing {
                relpath: "reporting/1.2.0/secret.zip".to_owned(),
            },
            ExecutionError::ArtifactUnreadable {
                relpath: "reporting/1.2.0/secret.zip".to_owned(),
                detail: "Permission denied (os error 13)".to_owned(),
            },
            ExecutionError::Staging(StagingError::Io(
                "creating stage: /data/staging: Permission denied (os error 13)".to_owned(),
            )),
            ExecutionError::Target(TargetError::StagedFileUnreadable {
                path: "payload/worker".to_owned(),
                detail: "Permission denied (os error 13)".to_owned(),
            }),
            ExecutionError::Target(TargetError::EntrypointNotExecutable(
                "Operation not permitted (os error 1)".to_owned(),
            )),
            ExecutionError::Executor(ExecutorError::Spawn(
                "No such file or directory (os error 2)".to_owned(),
            )),
            ExecutionError::Executor(ExecutorError::TargetVerification(
                TargetError::StagedFileUnreadable {
                    path: "payload/worker".to_owned(),
                    detail: "Permission denied (os error 13)".to_owned(),
                },
            )),
        ];
        for error in errors {
            let (status, body) = execution_error(&error).status_and_body();
            assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(body.code, "internal");
            assert_eq!(body.message, "internal error");
            let detail = execution_audit_detail(&error);
            assert!(!detail.contains("os error"), "{detail}");
            assert!(!detail.contains(".zip"), "{detail}");
            assert!(!detail.contains("Permission denied"), "{detail}");
        }
    }

    #[test]
    fn identity_validation_rejects_separators_controls_and_ansi() {
        for value in [
            "reporting/1.2.0",
            "reporting\\1.2.0",
            "reporting\n1.2.0",
            "reporting\t1.2.0",
            "reporting\u{1b}[31m",
            "..",
            ".hidden",
            "trailing.",
            "with space",
            "",
        ] {
            assert!(
                validate_identity("module_id", value).is_err(),
                "{value:?} must be refused"
            );
            assert_eq!(
                attributable(value),
                None,
                "{value:?} must not be attributed"
            );
        }
        for value in ["reporting-service", "1.2.3+build.7", "run", "a_b.c"] {
            assert!(
                validate_identity("module_id", value).is_ok(),
                "{value:?} must be accepted"
            );
            assert_eq!(attributable(value).as_deref(), Some(value));
        }
    }

    #[test]
    fn not_found_and_policy_mappings_are_stable() {
        let (status, body) = execution_error(&ExecutionError::Activation(
            ActivationError::NotRegistered {
                module_id: "missing".to_owned(),
                version: "1.0.0".to_owned(),
            },
        ))
        .status_and_body();
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(body.code, "module_not_found");

        let (status, body) = execution_error(&ExecutionError::Activation(
            ActivationError::NoActiveVersion {
                module_id: "idle".to_owned(),
            },
        ))
        .status_and_body();
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(body.code, "module_not_active");

        let (status, body) =
            execution_error(&ExecutionError::Overloaded { maximum: 1 }).status_and_body();
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.code, "server_busy");

        let (status, body) = execution_error(&ExecutionError::DeadlineExceeded {
            requested: Duration::from_secs(2),
            maximum: Duration::from_secs(1),
        })
        .status_and_body();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(body.code, "deadline_exceeded");
    }
}

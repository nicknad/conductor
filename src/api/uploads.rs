//! Authenticates requests, enforces request limits, streams uploads.
//! Must not trust package contents or activate plugins.
//!
//! `POST /v1/packages` accepts a `multipart/form-data` body with:
//!
//! - `package`: the exact ZIP bytes covered by the detached signature,
//!   streamed directly into a private quarantine file. The policy's
//!   `max_compressed_bytes` is enforced per chunk while writing — a lying
//!   `Content-Length` cannot force over-allocation, and the bound is the
//!   same one validation re-checks before hashing.
//! - `key_id`: text naming the trusted key.
//! - `signature`: standard-base64 Ed25519 signature bytes.
//! - `format_version` (optional): envelope version, defaults to the
//!   supported version; unknown versions are rejected before any key
//!   lookup or crypto.
//!
//! Two authentication layers, in order: the caller presents an operator
//! bearer token ([`require_bearer`]), then the package authenticates
//! itself via its detached signature. Anonymous uploads do not exist.
//!
//! Transfer guards: at most [`MAX_FORM_FIELDS`] multipart fields and a
//! concurrency slot per upload (excess uploads get `503` instead of
//! queueing unbounded disk and CPU work). Slow bodies are bounded by the
//! total request timeout, not a per-byte speed floor.
//!
//! On success the quarantine file is promoted to the artifact store, the
//! validated identity is registered in the module registry (idempotent for
//! the same digest; a version re-registered with different bytes is a
//! `409`), and the handler returns `201` with the module identity, hex
//! digest, and authorizing signer. On validation or promotion failure the
//! quarantine file is removed so hostile bytes cannot accumulate.
//! Validation, promotion, and registration run on a blocking thread
//! (synchronous file I/O and registry state) under the configured request
//! timeout.
//!
//! Every refusal is recorded once as a structured
//! [`RejectionEvent`](crate::audit::event::RejectionEvent) via the
//! tracing-only recorder. Status codes and bodies are unchanged by
//! recording.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Multipart, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::*;
use serde::Serialize;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Semaphore;

use crate::api::errors::ApiError;
use crate::audit::event::{RejectionEvent, RejectionStage};
use crate::audit::recorder::RejectionRecorder;
use crate::control_plane::upload_package::run_upload_workflow;
use crate::control_plane::validate_package::{PackageValidator, ValidationError};
use crate::modules::registry::{ModuleRegistry, RegistryError};
use crate::packages::signature::{
    PackageSignature, MAX_KEY_ID_BYTES, SUPPORTED_SIGNATURE_FORMAT_VERSION,
};
use crate::storage::artifact_store::PromoteError;

/// Caps for small text fields. The signature itself is 64 bytes (88 base64
/// characters); the generous bounds below leave room for envelope evolution
/// while the global body limit bounds total memory. The key-id bound is
/// shared with configuration so every configured key is addressable.
const MAX_SIGNATURE_TEXT_BYTES: usize = 16 * 1024;
const MAX_FORMAT_VERSION_TEXT_BYTES: usize = 16;

/// Maximum accepted multipart fields per upload. Four are legitimate
/// (`package`, `key_id`, `signature`, `format_version`); anything beyond
/// this fixed cap is field spam and is rejected before further parsing.
const MAX_FORM_FIELDS: usize = 16;

/// Operator bearer token authorizing upload callers. Comparison is
/// constant-time over SHA-256 digests so neither value nor length leaks
/// through timing, and `Debug` is redacted so state dumps in logs can
/// never carry the secret. An empty expected token denies everything:
/// misconfiguration fails closed, never open.
#[derive(Clone)]
pub struct ApiToken(Box<[u8]>);

impl ApiToken {
    #[must_use]
    pub fn new(token: impl Into<Vec<u8>>) -> Self {
        Self(token.into().into_boxed_slice())
    }

    /// Constant-time bearer check. Hashes both sides first so the expected
    /// length is not leaked by an early length comparison.
    #[must_use]
    pub fn verify(&self, presented: &str) -> bool {
        use sha2::{Digest as _, Sha256};
        use subtle::ConstantTimeEq as _;

        if self.0.is_empty() {
            return false;
        }
        let expected = Sha256::digest(&self.0);
        let got = Sha256::digest(presented.as_bytes());
        expected.as_slice().ct_eq(got.as_slice()).into()
    }
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Shared upload state. The validator snapshot and token are immutable; a
/// policy reload or token rotation builds a new state and swaps the router
/// rather than mutating one in place mid-validation.
#[derive(Debug, Clone)]
pub struct AppState {
    pub validator: Arc<PackageValidator>,
    pub quarantine_dir: PathBuf,
    pub artifact_dir: PathBuf,
    /// Module registry: versions already accepted. A version re-registered
    /// with different bytes is a conflict, never an overwrite.
    pub registry: Arc<ModuleRegistry>,
    /// Structured rejection recorder: every refused upload produces one
    /// tracing event (best-effort; never alters the response).
    pub recorder: Arc<RejectionRecorder>,
    pub request_timeout: Duration,
    pub api_token: ApiToken,
    /// Concurrency slots: one permit per in-flight upload.
    pub upload_slots: Arc<Semaphore>,
}

/// `201` body for an accepted package.
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub module_id: String,
    pub version: String,
    /// Lowercase hex SHA-256 over the exact validated bytes.
    pub digest: String,
    /// Key id that authorized the upload, for audit attribution.
    pub signer_key_id: String,
}

/// Server-issued request id (`x-request-id`), for incident correlation.
/// Absent when the request-id layer has not run (tests calling the handler
/// directly).
fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Pipeline stage for a validation failure, for audit attribution.
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

/// Records one rejection event and returns the caller-facing response.
/// `detail` defaults to the caller message when no more specific internal
/// reason exists (validation sites pass `err.to_string()` instead, so the
/// event keeps e.g. the unknown key id while the body stays generic).
#[allow(clippy::too_many_arguments)]
fn reject(
    recorder: &RejectionRecorder,
    request_id: Option<String>,
    stage: RejectionStage,
    api: ApiError,
    detail: Option<String>,
    key_id: Option<&str>,
    module_id: Option<String>,
    version: Option<String>,
    digest: Option<String>,
    byte_count: Option<u64>,
) -> Response {
    let code = api.code();
    let detail = detail.unwrap_or_else(|| api.message().to_owned());
    recorder.record(
        &RejectionEvent::new(stage, code, detail)
            .with_request_id(request_id)
            .with_key_id(key_id.map(str::to_owned))
            .with_module_id(module_id)
            .with_version(version)
            .with_digest(digest)
            .with_byte_count(byte_count),
    );
    api.into_response()
}

/// Rejects a repeated known text field. `package` is handled separately by
/// the quarantine guard; allowing `key_id`/`signature`/`format_version` to
/// silently overwrite would make the authenticated identity depend on part
/// order, which is ambiguous input, not a convenience.
fn duplicate_field(name: &'static str) -> Box<UploadFailure> {
    UploadFailure::from_api(
        RejectionStage::Multipart,
        ApiError::BadRequest(
            match name {
                "key_id" => "duplicate_key_id_field",
                "signature" => "duplicate_signature_field",
                _ => "duplicate_format_version_field",
            },
            format!("multipart field `{name}` may appear only once"),
        ),
    )
}

/// A failed upload: the caller-facing error plus the audit facts known at
/// the failure site. Converted once into a recorded response by
/// [`post_package`].
struct UploadFailure {
    api: ApiError,
    stage: RejectionStage,
    detail: String,
    key_id: Option<String>,
    module_id: Option<String>,
    version: Option<String>,
    digest: Option<String>,
    byte_count: Option<u64>,
}

impl UploadFailure {
    fn from_api(stage: RejectionStage, api: ApiError) -> Box<Self> {
        let detail = api.message().to_owned();
        Box::new(Self {
            api,
            stage,
            detail,
            key_id: None,
            module_id: None,
            version: None,
            digest: None,
            byte_count: None,
        })
    }

    /// Adds attribution that became known after the failure was created
    /// (for example the package byte count once streaming completed).
    /// Existing values win.
    fn with_attribution(
        mut self: Box<Self>,
        key_id: Option<String>,
        byte_count: Option<u64>,
    ) -> Box<Self> {
        if self.key_id.is_none() {
            self.key_id = key_id;
        }
        if self.byte_count.is_none() {
            self.byte_count = byte_count;
        }
        self
    }

    fn respond(self, recorder: &RejectionRecorder, request_id: Option<String>) -> Response {
        reject(
            recorder,
            request_id,
            self.stage,
            self.api,
            Some(self.detail),
            self.key_id.as_deref(),
            self.module_id,
            self.version,
            self.digest,
            self.byte_count,
        )
    }
}

/// Transport authentication: every `/v1` request must carry the operator
/// bearer token. Missing, malformed, and wrong tokens get the identical
/// `401` — no oracle distinguishing them. Package-signature authentication
/// happens later inside validation; this layer only decides who may ask.
pub async fn require_bearer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let id = request_id(request.headers());
    let presented = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match presented {
        Some(token) if state.api_token.verify(token) => next.run(request).await,
        _ => {
            let api = ApiError::Unauthorized {
                code: "missing_or_invalid_bearer",
                message: "valid bearer token required".to_owned(),
                challenge: "Bearer realm=\"package-upload\"",
            };
            reject(
                &state.recorder,
                id,
                RejectionStage::Transport,
                api,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        }
    }
}

/// Streams one upload into quarantine, validates it, promotes it, and
/// registers the module version. See the module docs for field layout and
/// limits.
///
/// Returns the response directly: every failure is recorded as a tracing
/// event before responding.
#[tracing::instrument(
    name = "upload_package",
    skip(state, headers, multipart),
    fields(package_bytes = tracing::field::Empty)
)]
pub async fn post_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let id = request_id(&headers);
    match process_upload(&state, multipart).await {
        Ok(response) => response,
        Err(failure) => (*failure).respond(&state.recorder, id),
    }
}

/// The upload pipeline. Every failure returns the caller-facing error plus
/// the audit facts known at the failure site; recording and response
/// conversion happen once in [`post_package`].
async fn process_upload(
    state: &AppState,
    mut multipart: Multipart,
) -> Result<Response, Box<UploadFailure>> {
    // Shed load before touching the body: no permit means the server is
    // already at its upload bound.
    let _permit = Arc::clone(&state.upload_slots)
        .try_acquire_owned()
        .map_err(|_| {
            UploadFailure::from_api(
                RejectionStage::Transport,
                ApiError::Overloaded(
                    "server is at its concurrent-upload bound; retry later".to_owned(),
                ),
            )
        })?;

    let max_bytes = state.validator.policy().archive.max_compressed_bytes;
    // Owns the quarantine file from creation: any error return below drops
    // the guard and deletes the partial file, so no failure path can leak
    // hostile bytes — including ones added later. Only the success path
    // disarms it via `keep`.
    let mut quarantine = QuarantineGuard::new();
    let mut field_count: usize = 0;
    let mut key_id: Option<String> = None;
    let mut signature_text: Option<String> = None;
    let mut format_version: u16 = SUPPORTED_SIGNATURE_FORMAT_VERSION;
    let mut format_version_seen = false;
    let mut package_bytes: Option<u64> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        UploadFailure::from_api(
            RejectionStage::Multipart,
            multipart_error(&e, "invalid_multipart"),
        )
    })? {
        field_count += 1;
        if field_count > MAX_FORM_FIELDS {
            return Err(UploadFailure::from_api(
                RejectionStage::Multipart,
                ApiError::BadRequest(
                    "too_many_fields",
                    format!("multipart body exceeds {MAX_FORM_FIELDS} fields"),
                ),
            ));
        }
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "package" => {
                if quarantine.contains() {
                    return Err(UploadFailure::from_api(
                        RejectionStage::Multipart,
                        ApiError::BadRequest(
                            "duplicate_package_field",
                            "only one package field is accepted".to_owned(),
                        ),
                    ));
                }
                let (path, std_file) = tokio::task::spawn_blocking({
                    let dir = state.quarantine_dir.clone();
                    move || crate::storage::quarantine::create_file(&dir)
                })
                .await
                .map_err(|e| {
                    UploadFailure::from_api(
                        RejectionStage::Internal,
                        ApiError::Internal(format!("quarantine join failed: {e}")),
                    )
                })?
                .map_err(|e| {
                    UploadFailure::from_api(
                        RejectionStage::Internal,
                        ApiError::Internal(format!("quarantine failed: {e}")),
                    )
                })?;
                let file = tokio::fs::File::from_std(std_file);
                let mut field = field;
                // Owned from creation: any error below — streaming or
                // limits — drops the guard and deletes the
                // partial file. The helper drops the write handle on
                // every failure path (Windows cannot remove an open
                // file); deletion itself is the guard's job.
                quarantine.store(path);
                let received = stream_package_to_quarantine(&mut field, file, max_bytes)
                    .await
                    .map_err(|e| UploadFailure::from_api(RejectionStage::Streaming, e))?;
                package_bytes = Some(received);
                tracing::Span::current().record("package_bytes", received);
            }
            "key_id" => {
                if key_id.is_some() {
                    return Err(duplicate_field("key_id"));
                }
                key_id = Some(
                    read_text_capped(field, MAX_KEY_ID_BYTES, "key_id")
                        .await
                        .map_err(|e| UploadFailure::from_api(RejectionStage::Multipart, e))?,
                );
            }
            "signature" => {
                if signature_text.is_some() {
                    return Err(duplicate_field("signature"));
                }
                signature_text = Some(
                    read_text_capped(field, MAX_SIGNATURE_TEXT_BYTES, "signature")
                        .await
                        .map_err(|e| UploadFailure::from_api(RejectionStage::Multipart, e))?,
                );
            }
            "format_version" => {
                if format_version_seen {
                    return Err(duplicate_field("format_version"));
                }
                format_version_seen = true;
                let text = read_text_capped(field, MAX_FORMAT_VERSION_TEXT_BYTES, "format_version")
                    .await
                    .map_err(|e| UploadFailure::from_api(RejectionStage::Multipart, e))?;
                format_version = parse_format_version(&text).map_err(|_| {
                    UploadFailure::from_api(
                        RejectionStage::Multipart,
                        ApiError::BadRequest(
                            "invalid_format_version",
                            format!("unsupported signature format version: {text:?}"),
                        ),
                    )
                })?;
            }
            _ => {
                // Drain unknown fields so a misbehaving client cannot stall
                // the connection; content is ignored.
                let mut field = field;
                while field
                    .chunk()
                    .await
                    .map_err(|e| {
                        UploadFailure::from_api(
                            RejectionStage::Multipart,
                            multipart_error(&e, "invalid_multipart"),
                        )
                    })?
                    .is_some()
                {}
            }
        }
    }
    // Check every cheap field before disarming the guard: a missing package,
    // key, or signature (or undecodable base64) must delete the quarantined
    // bytes through `QuarantineGuard::drop`, not leak them.
    if !quarantine.contains() {
        return Err(UploadFailure::from_api(
            RejectionStage::Multipart,
            ApiError::BadRequest(
                "missing_package",
                "multipart field `package` is required".to_owned(),
            ),
        ));
    }
    let key_id = key_id
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            UploadFailure::from_api(
                RejectionStage::Multipart,
                ApiError::BadRequest(
                    "missing_key_id",
                    "multipart field `key_id` is required".to_owned(),
                ),
            )
            .with_attribution(None, package_bytes)
        })?;
    let signature_text = signature_text.ok_or_else(|| {
        UploadFailure::from_api(
            RejectionStage::Multipart,
            ApiError::BadRequest(
                "missing_signature",
                "multipart field `signature` is required".to_owned(),
            ),
        )
        .with_attribution(Some(key_id.clone()), package_bytes)
    })?;
    let signature_bytes = BASE64_STANDARD.decode(signature_text.trim()).map_err(|e| {
        UploadFailure::from_api(
            RejectionStage::Multipart,
            ApiError::BadRequest(
                "invalid_signature_encoding",
                format!("signature is not valid base64: {e}"),
            ),
        )
        .with_attribution(Some(key_id.clone()), package_bytes)
    })?;
    // The write handle was closed by the streaming helper before the path
    // was stored, so validation opens the quarantined file itself with no
    // writer still attached. `keep` disarms the guard: from here on the
    // file is deleted explicitly on failure and kept on success.
    let Some(path) = quarantine.keep() else {
        return Err(UploadFailure::from_api(
            RejectionStage::Multipart,
            ApiError::BadRequest(
                "missing_package",
                "multipart field `package` is required".to_owned(),
            ),
        ));
    };
    // A second guard covers the window between `keep()` and the final
    // response. If the handler future is dropped (client disconnect or the
    // outer timeout layer), no error branch runs and the streaming guard is
    // already disarmed; this guard still deletes the file.
    let kept = KeptQuarantine::new(path);
    let path = kept.path().to_path_buf();
    let audit_key_id = key_id.clone();
    let audit_key_id_outer = key_id.clone();
    let envelope = PackageSignature {
        format_version,
        key_id,
        signature: signature_bytes,
    };

    let validator = Arc::clone(&state.validator);
    let registry = Arc::clone(&state.registry);
    let timeout = state.request_timeout;
    let blocking_path = path.clone();
    let artifact_dir = state.artifact_dir.clone();
    let audit_bytes = package_bytes;
    let outcome = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || -> Result<_, Box<UploadFailure>> {
            let audit_key = audit_key_id.clone();
            let bytes = audit_bytes;
            let verdict =
                run_upload_workflow(&validator, &blocking_path, &envelope).map_err(|err| {
                    let stage = validation_stage(&err);
                    let detail = err.to_string();
                    let api = ApiError::from(err);
                    Box::new(UploadFailure {
                        api,
                        stage,
                        detail,
                        key_id: Some(audit_key.clone()),
                        module_id: None,
                        version: None,
                        digest: None,
                        byte_count: bytes,
                    })
                })?;
            crate::storage::artifact_store::promote_quarantined(
                &artifact_dir,
                &blocking_path,
                &verdict,
            )
            .map_err(|e| {
                crate::storage::quarantine::discard(&blocking_path);
                let api = match e {
                    PromoteError::DigestMismatch => {
                        ApiError::Internal("quarantine bytes changed after validation".to_owned())
                    }
                    PromoteError::Io(message) => {
                        ApiError::Internal(format!("artifact promotion failed: {message}"))
                    }
                };
                let detail = api.message().to_owned();
                let artifact = verdict.artifact();
                Box::new(UploadFailure {
                    api,
                    stage: RejectionStage::Promotion,
                    detail,
                    key_id: Some(audit_key.clone()),
                    module_id: Some(artifact.module_id().to_owned()),
                    version: Some(artifact.version().to_owned()),
                    digest: Some(artifact.digest().to_hex()),
                    byte_count: bytes,
                })
            })?;
            // The registry records the promoted artifact's canonical relative
            // address (identity plus an execution locator); the layout is
            // owned by the artifact store.
            let promoted_relpath = crate::storage::artifact_store::artifact_relative_path(&verdict);
            // Post-promotion binding: the digest is now durable, so the
            // registry learns which bytes this module version means. A
            // version conflict leaves the promoted blob unreferenced
            // (immutable, never the source of truth) and rejects the
            // upload; an identical re-upload is idempotent. Storage
            // failures are server-side and never reported as conflicts.
            match crate::control_plane::register_package::register(
                &registry,
                &verdict,
                &promoted_relpath,
            ) {
                Ok(_) => Ok(verdict),
                Err(err) => {
                    let (stage, api) = match &err {
                        RegistryError::VersionConflict { .. } => (
                            RejectionStage::Registration,
                            ApiError::Conflict("version_conflict", err.to_string()),
                        ),
                        RegistryError::Storage(_) => (
                            RejectionStage::Internal,
                            ApiError::Internal(format!("registry storage failed: {err}")),
                        ),
                        RegistryError::InvalidArtifactPath { .. } => (
                            RejectionStage::Internal,
                            ApiError::Internal(format!("registration invariant violated: {err}")),
                        ),
                    };
                    let detail = api.message().to_owned();
                    // The verdict validated, so its identity is trustworthy
                    // audit attribution even though registration refused it.
                    let artifact = verdict.artifact();
                    Err(Box::new(UploadFailure {
                        api,
                        stage,
                        detail,
                        key_id: Some(audit_key.clone()),
                        module_id: Some(artifact.module_id().to_owned()),
                        version: Some(artifact.version().to_owned()),
                        digest: Some(artifact.digest().to_hex()),
                        byte_count: bytes,
                    }))
                }
            }
        }),
    )
    .await
    .map_err(|_| {
        crate::storage::quarantine::discard(&path);
        let api = ApiError::Timeout;
        let detail = api.message().to_owned();
        Box::new(UploadFailure {
            api,
            stage: RejectionStage::Transport,
            detail,
            key_id: Some(audit_key_id_outer.clone()),
            module_id: None,
            version: None,
            digest: None,
            byte_count: audit_bytes,
        })
    })?
    .map_err(|e| {
        // The blocking task was cancelled or panicked: no other branch will
        // consume the quarantined bytes.
        crate::storage::quarantine::discard(&path);
        let api = ApiError::Internal(format!("validation task failed: {e}"));
        let detail = api.message().to_owned();
        Box::new(UploadFailure {
            api,
            stage: RejectionStage::Internal,
            detail,
            key_id: Some(audit_key_id_outer.clone()),
            module_id: None,
            version: None,
            digest: None,
            byte_count: audit_bytes,
        })
    })?;

    match outcome {
        Ok(verdict) => {
            // Promotion consumed the quarantine file; disarm the drop guard
            // so cleanup is not attempted after a successful response.
            kept.keep();
            Ok((
                StatusCode::CREATED,
                Json(UploadResponse {
                    module_id: verdict.artifact().module_id().to_owned(),
                    version: verdict.artifact().version().to_owned(),
                    digest: verdict.artifact().digest().to_hex(),
                    signer_key_id: verdict.signer().key_id.clone(),
                }),
            )
                .into_response())
        }
        Err(failure) => Err(failure),
    }
}

/// Owns a quarantine file path from creation until the handler decides
/// its fate. Dropping the guard with a stored path deletes the file, so
/// every error return between streaming and the explicit verdict cleans
/// up without per-branch delete calls — including error paths added
/// later. The blocking delete in `drop` is best-effort by necessity
/// (drops cannot await); the success path disarms via [`keep`](Self::keep)
/// and manages the file explicitly.
struct QuarantineGuard {
    path: Option<PathBuf>,
}

impl QuarantineGuard {
    fn new() -> Self {
        Self { path: None }
    }

    fn store(&mut self, path: PathBuf) {
        self.path = Some(path);
    }

    fn contains(&self) -> bool {
        self.path.is_some()
    }

    /// Disarms the guard, returning the path for explicit management.
    fn keep(mut self) -> Option<PathBuf> {
        self.path.take()
    }
}

impl Drop for QuarantineGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            crate::storage::quarantine::discard(&path);
        }
    }
}

/// Owns a quarantine path after streaming has finished. The [`QuarantineGuard`]
/// can only cover the streaming phase (it is disarmed by `keep`), but the
/// handler future can still be dropped while validation runs. This guard
/// deletes the file on drop unless the success path disarms it, so
/// cancellation and outer timeouts cannot leak quarantine bytes.
struct KeptQuarantine {
    path: Option<PathBuf>,
}

impl KeptQuarantine {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("kept quarantine is armed until `keep`")
    }

    /// Disarms the guard, leaving the file in place.
    fn keep(mut self) {
        self.path.take();
    }
}

impl Drop for KeptQuarantine {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            crate::storage::quarantine::discard(&path);
        }
    }
}

/// Streams the `package` field into its quarantine file, enforcing
/// `max_bytes` per chunk so a lying `Content-Length` cannot force
/// over-allocation. Drops the write handle before returning any error
/// (Windows cannot remove an open file) and leaves deletion to the
/// caller's [`QuarantineGuard`]; the path is stored only on success.
async fn stream_package_to_quarantine(
    field: &mut axum::extract::multipart::Field<'_>,
    mut file: tokio::fs::File,
    max_bytes: u64,
) -> Result<u64, ApiError> {
    let fail = |file: tokio::fs::File, err: ApiError| {
        drop(file);
        Err(err)
    };
    let mut total: u64 = 0;
    loop {
        let chunk = match field.chunk().await {
            Ok(chunk) => chunk,
            Err(e) => {
                return fail(file, multipart_error(&e, "unreadable_package_chunk"));
            }
        };
        let Some(chunk) = chunk else { break };
        total += chunk.len() as u64;
        if total > max_bytes {
            let _ = file.shutdown().await;
            return fail(
                file,
                ApiError::PayloadTooLarge(format!(
                    "package exceeds {max_bytes} bytes while streaming"
                )),
            );
        }
        if let Err(e) = file.write_all(&chunk).await {
            return fail(
                file,
                ApiError::Internal(format!("quarantine write failed: {e}")),
            );
        }
    }
    if let Err(e) = file.flush().await {
        return fail(
            file,
            ApiError::Internal(format!("quarantine flush failed: {e}")),
        );
    }
    drop(file);
    Ok(total)
}

/// Maps a multipart extraction error to the API contract. axum reports a
/// body-cap violation as `413`; flattening every multipart failure to `400`
/// would make the status depend on whether the client sent `Content-Length`
/// and hide the real overload condition.
fn multipart_error(err: &axum::extract::multipart::MultipartError, code: &'static str) -> ApiError {
    if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge("request body exceeds the allowed size".to_owned())
    } else {
        ApiError::BadRequest(code, err.to_string())
    }
}

/// Parses the `format_version` text field strictly: canonical decimal digits
/// only, no sign, no leading zeros, fitting in `u16`. Rejects `+1`, `01`,
/// empty, and out-of-range values so the envelope version is unambiguous.
fn parse_format_version(text: &str) -> Result<u16, ()> {
    let trimmed = text.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    if trimmed.len() > 1 && trimmed.starts_with('0') {
        return Err(());
    }
    trimmed.parse::<u16>().map_err(|_| ())
}

/// Reads a small text field with a byte cap enforced per chunk, so a huge
/// field cannot force buffering before the limit applies.
async fn read_text_capped(
    mut field: axum::extract::multipart::Field<'_>,
    cap: usize,
    what: &'static str,
) -> Result<String, ApiError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| multipart_error(&e, "invalid_multipart"))?
    {
        if bytes.len() + chunk.len() > cap {
            return Err(ApiError::BadRequest(
                "field_too_large",
                format!("multipart field `{what}` exceeds {cap} bytes"),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| {
        ApiError::BadRequest(
            "invalid_field_encoding",
            format!("multipart field `{what}` is not UTF-8"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn response_serializes_audit_fields() {
        let body = UploadResponse {
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            digest: "ab".repeat(32),
            signer_key_id: "k1".to_owned(),
        };
        let json = serde_json::to_value(&body).expect("response must serialize");
        assert_eq!(json["signer_key_id"], "k1");
        assert_eq!(json["digest"].as_str().expect("digest").len(), 64);
    }

    #[test]
    fn bearer_check_accepts_only_the_configured_token() {
        let expected = ApiToken::new("correct-token-value");
        assert!(expected.verify("correct-token-value"));
        for wrong in ["", "correct-token-valu", "correct-token-value-", "wrong"] {
            assert!(
                !expected.verify(wrong),
                "must reject {wrong:?} without distinguishing cases"
            );
        }
    }

    #[test]
    fn empty_expected_token_denies_everything() {
        let expected = ApiToken::new("");
        assert!(!expected.verify(""));
        assert!(!expected.verify("anything"));
    }

    #[test]
    fn token_debug_never_carries_the_secret() {
        let expected = ApiToken::new("correct-token-value");
        let rendered = format!("{expected:?} {expected:?}");
        assert!(!rendered.contains("correct-token-value"));
    }

    #[test]
    fn format_version_parses_canonical_decimal_only() {
        assert_eq!(parse_format_version("1"), Ok(1));
        assert_eq!(parse_format_version(" 1 "), Ok(1));
        for bad in [
            "",
            " ",
            "+1",
            "-1",
            "01",
            "00",
            "1.0",
            "v1",
            "65536",
            "99999999999",
        ] {
            assert!(
                parse_format_version(bad).is_err(),
                "must reject {bad:?} as non-canonical"
            );
        }
    }

    #[test]
    fn kept_quarantine_deletes_on_drop_and_keeps_when_disarmed() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "conductor-kept-quarantine-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("test dir must be created");

        let dropped = dir.join("dropped.zip");
        std::fs::write(&dropped, b"quarantine").expect("file must be writable");
        {
            let _guard = KeptQuarantine::new(dropped.clone());
        }
        assert!(!dropped.exists(), "drop must delete the quarantined file");

        let kept_path = dir.join("kept.zip");
        std::fs::write(&kept_path, b"quarantine").expect("file must be writable");
        let guard = KeptQuarantine::new(kept_path.clone());
        assert_eq!(guard.path(), kept_path.as_path());
        guard.keep();
        assert!(kept_path.exists(), "an explicitly kept file must survive");

        let _ = std::fs::remove_dir_all(&dir);
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

        /// The parser accepts exactly canonical decimal `u16` text: optional
        /// surrounding whitespace, no sign, no leading zero, in range.
        #[test]
        fn format_version_accepts_exactly_canonical_u16_decimals(text in ".{0,24}") {
            let trimmed = text.trim();
            let expected = !trimmed.is_empty()
                && trimmed.bytes().all(|byte| byte.is_ascii_digit())
                && !(trimmed.len() > 1 && trimmed.starts_with('0'))
                && trimmed.parse::<u16>().is_ok();
            prop_assert_eq!(parse_format_version(&text).is_ok(), expected);
        }

        /// Every in-range version renders canonically and round-trips.
        #[test]
        fn every_u16_version_round_trips(version in any::<u16>()) {
            prop_assert_eq!(parse_format_version(&version.to_string()), Ok(version));
        }

        /// Adding a sign, decimal point, or leading zero is always rejected.
        #[test]
        fn decorated_numeric_forms_are_rejected(
            version in 0u16..=9999,
            prefix in "[+\\-.]",
            leading_zero in any::<bool>(),
        ) {
            let digits = if leading_zero {
                format!("0{version}")
            } else {
                version.to_string()
            };
            let text = format!("{prefix}{digits}");
            prop_assert!(parse_format_version(&text).is_err(), "{text:?} must be rejected");
        }
    }
}

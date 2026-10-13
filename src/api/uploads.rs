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
//! Transfer guards, all enforced while streaming: at most
//! [`MAX_FORM_FIELDS`] multipart fields; a minimum body-upload speed
//! ([`RateFloor`], rejecting trickle bodies with `408`); a concurrency
//! slot per upload (excess uploads get `503` instead of queueing
//! unbounded disk and CPU work).
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
//! Every refusal is recorded exactly once as a structured
//! [`RejectionEvent`](crate::audit::event::RejectionEvent): typed where the
//! handler or middleware still owns the error, generic for responses
//! produced by transport layers (timeouts, body limits, panics). Status
//! codes and bodies are unchanged by recording.

use std::path::PathBuf;
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
use crate::api::rejection::{request_id, Rejection};
use crate::control_plane::upload_package::run_upload_workflow;
use crate::control_plane::validate_package::PackageValidator;
use crate::audit::recorder::RejectionRecorder;
use crate::modules::registry::{ModuleRegistry, RegistryError};
use crate::packages::signature::{PackageSignature, SUPPORTED_SIGNATURE_FORMAT_VERSION};
use crate::storage::artifact_store::PromoteError;

/// Caps for small text fields. The signature itself is 64 bytes (88 base64
/// characters); the generous bounds below leave room for envelope evolution
/// while the global body limit bounds total memory.
const MAX_KEY_ID_BYTES: usize = 256;
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
    /// Structured rejection recorder: every refused upload produces exactly
    /// one event (tracing in this phase; durable rows in a later phase).
    pub recorder: Arc<RejectionRecorder>,
    pub request_timeout: Duration,
    pub api_token: ApiToken,
    /// Concurrency slots: one permit per in-flight upload.
    pub upload_slots: Arc<Semaphore>,
    /// Minimum accepted body-upload speed in bytes per second (0 disables,
    /// nonzero is expected in production).
    pub min_upload_bytes_per_sec: u64,
    /// Grace period before the rate floor applies, covering handshake and
    /// slow-start so small legitimate uploads never trip it.
    pub rate_grace: Duration,
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

/// Transport authentication: every `/v1` request must carry the operator
/// bearer token. Missing, malformed, and wrong tokens get the identical
/// `401` — no oracle distinguishing them. Package-signature authentication
/// happens later inside validation; this layer only decides who may ask.
/// Rejections are recorded as typed transport events.
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
            Rejection::from_api(api).into_recorded_response(&state.recorder, id)
        }
    }
}

/// Minimum body-upload-speed enforcement. Counts every consumed body byte
/// (package, text, and drained unknown fields alike — all consume
/// transfer) and trips once past the grace period when the average falls
/// below the floor. `min_rate == 0` disables the check.
struct RateFloor {
    min_bytes_per_sec: u64,
    grace: Duration,
    start: std::time::Instant,
    bytes: u64,
}

impl RateFloor {
    fn new(min_bytes_per_sec: u64, grace: Duration) -> Self {
        Self {
            min_bytes_per_sec,
            grace,
            start: std::time::Instant::now(),
            bytes: 0,
        }
    }

    fn note(&mut self, n: usize) -> Result<(), ApiError> {
        self.bytes += n as u64;
        if rate_floor_tripped(
            self.bytes,
            self.start.elapsed(),
            self.min_bytes_per_sec,
            self.grace,
        ) {
            return Err(ApiError::SlowUpload(format!(
                "body upload fell below {} bytes/s after the grace period",
                self.min_bytes_per_sec
            )));
        }
        Ok(())
    }
}

/// Pure rate-floor predicate: true once past `grace` when `bytes` averages
/// below `min_rate`. `u128` arithmetic cannot overflow (`u64` rate times
/// nanosecond elapsed). Separated from the middleware so tests prove the
/// exact boundary without sleeping.
fn rate_floor_tripped(bytes: u64, elapsed: Duration, min_rate: u64, grace: Duration) -> bool {
    if min_rate == 0 || elapsed < grace {
        return false;
    }
    (bytes as u128) < (min_rate as u128) * (elapsed.as_nanos()) / 1_000_000_000
}

/// Streams one upload into quarantine, validates it, promotes it, and
/// registers the module version. See the module docs for field layout and
/// limits.
///
/// Returns the response directly: every failure becomes a [`Rejection`],
/// so no path can escape unrecorded.
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
        Err(rejection) => rejection.into_recorded_response(&state.recorder, id),
    }
}

/// The upload pipeline. Every failure returns a [`Rejection`] carrying the
/// caller-facing error plus the audit evidence; recording and response
/// conversion happen once in [`post_package`].
async fn process_upload(state: &AppState, mut multipart: Multipart) -> Result<Response, Rejection> {
    // Shed load before touching the body: no permit means the server is
    // already at its upload bound.
    let _permit = Arc::clone(&state.upload_slots)
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::Overloaded("server is at its concurrent-upload bound; retry later".to_owned())
        })?;

    let max_bytes = state.validator.policy().archive.max_compressed_bytes;
    let mut rate = RateFloor::new(state.min_upload_bytes_per_sec, state.rate_grace);
    // Owns the quarantine file from creation: any error return below drops
    // the guard and deletes the partial file, so no failure path can leak
    // hostile bytes — including ones added later. Only the success path
    // disarms it via `keep`.
    let mut quarantine = QuarantineGuard::new();
    let mut field_count: usize = 0;
    let mut key_id: Option<String> = None;
    let mut signature_text: Option<String> = None;
    let mut format_version: u16 = SUPPORTED_SIGNATURE_FORMAT_VERSION;
    let mut package_bytes: Option<u64> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest("invalid_multipart", e.to_string()))?
    {
        field_count += 1;
        if field_count > MAX_FORM_FIELDS {
            return Err(ApiError::BadRequest(
                "too_many_fields",
                format!("multipart body exceeds {MAX_FORM_FIELDS} fields"),
            )
            .into());
        }
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "package" => {
                if quarantine.contains() {
                    return Err(ApiError::BadRequest(
                        "duplicate_package_field",
                        "only one package field is accepted".to_owned(),
                    )
                    .into());
                }
                let (path, std_file) = tokio::task::spawn_blocking({
                    let dir = state.quarantine_dir.clone();
                    move || crate::storage::quarantine::create_file(&dir)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("quarantine join failed: {e}")))?
                .map_err(|e| ApiError::Internal(format!("quarantine failed: {e}")))?;
                let file = tokio::fs::File::from_std(std_file);
                let mut field = field;
                // Owned from creation: any error below — streaming,
                // limits, rate floor — drops the guard and deletes the
                // partial file. The helper drops the write handle on
                // every failure path (Windows cannot remove an open
                // file); deletion itself is the guard's job.
                quarantine.store(path);
                let received =
                    stream_package_to_quarantine(&mut field, file, max_bytes, &mut rate).await?;
                package_bytes = Some(received);
                tracing::Span::current().record("package_bytes", received);
            }
            "key_id" => {
                key_id =
                    Some(read_text_capped(field, MAX_KEY_ID_BYTES, "key_id", &mut rate).await?);
            }
            "signature" => {
                signature_text = Some(
                    read_text_capped(field, MAX_SIGNATURE_TEXT_BYTES, "signature", &mut rate)
                        .await?,
                );
            }
            "format_version" => {
                let text = read_text_capped(
                    field,
                    MAX_FORMAT_VERSION_TEXT_BYTES,
                    "format_version",
                    &mut rate,
                )
                .await?;
                format_version = text.trim().parse::<u16>().map_err(|_| {
                    ApiError::BadRequest(
                        "invalid_format_version",
                        format!("unsupported signature format version: {text:?}"),
                    )
                })?;
            }
            _ => {
                // Drain unknown fields so a misbehaving client cannot stall
                // the connection; content is ignored but still counts toward
                // the rate floor, since it consumes transfer.
                let mut field = field;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| ApiError::BadRequest("invalid_multipart", e.to_string()))?
                {
                    rate.note(chunk.len())?;
                }
            }
        }
    }
    // The write handle was closed by the streaming helper before the path
    // was stored, so validation opens the quarantined file itself with no
    // writer still attached. `keep` disarms the guard: from here on the
    // file is deleted explicitly on failure and kept on success.
    let path = quarantine.keep().ok_or_else(|| {
        ApiError::BadRequest(
            "missing_package",
            "multipart field `package` is required".to_owned(),
        )
    })?;
    let key_id = key_id
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "missing_key_id",
                "multipart field `key_id` is required".to_owned(),
            )
        })?;
    let signature_text = signature_text.ok_or_else(|| {
        ApiError::BadRequest(
            "missing_signature",
            "multipart field `signature` is required".to_owned(),
        )
    })?;
    let signature_bytes = BASE64_STANDARD.decode(signature_text.trim()).map_err(|e| {
        ApiError::BadRequest(
            "invalid_signature_encoding",
            format!("signature is not valid base64: {e}"),
        )
    })?;
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
        tokio::task::spawn_blocking(move || -> Result<_, Rejection> {
            let verdict = run_upload_workflow(&validator, &blocking_path, &envelope)
                .map_err(Rejection::from_validation)
                .map_err(|rejection| {
                    rejection.with_upload(Some(audit_key_id.as_str()), audit_bytes)
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
                Rejection::from_api(api)
                    .with_upload(Some(audit_key_id.as_str()), audit_bytes)
                    .with_artifact(verdict.artifact())
            })?;
            // The registry records the promoted artifact's relative address
            // for reconciliation; the layout is owned by the artifact store.
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
                    let api = match &err {
                        RegistryError::VersionConflict { .. } => {
                            ApiError::Conflict("version_conflict", err.to_string())
                        }
                        RegistryError::Storage(_) => {
                            ApiError::Internal(format!("registry storage failed: {err}"))
                        }
                    };
                    Err(Rejection::from_api(api)
                        .with_upload(Some(audit_key_id.as_str()), audit_bytes)
                        .with_artifact(verdict.artifact()))
                }
            }
        }),
    )
    .await
    .map_err(|_| {
        crate::storage::quarantine::discard(&path);
        Rejection::from_api(ApiError::Timeout)
            .with_upload(Some(audit_key_id_outer.as_str()), audit_bytes)
    })?
    .map_err(|e| {
        Rejection::from_api(ApiError::Internal(format!("validation task failed: {e}")))
            .with_upload(Some(audit_key_id_outer.as_str()), audit_bytes)
    })?;

    match outcome {
        Ok(verdict) => Ok((
            StatusCode::CREATED,
            Json(UploadResponse {
                module_id: verdict.artifact().module_id().to_owned(),
                version: verdict.artifact().version().to_owned(),
                digest: verdict.artifact().digest().to_hex(),
                signer_key_id: verdict.signer().key_id.clone(),
            }),
        )
            .into_response()),
        Err(rejection) => {
            // Validation failures preserve their internal reason for the
            // audit record; promotion failures already discarded their
            // quarantine file. Best-effort discard covers both (idempotent).
            crate::storage::quarantine::discard(&path);
            Err(rejection)
        }
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

/// Streams the `package` field into its quarantine file, enforcing
/// `max_bytes` per chunk so a lying `Content-Length` cannot force
/// over-allocation, and noting every chunk against the rate floor so a
/// trickling body trips `408` instead of occupying a slot until the total
/// timeout. Drops the write handle before returning any error (Windows
/// cannot remove an open file) and leaves deletion to the caller's
/// [`QuarantineGuard`]; the path is stored only on success.
async fn stream_package_to_quarantine(
    field: &mut axum::extract::multipart::Field<'_>,
    mut file: tokio::fs::File,
    max_bytes: u64,
    rate: &mut RateFloor,
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
                return fail(
                    file,
                    ApiError::BadRequest("unreadable_package_chunk", e.to_string()),
                );
            }
        };
        let Some(chunk) = chunk else { break };
        if let Err(e) = rate.note(chunk.len()) {
            return fail(file, e);
        }
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

/// Reads a small text field with a byte cap enforced per chunk, so a huge
/// field cannot force buffering before the limit applies. Bytes count
/// toward the rate floor like every other consumed body byte.
async fn read_text_capped(
    mut field: axum::extract::multipart::Field<'_>,
    cap: usize,
    what: &'static str,
    rate: &mut RateFloor,
) -> Result<String, ApiError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| ApiError::BadRequest("invalid_multipart", e.to_string()))?
    {
        rate.note(chunk.len())?;
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
    fn rate_floor_trips_only_past_grace_below_speed() {
        // Below the floor after grace: trips.
        assert!(rate_floor_tripped(
            100,
            Duration::from_secs(10),
            1_000,
            Duration::from_secs(1)
        ));
        // Exactly at the floor: passes (strictly-below trips).
        assert!(!rate_floor_tripped(
            10_000,
            Duration::from_secs(10),
            1_000,
            Duration::from_secs(1)
        ));
        // Within grace: exempt regardless of speed.
        assert!(!rate_floor_tripped(
            1,
            Duration::from_millis(500),
            1_000,
            Duration::from_secs(1)
        ));
        // Disabled floor never trips.
        assert!(!rate_floor_tripped(
            0,
            Duration::from_secs(3600),
            0,
            Duration::from_secs(1)
        ));
        // Nanosecond-scale elapsed cannot overflow or divide by zero.
        assert!(!rate_floor_tripped(
            0,
            Duration::ZERO,
            1_000,
            Duration::ZERO
        ));
    }
}

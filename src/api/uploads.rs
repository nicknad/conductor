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
//! On success the quarantined file is kept for the artifact store to
//! promote and the handler returns `201` with the module identity, hex
//! digest, and authorizing signer. On validation failure the quarantine
//! file is removed so hostile bytes cannot accumulate. Validation runs on
//! a blocking thread (it is synchronous file I/O) under the configured
//! request timeout.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::prelude::*;
use serde::Serialize;
use tokio::io::AsyncWriteExt as _;

use crate::api::errors::ApiError;
use crate::application::upload_package::run_upload_workflow;
use crate::application::validate_package::PackageValidator;
use crate::packages::signature::{PackageSignature, SUPPORTED_SIGNATURE_FORMAT_VERSION};

/// Caps for small text fields. The signature itself is 64 bytes (88 base64
/// characters); the generous bounds below leave room for envelope evolution
/// while the global body limit bounds total memory.
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_SIGNATURE_TEXT_BYTES: usize = 16 * 1024;
const MAX_FORMAT_VERSION_TEXT_BYTES: usize = 16;

/// Shared upload state. The validator snapshot is immutable; a policy
/// reload builds a new state and swaps the router rather than mutating one
/// in place mid-validation.
#[derive(Debug, Clone)]
pub struct AppState {
    pub validator: Arc<PackageValidator>,
    pub quarantine_dir: PathBuf,
    pub request_timeout: Duration,
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

/// Streams one upload into quarantine, validates it, and mints the
/// artifact identity. See the module docs for field layout and limits.
#[tracing::instrument(
    name = "upload_package",
    skip(state, multipart),
    fields(package_bytes = tracing::field::Empty)
)]
pub async fn post_package(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, ApiError> {
    let max_bytes = state.validator.policy().archive.max_compressed_bytes;
    let mut package_path: Option<PathBuf> = None;
    let mut key_id: Option<String> = None;
    let mut signature_text: Option<String> = None;
    let mut format_version: u16 = SUPPORTED_SIGNATURE_FORMAT_VERSION;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest("invalid_multipart", e.to_string()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "package" => {
                if package_path.is_some() {
                    cleanup_partial(&mut package_path).await;
                    return Err(ApiError::BadRequest(
                        "duplicate_package_field",
                        "only one package field is accepted".to_owned(),
                    ));
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
                // The helper owns the write handle and deletes the partial
                // file on every failure path, so `package_path` is set only
                // on success and no error branch can leak hostile bytes.
                let received =
                    stream_package_to_quarantine(&mut field, &path, file, max_bytes).await?;
                tracing::Span::current().record("package_bytes", received);
                package_path = Some(path);
            }
            "key_id" => {
                key_id = Some(read_text_capped(field, MAX_KEY_ID_BYTES, "key_id").await?);
            }
            "signature" => {
                signature_text =
                    Some(read_text_capped(field, MAX_SIGNATURE_TEXT_BYTES, "signature").await?);
            }
            "format_version" => {
                let text = read_text_capped(field, MAX_FORMAT_VERSION_TEXT_BYTES, "format_version")
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
                // the connection; content is ignored.
                let mut field = field;
                while field
                    .chunk()
                    .await
                    .map_err(|e| ApiError::BadRequest("invalid_multipart", e.to_string()))?
                    .is_some()
                {}
            }
        }
    }
    // The write handle was closed by the streaming helper before the path
    // was stored, so validation opens the quarantined file itself with no
    // writer still attached.

    let path = package_path.ok_or_else(|| {
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
    let envelope = PackageSignature {
        format_version,
        key_id,
        signature: signature_bytes,
    };

    let validator = Arc::clone(&state.validator);
    let timeout = state.request_timeout;
    let blocking_path = path.clone();
    let outcome = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || {
            run_upload_workflow(&validator, &blocking_path, &envelope)
        }),
    )
    .await
    .map_err(|_| {
        crate::storage::quarantine::discard(&path);
        ApiError::Timeout
    })?
    .map_err(|e| ApiError::Internal(format!("validation task failed: {e}")))?;

    match outcome {
        Ok(outcome) => Ok((
            StatusCode::CREATED,
            Json(UploadResponse {
                module_id: outcome.artifact.module_id().to_owned(),
                version: outcome.artifact.version().to_owned(),
                digest: outcome.artifact.digest().to_hex(),
                signer_key_id: outcome.signer.key_id.clone(),
            }),
        )),
        Err(validation_err) => {
            crate::storage::quarantine::discard(&path);
            Err(ApiError::from(validation_err))
        }
    }
}

async fn cleanup_partial(path: &mut Option<PathBuf>) {
    if let Some(p) = path.take() {
        let _ = tokio::fs::remove_file(&p).await;
    }
}

/// Streams the `package` field into its quarantine file, enforcing
/// `max_bytes` per chunk so a lying `Content-Length` cannot force
/// over-allocation. Owns the write handle: it is shut down and closed
/// before any delete (Windows cannot remove an open file) and before the
/// caller stores the path, so validation later opens the file with no
/// writer attached. Every failure path deletes the partial file, so the
/// caller sets `package_path` only on success and no branch leaks hostile
/// bytes.
async fn stream_package_to_quarantine(
    field: &mut axum::extract::multipart::Field<'_>,
    path: &Path,
    mut file: tokio::fs::File,
    max_bytes: u64,
) -> Result<u64, ApiError> {
    let mut total: u64 = 0;
    loop {
        let chunk = match field.chunk().await {
            Ok(chunk) => chunk,
            Err(e) => {
                drop(file);
                let _ = tokio::fs::remove_file(path).await;
                return Err(ApiError::BadRequest(
                    "unreadable_package_chunk",
                    e.to_string(),
                ));
            }
        };
        let Some(chunk) = chunk else { break };
        total += chunk.len() as u64;
        if total > max_bytes {
            let _ = file.shutdown().await;
            drop(file);
            let _ = tokio::fs::remove_file(path).await;
            return Err(ApiError::PayloadTooLarge(format!(
                "package exceeds {max_bytes} bytes while streaming"
            )));
        }
        if let Err(e) = file.write_all(&chunk).await {
            drop(file);
            let _ = tokio::fs::remove_file(path).await;
            return Err(ApiError::Internal(format!("quarantine write failed: {e}")));
        }
    }
    if let Err(e) = file.flush().await {
        drop(file);
        let _ = tokio::fs::remove_file(path).await;
        return Err(ApiError::Internal(format!("quarantine flush failed: {e}")));
    }
    drop(file);
    Ok(total)
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
        .map_err(|e| ApiError::BadRequest("invalid_multipart", e.to_string()))?
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
}

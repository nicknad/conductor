//! Upload API: multipart streaming, limits, and verdict mapping through
//! the public HTTP surface.
//!
//! Each test builds a fresh router with trust configured by value and a
//! private quarantine directory, so tests can run in parallel without
//! sharing state. The golden package is built in-test (same precedent as
//! `tests/package_validation.rs`): it cannot drift from the schema.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::prelude::*;
use conductor::api::routes::router;
use conductor::api::uploads::AppState;
use conductor::application::validate_package::PackageValidationBuilder;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    canonical_payload, ConfiguredTrustedKeys, SignatureAlgorithm, TrustedSigningKey,
};
use tower::ServiceExt as _;

/// Test-only signing key. Must never sign anything outside these tests.
const TEST_SIGNING_KEY: [u8; 32] = [42u8; 32];
const BOUNDARY: &str = "conductor-test-boundary";

fn test_state(policy: PackageValidationPolicy, tag: &str) -> AppState {
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )]);
    let validator = PackageValidationBuilder::new(policy)
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let quarantine_dir = std::env::temp_dir().join(format!(
        "conductor-upload-api-{}-{}-{tag}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&quarantine_dir).expect("quarantine dir must be created");
    AppState {
        validator: Arc::new(validator),
        quarantine_dir,
        request_timeout: Duration::from_secs(10),
    }
}

fn golden_package_bytes() -> Vec<u8> {
    let manifest = serde_json::json!({
        "manifest_version": 1,
        "module_id": "reporting-service",
        "version": "1.2.0",
        "runtime": "rust",
        "entrypoint": "payload/reporting-service",
        "files": ["payload/reporting-service"],
    });
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("zip writer must accept manifest");
    writer
        .write_all(&serde_json::to_vec(&manifest).expect("manifest must serialize"))
        .expect("zip writer must accept manifest bytes");
    writer
        .start_file("payload/reporting-service", options)
        .expect("zip writer must accept payload");
    writer
        .write_all(b"not a real executable")
        .expect("zip writer must accept payload bytes");
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

fn signature_base64_for(bytes: &[u8]) -> String {
    use ed25519_dalek::{Signer as _, SigningKey};

    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let digest: [u8; 32] = Sha256DigestProvider
        .digest(bytes)
        .expect("hashing must succeed")
        .try_into()
        .expect("SHA-256 is 32 bytes");
    BASE64_STANDARD.encode(signing.sign(&canonical_payload(&digest)).to_bytes())
}

/// One multipart part with a text value.
fn text_part(body: &mut Vec<u8>, name: &str, value: &str) {
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
}

/// One multipart part carrying file bytes.
fn file_part(body: &mut Vec<u8>, name: &str, filename: &str, content_type: &str, bytes: &[u8]) {
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
}

fn finish_body(body: &mut Vec<u8>) -> Vec<u8> {
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    std::mem::take(body)
}

/// Standard golden upload body: package + key_id + signature.
fn golden_body(package: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", package);
    text_part(&mut body, "key_id", "k1");
    text_part(&mut body, "signature", &signature_base64_for(package));
    finish_body(&mut body)
}

async fn post_multipart(
    state: AppState,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value, PathBuf) {
    let app = router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/v1/packages")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(body))
        .expect("request must build");
    let response = app.oneshot(request).await.expect("router must respond");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).expect("error and success bodies are JSON");
    (status, json, state.quarantine_dir)
}

fn quarantine_zip_count(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .expect("quarantine dir must read")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "zip"))
        .count()
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

use std::io::Write as _;

#[tokio::test]
async fn healthz_reports_ok() {
    let state = test_state(PackageValidationPolicy::production(), "healthz");
    let app = router(state.clone());
    let request = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .expect("request must build");
    let response = app.oneshot(request).await.expect("router must respond");
    assert_eq!(response.status(), StatusCode::OK);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn valid_upload_returns_created_with_audit_fields() {
    let state = test_state(PackageValidationPolicy::production(), "valid");
    let package = golden_package_bytes();
    let (status, json, dir) = post_multipart(state.clone(), golden_body(&package)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["module_id"], "reporting-service");
    assert_eq!(json["version"], "1.2.0");
    assert_eq!(json["signer_key_id"], "k1");
    assert_eq!(
        json["digest"].as_str().expect("digest").len(),
        64,
        "digest must be 32-byte hex"
    );
    // Accepted bytes stay quarantined for the artifact store to promote.
    assert_eq!(quarantine_zip_count(&dir), 1);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn tampered_bytes_are_unauthorized_and_discarded() {
    let state = test_state(PackageValidationPolicy::production(), "tampered");
    let mut package = golden_package_bytes();
    // Sign the original, then flip a bit: authentication must fail before
    // any parsing verdict.
    let mut body = Vec::new();
    let signature = signature_base64_for(&package);
    let last = package.len() - 1;
    package[last] ^= 0xFF;
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    text_part(&mut body, "key_id", "k1");
    text_part(&mut body, "signature", &signature);
    let (status, json, dir) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "signature_verification_failed");
    assert_eq!(quarantine_zip_count(&dir), 0);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn unknown_key_is_unauthorized() {
    let state = test_state(PackageValidationPolicy::production(), "unknown-key");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    text_part(&mut body, "key_id", "someone-else");
    text_part(&mut body, "signature", &signature_base64_for(&package));
    let (status, json, _) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "unknown_signing_key");
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn missing_signature_field_is_bad_request() {
    let state = test_state(PackageValidationPolicy::production(), "missing-sig");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    text_part(&mut body, "key_id", "k1");
    let (status, json, _) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "missing_signature");
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn oversized_package_is_rejected_while_streaming() {
    let mut policy = PackageValidationPolicy::production();
    policy.archive.max_compressed_bytes = 10;
    let state = test_state(policy, "oversized");
    let package = golden_package_bytes();
    assert!(package.len() > 10);
    let (status, json, dir) = post_multipart(state.clone(), golden_body(&package)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json["code"], "payload_too_large");
    assert_eq!(quarantine_zip_count(&dir), 0);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn unknown_envelope_version_is_bad_request() {
    let state = test_state(PackageValidationPolicy::production(), "bad-version");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    text_part(&mut body, "key_id", "k1");
    text_part(&mut body, "signature", &signature_base64_for(&package));
    text_part(&mut body, "format_version", "99");
    let (status, json, _) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "invalid_signature_envelope");
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn duplicate_package_field_is_bad_request() {
    let state = test_state(PackageValidationPolicy::production(), "duplicate");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "a.zip", "application/zip", &package);
    file_part(&mut body, "package", "b.zip", "application/zip", &package);
    text_part(&mut body, "key_id", "k1");
    text_part(&mut body, "signature", &signature_base64_for(&package));
    let (status, json, _) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "duplicate_package_field");
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn oversized_text_field_is_bad_request() {
    let state = test_state(PackageValidationPolicy::production(), "big-field");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    text_part(&mut body, "key_id", &"k".repeat(300));
    text_part(&mut body, "signature", &signature_base64_for(&package));
    let (status, json, _) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "field_too_large");
    cleanup(&state.quarantine_dir);
}

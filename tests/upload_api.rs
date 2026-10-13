//! Upload API: multipart streaming, limits, transport hardening, and
//! verdict mapping through the public HTTP surface.
//!
//! Each test builds a fresh router with trust configured by value and a
//! private quarantine directory, so tests can run in parallel without
//! sharing state. The golden package is built in-test (same precedent as
//! `tests/package_validation.rs`): it cannot drift from the schema.
//!
//! One test per hardening effort: bearer auth (missing/wrong), security
//! response headers plus absent server identity, form-field cap,
//! concurrency bound, minimum upload speed, and TLS-only serving (see
//! `tests/tls_only.rs` for the socket proof; HSTS is asserted here).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::prelude::*;
use bytes::Bytes;
use conductor::api::routes::router;
use conductor::api::uploads::{ApiToken, AppState};
use conductor::audit::recorder::RejectionRecorder;
use conductor::audit::store::RejectionStore;
use conductor::control_plane::validate_package::PackageValidationBuilder;
use conductor::modules::registry::ModuleRegistry;
use conductor::packages::artifact::ArtifactDigest;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    canonical_payload, ConfiguredTrustedKeys, SignatureAlgorithm, TrustedSigningKey,
};
use tokio::sync::Semaphore;
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
    )])
    .expect("distinct test keys must build");
    let validator = PackageValidationBuilder::new(policy)
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let quarantine_dir = std::env::temp_dir().join(format!(
        "conductor-upload-api-{}-{}-{tag}-q",
        std::process::id(),
        nanos
    ));
    let artifact_dir = std::env::temp_dir().join(format!(
        "conductor-upload-api-{}-{}-{tag}-a",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&quarantine_dir).expect("quarantine dir must be created");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir must be created");
    // Durable rejection sink: a private in-memory store per test so rows
    // can be asserted without sharing state. Recorder failures stay
    // invisible to the response path by contract.
    let rejection_store =
        Arc::new(RejectionStore::open_in_memory().expect("rejection store must open"));
    AppState {
        validator: Arc::new(validator),
        quarantine_dir,
        artifact_dir,
        registry: Arc::new(ModuleRegistry::new()),
        recorder: Arc::new(RejectionRecorder::with_store(rejection_store)),
        request_timeout: Duration::from_secs(10),
        api_token: ApiToken::new("test-bearer-upload"),
        upload_slots: Arc::new(Semaphore::new(8)),
        min_upload_bytes_per_sec: 8_192,
        rate_grace: Duration::from_secs(5),
    }
}

fn golden_package_bytes() -> Vec<u8> {
    package_bytes_with_payload(b"not a real executable")
}

/// Golden identity (`reporting-service` `1.2.0`) with a caller-chosen
/// payload, for conflict cases that must differ only in bytes.
fn package_bytes_with_payload(payload: &[u8]) -> Vec<u8> {
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
        .write_all(payload)
        .expect("zip writer must accept payload bytes");
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

fn signature_base64_for(bytes: &[u8]) -> String {
    use ed25519_dalek::{Signer as _, SigningKey};

    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let digest: [u8; 32] = Sha256DigestProvider
        .digest(bytes)
        .expect("hashing must succeed");
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

/// Raw upload sender: full control over body, bearer, and extra headers.
/// Returns status, response headers, and raw body for header assertions.
async fn send_upload(
    state: &AppState,
    body: Body,
    bearer: Option<&str>,
    extra_headers: &[(&str, String)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let app = router(state.clone());
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/packages")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, value.as_str());
    }
    let request = builder.body(body).expect("request must build");
    let response = app.oneshot(request).await.expect("router must respond");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (status, headers, bytes.to_vec())
}

async fn post_multipart(
    state: AppState,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value, PathBuf) {
    let (status, _, bytes) =
        send_upload(&state, Body::from(body), Some("test-bearer-upload"), &[]).await;
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

/// `io::Write` sink shared with the test so rejection events can be
/// asserted on.
#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock must not poison")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Installs a thread-local subscriber capturing every audit event. The
/// guard must stay alive while requests are sent; `#[tokio::test]` uses a
/// current-thread runtime, so the router's events land on this thread.
fn capture_rejection_events() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(CaptureWriter(Arc::clone(&buffer)))
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .finish();
    (buffer, tracing::subscriber::set_default(subscriber))
}

fn captured_events(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    let captured = buffer.lock().expect("capture lock must not poison").clone();
    String::from_utf8(captured).expect("captured output must be UTF-8")
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
async fn healthz_carries_request_id() {
    // Pins the Set/Propagate request-id layer pairing: the id is
    // server-generated per response, so its presence proves the layers run
    // in the order the route table documents.
    let state = test_state(PackageValidationPolicy::production(), "request-id");
    let app = router(state.clone());
    let request = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .expect("request must build");
    let response = app.oneshot(request).await.expect("router must respond");
    let id = response
        .headers()
        .get("x-request-id")
        .expect("every response carries a request id");
    assert!(!id.is_empty());
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
    // Promotion consumes quarantine: nothing attacker-controlled is left
    // behind, and exactly one immutable artifact exists.
    assert_eq!(quarantine_zip_count(&dir), 0);
    let digest = json["digest"].as_str().expect("digest");
    let artifact = state
        .artifact_dir
        .join("reporting-service")
        .join("1.2.0")
        .join(format!("{digest}.zip"));
    assert!(artifact.is_file());
    assert_eq!(
        std::fs::read(&artifact).expect("artifact must read"),
        package
    );
    cleanup(&state.quarantine_dir);
    cleanup(&state.artifact_dir);
}

#[tokio::test]
async fn identical_reupload_is_idempotent_over_one_artifact() {
    let state = test_state(PackageValidationPolicy::production(), "idempotent");
    let package = golden_package_bytes();
    let (first, first_json, _) = post_multipart(state.clone(), golden_body(&package)).await;
    assert_eq!(first, StatusCode::CREATED);
    let (second, second_json, _) = post_multipart(state.clone(), golden_body(&package)).await;
    assert_eq!(second, StatusCode::CREATED);
    assert_eq!(second_json["digest"], first_json["digest"]);
    assert_eq!(quarantine_zip_count(&state.quarantine_dir), 0);
    // Exactly one immutable artifact file exists; the re-upload was
    // consumed as an identical duplicate, not written again.
    let version_dir = state.artifact_dir.join("reporting-service").join("1.2.0");
    let artifacts: Vec<_> = std::fs::read_dir(&version_dir)
        .expect("version dir must exist")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(artifacts.len(), 1);
    cleanup(&state.quarantine_dir);
    cleanup(&state.artifact_dir);
}

#[tokio::test]
async fn same_version_different_bytes_conflicts_with_409() {
    let state = test_state(PackageValidationPolicy::production(), "version-conflict");
    let package = golden_package_bytes();
    let (first, _, _) = post_multipart(state.clone(), golden_body(&package)).await;
    assert_eq!(first, StatusCode::CREATED);
    // Same module_id+version, different payload: valid signature, valid
    // package, but the version already means different bytes.
    let other = package_bytes_with_payload(b"different executable");
    let (conflict, json, _) = post_multipart(state.clone(), golden_body(&other)).await;
    assert_eq!(conflict, StatusCode::CONFLICT);
    assert_eq!(json["code"], "version_conflict");
    // The registered version still means the first bytes.
    let registered = state
        .registry
        .get("reporting-service", "1.2.0")
        .expect("lookup must succeed")
        .expect("version must stay registered");
    let expected: [u8; 32] = Sha256DigestProvider.digest(&package).expect("hash");
    assert_eq!(registered.digest, ArtifactDigest::new(expected));
    cleanup(&state.quarantine_dir);
    cleanup(&state.artifact_dir);
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
async fn unknown_key_is_unauthorized_without_key_oracle() {
    let state = test_state(PackageValidationPolicy::production(), "unknown-key");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    text_part(&mut body, "key_id", "someone-else");
    text_part(&mut body, "signature", &signature_base64_for(&package));
    let (status, json, _) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Same generic body as a bad signature: callers cannot probe for valid
    // key ids.
    assert_eq!(json["code"], "signature_verification_failed");
    assert_eq!(json["message"], "package signature verification failed");
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

// --- Transport hardening proofs: one test per effort. ---

#[tokio::test]
async fn upload_without_bearer_is_unauthorized() {
    let state = test_state(PackageValidationPolicy::production(), "no-bearer");
    let package = golden_package_bytes();
    let (status, headers, bytes) =
        send_upload(&state, Body::from(golden_body(&package)), None, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("body must be JSON");
    assert_eq!(json["code"], "missing_or_invalid_bearer");
    // RFC 9110 challenge names the transport scheme, not the package one.
    let challenge = headers
        .get("www-authenticate")
        .expect("401 must carry a challenge");
    assert!(challenge
        .to_str()
        .expect("challenge")
        .starts_with("Bearer "));
    // Nothing was quarantined: auth runs before the body streams.
    assert_eq!(quarantine_zip_count(&state.quarantine_dir), 0);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn wrong_bearer_is_indistinguishable_from_missing() {
    // No oracle: a wrong token gets the identical status and code as no
    // token, so callers cannot probe for token validity.
    let state = test_state(PackageValidationPolicy::production(), "wrong-bearer");
    let package = golden_package_bytes();
    let (status, _, bytes) = send_upload(
        &state,
        Body::from(golden_body(&package)),
        Some("wrong"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("body must be JSON");
    assert_eq!(json["code"], "missing_or_invalid_bearer");
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn responses_carry_security_headers_and_no_server_identity() {
    let state = test_state(PackageValidationPolicy::production(), "headers");
    let package = golden_package_bytes();
    let (status, headers, _) = send_upload(
        &state,
        Body::from(golden_body(&package)),
        Some("test-bearer-upload"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_security_headers(&headers);
    // Error responses are hardened identically: rejection must not leak
    // more than acceptance.
    let (status, err_headers, _) =
        send_upload(&state, Body::from(golden_body(&package)), None, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_security_headers(&err_headers);
    cleanup(&state.quarantine_dir);
}

/// Asserts the response hardening contract: every security header present
/// with its pinned value, and no header identifying the server stack.
fn assert_security_headers(headers: &HeaderMap) {
    let value = |name: &str| {
        headers
            .get(name)
            .unwrap_or_else(|| panic!("response must carry {name}"))
            .to_str()
            .expect("header must be visible ASCII")
            .to_owned()
    };
    assert_eq!(value("x-content-type-options"), "nosniff");
    assert_eq!(value("x-frame-options"), "DENY");
    assert_eq!(value("referrer-policy"), "no-referrer");
    assert_eq!(value("cache-control"), "no-store");
    assert!(
        value("strict-transport-security").starts_with("max-age=63072000"),
        "HSTS commits the service to HTTPS-only"
    );
    assert!(!value("x-request-id").is_empty());
    for identifying in ["server", "via", "x-powered-by", "x-aspnet-version"] {
        assert!(
            headers.get(identifying).is_none(),
            "response must not identify the server stack via {identifying}"
        );
    }
}

#[tokio::test]
async fn too_many_form_fields_rejected() {
    let state = test_state(PackageValidationPolicy::production(), "many-fields");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    text_part(&mut body, "key_id", "k1");
    text_part(&mut body, "signature", &signature_base64_for(&package));
    for i in 0..20 {
        text_part(&mut body, &format!("filler-{i}"), "filler");
    }
    let (status, json, dir) = post_multipart(state.clone(), finish_body(&mut body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "too_many_fields");
    assert_eq!(quarantine_zip_count(&dir), 0);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn concurrent_upload_bound_sheds_load() {
    // Zero slots: every upload is rejected before touching the body, so a
    // saturated server fails fast instead of queueing unbounded work.
    let mut state = test_state(PackageValidationPolicy::production(), "overloaded");
    state.upload_slots = Arc::new(Semaphore::new(0));
    let package = golden_package_bytes();
    let (status, _, bytes) = send_upload(
        &state,
        Body::from(golden_body(&package)),
        Some("test-bearer-upload"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("body must be JSON");
    assert_eq!(json["code"], "server_busy");
    assert_eq!(quarantine_zip_count(&state.quarantine_dir), 0);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn trickle_upload_rejected_with_408() {
    // Floor far above any legitimate speed with a millisecond grace, then
    // a body that stalls mid-transfer: the rate floor must trip instead
    // of occupying a slot until the total timeout.
    let mut state = test_state(PackageValidationPolicy::production(), "trickle");
    state.min_upload_bytes_per_sec = 50_000_000;
    state.rate_grace = Duration::from_millis(50);
    let full = golden_body(&golden_package_bytes());
    let (first, rest) = full.split_at(128);
    let first = first.to_vec();
    let rest = rest.to_vec();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::spawn(async move {
        let _ = tx.send(Ok(Bytes::from(first))).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = tx.send(Ok(Bytes::from(rest))).await;
    });
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    let (status, _, bytes) = send_upload(&state, body, Some("test-bearer-upload"), &[]).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("body must be JSON");
    assert_eq!(json["code"], "slow_upload");
    assert_eq!(quarantine_zip_count(&state.quarantine_dir), 0);
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn missing_bearer_records_exactly_one_transport_event() {
    let state = test_state(PackageValidationPolicy::production(), "audit-401");
    let (buffer, guard) = capture_rejection_events();
    let (status, _, _) = send_upload(&state, Body::empty(), None, &[]).await;
    drop(guard);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let events = captured_events(&buffer);
    assert_eq!(events.matches("package rejected").count(), 1, "{events}");
    assert!(events.contains("stage=\"transport\""), "{events}");
    assert!(
        events.contains("code=\"missing_or_invalid_bearer\""),
        "{events}"
    );
    assert!(
        events.contains("request_id=\""),
        "the server-issued request id must be attached: {events}"
    );
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn signature_failure_records_typed_event_with_internal_reason() {
    let state = test_state(PackageValidationPolicy::production(), "audit-signature");
    let package = golden_package_bytes();
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", "application/zip", &package);
    // Unknown key id: the response stays generic, the event keeps the
    // internal reason for operators.
    text_part(&mut body, "key_id", "k9");
    text_part(&mut body, "signature", &signature_base64_for(&package));
    let (buffer, guard) = capture_rejection_events();
    let (status, _, _) = send_upload(
        &state,
        Body::from(finish_body(&mut body)),
        Some("test-bearer-upload"),
        &[],
    )
    .await;
    drop(guard);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let events = captured_events(&buffer);
    assert_eq!(events.matches("package rejected").count(), 1, "{events}");
    assert!(events.contains("stage=\"signature\""), "{events}");
    assert!(
        events.contains("code=\"signature_verification_failed\""),
        "{events}"
    );
    assert!(
        events.contains("k9"),
        "internal key detail missing: {events}"
    );
    cleanup(&state.quarantine_dir);
}

#[tokio::test]
async fn malformed_multipart_body_records_one_typed_event() {
    let state = test_state(PackageValidationPolicy::production(), "audit-multipart");
    let (buffer, guard) = capture_rejection_events();
    // Valid bearer and multipart content type, but a body that fails to
    // parse inside the handler: the typed multipart path records exactly
    // one event, and the fallback must skip it (response marker).
    let (status, _, _) = send_upload(
        &state,
        Body::from("definitely not multipart"),
        Some("test-bearer-upload"),
        &[],
    )
    .await;
    drop(guard);
    assert!(status.is_client_error(), "unexpected status {status}");
    let events = captured_events(&buffer);
    assert_eq!(events.matches("package rejected").count(), 1, "{events}");
    assert!(events.contains("stage=\"multipart\""), "{events}");
    assert!(events.contains("code=\"invalid_multipart\""), "{events}");
    cleanup(&state.quarantine_dir);
}

fn rejection_rows(state: &AppState) -> Vec<conductor::audit::store::StoredRejection> {
    state
        .recorder
        .store()
        .expect("test state must attach a rejection store")
        .list()
        .expect("rejection rows must read")
}

#[tokio::test]
async fn version_conflict_persists_one_row_with_stage_code_and_attribution() {
    let state = test_state(PackageValidationPolicy::production(), "rejection-row");
    let package = golden_package_bytes();
    let (first, _, _) = post_multipart(state.clone(), golden_body(&package)).await;
    assert_eq!(first, StatusCode::CREATED);
    // Same module_id+version, different payload: the version already means
    // different bytes, so the upload is a 409 with an unchanged body.
    let other = package_bytes_with_payload(b"different executable");
    let (conflict, json, _) = post_multipart(state.clone(), golden_body(&other)).await;
    assert_eq!(conflict, StatusCode::CONFLICT);
    assert_eq!(json["code"], "version_conflict");
    let rows = rejection_rows(&state);
    assert_eq!(rows.len(), 1, "one rejection must persist exactly one row");
    let row = &rows[0];
    assert_eq!(row.stage, "registration");
    assert_eq!(row.code, "version_conflict");
    assert_eq!(row.module_id.as_deref(), Some("reporting-service"));
    assert_eq!(row.version.as_deref(), Some("1.2.0"));
    assert_eq!(row.key_id.as_deref(), Some("k1"));
    assert_eq!(
        row.digest.as_deref().map(str::len),
        Some(64),
        "digest attribution must survive once the digest stage was reached"
    );
    assert!(
        row.byte_count.is_some(),
        "streamed byte count must be attributed"
    );
    assert!(
        !row.detail.is_empty(),
        "the internal reason must be persisted"
    );
    cleanup(&state.quarantine_dir);
    cleanup(&state.artifact_dir);
}

#[tokio::test]
async fn accepted_upload_persists_no_rejection_row() {
    let state = test_state(PackageValidationPolicy::production(), "accepted-no-row");
    let package = golden_package_bytes();
    let (status, _, _) = post_multipart(state.clone(), golden_body(&package)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(
        rejection_rows(&state).is_empty(),
        "an accepted upload must leave the rejection table empty"
    );
    cleanup(&state.quarantine_dir);
    cleanup(&state.artifact_dir);
}

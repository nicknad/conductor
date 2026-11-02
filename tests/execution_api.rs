//! Activation and execution HTTP API end to end: a signed package is
//! uploaded through the real upload route, activated, and executed through
//! the assembled host's shared `ExecutionService`.
//!
//! Unix-gated because the worker fixtures are `#!/bin/sh` entrypoints and
//! the executor only controls process groups on Unix. Process-spawning tests
//! are serialized (`#[serial]`) so fixture exec permissions cannot race an
//! in-flight spawn.

#![cfg(unix)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::prelude::*;
use conductor::api::routes::router;
use conductor::api::uploads::AppState;
use conductor::config::{Config, TrustedKeyConfig};
use conductor::control_plane::execute_module::ActivationHook;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::signature::{canonical_payload, SignatureAlgorithm};
use conductor::server::Host;
use ed25519_dalek::{Signer as _, SigningKey};
use serial_test::serial;
use tower::ServiceExt as _;

/// Test-only signing key. Must never sign anything outside these tests.
const TEST_SIGNING_KEY: [u8; 32] = [42u8; 32];
const TOKEN: &str = "execution-api-token";
const BOUNDARY: &str = "conductor-execution-api-boundary";
const MODULE_ID: &str = "worker-fixture";

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

const SCRIPT_ROWS_3: &str = r#"#!/bin/sh
read -r line
printf 'diag-one\n' >&2
printf '{"protocol_version":1,"status":"ok","result":{"rows":3}}\n'
"#;

const SCRIPT_ROWS_4: &str = r#"#!/bin/sh
read -r line
printf 'diag-two\n' >&2
printf '{"protocol_version":1,"status":"ok","result":{"rows":4}}\n'
"#;

fn temp_root(tag: &str) -> PathBuf {
    let count = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "conductor-execution-api-{}-{tag}-{count}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

fn config_for(root: &Path, max_deadline_secs: u64, max_concurrent: usize) -> Config {
    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    Config {
        http_bind: "127.0.0.1:0".to_owned(),
        storage_root: root.to_path_buf(),
        api_token: Some(TOKEN.to_owned()),
        trusted_keys: vec![TrustedKeyConfig {
            key_id: "k1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_base64: BASE64_STANDARD.encode(signing.verifying_key().to_bytes()),
        }],
        max_execution_deadline_secs: max_deadline_secs,
        max_concurrent_executions: max_concurrent,
        ..Config::default()
    }
}

fn assembled_state(root: &Path, max_deadline_secs: u64, max_concurrent: usize) -> AppState {
    Host::assemble(config_for(root, max_deadline_secs, max_concurrent))
        .expect("valid test configuration must assemble")
        .into_state()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256DigestProvider
        .digest(bytes)
        .expect("hash must succeed")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Builds a package whose entrypoint is the supplied shell script. A v2
/// manifest declares real per-file integrity; a v1 manifest lists paths only
/// so execution must refuse it later.
fn package_bytes(module_id: &str, version: &str, manifest_version: u32, script: &str) -> Vec<u8> {
    let files = if manifest_version == 2 {
        vec![serde_json::json!({
            "path": "payload/worker",
            "size": script.len() as u64,
            "sha256": sha256_hex(script.as_bytes()),
        })]
    } else {
        vec![serde_json::json!("payload/worker")]
    };
    let manifest = serde_json::json!({
        "manifest_version": manifest_version,
        "module_id": module_id,
        "version": version,
        "runtime": "rust",
        "entrypoint": "payload/worker",
        "files": files,
    });
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("manifest entry must be writable");
    writer
        .write_all(&serde_json::to_vec(&manifest).expect("manifest must serialize"))
        .expect("manifest bytes must be writable");
    writer
        .start_file("payload/worker", options)
        .expect("payload entry must be writable");
    writer
        .write_all(script.as_bytes())
        .expect("payload bytes must be writable");
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

fn signature_base64_for(bytes: &[u8]) -> String {
    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let digest: [u8; 32] = Sha256DigestProvider
        .digest(bytes)
        .expect("hashing must succeed");
    BASE64_STANDARD.encode(signing.sign(&canonical_payload(&digest)).to_bytes())
}

fn text_part(body: &mut Vec<u8>, name: &str, value: &str) {
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
}

fn file_part(body: &mut Vec<u8>, name: &str, filename: &str, bytes: &[u8]) {
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/zip\r\n\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
}

fn upload_body(package: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    file_part(&mut body, "package", "pkg.zip", package);
    text_part(&mut body, "key_id", "k1");
    text_part(&mut body, "signature", &signature_base64_for(package));
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn post_upload(
    state: &AppState,
    package: &[u8],
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    post_bytes(
        state,
        "/v1/packages",
        upload_body(package),
        "multipart/form-data; boundary=conductor-execution-api-boundary",
        bearer,
    )
    .await
}

async fn post_json(
    state: &AppState,
    uri: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    post_bytes(
        state,
        uri,
        serde_json::to_vec(&body).expect("request body must serialize"),
        "application/json",
        bearer,
    )
    .await
}

async fn post_bytes(
    state: &AppState,
    uri: &str,
    body: Vec<u8>,
    content_type: &str,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", content_type);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = router(state.clone())
        .oneshot(builder.body(Body::from(body)).expect("request must build"))
        .await
        .expect("router must respond");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body must read");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn activate_uri(module_id: &str) -> String {
    format!("/v1/modules/{module_id}/activate")
}

fn execute_uri(module_id: &str) -> String {
    format!("/v1/modules/{module_id}/executions")
}

fn assert_generic_error(json: &serde_json::Value, root: &Path) {
    let message = json["message"]
        .as_str()
        .expect("error body must carry a message");
    assert!(!message.is_empty(), "error message must not be empty");
    assert!(
        !message.contains(root.to_str().expect("temp root must be UTF-8")),
        "error leaked the storage root: {message}"
    );
    assert!(
        !message.contains(".zip"),
        "error leaked an artifact path: {message}"
    );
    assert!(
        !message.contains("os error") && !message.contains("No such file"),
        "error leaked OS detail: {message}"
    );
}

#[tokio::test]
#[serial]
async fn authenticated_upload_activate_and_execute_round_trip() {
    let root = temp_root("round-trip");
    let state = assembled_state(&root, 30, 4);

    let (status, first) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, second) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.3.0", 2, SCRIPT_ROWS_4),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, activated) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(activated["module_id"], MODULE_ID);
    assert_eq!(activated["version"], "1.2.0");
    assert_eq!(activated["digest"], first["digest"]);
    assert_eq!(activated["signer_key_id"], "k1");

    let (status, executed) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({
            "function": "run",
            "configuration": {"batch": 7},
            "deadline_secs": 5
        }),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "execute body: {executed}");
    assert_eq!(executed["module_id"], MODULE_ID);
    assert_eq!(executed["version"], "1.2.0");
    assert_eq!(executed["digest"], first["digest"]);
    assert_eq!(executed["outcome"], "succeeded");
    assert!(executed["execution_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert!(executed["duration_ms"].is_u64());
    assert!(
        executed["stdout"]
            .as_str()
            .is_some_and(|out| out.contains("\"rows\":3")),
        "stdout must carry the worker protocol response: {executed}"
    );
    assert!(
        executed["stderr"]
            .as_str()
            .is_some_and(|err| err.contains("diag-one")),
        "stderr must carry worker diagnostics: {executed}"
    );

    // Pinned execution overrides the active pointer for this one request.
    let (status, pinned) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({
            "version": "1.3.0",
            "function": "run",
            "deadline_secs": 5
        }),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "pinned body: {pinned}");
    assert_eq!(pinned["version"], "1.3.0");
    assert_eq!(pinned["digest"], second["digest"]);
    assert_eq!(pinned["outcome"], "succeeded");
    assert!(
        pinned["stdout"]
            .as_str()
            .is_some_and(|out| out.contains("\"rows\":4")),
        "pinned version must run its own bytes: {pinned}"
    );

    let active = state
        .registry
        .get_active(MODULE_ID)
        .expect("active lookup must succeed")
        .expect("activation must persist the pointer");
    assert_eq!(active.version, "1.2.0");
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn activation_persists_across_an_assembled_host_restart() {
    let root = temp_root("activation-persist");
    let config = config_for(&root, 30, 4);
    let first = Host::assemble(config.clone())
        .expect("first assembly must succeed")
        .into_state();
    let (status, _) = post_upload(
        &first,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &first,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    drop(first);

    let second = Host::assemble(config)
        .expect("restart assembly must succeed")
        .into_state();
    let active = second
        .registry
        .get_active(MODULE_ID)
        .expect("active lookup must succeed")
        .expect("the active pointer must survive a restart");
    assert_eq!(active.version, "1.2.0");
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn both_routes_require_the_bearer_token() {
    let root = temp_root("unauthenticated");
    let state = assembled_state(&root, 30, 4);
    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    for (uri, body) in [
        (
            activate_uri(MODULE_ID),
            serde_json::json!({"version": "1.2.0"}),
        ),
        (
            execute_uri(MODULE_ID),
            serde_json::json!({"function": "run", "deadline_secs": 5}),
        ),
    ] {
        let (status, json) = post_json(&state, &uri, body, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "uri {uri}");
        assert_eq!(json["code"], "missing_or_invalid_bearer");
        assert_generic_error(&json, &root);
    }
    assert_eq!(
        state
            .registry
            .get_active(MODULE_ID)
            .expect("active lookup must succeed"),
        None,
        "an unauthenticated activation must not persist anything"
    );
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn unknown_and_inactive_modules_are_not_found() {
    let root = temp_root("not-found");
    let state = assembled_state(&root, 30, 4);

    let (status, missing) = post_json(
        &state,
        &execute_uri("missing-module"),
        serde_json::json!({"version": "1.0.0", "function": "run", "deadline_secs": 5}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing["code"], "module_not_found");
    assert_generic_error(&missing, &root);

    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, inactive) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 5}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(inactive["code"], "module_not_active");
    assert_generic_error(&inactive, &root);
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn v1_manifest_is_refused_for_execution_but_activates() {
    let root = temp_root("legacy-manifest");
    let state = assembled_state(&root, 30, 4);
    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 1, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 5}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["code"], "legacy_manifest");
    assert_generic_error(&json, &root);
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn tampered_artifact_is_refused_without_leaking_its_path() {
    let root = temp_root("tampered-artifact");
    let state = assembled_state(&root, 30, 4);
    let (status, uploaded) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let digest = uploaded["digest"].as_str().expect("digest");
    let artifact = state
        .artifact_dir
        .join(MODULE_ID)
        .join("1.2.0")
        .join(format!("{digest}.zip"));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&artifact)
        .expect("promoted artifact must open");
    file.write_all(b"tampered")
        .expect("artifact tamper must write");
    drop(file);

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 5}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["code"], "artifact_integrity_failed");
    assert_generic_error(&json, &root);
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn deadline_over_the_host_maximum_is_rejected_before_any_worker() {
    let root = temp_root("deadline");
    let state = assembled_state(&root, 5, 4);
    let marker = root.join("worker-started");
    let script = format!(
        "#!/bin/sh\nread -r line\ntouch '{}'\nprintf '{{\"protocol_version\":1,\"status\":\"ok\",\"result\":{{}}}}\\n'\n",
        marker.display()
    );
    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, &script),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 6}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "deadline_exceeded");
    assert_generic_error(&json, &root);
    assert!(
        !marker.exists(),
        "a refused deadline must not spawn a worker"
    );

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 0}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "invalid_deadline");
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn omitted_deadline_is_clamped_to_the_host_maximum() {
    let root = temp_root("deadline-default-clamped");
    // A host maximum below the 30s documented default must stay usable when
    // the caller omits `deadline_secs`.
    let state = assembled_state(&root, 5, 4);
    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an omitted deadline must be clamped, not rejected: {json}"
    );
    assert_eq!(json["outcome"], "succeeded");
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn execution_capacity_exhaustion_is_service_unavailable() {
    let root = temp_root("overloaded");
    let state = assembled_state(&root, 5, 1);
    let marker = root.join("worker-started");
    let script = format!(
        "#!/bin/sh\nread -r line\ntouch '{}'\nsleep 5\nprintf '{{\"protocol_version\":1,\"status\":\"ok\",\"result\":{{}}}}\\n'\n",
        marker.display()
    );
    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, &script),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let first = {
        let state = state.clone();
        let uri = execute_uri(MODULE_ID);
        tokio::spawn(async move {
            post_json(
                &state,
                &uri,
                serde_json::json!({"function": "run", "deadline_secs": 3}),
                Some(TOKEN),
            )
            .await
        })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first worker must start before overload is probed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 1}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["code"], "server_busy");
    assert_generic_error(&json, &root);

    let (first_status, first_body) = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .expect("the first execution must finish")
        .expect("the first execution task must not panic");
    assert_eq!(first_status, StatusCode::OK, "first body: {first_body}");
    assert_eq!(first_body["outcome"], "timed_out");
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn oversized_json_body_is_rejected_at_the_route_bound() {
    let root = temp_root("body-limit");
    let state = assembled_state(&root, 30, 4);
    let body = serde_json::json!({
        "function": "x".repeat(2 * 1024 * 1024),
        "deadline_secs": 5
    });

    let (status, json) = post_json(&state, &execute_uri(MODULE_ID), body, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json["code"], "payload_too_large");
    assert_generic_error(&json, &root);
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn activation_refuses_a_missing_artifact_without_persisting_a_pointer() {
    let root = temp_root("activation-missing-artifact");
    let state = assembled_state(&root, 30, 4);
    let (status, uploaded) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let digest = uploaded["digest"].as_str().expect("digest");
    let artifact = state
        .artifact_dir
        .join(MODULE_ID)
        .join("1.2.0")
        .join(format!("{digest}.zip"));
    std::fs::remove_file(&artifact).expect("artifact must be removable");

    let (status, json) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["code"], "internal");
    assert_eq!(json["message"], "internal error");
    assert_generic_error(&json, &root);
    assert_eq!(
        state
            .registry
            .get_active(MODULE_ID)
            .expect("active lookup must succeed"),
        None,
        "activation must not persist a pointer for an unusable artifact"
    );
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn missing_artifact_after_activation_is_a_generic_internal_error() {
    let root = temp_root("execution-missing-artifact");
    let state = assembled_state(&root, 30, 4);
    let (status, uploaded) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let digest = uploaded["digest"].as_str().expect("digest");
    let artifact = state
        .artifact_dir
        .join(MODULE_ID)
        .join("1.2.0")
        .join(format!("{digest}.zip"));
    std::fs::remove_file(&artifact).expect("artifact must be removable");

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 5}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["code"], "internal");
    assert_eq!(json["message"], "internal error");
    assert_generic_error(&json, &root);
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn staging_host_io_failure_is_a_generic_internal_error() {
    let root = temp_root("staging-host-io");
    let state = assembled_state(&root, 30, 4);
    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Replace the private staging root with a regular file after assembly.
    // Extraction can no longer create a stage directory, which is host I/O,
    // not a package-content refusal.
    let staging = root.join("staging");
    std::fs::remove_dir_all(&staging).expect("staging root must be removable");
    std::fs::write(&staging, b"not a directory").expect("blocking file must be written");

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run", "deadline_secs": 5}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["code"], "internal");
    assert_eq!(json["message"], "internal error");
    assert_generic_error(&json, &root);
    cleanup(&root);
}

#[tokio::test]
#[serial]
async fn audit_rows_contain_no_paths_os_errors_or_control_identities() {
    let root = temp_root("audit-sanitization");
    let state = assembled_state(&root, 30, 4);
    let store = std::sync::Arc::clone(
        state
            .recorder
            .store()
            .expect("assembled host must attach a durable store"),
    );

    // A tampered artifact reaches the digest/size refusal and must leave a
    // sanitized row.
    let (status, uploaded) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let digest = uploaded["digest"].as_str().expect("digest");
    let artifact = state
        .artifact_dir
        .join(MODULE_ID)
        .join("1.2.0")
        .join(format!("{digest}.zip"));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&artifact)
        .expect("artifact must open");
    file.write_all(b"tampered").expect("tamper must write");
    drop(file);
    let (status, json) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.2.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["code"], "artifact_integrity_failed");

    // An unreadable artifact (symlink loop) reaches the canonicalization I/O
    // refusal, whose Display text contains an OS error and a relpath.
    let (status, uploaded) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.3.0", 2, SCRIPT_ROWS_4),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let digest = uploaded["digest"].as_str().expect("digest");
    let artifact = state
        .artifact_dir
        .join(MODULE_ID)
        .join("1.3.0")
        .join(format!("{digest}.zip"));
    std::fs::remove_file(&artifact).expect("artifact must be removable");
    std::os::unix::fs::symlink(&artifact, &artifact).expect("self symlink must be creatable");
    let (status, json) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.3.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["code"], "internal");
    assert_eq!(json["message"], "internal error");

    // Percent-decoded control characters and an ANSI escape must be refused
    // before any registry work, and must not be persisted as attribution.
    let (status, json) = post_json(
        &state,
        "/v1/modules/bad%0Amodule/activate",
        serde_json::json!({"version": "1.0.0"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "invalid_identity");

    let (status, json) = post_json(
        &state,
        &activate_uri(MODULE_ID),
        serde_json::json!({"version": "1.0.0\u{1b}[31m"}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "invalid_identity");

    let (status, json) = post_json(
        &state,
        &execute_uri(MODULE_ID),
        serde_json::json!({"function": "run\u{1b}[31m", "deadline_secs": 5}),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "invalid_identity");

    let rows = store.list().expect("rejection rows must read back");
    assert!(
        rows.len() >= 5,
        "each refusal must produce one durable row: {rows:?}"
    );
    let root_text = root.to_str().expect("temp root must be UTF-8");
    for row in &rows {
        let detail = &row.detail;
        assert!(!detail.contains(".zip"), "detail leaked a path: {detail}");
        assert!(
            !detail.to_ascii_lowercase().contains("os error"),
            "detail leaked an OS error: {detail}"
        );
        assert!(
            !detail.contains("Permission denied"),
            "detail leaked an OS error: {detail}"
        );
        assert!(
            !detail.contains(root_text),
            "detail leaked the storage root: {detail}"
        );
        assert!(
            !detail.chars().any(char::is_control),
            "detail contains a control character: {detail:?}"
        );
        assert!(
            !detail.contains('\u{1b}'),
            "detail contains an ANSI escape: {detail:?}"
        );
        for value in [&row.module_id, &row.version, &row.key_id]
            .into_iter()
            .flatten()
        {
            assert!(
                !value.chars().any(char::is_control),
                "attribution contains a control character: {value:?}"
            );
            assert!(
                !value.contains('\u{1b}'),
                "attribution contains an ANSI escape: {value:?}"
            );
        }
    }
    cleanup(&root);
}

#[tokio::test(flavor = "current_thread")]
#[serial]
async fn blocked_activation_does_not_starve_the_health_probe() {
    let root = temp_root("activation-blocking");
    let mut state = assembled_state(&root, 30, 4);
    let (status, _) = post_upload(
        &state,
        &package_bytes(MODULE_ID, "1.2.0", 2, SCRIPT_ROWS_3),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let started_tx = std::sync::Mutex::new(Some(started_tx));
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let hook = ActivationHook::new(move || {
        if let Some(started_tx) = started_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = started_tx.send(());
        }
        let _ = release_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv();
    });
    state.execution_service = std::sync::Arc::new(
        (*state.execution_service)
            .clone()
            .with_activation_hook(hook),
    );

    let activation = tokio::spawn({
        let state = state.clone();
        let uri = activate_uri(MODULE_ID);
        async move {
            post_json(
                &state,
                &uri,
                serde_json::json!({"version": "1.2.0"}),
                Some(TOKEN),
            )
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(5), started_rx)
        .await
        .expect("blocking activation must start")
        .expect("activation hook must signal");

    let request = Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .expect("health request must build");
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        router(state.clone()).oneshot(request),
    )
    .await
    .expect("healthz must not wait for the blocked activation")
    .expect("router must respond");
    assert_eq!(response.status(), StatusCode::OK);

    release_tx
        .send(())
        .expect("blocked activation must still be waiting");
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), activation)
        .await
        .expect("activation must finish after release")
        .expect("activation task must not panic");
    assert_eq!(status, StatusCode::OK, "activation body: {body}");
    cleanup(&root);
}

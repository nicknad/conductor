//! Scheduler HTTP surface end to end: create/list/enable/disable/trigger,
//! durable runs, and a successful run through the pinned execution service.

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
use conductor::control_plane::scheduler::job::{next_run_at, MAX_INTERVAL_SECS};
use conductor::control_plane::scheduler::{JobFailureCode, JobRunState, Trigger};
use conductor::modules::registry::{IntegrityState, ModuleRecord};
use conductor::packages::artifact::ArtifactDigest;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::signature::SignatureAlgorithm;
use conductor::server::Host;
use conductor::storage::artifact_store::canonical_artifact_relpath;
use serde_json::{json, Value};
use serial_test::serial;
use tower::ServiceExt as _;

const TOKEN: &str = "scheduler-api-token";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "conductor-scheduler-api-{}-{tag}-{count}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: &Path) -> Config {
    Config {
        storage_root: root.to_path_buf(),
        api_token: Some(TOKEN.to_owned()),
        trusted_keys: vec![TrustedKeyConfig {
            key_id: "k1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_base64: BASE64_STANDARD.encode([9u8; 32]),
        }],
        max_execution_deadline_secs: 30,
        max_concurrent_executions: 4,
        ..Config::default()
    }
}

async fn assembled(tag: &str) -> (AppState, Scratch) {
    let scratch = Scratch::new(tag);
    let host = Host::assemble(config(scratch.path())).expect("host must assemble");
    (host.into_state(), scratch)
}

async fn state_with_capacity(tag: &str, max_concurrent_executions: usize) -> (AppState, Scratch) {
    let scratch = Scratch::new(tag);
    let mut config = config(scratch.path());
    config.max_concurrent_executions = max_concurrent_executions;
    let host = Host::assemble(config).expect("host must assemble");
    let state = host.into_state();
    state.scheduler.start().await.expect("scheduler must start");
    (state, scratch)
}

async fn state(tag: &str) -> (AppState, Scratch) {
    let (state, scratch) = assembled(tag).await;
    state.scheduler.start().await.expect("scheduler must start");
    (state, scratch)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256DigestProvider
        .digest(bytes)
        .expect("hash")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn package(module_id: &str, version: &str, script: &str) -> (Vec<u8>, String) {
    let manifest = json!({
        "manifest_version": 2,
        "module_id": module_id,
        "version": version,
        "runtime": "rust",
        "entrypoint": "payload/worker",
        "files": [{
            "path": "payload/worker",
            "size": script.len() as u64,
            "sha256": sha256_hex(script.as_bytes()),
        }],
    });
    let manifest_json = serde_json::to_string(&manifest).expect("manifest");
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("manifest entry");
    writer
        .write_all(manifest_json.as_bytes())
        .expect("manifest bytes");
    writer
        .start_file("payload/worker", options)
        .expect("worker entry");
    writer.write_all(script.as_bytes()).expect("worker bytes");
    writer.finish().expect("zip");
    (cursor.into_inner(), manifest_json)
}

fn install_package(state: &AppState, module_id: &str, version: &str, script: &str) {
    let (bytes, manifest_json) = package(module_id, version, script);
    let digest_bytes = Sha256DigestProvider.digest(&bytes).expect("digest");
    let digest = ArtifactDigest::new(digest_bytes);
    let relpath = canonical_artifact_relpath(module_id, version, &digest);
    let artifact_path = state.artifact_dir.join(&relpath);
    std::fs::create_dir_all(artifact_path.parent().expect("artifact parent"))
        .expect("artifact parent mkdir");
    std::fs::write(&artifact_path, &bytes).expect("artifact write");
    state
        .registry
        .record(ModuleRecord {
            module_id: module_id.to_owned(),
            version: version.to_owned(),
            digest,
            signer_key_id: "k1".to_owned(),
            runtime: "rust".to_owned(),
            manifest_version: 2,
            manifest_json,
            artifact_relpath: relpath,
            artifact_size: bytes.len() as u64,
            integrity_state: IntegrityState::Ok,
            registered_at: SystemTime::now(),
        })
        .expect("registry record");
}

async fn send_json(
    state: &AppState,
    method: &str,
    uri: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value).expect("body"))
        }
        None => Body::empty(),
    };
    let response = router(state.clone())
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("router response");
    let status = response.status();
    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else if is_json {
        serde_json::from_slice(&bytes).expect("JSON response body must parse")
    } else {
        Value::String(String::from_utf8(bytes.to_vec()).expect("text response must be UTF-8"))
    };
    (status, value)
}

async fn create_job(state: &AppState, module_id: &str, version: &str) -> String {
    let (status, body) = send_json(
        state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": module_id,
            "version": version,
            "function": "run",
            "trigger": {"kind": "manual"},
            "payload": {"marker": "payload-secret-marker"},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    assert!(
        !body.to_string().contains("payload-secret-marker"),
        "payload must not be echoed: {body}"
    );
    body["job_id"].as_str().expect("job id").to_owned()
}

async fn wait_for_terminal(state: &AppState, job_id: &str) -> Value {
    for _ in 0..200 {
        let (status, body) = send_json(
            state,
            "GET",
            &format!("/v1/jobs/{job_id}/runs"),
            None,
            Some(TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "runs response: {body}");
        if let Some(run) = body["runs"].as_array().and_then(|runs| runs.first()) {
            let run_state = run["state"].as_str().unwrap_or("");
            if matches!(
                run_state,
                "succeeded" | "failed" | "refused" | "interrupted"
            ) {
                return run.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("run for {job_id} did not reach a terminal state");
}

async fn wait_for_run_state(state: &AppState, job_id: &str, wanted: &str) -> Value {
    for _ in 0..200 {
        let (status, body) = send_json(
            state,
            "GET",
            &format!("/v1/jobs/{job_id}/runs"),
            None,
            Some(TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "runs response: {body}");
        if let Some(run) = body["runs"]
            .as_array()
            .and_then(|runs| runs.iter().find(|run| run["state"] == wanted))
        {
            return run.clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("run for {job_id} did not reach {wanted}");
}

async fn list_job(state: &AppState, job_id: &str) -> Value {
    let (status, body) = send_json(state, "GET", "/v1/jobs?limit=200", None, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "jobs response: {body}");
    body["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .find(|job| job["job_id"] == job_id)
        .expect("created job")
        .clone()
}

#[tokio::test]
#[serial]
async fn manual_trigger_runs_through_execution_history() {
    let (state, _scratch) = state("success").await;
    install_package(
        &state,
        "worker-fixture",
        "1.0.0",
        "#!/bin/sh\nread -r line\nprintf '{\"protocol_version\":1,\"status\":\"ok\",\"result\":{\"rows\":3}}\\n'\n",
    );
    let job_id = create_job(&state, "worker-fixture", "1.0.0").await;

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "trigger response: {body}");
    let run = wait_for_terminal(&state, &job_id).await;
    assert_eq!(run["state"], "succeeded");
    assert_eq!(run["attempt"], 1);
    let execution_id = run["execution_id"].as_str().expect("execution id");

    let (status, execution) = send_json(
        &state,
        "GET",
        &format!("/v1/executions/{execution_id}"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(execution["outcome"], "succeeded");

    let (status, _) = send_json(&state, "GET", "/readyz", None, None).await;
    assert_eq!(status, StatusCode::OK);
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn pinned_job_dispatch_does_not_change_the_active_pointer() {
    let (state, _scratch) = state("active-pointer").await;
    install_package(
        &state,
        "worker-fixture",
        "1.0.0",
        "#!/bin/sh\nread -r line\nprintf '{\"protocol_version\":1,\"status\":\"ok\",\"result\":null}\\n'\n",
    );
    install_package(
        &state,
        "worker-fixture",
        "1.1.0",
        "#!/bin/sh\nread -r line\nprintf '{\"protocol_version\":1,\"status\":\"ok\",\"result\":null}\\n'\n",
    );
    state
        .execution_service
        .activate("worker-fixture", "1.0.0")
        .await
        .expect("activate");

    let job_id = create_job(&state, "worker-fixture", "1.1.0").await;
    send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    let run = wait_for_terminal(&state, &job_id).await;
    assert_eq!(run["state"], "succeeded");
    let execution_id = run["execution_id"].as_str().expect("execution id");
    let (status, execution) = send_json(
        &state,
        "GET",
        &format!("/v1/executions/{execution_id}"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        execution["version"], "1.1.0",
        "the pinned version's bytes must be the ones that ran"
    );

    let active = state
        .registry
        .get_active("worker-fixture")
        .expect("active lookup")
        .expect("active pointer");
    assert_eq!(
        active.version, "1.0.0",
        "a pinned job must not repoint active_versions"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn disabled_job_refuses_triggers_and_cancels_queued_runs() {
    let (state, _scratch) = state("disable").await;
    let job_id = create_job(&state, "missing-module", "1.0.0").await;
    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/disable"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable response: {body}");
    assert_eq!(body["enabled"], false);

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "job_disabled");

    // Stop the loop so the enqueue/disable ordering is deterministic; the
    // store and API remain usable while the scheduler is stopped.
    state.scheduler.stop().await;
    let queued_job = create_job(&state, "missing-module", "1.0.0").await;
    state
        .scheduler
        .enqueue_manual(&queued_job)
        .await
        .expect("enqueue");
    send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{queued_job}/disable"),
        None,
        Some(TOKEN),
    )
    .await;
    state
        .scheduler
        .tick_once(SystemTime::now() + Duration::from_secs(1))
        .await
        .expect("tick");
    let run = wait_for_terminal(&state, &queued_job).await;
    assert_eq!(run["state"], "refused");
    assert_eq!(run["failure_code"], "job_disabled");
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn missing_module_dispatch_is_refused_without_history() {
    let (state, _scratch) = state("missing").await;
    let job_id = create_job(&state, "missing-module", "1.0.0").await;
    let (status, _) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    state
        .scheduler
        .tick_once(SystemTime::now() + Duration::from_secs(1))
        .await
        .expect("tick");
    let run = wait_for_terminal(&state, &job_id).await;
    assert_eq!(run["state"], "refused");
    assert_eq!(run["failure_code"], JobFailureCode::ModuleNotFound.as_str());
    let history = state
        .execution_service
        .list_executions(10, 0)
        .await
        .expect("history");
    assert!(
        history.is_empty(),
        "pre-spawn refusal must not write history"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn two_manual_triggers_are_distinct_runs() {
    let (state, _scratch) = state("duplicate").await;
    let job_id = create_job(&state, "missing-module", "1.0.0").await;
    for _ in 0..2 {
        let (status, _) = send_json(
            &state,
            "POST",
            &format!("/v1/jobs/{job_id}/trigger"),
            None,
            Some(TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    let (status, body) = send_json(
        &state,
        "GET",
        &format!("/v1/jobs/{job_id}/runs"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["runs"].as_array().expect("runs").len(),
        2,
        "manual triggers are not idempotent in this slice"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn job_routes_require_bearer_auth() {
    let (state, _scratch) = state("auth").await;
    let (status, _) = send_json(&state, "GET", "/v1/jobs", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn trigger_before_start_and_readyz_after_stop_are_unavailable() {
    let (state, _scratch) = assembled("unavailable").await;
    let job_id = create_job(&state, "missing-module", "1.0.0").await;
    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "scheduler_unavailable");

    state.scheduler.start().await.expect("start");
    let (status, _) = send_json(&state, "GET", "/readyz", None, None).await;
    assert_eq!(status, StatusCode::OK);
    state.scheduler.stop().await;
    let (status, _) = send_json(&state, "GET", "/readyz", None, None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
#[serial]
async fn interval_create_is_accepted_and_schedules_the_first_run() {
    let (state, _scratch) = state("interval-create").await;
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "interval", "interval_secs": 3600},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    assert_eq!(body["trigger"]["kind"], "interval");
    assert_eq!(body["trigger"]["interval_secs"], 3600);
    assert_eq!(body["enabled"], true);
    let created_at = body["created_at_ms"].as_i64().expect("created_at");
    let next_run_at = body["next_run_at_ms"].as_i64().expect("next_run_at");
    assert!(created_at >= before);
    assert_eq!(
        next_run_at,
        created_at + 3_600_000,
        "the first run is one interval after the same now used for created_at"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn disabled_interval_create_has_no_next_run() {
    let (state, _scratch) = state("interval-disabled-create").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "interval", "interval_secs": 3600},
            "enabled": false,
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    assert_eq!(body["trigger"]["kind"], "interval");
    assert!(
        body["next_run_at_ms"].is_null(),
        "a disabled interval job must not schedule a run: {body}"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn interval_bounds_reject_zero_and_over_the_maximum() {
    let (state, _scratch) = state("interval-bounds").await;
    for interval_secs in [0, MAX_INTERVAL_SECS + 1] {
        let (status, body) = send_json(
            &state,
            "POST",
            "/v1/jobs",
            Some(json!({
                "module_id": "missing-module",
                "version": "1.0.0",
                "function": "run",
                "trigger": {"kind": "interval", "interval_secs": interval_secs},
            })),
            Some(TOKEN),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "interval_secs={interval_secs} response: {body}"
        );
        assert_eq!(body["code"], "invalid_trigger");
    }
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn cron_create_schedules_the_next_utc_occurrence() {
    let (state, _scratch) = state("cron-create").await;
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "cron", "expression": "* * * * *"},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    assert_eq!(body["trigger"]["kind"], "cron");
    assert_eq!(body["trigger"]["expression"], "* * * * *");
    assert_eq!(body["enabled"], true);
    let created_at = body["created_at_ms"].as_i64().expect("created_at");
    let next_run_at = body["next_run_at_ms"].as_i64().expect("next_run_at");
    assert!(
        next_run_at > created_at,
        "the first run must be strictly after now (created={created_at}, next={next_run_at})"
    );
    assert!(
        next_run_at - created_at <= 60_000,
        "a wildcard minute expression must schedule within one minute"
    );
    assert_eq!(
        next_run_at % 60_000,
        0,
        "the boundary must be a whole UTC minute"
    );
    assert!(next_run_at > before);
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn cron_create_rejects_invalid_and_impossible_expressions() {
    let (state, _scratch) = state("cron-invalid").await;
    for expression in [
        "60 * * * *",
        "0 0 31 2 *",
        "0 0 * * * *",
        "@daily",
        "0 0 * * MON",
    ] {
        let (status, body) = send_json(
            &state,
            "POST",
            "/v1/jobs",
            Some(json!({
                "module_id": "missing-module",
                "version": "1.0.0",
                "function": "run",
                "trigger": {"kind": "cron", "expression": expression},
            })),
            Some(TOKEN),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{expression:?} response: {body}"
        );
        assert_eq!(body["code"], "invalid_trigger");
        assert!(
            !body.to_string().contains(expression),
            "the raw expression must not be echoed: {body}"
        );
    }
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn disabled_cron_create_has_no_next_run() {
    let (state, _scratch) = state("cron-disabled-create").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "cron", "expression": "*/5 * * * *"},
            "enabled": false,
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    assert_eq!(body["trigger"]["kind"], "cron");
    assert!(
        body["next_run_at_ms"].is_null(),
        "a disabled cron job must not schedule a run: {body}"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn enable_rejects_an_impossible_cron_job_and_leaves_it_disabled() {
    let (state, _scratch) = state("cron-enable-impossible").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "cron", "expression": "0 0 31 2 *"},
            "enabled": false,
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    assert_eq!(body["enabled"], false);
    assert!(body["next_run_at_ms"].is_null());
    let job_id = body["job_id"].as_str().expect("job id").to_owned();

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/enable"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "enable response: {body}");
    assert_eq!(body["code"], "invalid_trigger");

    let (status, body) = send_json(&state, "GET", "/v1/jobs", None, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    let job = body["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .find(|job| job["job_id"] == job_id)
        .expect("created job");
    assert_eq!(job["enabled"], false, "enable must not flip the job");
    assert!(job["next_run_at_ms"].is_null());
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn enabling_a_disabled_manual_job_succeeds_without_a_next_run() {
    let (state, _scratch) = state("manual-enable").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "manual"},
            "enabled": false,
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    assert_eq!(body["enabled"], false);
    let job_id = body["job_id"].as_str().expect("job id").to_owned();

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/enable"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enable response: {body}");
    assert_eq!(body["enabled"], true);
    assert!(
        body["next_run_at_ms"].is_null(),
        "a manual job has no scheduled boundary: {body}"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn disable_clears_and_enable_recomputes_a_cron_next_run() {
    let (state, _scratch) = state("cron-toggle").await;
    let expression = "*/5 * * * *";
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "cron", "expression": expression},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    let job_id = body["job_id"].as_str().expect("job id").to_owned();
    assert!(body["next_run_at_ms"].as_i64().is_some());

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/disable"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable response: {body}");
    assert!(
        body["next_run_at_ms"].is_null(),
        "disable must clear the boundary: {body}"
    );

    let before = SystemTime::now();
    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/enable"),
        None,
        Some(TOKEN),
    )
    .await;
    let after = SystemTime::now();
    assert_eq!(status, StatusCode::OK, "enable response: {body}");
    let next_after = body["next_run_at_ms"]
        .as_i64()
        .expect("recomputed next_run_at");
    let trigger = Trigger::Cron {
        expression: expression.to_owned(),
    };
    let lower = next_run_at(&trigger, before).expect("lower cron boundary");
    let upper = next_run_at(&trigger, after).expect("upper cron boundary");
    let next_time =
        UNIX_EPOCH + Duration::from_millis(u64::try_from(next_after).expect("positive"));
    assert!(
        next_time >= lower && next_time <= upper,
        "enable must recompute a cron boundary inside the captured window"
    );
    assert_eq!(
        next_after % 300_000,
        0,
        "the recomputed boundary must be a whole five-minute UTC boundary"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn manual_trigger_on_an_enabled_cron_job_keeps_the_cron_boundary() {
    let (state, _scratch) = state("cron-manual").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "cron", "expression": "0 0 29 2 *"},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    let job_id = body["job_id"].as_str().expect("job id").to_owned();
    let next_before = body["next_run_at_ms"]
        .as_i64()
        .expect("initial next_run_at");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "trigger response: {body}");
    let run = wait_for_terminal(&state, &job_id).await;
    assert_eq!(run["trigger"], "manual");

    let (status, body) = send_json(&state, "GET", "/v1/jobs", None, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    let job = body["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .find(|job| job["job_id"] == job_id)
        .expect("created job");
    assert_eq!(
        job["next_run_at_ms"].as_i64(),
        Some(next_before),
        "a manual run must not move the cron boundary"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn disable_clears_and_enable_recomputes_an_interval_next_run() {
    let (state, _scratch) = state("interval-toggle").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "interval", "interval_secs": 3600},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    let job_id = body["job_id"].as_str().expect("job id").to_owned();
    let next_before = body["next_run_at_ms"]
        .as_i64()
        .expect("initial next_run_at");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/disable"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable response: {body}");
    assert_eq!(body["enabled"], false);
    assert!(
        body["next_run_at_ms"].is_null(),
        "disable must clear the boundary: {body}"
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/enable"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enable response: {body}");
    assert_eq!(body["enabled"], true);
    let next_after = body["next_run_at_ms"]
        .as_i64()
        .expect("recomputed next_run_at");
    assert!(
        next_after > next_before,
        "enable must recompute now+interval (before={next_before}, after={next_after})"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn manual_trigger_on_an_interval_job_keeps_the_interval_boundary() {
    let (state, _scratch) = state("interval-manual").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing-module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "interval", "interval_secs": 3600},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create response: {body}");
    let job_id = body["job_id"].as_str().expect("job id").to_owned();
    let next_before = body["next_run_at_ms"]
        .as_i64()
        .expect("initial next_run_at");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "trigger response: {body}");
    let run = wait_for_terminal(&state, &job_id).await;
    assert_eq!(run["trigger"], "manual");

    let (status, body) = send_json(&state, "GET", "/v1/jobs", None, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    let job = body["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .find(|job| job["job_id"] == job_id)
        .expect("created job");
    assert_eq!(
        job["next_run_at_ms"].as_i64(),
        Some(next_before),
        "a manual run must not move the interval boundary"
    );
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn create_rejects_unsafe_identity_and_bad_pagination() {
    let (state, _scratch) = state("bounds").await;
    let (status, body) = send_json(
        &state,
        "POST",
        "/v1/jobs",
        Some(json!({
            "module_id": "missing/../module",
            "version": "1.0.0",
            "function": "run",
            "trigger": {"kind": "manual"},
        })),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_identity");

    let (status, body) = send_json(&state, "GET", "/v1/jobs?limit=0", None, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_pagination");
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn cancel_route_requires_bearer_auth() {
    let (state, _scratch) = assembled("cancel-auth").await;
    let job_id = create_job(&state, "missing-module", "1.0.0").await;
    let run = state
        .scheduler
        .enqueue_manual(&job_id)
        .await
        .expect("enqueue");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/runs/{}/cancel", run.run_id),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "cancel response: {body}");
    let runs = state
        .scheduler
        .list_runs(&job_id, 10, 0)
        .await
        .expect("runs");
    assert_eq!(runs[0].state, JobRunState::Queued);
}

#[tokio::test]
#[serial]
async fn authenticated_queued_cancel_returns_202_and_terminalizes_the_run() {
    let (state, _scratch) = state_with_capacity("cancel-queued", 1).await;
    install_package(
        &state,
        "cancel-queue-worker",
        "1.0.0",
        "#!/bin/sh\nread -r line\nsleep 5\nprintf '{\"protocol_version\":1,\"status\":\"ok\",\"result\":null}\\n'\n",
    );
    let job_id = create_job(&state, "cancel-queue-worker", "1.0.0").await;
    let job_before = list_job(&state, &job_id).await;

    let (status, first) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "first trigger: {first}");
    wait_for_run_state(&state, &job_id, "running").await;

    let (status, second) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "second trigger: {second}");
    assert_eq!(
        second["state"], "queued",
        "the only slot is occupied by the first run: {second}"
    );
    let run_id = second["run_id"].as_str().expect("run id").to_owned();

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/runs/{run_id}/cancel"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "cancel response: {body}");
    assert_eq!(body["run_id"], run_id);
    assert_eq!(body["state"], "failed");
    assert_eq!(body["outcome"], "cancelled");
    assert!(body["execution_id"].is_null());
    assert!(
        body["finished_at_ms"].as_i64().is_some(),
        "a queued cancel must set finished_at: {body}"
    );

    let (status, body) = send_json(
        &state,
        "GET",
        &format!("/v1/jobs/{job_id}/runs"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let runs = body["runs"].as_array().expect("runs");
    assert_eq!(runs.len(), 2, "a cancelled run must not enqueue a retry");
    let cancelled = runs
        .iter()
        .find(|run| run["run_id"] == run_id)
        .expect("cancelled run");
    assert_eq!(cancelled["state"], "failed");
    assert_eq!(cancelled["outcome"], "cancelled");
    let job_after = list_job(&state, &job_id).await;
    assert_eq!(job_after["enabled"], job_before["enabled"]);
    assert_eq!(job_after["next_run_at_ms"], job_before["next_run_at_ms"]);
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn cancel_is_unavailable_before_the_scheduler_starts() {
    let (state, _scratch) = assembled("cancel-stopped").await;
    let job_id = create_job(&state, "missing-module", "1.0.0").await;
    let run = state
        .scheduler
        .enqueue_manual(&job_id)
        .await
        .expect("enqueue");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/runs/{}/cancel", run.run_id),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "cancel response: {body}"
    );
    assert_eq!(body["code"], "scheduler_unavailable");
}

#[tokio::test]
#[serial]
async fn authenticated_running_cancel_returns_202_and_records_cancelled() {
    let (state, _scratch) = state("cancel-running").await;
    install_package(
        &state,
        "cancel-worker",
        "1.0.0",
        "#!/bin/sh\nread -r line\nsleep 5\nprintf '{\"protocol_version\":1,\"status\":\"ok\",\"result\":null}\\n'\n",
    );
    let job_id = create_job(&state, "cancel-worker", "1.0.0").await;
    let job_before = list_job(&state, &job_id).await;
    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "trigger response: {body}");

    let running = wait_for_run_state(&state, &job_id, "running").await;
    let run_id = running["run_id"].as_str().expect("run id").to_owned();
    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/runs/{run_id}/cancel"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "cancel response: {body}");
    assert_eq!(body["run_id"], run_id);
    assert!(
        matches!(body["state"].as_str(), Some("running" | "failed")),
        "the accepted cancel returns the current row: {body}"
    );

    let terminal = wait_for_terminal(&state, &job_id).await;
    assert_eq!(terminal["run_id"], run_id);
    assert_eq!(terminal["state"], "failed");
    assert_eq!(terminal["outcome"], "cancelled");
    assert!(
        terminal["execution_id"].as_str().is_some(),
        "a cancelled worker must still write its execution receipt: {terminal}"
    );
    let runs = state
        .scheduler
        .list_runs(&job_id, 10, 0)
        .await
        .expect("runs");
    assert_eq!(runs.len(), 1, "a cancelled run must not enqueue a retry");
    let job_after = list_job(&state, &job_id).await;
    assert_eq!(job_after["enabled"], job_before["enabled"]);
    assert_eq!(job_after["next_run_at_ms"], job_before["next_run_at_ms"]);
    state.scheduler.stop().await;
}

#[tokio::test]
#[serial]
async fn cancel_errors_map_to_stable_not_found_conflict_and_bad_request() {
    let (state, _scratch) = state("cancel-errors").await;
    let job_id = create_job(&state, "missing-module", "1.0.0").await;
    let other_job = create_job(&state, "missing-module", "1.0.0").await;
    let (status, triggered) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/trigger"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "trigger response: {triggered}"
    );
    let run_id = triggered["run_id"].as_str().expect("run id").to_owned();
    wait_for_terminal(&state, &job_id).await;

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{other_job}/runs/{run_id}/cancel"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "wrong job response: {body}");
    assert_eq!(body["code"], "run_not_found");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/runs/missing-run/cancel"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "missing run response: {body}"
    );
    assert_eq!(body["code"], "run_not_found");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/bad%21id/runs/{run_id}/cancel"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "bad job response: {body}");
    assert_eq!(body["code"], "invalid_job_id");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/runs/bad%21run/cancel"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "bad run response: {body}");
    assert_eq!(body["code"], "invalid_run_id");

    let (status, body) = send_json(
        &state,
        "POST",
        &format!("/v1/jobs/{job_id}/runs/{run_id}/cancel"),
        None,
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "terminal cancel: {body}");
    assert_eq!(body["code"], "run_not_cancellable");
    state.scheduler.stop().await;
}

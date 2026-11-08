//! Property tests for the upload endpoint's input boundary.
//!
//! The oracle is intentionally weak but broad: arbitrary bodies must never
//! panic or surface as a server error, auth must be decided before parsing,
//! security headers and a request id must be present on handler responses,
//! and every rejection must restore its upload slot and leave no quarantine
//! file. Container-format correctness is covered by the example tests; this
//! suite looks for crashes and cleanup leaks across generated inputs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use conductor::api::routes::router;
use conductor::api::uploads::{ApiToken, AppState};
use conductor::audit::recorder::RejectionRecorder;
use conductor::control_plane::activate_module::ActivationPolicy;
use conductor::control_plane::execute_module::ExecutionService;
use conductor::control_plane::scheduler::SchedulerService;
use conductor::control_plane::validate_package::PackageValidationBuilder;
use conductor::executions::executor::ExecutionLimits;
use conductor::executions::history::ExecutionHistoryStore;
use conductor::metrics::{Metrics, MetricsOptions};
use conductor::modules::registry::ModuleRegistry;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    ConfiguredTrustedKeys, SignatureAlgorithm, TrustedSigningKey,
};
use conductor::readiness::Readiness;
use conductor::storage::database::Database;
use proptest::prelude::*;
use tokio::sync::Semaphore;
use tower::ServiceExt as _;

const BOUNDARY: &str = "conductor-property-boundary";
const TOKEN: &str = "property-test-token";
const UPLOAD_SLOTS: usize = 4;

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "conductor-property-{}-{nanos}-{count}-{tag}",
        std::process::id()
    ))
}

/// Tightens fixture directories to the owner-only mode ExecutionService
/// validates, independent of the runner's umask.
#[cfg(unix)]
fn tighten_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("fixture directory permissions must be settable");
}

#[cfg(not(unix))]
fn tighten_private(_path: &Path) {}

fn test_state(tag: &str) -> (AppState, PathBuf) {
    let root = temp_dir(tag);
    let quarantine_dir = root.join("quarantine");
    let artifact_dir = root.join("artifacts");
    let staging_dir = root.join("staging");
    std::fs::create_dir_all(&quarantine_dir).expect("quarantine dir must be created");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir must be created");
    std::fs::create_dir_all(&staging_dir).expect("staging dir must be created");
    tighten_private(&root);
    tighten_private(&quarantine_dir);
    tighten_private(&artifact_dir);
    tighten_private(&staging_dir);

    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        vec![0u8; 32],
    )])
    .expect("distinct test keys must build");
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    let registry = Arc::new(ModuleRegistry::new());
    let metrics = Metrics::new(MetricsOptions::default()).expect("metrics must build");
    let execution_service = Arc::new(
        ExecutionService::new(
            Arc::clone(&registry),
            artifact_dir.clone(),
            staging_dir,
            ActivationPolicy::new(vec!["rust".to_owned()]).expect("activation policy"),
            ExecutionLimits::default(),
            Duration::from_secs(30),
            PackageValidationPolicy::production(),
            HashSet::from(["k1".to_owned()]),
            UPLOAD_SLOTS,
            Arc::new(ExecutionHistoryStore::open_in_memory().expect("execution history must open")),
            Arc::clone(&metrics),
        )
        .expect("execution service must build"),
    );

    let database = Arc::new(Database::open_in_memory().expect("database must open"));
    database.migrate().expect("database must migrate");
    let readiness = Arc::new(Readiness::new(database.check_ready().is_ok()));
    let scheduler = Arc::new(
        SchedulerService::in_memory_for_test(
            Arc::clone(&execution_service),
            Arc::clone(&metrics),
            Arc::clone(&readiness),
            UPLOAD_SLOTS,
        )
        .expect("test scheduler must build"),
    );
    let state = AppState {
        validator: Arc::new(validator),
        quarantine_dir,
        artifact_dir,
        registry,
        recorder: Arc::new(RejectionRecorder::new()),
        request_timeout: Duration::from_secs(10),
        api_token: ApiToken::new(TOKEN),
        upload_slots: Arc::new(Semaphore::new(UPLOAD_SLOTS)),
        execution_service,
        scheduler,
        metrics,
        database,
        readiness,
    };
    (state, root)
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

async fn send(state: &AppState, body: Vec<u8>, bearer: Option<&str>) -> (StatusCode, HeaderMap) {
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
    let response = router(state.clone())
        .oneshot(builder.body(Body::from(body)).expect("request must build"))
        .await
        .expect("router must respond");
    (response.status(), response.headers().clone())
}

fn assert_transport_headers(headers: &HeaderMap) {
    for name in [
        "x-request-id",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "cache-control",
        "cross-origin-resource-policy",
    ] {
        assert!(headers.contains_key(name), "missing {name}");
    }
}

fn quarantine_count(state: &AppState) -> usize {
    std::fs::read_dir(&state.quarantine_dir)
        .expect("quarantine dir must read")
        .count()
}

/// One text or file part with raw bytes; property inputs are not required to
/// be valid UTF-8 or to avoid the boundary sequence.
fn raw_part(body: &mut Vec<u8>, name: &str, value: &[u8]) {
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(value);
    body.extend_from_slice(b"\r\n");
}

#[test]
fn fresh_state_starts_with_every_upload_slot() {
    let (state, root) = test_state("slots");
    assert_eq!(state.upload_slots.available_permits(), UPLOAD_SLOTS);
    assert_eq!(quarantine_count(&state), 0);
    cleanup(&root);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn unauthenticated_bodies_are_rejected_before_parsing(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let (state, root) = test_state("unauth");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime must build");
        let (status, headers) = runtime.block_on(send(&state, body, None));
        prop_assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_transport_headers(&headers);
        prop_assert_eq!(quarantine_count(&state), 0);
        prop_assert_eq!(state.upload_slots.available_permits(), UPLOAD_SLOTS);
        cleanup(&root);
    }

    #[test]
    fn authenticated_arbitrary_bodies_never_escape_as_server_errors(body in prop::collection::vec(any::<u8>(), 0..8192)) {
        let (state, root) = test_state("authenticated");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime must build");
        let (status, headers) = runtime.block_on(send(&state, body, Some(TOKEN)));
        prop_assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "arbitrary body produced {}",
            status
        );
        assert_transport_headers(&headers);
        if status != StatusCode::CREATED {
            prop_assert_eq!(quarantine_count(&state), 0, "rejection leaked quarantine bytes");
        }
        prop_assert_eq!(state.upload_slots.available_permits(), UPLOAD_SLOTS);
        cleanup(&root);
    }

    #[test]
    fn arbitrary_field_octets_never_escape_as_server_errors(
        package in prop::collection::vec(any::<u8>(), 0..512),
        key_id in prop::collection::vec(any::<u8>(), 0..128),
        signature in prop::collection::vec(any::<u8>(), 0..128),
        format_version in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let (state, root) = test_state("fields");
        let mut body = Vec::new();
        raw_part(&mut body, "package", &package);
        raw_part(&mut body, "key_id", &key_id);
        raw_part(&mut body, "signature", &signature);
        raw_part(&mut body, "format_version", &format_version);
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime must build");
        let (status, headers) = runtime.block_on(send(&state, body, Some(TOKEN)));
        prop_assert_ne!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "arbitrary fields produced {}",
            status
        );
        assert_transport_headers(&headers);
        if status != StatusCode::CREATED {
            prop_assert_eq!(quarantine_count(&state), 0, "rejection leaked quarantine bytes");
        }
        prop_assert_eq!(state.upload_slots.available_permits(), UPLOAD_SLOTS);
        cleanup(&root);
    }

    #[test]
    fn only_the_configured_bearer_is_authorized(
        presented in prop_oneof![
            Just(TOKEN.to_owned()),
            "[A-Za-z0-9._~+/=\\-]{0,64}",
        ],
    ) {
        let (state, root) = test_state("bearer");
        let body = b"--boundary--\r\n".to_vec();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime must build");
        let (status, _) = runtime.block_on(send(&state, body, Some(&presented)));
        prop_assert_eq!(status == StatusCode::UNAUTHORIZED, presented != TOKEN);
        cleanup(&root);
    }
}

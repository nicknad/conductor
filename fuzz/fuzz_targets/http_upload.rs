#![no_main]

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use conductor::api::routes::router;
use conductor::api::uploads::{ApiToken, AppState};
use conductor::audit::recorder::RejectionRecorder;
use conductor::control_plane::activate_module::ActivationPolicy;
use conductor::control_plane::execute_module::ExecutionService;
use conductor::control_plane::validate_package::PackageValidationBuilder;
use conductor::executions::executor::ExecutionLimits;
use conductor::modules::registry::ModuleRegistry;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    ConfiguredTrustedKeys, SignatureAlgorithm, TrustedSigningKey,
};
use libfuzzer_sys::fuzz_target;
use tokio::sync::Semaphore;
use tower::ServiceExt as _;

const BOUNDARY: &str = "conductor-fuzz-boundary";
// Harness fixture accepted by the test-only trust store, not a credential.
// nosemgrep: generic.hardcoded-secret
const TOKEN: &str = "fuzz-token";

/// Inputs are arbitrary request bodies; the endpoint state is initialized
/// once per process so iterations measure parsing, not setup.
fn state() -> &'static AppState {
    static STATE: OnceLock<AppState> = OnceLock::new();
    STATE.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("conductor-fuzz-http-{}", std::process::id()));
        let quarantine_dir = root.join("quarantine");
        let artifact_dir = root.join("artifacts");
        let staging_dir = root.join("staging");
        std::fs::create_dir_all(&quarantine_dir).expect("quarantine dir");
        std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
        std::fs::create_dir_all(&staging_dir).expect("staging dir");
        for dir in [&quarantine_dir, &artifact_dir, &staging_dir] {
            private_dir(dir);
        }

        let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            vec![0u8; 32],
        )])
        .expect("fixed key");
        let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
            .trusted_keys(keys)
            .build()
            .expect("fixed validator");
        let registry = Arc::new(ModuleRegistry::new());
        let execution_service = Arc::new(
            ExecutionService::new(
                Arc::clone(&registry),
                artifact_dir.clone(),
                staging_dir,
                ActivationPolicy::new(vec!["rust".to_owned()]).expect("fixed policy"),
                ExecutionLimits::default(),
                Duration::from_secs(30),
                PackageValidationPolicy::production(),
                HashSet::from(["k1".to_owned()]),
                4,
            )
            .expect("fixed execution service"),
        );

        AppState {
            validator: Arc::new(validator),
            quarantine_dir,
            artifact_dir,
            registry,
            recorder: Arc::new(RejectionRecorder::new()),
            request_timeout: Duration::from_secs(10),
            api_token: ApiToken::new(TOKEN),
            upload_slots: Arc::new(Semaphore::new(4)),
            execution_service,
        }
    })
}

#[cfg(unix)]
fn private_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("fuzz fixture directory must be owner-only");
}

#[cfg(not(unix))]
fn private_dir(_path: &std::path::Path) {}

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let app_state = state().clone();
    let permits_before = app_state.upload_slots.available_permits();

    let request = Request::builder()
        .method("POST")
        .uri("/v1/packages")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::from(data.to_vec()))
        .expect("request");

    let (status, headers) = runtime.block_on(async move {
        let response = router(app_state)
            .oneshot(request)
            .await
            .expect("router must respond");
        (response.status(), response.headers().clone())
    });

    // Endpoint oracle: arbitrary authenticated bodies are rejected, never
    // crash into a server error, always carry the transport guarantees, and
    // always return their upload slot.
    // 503 is a legitimate overload/timeout outcome; only an unexpected
    // internal failure is a fuzz finding.
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "arbitrary body produced {status}"
    );
    assert!(headers.contains_key("x-request-id"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("x-content-type-options"));
    assert_eq!(state().upload_slots.available_permits(), permits_before);
    assert_ne!(status, StatusCode::OK);
});

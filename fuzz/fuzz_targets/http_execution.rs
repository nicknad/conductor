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

// Harness fixture accepted by the test-only trust store, not a credential.
// nosemgrep: generic.hardcoded-secret
const TOKEN: &str = "fuzz-token";

/// Arbitrary JSON bodies are sent to either activation or execution. No
/// module is registered, so valid requests are expected to reach the `404`
/// not-found path; the oracle is that neither endpoint maps arbitrary input
/// to a server error or loses its transport guarantees.
fn state() -> &'static AppState {
    static STATE: OnceLock<AppState> = OnceLock::new();
    STATE.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("conductor-fuzz-json-{}", std::process::id()));
        let quarantine_dir = root.join("quarantine");
        let artifact_dir = root.join("artifacts");
        let staging_dir = root.join("staging");
        for dir in [&quarantine_dir, &artifact_dir, &staging_dir] {
            std::fs::create_dir_all(dir).expect("fuzz fixture dir");
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

    let uri = if data.first().is_some_and(|byte| byte & 1 == 0) {
        "/v1/modules/fuzz-module/activate"
    } else {
        "/v1/modules/fuzz-module/executions"
    };
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
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

    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "arbitrary JSON produced {status}"
    );
    assert!(headers.contains_key("x-request-id"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("x-content-type-options"));
});

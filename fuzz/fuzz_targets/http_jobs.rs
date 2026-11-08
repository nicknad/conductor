#![no_main]

use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::prelude::*;
use conductor::api::routes::router;
use conductor::api::uploads::AppState;
use conductor::config::{Config, TrustedKeyConfig};
use conductor::packages::signature::SignatureAlgorithm;
use conductor::server::Host;
use libfuzzer_sys::fuzz_target;
use tower::ServiceExt as _;

// Harness fixture accepted by the test-only trust store, not a credential.
// nosemgrep: generic.hardcoded-secret
const TOKEN: &str = "fuzz-token";

fn state() -> &'static AppState {
    static STATE: OnceLock<AppState> = OnceLock::new();
    STATE.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "conductor-fuzz-jobs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        let config = Config {
            storage_root: root,
            api_token: Some(TOKEN.to_owned()),
            trusted_keys: vec![TrustedKeyConfig {
                key_id: "k1".to_owned(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_base64: BASE64_STANDARD.encode([9u8; 32]),
            }],
            ..Config::default()
        };
        Host::assemble(config)
            .expect("fixed fuzz host")
            .into_state()
    })
}

/// Percent-encodes every byte so arbitrary input can be embedded in a URI.
fn percent_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len() * 3);
    for byte in bytes {
        encoded.push('%');
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn list_uri(data: &[u8]) -> String {
    const FIXED: [&str; 8] = [
        "/v1/jobs",
        "/v1/jobs?limit=0",
        "/v1/jobs?limit=1",
        "/v1/jobs?limit=200",
        "/v1/jobs?limit=201",
        "/v1/jobs?offset=0",
        "/v1/jobs?offset=1000001",
        "/v1/jobs?limit=1&limit=2",
    ];
    let selector = data.get(1).copied().unwrap_or(0);
    let index = usize::from(selector) % (FIXED.len() + 1);
    if index == FIXED.len() {
        let value = percent_encode(data.get(2..).unwrap_or_default());
        match selector % 3 {
            0 => format!("/v1/jobs?limit={value}"),
            1 => format!("/v1/jobs?offset={value}"),
            _ => format!("/v1/jobs?limit={value}&offset={value}"),
        }
    } else {
        FIXED[index].to_owned()
    }
}

fn job_uri(data: &[u8], suffix: &str) -> String {
    let id = percent_encode(data.get(2..).unwrap_or_default());
    format!("/v1/jobs/{id}{suffix}")
}

fn request_for(data: &[u8]) -> (Method, String, Body) {
    match data.first().copied().unwrap_or(0) % 6 {
        0 => (
            Method::POST,
            "/v1/jobs".to_owned(),
            Body::from(data.to_vec()),
        ),
        1 => (Method::GET, list_uri(data), Body::empty()),
        2 => (Method::POST, job_uri(data, "/trigger"), Body::empty()),
        3 => (Method::POST, job_uri(data, "/enable"), Body::empty()),
        4 => (Method::POST, job_uri(data, "/disable"), Body::empty()),
        _ => (Method::GET, job_uri(data, "/runs"), Body::empty()),
    }
}

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let app_state = state().clone();

    let (method, uri, body) = request_for(data);
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(body)
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
        "arbitrary input produced {status}"
    );
    assert!(headers.contains_key("x-request-id"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("x-content-type-options"));
});

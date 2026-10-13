//! Route table wiring.
//!
//! Builds the axum [`Router`](axum::Router) for the upload API plus a
//! `GET /healthz` liveness probe. Defense in depth around the handler's own
//! streaming cap:
//!
//! - [`RequestBodyLimitLayer`](tower_http::limit::RequestBodyLimitLayer)
//!   bounds the total body (package bound plus 1 MiB multipart framing
//!   slack) so giant text fields cannot force buffering before per-field
//!   caps apply;
//! - [`TimeoutLayer`](tower::timeout::TimeoutLayer) bounds the whole
//!   request including slow bodies;
//! - [`TraceLayer`](tower_http::trace::TraceLayer) emits one span per
//!   request with the matched route.

use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::api::uploads::{post_package, AppState};

/// Multipart framing slack over the policy package bound for the outer
/// body limit. The handler's streaming check remains authoritative; this
/// layer only keeps a malicious `Content-Length` from forcing allocation
/// before the first chunk is inspected.
const MULTIPART_SLACK_BYTES: usize = 1 << 20;

/// Builds the HTTP route table for the given state.
pub fn router(state: AppState) -> Router {
    let max_body = state
        .validator
        .policy()
        .archive
        .max_compressed_bytes
        .saturating_add(MULTIPART_SLACK_BYTES as u64)
        .min(usize::MAX as u64) as usize;
    let timeout = state.request_timeout.max(Duration::from_secs(1));
    Router::new()
        .route("/v1/packages", post(post_package))
        .route("/healthz", get(healthz))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            timeout,
        ))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

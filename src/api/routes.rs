//! Route table wiring.
//!
//! Builds the axum [`Router`](axum::Router) for the upload API plus a
//! `GET /healthz` liveness probe. Layers, outermost first:
//!
//! - [`CatchPanicLayer`](tower_http::catch_panic::CatchPanicLayer):
//!   a panicking handler becomes a bare `500`, never a stack trace or
//!   version string;
//! - [`TimeoutLayer`](tower_http::timeout::TimeoutLayer): bounds the whole
//!   request including slow bodies and stalled field boundaries;
//! - [`RequestBodyLimitLayer`](tower_http::limit::RequestBodyLimitLayer):
//!   bounds the total body (package bound plus 1 MiB multipart framing
//!   slack) so giant text fields cannot force buffering before per-field
//!   caps apply;
//! - [`TraceLayer`](tower_http::trace::TraceLayer): one span per request
//!   with the matched route;
//! - [`SetRequestIdLayer`](tower_http::request_id::SetRequestIdLayer) plus
//!   [`PropagateRequestIdLayer`](tower_http::request_id::PropagateRequestIdLayer):
//!   every response carries an `x-request-id` for incident correlation
//!   (server-generated, never trusted from the client);
//! - response security headers on every response: no sniffing, no
//!   framing, no referrer, no caching, HSTS (the service is TLS-only).
//!
//! Per-route: [`require_bearer`](crate::api::uploads::require_bearer)
//! gates every `/v1` route on the operator token, and
//! [`limit_headers`](crate::api::middleware::limit_headers) rejects header
//! bloat with `431` as the innermost global layer, just outside the routes. `/healthz` is intentionally
//! unauthenticated — load balancers cannot present credentials — and
//! returns only `ok`, no version or topology detail.

use std::time::Duration;

use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::api::middleware::limit_headers;
use crate::api::uploads::{post_package, require_bearer, AppState};

/// Multipart framing slack over the policy package bound for the outer
/// body limit. The handler's streaming check remains authoritative; this
/// layer only keeps a malicious `Content-Length` from forcing allocation
/// before the first chunk is inspected.
const MULTIPART_SLACK_BYTES: usize = 1 << 20;

/// Builds the HTTP route table for the given state.
///
/// Request flow is outermost-first: panic containment, total timeout,
/// body bound, tracing, request-id issue then echo, security headers,
/// header-bloat rejection, then the routes. Note the `.layer` add order
/// below reads innermost-first: axum runs the *last* added layer first,
/// so `SetRequestIdLayer` is added after `PropagateRequestIdLayer` to
/// make issue-then-echo hold. The `x-request-id` integration test pins
/// this pairing — if the header goes missing, this ordering regressed.
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
        .route(
            "/v1/packages",
            post(post_package).route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer,
            )),
        )
        .route("/healthz", get(healthz))
        .layer(middleware::from_fn(limit_headers))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            timeout,
        ))
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

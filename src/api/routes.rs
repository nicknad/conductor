//! Route table wiring.
//!
//! Builds the axum [`Router`](axum::Router) for the upload API plus a
//! `GET /healthz` liveness probe. Layers, outermost first:
//!
//! - response security headers on every response, including transport
//!   rejections: no sniffing, no framing, no referrer, no caching, HSTS
//!   (the service is TLS-only);
//! - [`SetRequestIdLayer`](tower_http::request_id::SetRequestIdLayer) plus
//!   [`PropagateRequestIdLayer`](tower_http::request_id::PropagateRequestIdLayer):
//!   every response carries an `x-request-id` for incident correlation
//!   (server-generated, never trusted from the client);
//! - [`TraceLayer`](tower_http::trace::TraceLayer): one span per request
//!   with the matched route;
//! - [`TimeoutLayer`](tower_http::timeout::TimeoutLayer): bounds the whole
//!   request including slow bodies and stalled field boundaries;
//! - [`CatchPanicLayer`](tower_http::catch_panic::CatchPanicLayer):
//!   a panicking handler becomes a bare `500`, never a stack trace or
//!   version string;
//! - [`RequestBodyLimitLayer`](tower_http::limit::RequestBodyLimitLayer) on
//!   the upload route only, inside bearer auth: bounds the total body
//!   (package bound plus 1 MiB multipart framing slack) so giant text
//!   fields cannot force buffering before per-field caps apply, and an
//!   unauthenticated caller cannot probe the body limit. axum's extractor
//!   default (2 MiB) is disabled so the policy bound stays authoritative.
//!
//! Per-route: [`require_bearer`](crate::api::uploads::require_bearer)
//! gates every `/v1` route on the operator token. `/healthz` is
//! intentionally unauthenticated — load balancers cannot present
//! credentials — and returns only `ok`, no version or topology detail.

use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::api::uploads::{post_package, require_bearer, AppState};
use crate::api::PACKAGE_UPLOAD_PATH;

/// Multipart framing slack over the policy package bound for the outer
/// body limit. The handler's streaming check remains authoritative; this
/// layer only keeps a malicious `Content-Length` from forcing allocation
/// before the first chunk is inspected.
const MULTIPART_SLACK_BYTES: usize = 1 << 20;

/// Builds the HTTP route table for the given state.
///
/// Request flow is outermost-first: security headers, a fresh request id,
/// tracing, total timeout, panic containment, then the route with its body
/// bound and bearer auth. Note the `.layer` add order below reads
/// innermost-first: axum runs the *last* added layer first, so
/// `SetRequestIdLayer` is added after `PropagateRequestIdLayer` to make
/// issue-then-echo hold, and the header layers are added last so transport
/// rejections still carry them. The `x-request-id` integration tests pin
/// this pairing — if a client-supplied id survives or the header goes
/// missing, this ordering regressed.
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
            PACKAGE_UPLOAD_PATH,
            post(post_package)
                // Added first, so bearer auth below stays outermost: an
                // unauthenticated caller cannot probe or reach the body
                // limit and parser.
                .route_layer(RequestBodyLimitLayer::new(max_body))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_bearer,
                )),
        )
        .route("/healthz", get(healthz))
        // axum's extractor default is 2 MiB; disabling it keeps the
        // route-scoped RequestBodyLimitLayer (policy bound + framing slack)
        // authoritative for valid uploads.
        .layer(DefaultBodyLimit::disable())
        .layer(CatchPanicLayer::new())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        // tower-http preserves an inbound id; strip it before the issuer
        // runs so request ids are always server-generated.
        .layer(middleware::from_fn(strip_client_request_id))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("cross-origin-resource-policy"),
            axum::http::HeaderValue::from_static("same-origin"),
        ))
        .with_state(state)
}

/// Removes any client-supplied `x-request-id` before the id issuer runs.
/// `SetRequestIdLayer` only inserts when the header is absent; without this
/// strip, `PropagateRequestIdLayer` would echo an attacker-chosen value and
/// audit records would inherit it.
async fn strip_client_request_id(mut request: Request, next: Next) -> Response {
    request.headers_mut().remove("x-request-id");
    next.run(request).await
}

async fn healthz() -> &'static str {
    "ok"
}

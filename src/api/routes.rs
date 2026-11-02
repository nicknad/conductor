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

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::api::errors::ApiError;
use crate::api::executions::{post_activate, post_execute};
use crate::api::uploads::{post_package, request_id, require_bearer, AppState};
use crate::api::{
    ACTIVATE_MODULE_PATH, EXECUTE_MODULE_PATH, JSON_BODY_LIMIT_BYTES, PACKAGE_UPLOAD_PATH,
};
use crate::audit::event::{RejectionEvent, RejectionStage};

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
                // limit and parser. The mapper sits between auth and the
                // limit so layer/extractor refusals are still recorded and
                // rendered as the JSON error contract.
                .route_layer(RequestBodyLimitLayer::new(max_body))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    map_transport_rejection,
                ))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_bearer,
                )),
        )
        .route(
            ACTIVATE_MODULE_PATH,
            post(post_activate)
                // Same order as the upload route: bearer auth outermost so
                // an unauthenticated caller cannot probe the JSON body
                // limit, then the mapper turns limit refusals into the JSON
                // error contract.
                .route_layer(RequestBodyLimitLayer::new(JSON_BODY_LIMIT_BYTES))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    map_json_rejection,
                ))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_bearer,
                )),
        )
        .route(
            EXECUTE_MODULE_PATH,
            post(post_execute)
                .route_layer(RequestBodyLimitLayer::new(JSON_BODY_LIMIT_BYTES))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    map_json_rejection,
                ))
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

/// Rewrites refusals produced before the handler (extractor rejection and
/// `RequestBodyLimitLayer`) into the API's JSON error contract and records
/// them once. Handler refusals are already JSON and were already recorded by
/// `post_package`, so they pass through untouched.
async fn map_transport_rejection(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let response = next.run(request).await;
    let status = response.status();
    if status != StatusCode::BAD_REQUEST && status != StatusCode::PAYLOAD_TOO_LARGE {
        return response;
    }
    let already_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if already_json {
        return response;
    }

    let (stage, api) = if status == StatusCode::PAYLOAD_TOO_LARGE {
        (
            RejectionStage::Transport,
            ApiError::PayloadTooLarge("request body exceeds the allowed size".to_owned()),
        )
    } else {
        (
            RejectionStage::Multipart,
            ApiError::BadRequest(
                "invalid_multipart",
                "malformed multipart/form-data request".to_owned(),
            ),
        )
    };
    state
        .recorder
        .record(&RejectionEvent::new(stage, api.code(), api.message()).with_request_id(request_id));
    api.into_response()
}

/// Pure decision for the JSON route's transport-refusal mapper. Kept
/// separate so the status/content-type matrix is directly testable: only a
/// non-JSON 400/413 is rewritten; handler JSON and every other status pass
/// through.
fn json_rejection_for(status: StatusCode, already_json: bool) -> Option<ApiError> {
    if already_json {
        return None;
    }
    match status {
        StatusCode::PAYLOAD_TOO_LARGE => Some(ApiError::PayloadTooLarge(
            "request body exceeds the allowed size".to_owned(),
        )),
        StatusCode::BAD_REQUEST => Some(ApiError::BadRequest(
            "invalid_request_body",
            "request body must be valid JSON matching the documented schema".to_owned(),
        )),
        _ => None,
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// Rewrites refusals produced before the JSON handlers (body limit or a
/// request the extractor could not read) into the API's JSON error contract
/// and records them once. Handler-produced JSON refusals pass through
/// unchanged because they already carry `application/json`.
async fn map_json_rejection(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let id = request_id(request.headers());
    let response = next.run(request).await;
    let already_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    let Some(api) = json_rejection_for(response.status(), already_json) else {
        return response;
    };
    let code = api.code();
    state.recorder.record(
        &RejectionEvent::new(RejectionStage::Request, code, api.message()).with_request_id(id),
    );
    api.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_rejection_matrix_is_exact() {
        assert!(matches!(
            json_rejection_for(StatusCode::BAD_REQUEST, false),
            Some(ApiError::BadRequest("invalid_request_body", _))
        ));
        assert!(matches!(
            json_rejection_for(StatusCode::PAYLOAD_TOO_LARGE, false),
            Some(ApiError::PayloadTooLarge(_))
        ));
        assert!(json_rejection_for(StatusCode::UNPROCESSABLE_ENTITY, false).is_none());
        assert!(json_rejection_for(StatusCode::BAD_REQUEST, true).is_none());
        assert!(json_rejection_for(StatusCode::PAYLOAD_TOO_LARGE, true).is_none());
    }
}

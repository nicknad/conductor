//! Transport guards: fixed request-header bounds enforced before any
//! handler runs, plus the outermost rejection-audit fallback.
//!
//! Hyper already caps headers at the socket level (`max_headers`,
//! `max_buf_size`, tuned in the binary's TLS serving path); this layer is
//! the stricter, testable enforcement: a legitimate upload needs fewer
//! than ten headers, so anything beyond these fixed caps is hostile
//! header bloat and is rejected with `431` without touching multipart
//! parsing, quarantine, or validation.
//!
//! Rejections produced by transport layers that never reach the handler
//! (timeouts, body limits, panics) are recorded as one generic
//! `package_rejected` event by [`audit_unhandled_rejections`], which runs
//! outermost and skips responses marked as already recorded by
//! [`crate::api::rejection`].

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::api::errors::ApiError;
use crate::api::rejection::{fallback_event, request_id, Rejection, RejectionRecorded};
use crate::api::uploads::AppState;
use crate::api::PACKAGE_UPLOAD_PATH;

/// Maximum accepted request headers. Fixed invariant, not operator
/// config: raising it is a code change, like the archive hard maxima.
pub const MAX_REQUEST_HEADERS: usize = 32;

/// Maximum accepted total request-header bytes (names plus values).
/// Fixed invariant; the 8 KiB budget dwarfs legitimate upload headers.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Rejects header bloat before routing. Runs as a global layer so even
/// unauthenticated probes pay nothing beyond this check. Upload-route
/// rejections are recorded as typed transport events; other paths keep the
/// bare error response.
pub async fn limit_headers(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let id = request_id(request.headers());
    match check_header_limits(request.headers()) {
        Ok(()) => next.run(request).await,
        Err(api) => {
            if request.uri().path() == PACKAGE_UPLOAD_PATH {
                Rejection::from_api(api).into_recorded_response(&state.recorder, id)
            } else {
                api.into_response()
            }
        }
    }
}

/// Outermost audit fallback: any 4xx/5xx response on the upload route that
/// carries no typed rejection marker (tower-level timeouts, body limits,
/// panics) is recorded as one generic transport event. Typed paths mark
/// their responses, so nothing is recorded twice.
pub async fn audit_unhandled_rejections(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    let already_recorded = response.extensions().get::<RejectionRecorded>().is_some();
    if let Some(event) = fallback_event(&path, response.status(), already_recorded) {
        state
            .recorder
            .record(&event.with_request_id(request_id(response.headers())));
    }
    response
}

/// Pure header-limit check: count cap plus total-byte cap. Separate from
/// the middleware so tests prove the exact boundary without a socket.
pub fn check_header_limits(headers: &HeaderMap) -> Result<(), ApiError> {
    let count = headers.len();
    if count > MAX_REQUEST_HEADERS {
        return Err(ApiError::HeadersTooLarge(format!(
            "request carries {count} headers, max {MAX_REQUEST_HEADERS}"
        )));
    }
    let bytes: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len())
        .sum();
    if bytes > MAX_HEADER_BYTES {
        return Err(ApiError::HeadersTooLarge(format!(
            "request headers total {bytes} bytes, max {MAX_HEADER_BYTES}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn headers_with(count: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for i in 0..count {
            let name: HeaderName = format!("x-proof-{i}")
                .parse()
                .expect("header name must parse");
            headers.insert(name, HeaderValue::from_static("v"));
        }
        headers
    }

    #[test]
    fn empty_headers_pass() {
        check_header_limits(&HeaderMap::new()).expect("empty headers must pass");
    }

    #[test]
    fn header_count_boundary_is_exact() {
        check_header_limits(&headers_with(MAX_REQUEST_HEADERS)).expect("exactly the cap must pass");
        assert!(matches!(
            check_header_limits(&headers_with(MAX_REQUEST_HEADERS + 1)),
            Err(ApiError::HeadersTooLarge(_))
        ));
    }

    #[test]
    fn header_byte_boundary_is_exact() {
        let mut headers = HeaderMap::new();
        // One byte of headroom left: name (1) + value must fit the budget.
        let name: HeaderName = "x".parse().expect("header name must parse");
        headers.insert(
            name,
            HeaderValue::from_bytes(&vec![b'v'; MAX_HEADER_BYTES - 1])
                .expect("header value must build"),
        );
        check_header_limits(&headers).expect("exactly the byte cap must pass");
        let name: HeaderName = "y".parse().expect("header name must parse");
        headers.insert(name, HeaderValue::from_static("vv"));
        assert!(matches!(
            check_header_limits(&headers),
            Err(ApiError::HeadersTooLarge(_))
        ));
    }
}

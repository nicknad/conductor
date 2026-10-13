//! HTTP interface. Receives requests; never validates ZIP internals
//! or activates modules directly.

pub mod errors;
pub mod routes;
pub mod uploads;

/// The package-upload route. Only rejections on this path are package
/// rejections; transport-layer failures elsewhere (health probes, unknown
/// routes) are not evented.
pub(crate) const PACKAGE_UPLOAD_PATH: &str = "/v1/packages";

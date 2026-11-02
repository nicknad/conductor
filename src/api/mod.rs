//! HTTP interface. Receives requests; never validates ZIP internals
//! or activates modules directly.

pub mod errors;
pub mod executions;
pub mod routes;
pub mod uploads;

/// The package-upload route. Only rejections on this path are package
/// rejections; transport-layer failures elsewhere (health probes, unknown
/// routes) are not evented.
pub(crate) const PACKAGE_UPLOAD_PATH: &str = "/v1/packages";

/// Activates and persists one registered module version.
pub(crate) const ACTIVATE_MODULE_PATH: &str = "/v1/modules/{module_id}/activate";

/// Executes one function of the active (or pinned) module version.
pub(crate) const EXECUTE_MODULE_PATH: &str = "/v1/modules/{module_id}/executions";

/// Lists durable execution receipts, newest first.
pub(crate) const EXECUTIONS_PATH: &str = "/v1/executions";

/// Returns one durable execution receipt by id.
pub(crate) const EXECUTION_DETAIL_PATH: &str = "/v1/executions/{execution_id}";

/// Route-scoped JSON body limit for activation and execution requests.
pub(crate) const JSON_BODY_LIMIT_BYTES: usize = 1 << 20;

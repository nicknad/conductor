//! Control plane: use cases and workflow orchestration. Owns sequencing
//! and lifecycle transitions; implements no format parsing or cryptography.

pub mod activate_module;
pub mod lifecycle;
pub mod register_package;
pub mod upload_package;
pub mod validate_package;

//! Audit surface: structured rejection events for refused packages.
//!
//! Every rejected upload produces one event carrying the pipeline stage,
//! the stable machine code returned to the caller, and the internal reason
//! (which may be more specific than the external response body). Events
//! are emitted as structured `tracing` records and, when a store is
//! attached, as durable `package_rejections` rows.

pub mod event;
pub mod recorder;
pub mod store;

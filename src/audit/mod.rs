//! Audit surface: structured rejection events for refused packages.
//!
//! Every rejected upload produces exactly one event carrying the pipeline
//! stage, the stable machine code returned to the caller, and the internal
//! reason (which may be more specific than the external response body).
//! Events are emitted as structured `tracing` records; durable storage
//! reuses the same shape in a later phase (see
//! `docs/design-persistence.md`).

pub mod event;
pub mod recorder;

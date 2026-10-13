//! Filesystem persistence. Controls where untrusted uploads, temporary
//! extraction, and trusted artifacts live.

pub mod artifact_store;
pub mod quarantine;
pub mod staging;

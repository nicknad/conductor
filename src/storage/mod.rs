//! Filesystem persistence. Controls where untrusted uploads, temporary
//! extraction, and trusted artifacts live.

pub mod artifact_store;
pub mod database;
pub mod quarantine;
pub mod staging;

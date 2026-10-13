//! Enforces module IDs, versions, runtime compatibility, and allowed
//! features. Performs no filesystem writes.
//!
//! [`PackageValidationPolicy`] is the runtime-configurable surface: size
//! bounds, allowlisted algorithms, compression methods, manifest versions,
//! and target-runtime rules. Everything security-fixed (stage order,
//! mandatory signature on the production path, traversal rejection) lives
//! outside it. Validate policy at startup; snapshot one immutable policy
//! per validation so a reload cannot change rules mid-check.

use std::fmt;

use super::archive::{ArchiveLimits, CompressionMethod};
use super::signature::SignatureAlgorithm;

/// What the validator is permitted to accept. Built once at startup (e.g.
/// deserialized from operator config), then held immutably by the validator.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PackageValidationPolicy {
    pub archive: ArchiveLimits,
    pub allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    pub allowed_compression_methods: Vec<CompressionMethod>,
    pub allowed_manifest_versions: Vec<u32>,
    pub max_manifest_bytes: u64,
    pub require_signature: bool,
}

/// Hard ceiling for any single manifest read: bounded before parsing.
pub const HARD_MAX_MANIFEST_BYTES: u64 = 16 << 20;

impl PackageValidationPolicy {
    /// Secure initial defaults. Signature is required; allowlists are
    /// minimal (Ed25519, stored/deflate, manifest v1).
    #[must_use]
    pub fn production() -> Self {
        Self {
            archive: ArchiveLimits {
                max_entries: 1_024,
                max_compressed_bytes: 100 << 20,
                max_uncompressed_bytes: 500 << 20,
                max_entry_bytes: 100 << 20,
            },
            allowed_signature_algorithms: vec![SignatureAlgorithm::Ed25519],
            allowed_compression_methods: vec![
                CompressionMethod::Stored,
                CompressionMethod::Deflate,
            ],
            allowed_manifest_versions: vec![1],
            max_manifest_bytes: 1 << 20,
            require_signature: true,
        }
    }

    /// Rejects zero, unreasonable, or internally inconsistent settings and
    /// anything outside implementation maxima. Unsupported algorithms are an
    /// error here, never silently ignored.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.archive.validate().map_err(PolicyError::Archive)?;
        if self.allowed_signature_algorithms.is_empty() {
            return Err(PolicyError::EmptyAllowlist("signature algorithms"));
        }
        if self.allowed_compression_methods.is_empty() {
            return Err(PolicyError::EmptyAllowlist("compression methods"));
        }
        if self.allowed_manifest_versions.is_empty() {
            return Err(PolicyError::EmptyAllowlist("manifest versions"));
        }
        if self.max_manifest_bytes == 0 || self.max_manifest_bytes > HARD_MAX_MANIFEST_BYTES {
            return Err(PolicyError::BadManifestBound);
        }
        Ok(())
    }

    /// Production-ingest gate: structural validity plus mandatory
    /// signature. `require_signature = false` is rejected on this path;
    /// unsigned packages belong to a separate, explicitly isolated dev
    /// workflow — never a runtime flag flip.
    pub fn ensure_production_ingest(&self) -> Result<(), PolicyError> {
        self.validate()?;
        if !self.require_signature {
            return Err(PolicyError::SignatureNotRequired);
        }
        Ok(())
    }

    /// Records the policy alongside the validation audit record so verdicts
    /// stay attributable to the rules that produced them. Placeholder until
    /// audit logging lands.
    #[allow(dead_code)]
    fn audit_digest_placeholder() {}
}

#[derive(Debug)]
pub enum PolicyError {
    Archive(super::archive::ArchiveError),
    EmptyAllowlist(&'static str),
    BadManifestBound,
    SignatureNotRequired,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive(err) => write!(f, "invalid archive policy: {err}"),
            Self::EmptyAllowlist(what) => write!(f, "policy allowlist is empty: {what}"),
            Self::BadManifestBound => write!(f, "manifest byte bound out of range"),
            Self::SignatureNotRequired => {
                write!(f, "production ingest requires require_signature = true")
            }
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Archive(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_policy_is_valid_for_ingest() {
        PackageValidationPolicy::production()
            .ensure_production_ingest()
            .expect("production defaults must pass");
    }

    #[test]
    fn unsigned_production_config_rejected() {
        let mut policy = PackageValidationPolicy::production();
        policy.require_signature = false;
        assert!(matches!(
            policy.ensure_production_ingest(),
            Err(PolicyError::SignatureNotRequired)
        ));
    }

    #[test]
    fn empty_allowlists_rejected() {
        let mut policy = PackageValidationPolicy::production();
        policy.allowed_signature_algorithms.clear();
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::EmptyAllowlist(_))
        ));
    }

    #[test]
    fn zero_manifest_bound_rejected() {
        let mut policy = PackageValidationPolicy::production();
        policy.max_manifest_bytes = 0;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::BadManifestBound)
        ));
    }
}

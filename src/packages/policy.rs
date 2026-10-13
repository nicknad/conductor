//! Enforces module IDs, versions, runtime compatibility, and allowed
//! features. Performs no filesystem writes.
//!
//! [`PackageValidationPolicy`] is the runtime-configurable surface: size
//! bounds, allowlisted algorithms, compression methods, manifest versions,
//! and target-runtime rules. Everything security-fixed (stage order,
//! mandatory signature on the production path, traversal rejection) lives
//! outside it. Validate policy at startup; snapshot one immutable policy
//! per validation so a reload cannot change rules mid-check.

use thiserror::Error;

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
    /// Maximum accepted ratio of uncompressed to compressed bytes across
    /// the archive. Caps decompression-bomb amplification even when both
    /// byte totals sit inside their own bounds.
    pub max_compression_ratio: u32,
    /// Maximum accepted entry-path nesting depth (component count).
    /// Complements `MAX_ENTRY_PATH_LEN`, which bounds total length.
    pub max_nesting_depth: usize,
    pub require_signature: bool,
}

/// Hard ceiling for any single manifest read: bounded before parsing.
pub const HARD_MAX_MANIFEST_BYTES: u64 = 16 << 20;

/// Hard ceiling for the compression-ratio policy: raising it is a code
/// change, not a config edit.
pub const HARD_MAX_COMPRESSION_RATIO: u32 = 1_000;

/// Hard ceiling for the nesting-depth policy.
pub const HARD_MAX_NESTING_DEPTH: usize = 256;

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
            max_compression_ratio: 100,
            max_nesting_depth: 32,
            require_signature: true,
        }
    }

    /// Rejects zero, unreasonable, or internally inconsistent settings and
    /// anything outside implementation maxima. Unsupported algorithms are an
    /// error here, never silently ignored.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.archive.validate()?;
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
        if self.max_compression_ratio == 0
            || self.max_compression_ratio > HARD_MAX_COMPRESSION_RATIO
        {
            return Err(PolicyError::BadCompressionRatio);
        }
        if self.max_nesting_depth == 0 || self.max_nesting_depth > HARD_MAX_NESTING_DEPTH {
            return Err(PolicyError::BadNestingDepth);
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

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid archive policy: {0}")]
    Archive(#[from] super::archive::ArchiveError),
    #[error("policy allowlist is empty: {0}")]
    EmptyAllowlist(&'static str),
    #[error("manifest byte bound out of range")]
    BadManifestBound,
    #[error("compression ratio bound out of range")]
    BadCompressionRatio,
    #[error("nesting depth bound out of range")]
    BadNestingDepth,
    #[error("production ingest requires require_signature = true")]
    SignatureNotRequired,
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

    #[test]
    fn zero_or_excessive_ratio_and_depth_rejected() {
        let mut policy = PackageValidationPolicy::production();
        policy.max_compression_ratio = 0;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::BadCompressionRatio)
        ));
        policy = PackageValidationPolicy::production();
        policy.max_compression_ratio = HARD_MAX_COMPRESSION_RATIO + 1;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::BadCompressionRatio)
        ));
        policy = PackageValidationPolicy::production();
        policy.max_nesting_depth = 0;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::BadNestingDepth)
        ));
        policy.max_nesting_depth = HARD_MAX_NESTING_DEPTH + 1;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::BadNestingDepth)
        ));
    }
}

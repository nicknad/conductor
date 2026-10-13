//! Coordinates the security checks and decides whether a package passes.
//! ZIP mechanics live in `crate::packages::archive`.
//!
//! [`PackageValidationBuilder`] wires injectable dependencies with secure
//! defaults; [`PackageValidator`] owns the fixed stage order:
//!
//! 1. policy gate (production ingest requires a signature),
//! 2. authenticate the exact package bytes: stream the upload into
//!    quarantine while hashing SHA-256, then verify the detached
//!    [`PackageSignature`](crate::packages::signature::PackageSignature)
//!    against the trust store (not wired yet),
//! 3. archive inspection under [`ArchiveLimits`](crate::packages::archive::ArchiveLimits),
//! 4. manifest parsing and inventory validation (not wired yet),
//! 5. staged extraction with hashing plus module/runtime policy (not wired yet),
//! 6. promotion verdict minting a [`ValidatedArtifact`](crate::packages::artifact::ValidatedArtifact).
//!
//! Authentication precedes parsing: nothing inside the archive is trusted
//! before the outer bytes verify. Hashing and inspection operate on the
//! same private quarantined file — never hash one file and reopen an
//! attacker-controlled path for extraction (TOCTOU).
//!
//! Callers cannot omit stages or build a production validator without a
//! trust store — [`build`](PackageValidationBuilder::build) fails closed
//! when it is missing, and there is no `skip_signature_verification`
//! switch. Tests configure trust by value (`ConfiguredTrustedKeys`); fake
//! verifier/reader backends arrive as `#[cfg(test)]` seams with their real
//! counterparts. Configure the builder once at startup; to reconfigure,
//! build a new immutable validator and publish it atomically so one
//! validation never observes a policy halfway through a reload.

use std::path::Path;
use thiserror::Error;

use crate::packages::archive::{ArchiveError, ZipArchiveReader};
use crate::packages::digest::Sha256DigestProvider;
use crate::packages::policy::{PackageValidationPolicy, PolicyError};
use crate::packages::signature::{ConfiguredTrustedKeys, Ed25519Verifier};

/// Runs the mandatory stages in a fixed order and returns a verdict or a
/// typed error. Holds one immutable policy snapshot per instance.
pub struct PackageValidator {
    archive_reader: ZipArchiveReader,
    signature_verifier: Ed25519Verifier,
    trusted_keys: ConfiguredTrustedKeys,
    digest: Sha256DigestProvider,
    policy: PackageValidationPolicy,
}

impl PackageValidator {
    fn new(
        archive_reader: ZipArchiveReader,
        signature_verifier: Ed25519Verifier,
        trusted_keys: ConfiguredTrustedKeys,
        digest: Sha256DigestProvider,
        policy: PackageValidationPolicy,
    ) -> Self {
        Self {
            archive_reader,
            signature_verifier,
            trusted_keys,
            digest,
            policy,
        }
    }

    #[must_use]
    pub fn policy(&self) -> &PackageValidationPolicy {
        &self.policy
    }

    #[must_use]
    pub fn archive_reader(&self) -> &ZipArchiveReader {
        &self.archive_reader
    }

    #[must_use]
    pub fn signature_verifier(&self) -> &Ed25519Verifier {
        &self.signature_verifier
    }

    #[must_use]
    pub fn trusted_keys(&self) -> &ConfiguredTrustedKeys {
        &self.trusted_keys
    }

    #[must_use]
    pub fn digest(&self) -> &Sha256DigestProvider {
        &self.digest
    }

    /// Fixed-order validation. Stages 3+ are not wired yet, so success is
    /// currently unreachable: the method proves stage order and dependency
    /// wiring, then fails closed.
    pub fn validate(&self, archive: &Path) -> Result<(), ValidationError> {
        self.policy.ensure_production_ingest()?;
        let _inspected = self.archive_reader.inspect(archive, &self.policy.archive)?;
        Err(ValidationError::NotImplemented(
            "manifest/signature stage not wired yet",
        ))
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("policy gate failed: {0}")]
    Policy(#[from] PolicyError),
    #[error("archive inspection failed: {0}")]
    Archive(#[from] ArchiveError),
    #[error("validation stage pending: {0}")]
    NotImplemented(&'static str),
}

/// Builder failure: required configuration missing. There is no
/// skip-verification switch; the only way to obtain a validator is to
/// supply a trust store.
#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cannot build validator without a trust store: supply trusted keys")]
    MissingTrustStore,
}

/// Assembles a [`PackageValidator`] from concrete components. Backends are
/// fixed single implementations; the configurable inputs are the policy
/// (constructor) and the trust store (setter). [`build`](Self::build)
/// fails if the trust store is missing.
pub struct PackageValidationBuilder {
    archive_reader: ZipArchiveReader,
    signature_verifier: Ed25519Verifier,
    trusted_keys: Option<ConfiguredTrustedKeys>,
    digest: Sha256DigestProvider,
    policy: PackageValidationPolicy,
}

impl PackageValidationBuilder {
    #[must_use]
    pub fn new(policy: PackageValidationPolicy) -> Self {
        Self {
            archive_reader: ZipArchiveReader,
            signature_verifier: Ed25519Verifier,
            trusted_keys: None,
            digest: Sha256DigestProvider,
            policy,
        }
    }

    #[must_use]
    pub fn trusted_keys(mut self, keys: ConfiguredTrustedKeys) -> Self {
        self.trusted_keys = Some(keys);
        self
    }

    /// Builds the validator, failing closed when the trust store is absent.
    pub fn build(self) -> Result<PackageValidator, BuildError> {
        Ok(PackageValidator::new(
            self.archive_reader,
            self.signature_verifier,
            self.trusted_keys.ok_or(BuildError::MissingTrustStore)?,
            self.digest,
            self.policy,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::digest::DigestAlgorithm;
    use crate::packages::signature::{SignatureAlgorithm, SignatureError, TrustedSigningKey};

    fn test_keys() -> ConfiguredTrustedKeys {
        ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            vec![],
        )])
    }

    fn test_validator(policy: PackageValidationPolicy) -> PackageValidator {
        PackageValidationBuilder::new(policy)
            .trusted_keys(test_keys())
            .build()
            .expect("test validator must build")
    }

    #[test]
    fn build_fails_without_trust_store() {
        let result = PackageValidationBuilder::new(PackageValidationPolicy::production()).build();
        assert!(matches!(result, Err(BuildError::MissingTrustStore)));
    }

    #[test]
    fn defaults_fail_closed_after_policy_gate() {
        let validator = test_validator(PackageValidationPolicy::production());
        assert!(validator.policy().require_signature);
        assert_eq!(validator.digest().algorithm(), DigestAlgorithm::Sha256);
        let err = validator.validate(Path::new("pkg.zip")).unwrap_err();
        assert!(matches!(err, ValidationError::Archive(_)));
    }

    #[test]
    fn unsigned_config_rejected_before_archive_stage() {
        let mut policy = PackageValidationPolicy::production();
        policy.require_signature = false;
        let validator = test_validator(policy);
        let err = validator.validate(Path::new("pkg.zip")).unwrap_err();
        assert!(matches!(err, ValidationError::Policy(_)));
    }

    #[test]
    fn trust_store_is_configured_by_value() {
        let validator = test_validator(PackageValidationPolicy::production());
        assert!(validator.trusted_keys().key("k1").is_some());
        assert!(validator.trusted_keys().key("unknown").is_none());
        let verify = validator.signature_verifier().verify(
            &TrustedSigningKey::new("k1", SignatureAlgorithm::Ed25519, vec![]),
            b"m",
            b"s",
        );
        assert!(matches!(verify, Err(SignatureError::NotImplemented)));
    }
}

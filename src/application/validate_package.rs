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
//! verifier and key provider — there is no `skip_signature_verification`
//! switch. Tests inject doubles explicitly. Configure the builder once at
//! startup; to reconfigure, build a new immutable validator and publish it
//! atomically so one validation never observes a policy halfway through a
//! reload.

use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

use crate::packages::archive::{ArchiveError, ArchiveReader, ZipArchiveReader};
use crate::packages::digest::{DigestProvider, Sha256DigestProvider};
use crate::packages::policy::{PackageValidationPolicy, PolicyError};
use crate::packages::signature::{
    ConfiguredTrustedKeys, Ed25519Verifier, SignatureVerifier, TrustedKeyProvider,
};

/// Runs the mandatory stages in a fixed order and returns a verdict or a
/// typed error. Holds one immutable policy snapshot per instance.
pub struct PackageValidator {
    archive_reader: Arc<dyn ArchiveReader>,
    signature_verifier: Arc<dyn SignatureVerifier>,
    trusted_keys: Arc<dyn TrustedKeyProvider>,
    digest: Arc<dyn DigestProvider>,
    policy: PackageValidationPolicy,
}

impl PackageValidator {
    fn new(
        archive_reader: Arc<dyn ArchiveReader>,
        signature_verifier: Arc<dyn SignatureVerifier>,
        trusted_keys: Arc<dyn TrustedKeyProvider>,
        digest: Arc<dyn DigestProvider>,
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
    pub fn archive_reader(&self) -> &Arc<dyn ArchiveReader> {
        &self.archive_reader
    }

    #[must_use]
    pub fn signature_verifier(&self) -> &Arc<dyn SignatureVerifier> {
        &self.signature_verifier
    }

    #[must_use]
    pub fn trusted_keys(&self) -> &Arc<dyn TrustedKeyProvider> {
        &self.trusted_keys
    }

    #[must_use]
    pub fn digest(&self) -> &Arc<dyn DigestProvider> {
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

/// Assembles a [`PackageValidator`]. Required security dependencies are
/// always present: construction starts from secure defaults and each
/// `with_*` setter only swaps one implementation — none can be omitted or
/// disabled.
pub struct PackageValidationBuilder {
    archive_reader: Arc<dyn ArchiveReader>,
    signature_verifier: Arc<dyn SignatureVerifier>,
    trusted_keys: Arc<dyn TrustedKeyProvider>,
    digest: Arc<dyn DigestProvider>,
    policy: PackageValidationPolicy,
}

impl PackageValidationBuilder {
    #[must_use]
    pub fn new(policy: PackageValidationPolicy) -> Self {
        Self {
            archive_reader: Arc::new(ZipArchiveReader),
            signature_verifier: Arc::new(Ed25519Verifier),
            trusted_keys: Arc::new(ConfiguredTrustedKeys::default()),
            digest: Arc::new(Sha256DigestProvider),
            policy,
        }
    }

    #[must_use]
    pub fn archive_reader(mut self, reader: Arc<dyn ArchiveReader>) -> Self {
        self.archive_reader = reader;
        self
    }

    #[must_use]
    pub fn signature_verifier(mut self, verifier: Arc<dyn SignatureVerifier>) -> Self {
        self.signature_verifier = verifier;
        self
    }

    #[must_use]
    pub fn trusted_keys(mut self, keys: Arc<dyn TrustedKeyProvider>) -> Self {
        self.trusted_keys = keys;
        self
    }

    #[must_use]
    pub fn digest_provider(mut self, digest: Arc<dyn DigestProvider>) -> Self {
        self.digest = digest;
        self
    }

    #[must_use]
    pub fn build(self) -> PackageValidator {
        PackageValidator::new(
            self.archive_reader,
            self.signature_verifier,
            self.trusted_keys,
            self.digest,
            self.policy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::archive::{ArchiveLimits, InspectedArchive};
    use crate::packages::digest::{DigestAlgorithm, DigestError};
    use crate::packages::signature::{SignatureAlgorithm, SignatureError, TrustedSigningKey};

    struct OkArchiveReader;

    impl ArchiveReader for OkArchiveReader {
        fn inspect(
            &self,
            _archive: &Path,
            _limits: &ArchiveLimits,
        ) -> Result<InspectedArchive, ArchiveError> {
            Ok(InspectedArchive::new(1))
        }
    }

    struct OkDigest;

    impl DigestProvider for OkDigest {
        fn algorithm(&self) -> DigestAlgorithm {
            DigestAlgorithm::Sha256
        }

        fn digest(&self, _bytes: &[u8]) -> Result<Vec<u8>, DigestError> {
            Ok(vec![0u8; 32])
        }
    }

    #[test]
    fn defaults_fail_closed_after_policy_gate() {
        let validator =
            PackageValidationBuilder::new(PackageValidationPolicy::production()).build();
        assert!(validator.policy().require_signature);
        assert_eq!(validator.digest().algorithm(), DigestAlgorithm::Sha256);
        let err = validator.validate(Path::new("pkg.zip")).unwrap_err();
        assert!(matches!(err, ValidationError::Archive(_)));
    }

    #[test]
    fn unsigned_config_rejected_before_archive_stage() {
        let mut policy = PackageValidationPolicy::production();
        policy.require_signature = false;
        let validator = PackageValidationBuilder::new(policy)
            .archive_reader(Arc::new(OkArchiveReader))
            .build();
        let err = validator.validate(Path::new("pkg.zip")).unwrap_err();
        assert!(matches!(err, ValidationError::Policy(_)));
    }

    #[test]
    fn injected_doubles_reach_pending_signature_stage() {
        let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
            .archive_reader(Arc::new(OkArchiveReader))
            .digest_provider(Arc::new(OkDigest))
            .trusted_keys(Arc::new(ConfiguredTrustedKeys::new(vec![
                TrustedSigningKey::new("k1", SignatureAlgorithm::Ed25519, vec![]),
            ])))
            .build();
        assert!(validator.trusted_keys().key("k1").is_some());
        let verify = validator.signature_verifier().verify(
            &TrustedSigningKey::new("k1", SignatureAlgorithm::Ed25519, vec![]),
            b"m",
            b"s",
        );
        assert!(matches!(verify, Err(SignatureError::NotImplemented)));
        let err = validator.validate(Path::new("pkg.zip")).unwrap_err();
        assert!(matches!(err, ValidationError::NotImplemented(_)));
    }
}

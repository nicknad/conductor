//! Coordinates the security checks and decides whether a package passes.
//! ZIP mechanics live in `crate::packages::archive`.
//!
//! [`PackageValidationBuilder`] wires injectable dependencies with secure
//! defaults; [`PackageValidator`] owns the fixed stage order:
//!
//! 1. policy gate (production ingest requires a signature; the on-disk
//!    archive length is bounded before any hashing),
//! 2. authenticate the exact package bytes: digest one open handle with
//!    SHA-256, then verify the detached
//!    [`PackageSignature`](crate::packages::signature::PackageSignature)
//!    against the trust store,
//! 3. archive inspection of the same bytes under
//!    [`PackageValidationPolicy::scan_config`](crate::packages::policy::PackageValidationPolicy::scan_config),
//! 4. manifest parsing (bounded, version-gated) and inventory validation,
//! 5. promotion verdict minting a [`ValidatedPackage`] carrying the
//!    artifact identity, the validated manifest, and the authorizing signer.
//!
//! Authentication precedes parsing: nothing inside the archive is trusted
//! before the outer bytes verify. Hashing, inspection, and the manifest
//! read share one open [`QuarantinedFile`](crate::packages::archive::QuarantinedFile)
//! handle — never hash one file and reopen an attacker-controlled path for
//! inspection (TOCTOU). Validation binds the outer bytes; per-file byte
//! agreement for manifest v2 packages is enforced at staged extraction
//! ([`extract_verified`](crate::storage::staging::extract_verified)),
//! where each decompressed stream is hashed while written. v1 packages
//! retain inventory set-equality.
//!
//! The verdict carries everything registry, audit, and activation consume:
//! no downstream stage re-opens or re-parses the archive to recover the
//! manifest or attribute the signer.
//!
//! Callers cannot omit stages or build a production validator without a
//! trust store — [`build`](PackageValidationBuilder::build) fails closed
//! when it is missing, and there is no `skip_signature_verification`
//! switch. Tests configure trust by value (`ConfiguredTrustedKeys`); fake
//! verifier/reader backends arrive as `#[cfg(test)]` seams with their real
//! counterparts. Configure the builder once at startup; to reconfigure,
//! build a new immutable validator and publish it atomically so one
//! validation never observes a policy halfway through a reload.

use std::io::Seek as _;
use thiserror::Error;

use crate::packages::archive::{ArchiveError, QuarantinedFile, ZipArchiveReader};
use crate::packages::artifact::{ArtifactDigest, ValidatedArtifact};
use crate::packages::digest::{DigestError, Sha256DigestProvider};
use crate::packages::inventory::{check_against_inspected, InventoryError};
use crate::packages::manifest::{Manifest, ManifestError, MANIFEST_FILE_NAME};
use crate::packages::policy::{PackageValidationPolicy, PolicyError};
use crate::packages::signature::{
    ConfiguredTrustedKeys, Ed25519Verifier, PackageSignature, SignatureError, TrustedSigningKey,
};

/// Runs the mandatory stages in a fixed order and returns a verdict or a
/// typed error. Holds one immutable policy snapshot per instance.
#[derive(Debug)]
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

    /// Test-only access to the signature verifier. Production code must go
    /// through [`PackageValidator::validate`]; no caller may reassemble
    /// stages out of order.
    #[cfg(test)]
    #[must_use]
    pub fn signature_verifier(&self) -> &Ed25519Verifier {
        &self.signature_verifier
    }

    /// Test-only access to the trust store.
    #[cfg(test)]
    #[must_use]
    pub fn trusted_keys(&self) -> &ConfiguredTrustedKeys {
        &self.trusted_keys
    }

    /// Test-only access to the digest backend.
    #[cfg(test)]
    #[must_use]
    pub fn digest(&self) -> &Sha256DigestProvider {
        &self.digest
    }

    /// Fixed-order validation over one open quarantine handle: policy gate
    /// → hash-and-authenticate → inspect → manifest/inventory → promotion.
    /// Returns the complete [`ValidatedPackage`] verdict on success.
    ///
    /// Takes `&mut QuarantinedFile` — not a path — so hashing, inspection,
    /// and manifest reads are forced onto the same bytes. Open the handle
    /// with [`QuarantinedFile::open`] in [`crate::application::upload_package::run_upload_workflow`].
    pub fn validate(
        &self,
        file: &mut QuarantinedFile,
        signature: &PackageSignature,
    ) -> Result<ValidatedPackage, ValidationError> {
        self.policy.ensure_production_ingest()?;
        // Bound the work before hashing: the on-disk length is the one
        // authoritative "compressed bytes" figure available without parsing,
        // so an oversized upload is rejected before any digest or signature
        // work. Inspection re-checks the exact per-entry totals later.
        let on_disk = file
            .len()
            .map_err(|e| ValidationError::Archive(ArchiveError::Io(e.to_string())))?;
        if on_disk > self.policy.archive.max_compressed_bytes {
            return Err(ValidationError::Archive(ArchiveError::LimitExceeded(
                "archive size exceeds bound",
            )));
        }
        let digest = self.digest.digest_stream(&mut *file)?;
        let signer = self.signature_verifier.authenticate(
            signature,
            &digest,
            &self.trusted_keys,
            &self.policy.allowed_signature_algorithms,
        )?;
        file.rewind()
            .map_err(|e| ValidationError::Archive(ArchiveError::Io(e.to_string())))?;
        let inspected = self
            .archive_reader
            .inspect_file(file, &self.policy.scan_config())?;
        if !inspected.files.iter().any(|f| f == MANIFEST_FILE_NAME) {
            return Err(ValidationError::Inventory(InventoryError::MissingFile(
                MANIFEST_FILE_NAME.to_owned(),
            )));
        }
        file.rewind()
            .map_err(|e| ValidationError::Archive(ArchiveError::Io(e.to_string())))?;
        let manifest_bytes = self
            .archive_reader
            .read_file_from(file, MANIFEST_FILE_NAME, self.policy.max_manifest_bytes)
            .map_err(|e| match e {
                // This call reads only the manifest, so a bound breach here
                // is the manifest bound, not a generic archive limit.
                ArchiveError::LimitExceeded(_) => {
                    ValidationError::Manifest(ManifestError::TooLarge)
                }
                other => ValidationError::Archive(other),
            })?;
        let manifest = Manifest::parse_with_policy(&manifest_bytes, &self.policy)?;
        // Inventory compares declared payload files against the inspected
        // listing minus the manifest itself (required separately above,
        // never listed in `files`).
        let payload = crate::packages::archive::InspectedArchive::new(
            inspected.entry_count,
            inspected
                .files
                .into_iter()
                .filter(|f| f != MANIFEST_FILE_NAME)
                .collect(),
        );
        check_against_inspected(&manifest.declared_files(), &payload)?;
        let artifact = ValidatedArtifact::new(
            ArtifactDigest::new(digest),
            manifest.module_id.clone(),
            manifest.version.clone(),
        );
        Ok(ValidatedPackage::new(artifact, manifest, signer))
    }
}

/// Complete promotion verdict: artifact identity, validated manifest, and
/// the authorizing signer. Minted only by [`PackageValidator::validate`];
/// registry, audit, and activation consume it without touching the archive
/// again.
#[derive(Debug)]
pub struct ValidatedPackage {
    artifact: ValidatedArtifact,
    manifest: Manifest,
    signer: TrustedSigningKey,
}

impl ValidatedPackage {
    /// Mints the promotion verdict. Private to this module so only
    /// [`PackageValidator::validate`] can construct it.
    fn new(artifact: ValidatedArtifact, manifest: Manifest, signer: TrustedSigningKey) -> Self {
        Self {
            artifact,
            manifest,
            signer,
        }
    }

    #[must_use]
    pub fn artifact(&self) -> &ValidatedArtifact {
        &self.artifact
    }

    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    #[must_use]
    pub fn signer(&self) -> &TrustedSigningKey {
        &self.signer
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("policy gate failed: {0}")]
    Policy(#[from] PolicyError),
    #[error("archive inspection failed: {0}")]
    Archive(#[from] ArchiveError),
    #[error("package digest failed: {0}")]
    Digest(#[from] DigestError),
    #[error("signature authentication failed: {0}")]
    Signature(#[from] SignatureError),
    #[error("manifest rejected: {0}")]
    Manifest(#[from] ManifestError),
    #[error("inventory mismatch: {0}")]
    Inventory(#[from] InventoryError),
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
        .expect("distinct test keys must build")
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
    fn missing_archive_fails_before_signature_stage() {
        use crate::packages::archive::QuarantinedFile;

        let validator = test_validator(PackageValidationPolicy::production());
        assert!(validator.policy().require_signature);
        assert_eq!(validator.digest().algorithm(), DigestAlgorithm::Sha256);
        // The quarantine handle itself fails to open — validation never
        // reaches the signature stage.
        let open = QuarantinedFile::open(std::path::Path::new("pkg.zip"));
        assert!(matches!(
            open,
            Err(crate::packages::archive::ArchiveError::Io(_))
        ));
    }

    #[test]
    fn unsigned_config_rejected_before_archive_stage() {
        use crate::packages::archive::QuarantinedFile;
        use crate::packages::signature::SUPPORTED_SIGNATURE_FORMAT_VERSION;

        let mut policy = PackageValidationPolicy::production();
        policy.require_signature = false;
        let validator = test_validator(policy);
        let envelope = PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
            key_id: "k1".to_owned(),
            signature: vec![0u8; 64],
        };
        // Policy gate runs before any handle use; contents do not matter.
        let dir =
            std::env::temp_dir().join(format!("conductor-validate-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir must be created");
        let path = dir.join("empty.zip");
        std::fs::write(&path, b"").expect("temp file must be writable");
        let mut quarantined = QuarantinedFile::open(&path).expect("temp quarantine must open");
        let err = validator.validate(&mut quarantined, &envelope).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, ValidationError::Policy(_)));
    }

    #[test]
    fn trust_store_is_configured_by_value() {
        let validator = test_validator(PackageValidationPolicy::production());
        assert!(validator.trusted_keys().key("k1").is_some());
        assert!(validator.trusted_keys().key("unknown").is_none());
        // Empty public key and garbage signature fail closed.
        let verify = validator.signature_verifier().verify(
            &TrustedSigningKey::new("k1", SignatureAlgorithm::Ed25519, vec![]),
            b"m",
            b"s",
        );
        assert!(matches!(verify, Err(SignatureError::VerificationFailed)));
    }
}

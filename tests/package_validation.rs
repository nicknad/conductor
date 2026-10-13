//! Package validation: policy gates and pipeline stage order through the
//! public API.
//!
//! What must hold:
//! - the production policy passes its own ingest gate; an unsigned
//!   configuration is rejected before any archive stage runs;
//! - the builder always yields a validator with all four dependencies
//!   present (injected or defaulted) — stages cannot be omitted;
//! - manifest reads are bounded by the policy's `max_manifest_bytes`;
//! - until backends land, validation fails closed with typed errors.

use std::path::Path;
use std::sync::Arc;

use conductor::application::validate_package::{PackageValidationBuilder, ValidationError};
use conductor::packages::archive::{ArchiveError, ArchiveReader};
use conductor::packages::archive::{ArchiveLimits, InspectedArchive};
use conductor::packages::manifest::{Manifest, ManifestError};
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::SignatureAlgorithm;

#[test]
fn production_policy_demands_signatures_and_ed25519() {
    let policy = PackageValidationPolicy::production();
    policy
        .ensure_production_ingest()
        .expect("production policy must be ingestable");
    assert!(policy.require_signature);
    assert!(policy
        .allowed_signature_algorithms
        .contains(&SignatureAlgorithm::Ed25519));
}

#[test]
fn unsigned_config_rejected_before_archive_stage() {
    struct MustNotRun;
    impl ArchiveReader for MustNotRun {
        fn inspect(
            &self,
            _archive: &Path,
            _limits: &ArchiveLimits,
        ) -> Result<InspectedArchive, ArchiveError> {
            panic!("archive stage must not run when the policy gate fails");
        }
    }

    let mut policy = PackageValidationPolicy::production();
    policy.require_signature = false;
    let validator = PackageValidationBuilder::new(policy)
        .archive_reader(Arc::new(MustNotRun))
        .build();
    assert!(matches!(
        validator.validate(Path::new("pkg.zip")),
        Err(ValidationError::Policy(_))
    ));
}

#[test]
fn validator_fails_closed_until_backends_land() {
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production()).build();
    assert!(matches!(
        validator.validate(Path::new("pkg.zip")),
        Err(ValidationError::Archive(_))
    ));
}

#[test]
fn manifest_reads_are_bounded_by_policy() {
    let policy = PackageValidationPolicy::production();
    let oversized = vec![0u8; (policy.max_manifest_bytes + 1) as usize];
    assert!(matches!(
        Manifest::parse_bounded(&oversized, policy.max_manifest_bytes, &[1]),
        Err(ManifestError::TooLarge)
    ));
    assert!(matches!(
        Manifest::parse_bounded(&[], policy.max_manifest_bytes, &[1]),
        Err(ManifestError::Invalid(_))
    ));
}

//! Package validation: policy gates and pipeline stage order through the
//! public API.
//!
//! What must hold:
//! - the production policy passes its own ingest gate; an unsigned
//!   configuration is rejected before any archive stage runs;
//! - the builder refuses to yield a validator without a trust store;
//! - trust is configured by value (`ConfiguredTrustedKeys`);
//! - manifest reads are bounded by the policy's `max_manifest_bytes`;
//! - a missing archive fails at I/O before the signature stage runs.

use std::path::Path;

use conductor::application::validate_package::{
    BuildError, PackageValidationBuilder, ValidationError,
};
use conductor::packages::manifest::{Manifest, ManifestError};
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm, TrustedSigningKey,
    SUPPORTED_SIGNATURE_FORMAT_VERSION,
};

fn test_keys() -> ConfiguredTrustedKeys {
    ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        vec![],
    )])
}

fn dummy_envelope() -> PackageSignature {
    PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "k1".to_owned(),
        signature: vec![0u8; 64],
    }
}

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
fn builder_refuses_to_omit_the_trust_store() {
    assert!(matches!(
        PackageValidationBuilder::new(PackageValidationPolicy::production()).build(),
        Err(BuildError::MissingTrustStore)
    ));
}

#[test]
fn unsigned_config_rejected_before_archive_stage() {
    let mut policy = PackageValidationPolicy::production();
    policy.require_signature = false;
    let validator = PackageValidationBuilder::new(policy)
        .trusted_keys(test_keys())
        .build()
        .expect("test validator must build");
    assert!(matches!(
        validator.validate(Path::new("pkg.zip"), &dummy_envelope()),
        Err(ValidationError::Policy(_))
    ));
}

#[test]
fn missing_archive_fails_before_signature_stage() {
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(test_keys())
        .build()
        .expect("test validator must build");
    assert!(validator.trusted_keys().key("k1").is_some());
    assert!(matches!(
        validator.validate(Path::new("pkg.zip"), &dummy_envelope()),
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

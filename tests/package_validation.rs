//! Package validation: policy gates and pipeline stage order through the
//! public API.
//!
//! What must hold:
//! - the production policy passes its own ingest gate; an unsigned
//!   configuration is rejected before any archive stage runs;
//! - the builder refuses to yield a validator without a trust store;
//! - trust is configured by value (`ConfiguredTrustedKeys`);
//! - manifest reads are bounded by the policy's `max_manifest_bytes`;
//! - a missing archive fails at I/O before the signature stage runs;
//! - a well-formed signed package validates end to end and mints an
//!   artifact bound to the exact bytes (positive path plus tamper cases).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use conductor::application::validate_package::{
    BuildError, PackageValidationBuilder, PackageValidator, ValidationError,
};
use conductor::packages::artifact::ArtifactDigest;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::manifest::{Manifest, ManifestError};
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    canonical_payload, ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm,
    TrustedSigningKey, SUPPORTED_SIGNATURE_FORMAT_VERSION,
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

// --- End-to-end golden path: the package is built in-test so it can never
// drift from the schema, then signed over its exact bytes. ---

/// Test-only signing key. Precedent: unit tests sign with fixed keys; this
/// private key must never sign anything outside these tests.
const TEST_SIGNING_KEY: [u8; 32] = [42u8; 32];

/// Wrote `bytes` to a process-unique temp path; removed on drop so a
/// failing assertion cannot leak staging files.
struct TempPackage(PathBuf);

impl TempPackage {
    fn write(bytes: &[u8], tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "conductor-test-{}-{}-{}.zip",
            std::process::id(),
            tag,
            bytes.len()
        ));
        std::fs::write(&path, bytes).expect("test package must be writable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPackage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn golden_package_bytes() -> Vec<u8> {
    let manifest = serde_json::json!({
        "manifest_version": 1,
        "module_id": "reporting-service",
        "version": "1.2.0",
        "runtime": "rust",
        "entrypoint": "payload/reporting-service",
        "files": ["payload/reporting-service"],
    });
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("zip writer must accept manifest");
    writer
        .write_all(&serde_json::to_vec(&manifest).expect("manifest must serialize"))
        .expect("zip writer must accept manifest bytes");
    writer
        .start_file("payload/reporting-service", options)
        .expect("zip writer must accept payload");
    writer
        .write_all(b"not a real executable")
        .expect("zip writer must accept payload bytes");
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

fn golden_setup() -> (PackageValidator, Vec<u8>, PackageSignature) {
    use ed25519_dalek::{Signer as _, SigningKey};

    let bytes = golden_package_bytes();
    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let digest: [u8; 32] = Sha256DigestProvider
        .digest(&bytes)
        .expect("hashing must succeed")
        .try_into()
        .expect("SHA-256 is 32 bytes");
    let signature = signing.sign(&canonical_payload(&digest));
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )]);
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    let envelope = PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "k1".to_owned(),
        signature: signature.to_bytes().to_vec(),
    };
    (validator, bytes, envelope)
}

#[test]
fn valid_signed_package_mints_artifact_bound_to_exact_bytes() {
    let (validator, bytes, envelope) = golden_setup();
    let package = TempPackage::write(&bytes, "valid");
    let artifact = validator
        .validate(package.path(), &envelope)
        .expect("valid signed package must validate");
    assert_eq!(artifact.module_id(), "reporting-service");
    assert_eq!(artifact.version(), "1.2.0");
    let expected = ArtifactDigest::new(
        Sha256DigestProvider
            .digest(&bytes)
            .expect("hashing must succeed")
            .try_into()
            .expect("SHA-256 is 32 bytes"),
    );
    assert_eq!(artifact.digest(), &expected);
}

#[test]
fn tampered_bytes_fail_authentication_not_parsing() {
    let (validator, mut bytes, envelope) = golden_setup();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let package = TempPackage::write(&bytes, "tampered");
    // Authentication runs before inspection, so a one-bit flip is a
    // signature failure even though the ZIP is now also corrupt.
    assert!(matches!(
        validator.validate(package.path(), &envelope),
        Err(ValidationError::Signature(_))
    ));
}

#[test]
fn unknown_signing_key_fails_before_crypto() {
    let (validator, bytes, _) = golden_setup();
    let package = TempPackage::write(&bytes, "unknown-key");
    let envelope = PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "someone-else".to_owned(),
        signature: vec![0u8; 64],
    };
    assert!(matches!(
        validator.validate(package.path(), &envelope),
        Err(ValidationError::Signature(_))
    ));
}

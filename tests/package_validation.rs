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
use conductor::packages::archive::{ArchiveError, QuarantinedFile};
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
    .expect("distinct test keys must build")
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
    // Policy gate runs before any handle use; write a dummy file so the
    // handle opens, then expect the policy rejection.
    let package = TempPackage::write(b"dummy", "unsigned");
    let mut quarantined =
        QuarantinedFile::open(package.path()).expect("temp quarantine must open");
    assert!(matches!(
        validator.validate(&mut quarantined, &dummy_envelope()),
        Err(ValidationError::Policy(_))
    ));
}

#[test]
fn missing_archive_fails_before_signature_stage() {
    let _validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(test_keys())
        .build()
        .expect("test validator must build");
    // The quarantine handle itself fails to open — validation never reaches
    // the signature stage. Trust is configured by value at build time.
    assert!(matches!(
        QuarantinedFile::open(Path::new("pkg.zip")),
        Err(ArchiveError::Io(_))
    ));
}

/// The compressed-size bound is a pre-digest gate: an oversized archive
/// must not be hashed and authenticated first. The envelope here names an
/// unknown key, so reaching a signature failure would prove the ordering
/// is wrong; `Archive(LimitExceeded)` proves the size gate ran first.
#[test]
fn oversized_archive_is_rejected_before_digest_and_signature() {
    let mut policy = PackageValidationPolicy::production();
    policy.archive.max_compressed_bytes = 1;
    let (validator, _signing) = real_key_validator(policy);
    let bytes = golden_package_bytes();
    let package = TempPackage::write(&bytes, "oversized");
    let envelope = PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "someone-else".to_owned(),
        signature: vec![0u8; 64],
    };
    assert!(matches!(
        validate_path(&validator, package.path(), &envelope),
        Err(ValidationError::Archive(ArchiveError::LimitExceeded(_)))
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
//
// "Golden" here means the single known-good reference package: a valid
// manifest plus its payload, hashed and signed exactly as production
// requires. Positive-path tests validate it as-is; negative tests derive
// from it by breaking exactly one property (flipped byte, wrong key,
// missing manifest, undeclared file) so each failure names its stage.

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

/// Opens `path` as a quarantine handle and runs the fixed validation order.
/// Every test threads one handle — never a bare path — mirroring production.
fn validate_path(
    validator: &PackageValidator,
    path: &Path,
    envelope: &PackageSignature,
) -> Result<
    conductor::application::validate_package::ValidatedPackage,
    ValidationError,
> {
    let mut quarantined = QuarantinedFile::open(path).expect("temp quarantine must open");
    validator.validate(&mut quarantined, envelope)
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
    package_bytes(
        &serde_json::to_vec(&manifest).expect("manifest must serialize"),
        &[(
            "payload/reporting-service",
            b"not a real executable".as_slice(),
        )],
    )
}

/// Assembles a Stored archive from a manifest document plus payload files.
fn package_bytes(manifest: &[u8], payloads: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("zip writer must accept manifest");
    writer
        .write_all(manifest)
        .expect("zip writer must accept manifest bytes");
    for (name, data) in payloads {
        writer
            .start_file(*name, options)
            .expect("zip writer must accept payload");
        writer
            .write_all(data)
            .expect("zip writer must accept payload bytes");
    }
    writer.finish().expect("zip must finalize");
    cursor.into_inner()
}

fn manifest_doc(files: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "manifest_version": 1,
        "module_id": "reporting-service",
        "version": "1.2.0",
        "runtime": "rust",
        "entrypoint": "payload/reporting-service",
        "files": files,
    }))
    .expect("manifest must serialize")
}

fn real_key_validator(
    policy: PackageValidationPolicy,
) -> (PackageValidator, ed25519_dalek::SigningKey) {
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )])
    .expect("distinct test keys must build");
    let validator = PackageValidationBuilder::new(policy)
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    (validator, signing)
}

fn sign_package(signing: &ed25519_dalek::SigningKey, bytes: &[u8]) -> (PackageSignature, [u8; 32]) {
    use ed25519_dalek::Signer as _;

    let digest: [u8; 32] = Sha256DigestProvider
        .digest(bytes)
        .expect("hashing must succeed");
    let signature = signing.sign(&canonical_payload(&digest));
    (
        PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
            key_id: "k1".to_owned(),
            signature: signature.to_bytes().to_vec(),
        },
        digest,
    )
}

/// Assembles the golden package: manifest plus payload, hashed and signed
/// with the test key. Returns the validator trusting that key, the exact
/// bytes, and their detached signature — everything `validate` needs.
fn golden_setup() -> (PackageValidator, Vec<u8>, PackageSignature) {
    let bytes = golden_package_bytes();
    let (validator, signing) = real_key_validator(PackageValidationPolicy::production());
    let (envelope, _) = sign_package(&signing, &bytes);
    (validator, bytes, envelope)
}

#[test]
fn valid_signed_package_mints_artifact_bound_to_exact_bytes() {
    let (validator, bytes, envelope) = golden_setup();
    let package = TempPackage::write(&bytes, "valid");
    let verdict = validate_path(&validator, package.path(), &envelope)
        .expect("valid signed package must validate");
    assert_eq!(verdict.artifact().module_id(), "reporting-service");
    assert_eq!(verdict.artifact().version(), "1.2.0");
    // The verdict carries the validated manifest and authorizing signer so
    // registry/audit consumers never re-open or re-parse the archive.
    assert_eq!(verdict.manifest().entrypoint, "payload/reporting-service");
    assert_eq!(verdict.manifest().module_id, "reporting-service");
    assert_eq!(verdict.signer().key_id, "k1");
    let expected = ArtifactDigest::new(
        Sha256DigestProvider
            .digest(&bytes)
            .expect("hashing must succeed"),
    );
    assert_eq!(verdict.artifact().digest(), &expected);
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
        validate_path(&validator, package.path(), &envelope),
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
        validate_path(&validator, package.path(), &envelope),
        Err(ValidationError::Signature(_))
    ));
}

#[test]
fn package_without_manifest_fails_inventory() {
    let (validator, signing) = real_key_validator(PackageValidationPolicy::production());
    // Payload only: no manifest.json in the archive.
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("payload/reporting-service", options)
        .expect("zip writer must accept payload");
    writer
        .write_all(b"not a real executable")
        .expect("zip writer must accept payload bytes");
    writer.finish().expect("zip must finalize");
    let bytes = cursor.into_inner();
    let (envelope, _) = sign_package(&signing, &bytes);
    let package = TempPackage::write(&bytes, "no-manifest");
    assert!(matches!(
        validate_path(&validator, package.path(), &envelope),
        Err(ValidationError::Inventory(_))
    ));
}

#[test]
fn inventory_mismatches_fail_in_both_directions() {
    let (validator, signing) = real_key_validator(PackageValidationPolicy::production());
    // Manifest declares a file the archive does not contain.
    let bytes = package_bytes(
        &manifest_doc(&["payload/reporting-service", "payload/ghost"]),
        &[("payload/reporting-service", b"not a real executable")],
    );
    let (envelope, _) = sign_package(&signing, &bytes);
    let package = TempPackage::write(&bytes, "missing-file");
    assert!(matches!(
        validate_path(&validator, package.path(), &envelope),
        Err(ValidationError::Inventory(_))
    ));
    // Archive contains a file the manifest does not declare.
    let bytes = package_bytes(
        &manifest_doc(&["payload/reporting-service"]),
        &[
            ("payload/reporting-service", b"not a real executable"),
            ("payload/stowaway", b"smuggled"),
        ],
    );
    let (envelope, _) = sign_package(&signing, &bytes);
    let package = TempPackage::write(&bytes, "extra-file");
    assert!(matches!(
        validate_path(&validator, package.path(), &envelope),
        Err(ValidationError::Inventory(_))
    ));
}

#[test]
fn oversized_manifest_maps_to_manifest_bound() {
    let mut policy = PackageValidationPolicy::production();
    policy.max_manifest_bytes = 10;
    let (validator, signing) = real_key_validator(policy);
    let bytes = golden_package_bytes();
    let (envelope, _) = sign_package(&signing, &bytes);
    let package = TempPackage::write(&bytes, "big-manifest");
    assert!(matches!(
        validate_path(&validator, package.path(), &envelope),
        Err(ValidationError::Manifest(_))
    ));
}

#[test]
fn disallowed_manifest_version_is_rejected() {
    let mut policy = PackageValidationPolicy::production();
    policy.allowed_manifest_versions = vec![2];
    let (validator, signing) = real_key_validator(policy);
    let bytes = golden_package_bytes();
    let (envelope, _) = sign_package(&signing, &bytes);
    let package = TempPackage::write(&bytes, "bad-version");
    assert!(matches!(
        validate_path(&validator, package.path(), &envelope),
        Err(ValidationError::Manifest(_))
    ));
}

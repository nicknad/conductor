//! Upload workflow: the public entry point opens quarantine and sequences
//! validation. These tests exercise `run_upload_workflow`, not just the
//! validator it wraps.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use conductor::control_plane::upload_package::run_upload_workflow;
use conductor::control_plane::validate_package::{PackageValidationBuilder, ValidationError};
use conductor::packages::archive::ArchiveError;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm, TrustedSigningKey,
    SUPPORTED_SIGNATURE_FORMAT_VERSION,
};

fn test_validator() -> conductor::control_plane::validate_package::PackageValidator {
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        vec![0u8; 32],
    )])
    .expect("distinct test keys must build");
    PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("test validator must build")
}

fn missing_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "conductor-upload-workflow-{}-{nanos}-{tag}.zip",
        std::process::id()
    ))
}

#[test]
fn missing_archive_is_rejected_before_validation() {
    let envelope = PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "k1".to_owned(),
        signature: vec![0u8; 64],
    };
    let err = run_upload_workflow(&test_validator(), &missing_path("missing"), &envelope)
        .expect_err("a missing quarantine path must fail");
    assert!(matches!(err, ValidationError::Archive(ArchiveError::Io(_))));
}

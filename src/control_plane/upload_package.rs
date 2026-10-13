//! Coordinates ingestion: quarantine, inspect, authenticate, validate
//! contents, validate policy, promote.
//!
//! The workflow owns the quarantine handle: the HTTP layer streams the
//! request body into quarantine first (enforcing its byte bound while
//! writing), then calls [`run_upload_workflow`] on a blocking thread with
//! the quarantine path. This function opens one [`QuarantinedFile`] and
//! threads it through [`PackageValidator::validate`], so hashing,
//! inspection, and manifest reads share the same handle — never a reopened
//! attacker-controlled path. Staged extraction with per-file byte agreement
//! and artifact-store promotion land here once `storage::staging` is real;
//! until then the verdict binds the exact validated bytes via the outer
//! digest plus inventory set-equality.

use std::path::Path;

use crate::control_plane::validate_package::{PackageValidator, ValidatedPackage, ValidationError};
use crate::packages::archive::QuarantinedFile;
use crate::packages::signature::PackageSignature;

/// Runs the ingestion workflow end to end and returns the validation
/// verdict: artifact identity, validated manifest, and authorizing signer.
///
/// `archive_path` must be a private quarantine file the server wrote, not a
/// client-supplied path. Opens one quarantine handle and sequences
/// quarantine → validation → audit. Stages and their order are fixed by
/// [`PackageValidator`].
pub fn run_upload_workflow(
    validator: &PackageValidator,
    archive_path: &Path,
    signature: &PackageSignature,
) -> Result<ValidatedPackage, ValidationError> {
    let mut quarantined = QuarantinedFile::open(archive_path).map_err(ValidationError::Archive)?;
    let verdict = validator.validate(&mut quarantined, signature)?;
    tracing::info!(
        module_id = verdict.artifact().module_id(),
        version = verdict.artifact().version(),
        digest = verdict.artifact().digest().to_hex(),
        signer_key_id = verdict.signer().key_id.as_str(),
        "package validated"
    );
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::validate_package::PackageValidationBuilder;
    use crate::packages::policy::PackageValidationPolicy;
    use crate::packages::signature::{
        canonical_payload, ConfiguredTrustedKeys, SignatureAlgorithm, TrustedSigningKey,
        SUPPORTED_SIGNATURE_FORMAT_VERSION,
    };
    use std::io::Write as _;

    #[test]
    fn workflow_mints_artifact_and_attributes_signer() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        )])
        .expect("distinct test keys must build");
        let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
            .trusted_keys(keys)
            .build()
            .expect("test validator must build");

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
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("manifest.json", options)
            .expect("zip must accept manifest");
        writer
            .write_all(&serde_json::to_vec(&manifest).expect("manifest serializes"))
            .expect("zip must accept bytes");
        writer
            .start_file("payload/reporting-service", options)
            .expect("zip must accept payload");
        writer
            .write_all(b"not a real executable")
            .expect("zip must accept bytes");
        writer.finish().expect("zip must finalize");
        let bytes = cursor.into_inner();

        let digest: [u8; 32] = crate::packages::digest::Sha256DigestProvider
            .digest(&bytes)
            .expect("hashing must succeed");
        let signature = signing.sign(&canonical_payload(&digest));
        let envelope = PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
            key_id: "k1".to_owned(),
            signature: signature.to_bytes().to_vec(),
        };

        let dir = std::env::temp_dir().join(format!("conductor-workflow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir must be created");
        let path = dir.join("pkg.zip");
        std::fs::write(&path, &bytes).expect("package must be writable");

        let outcome =
            run_upload_workflow(&validator, &path, &envelope).expect("valid package must validate");
        assert_eq!(outcome.artifact().module_id(), "reporting-service");
        assert_eq!(outcome.signer().key_id, "k1");
        assert_eq!(outcome.manifest().entrypoint, "payload/reporting-service");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

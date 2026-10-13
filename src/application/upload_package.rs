//! Coordinates ingestion: quarantine, inspect, authenticate, validate
//! contents, validate policy, promote.
//!
//! The workflow is synchronous file I/O over a quarantined path: the HTTP
//! layer streams the request body into quarantine first (enforcing its byte
//! bound while writing), then calls [`run_upload_workflow`] on a blocking
//! thread. Validation runs on the same quarantined file it hashed — never a
//! reopened attacker-controlled path.

use std::path::Path;

use crate::application::validate_package::{PackageValidator, ValidationError};
use crate::packages::artifact::ValidatedArtifact;
use crate::packages::signature::{PackageSignature, TrustedSigningKey};

/// A validated upload: the promoted artifact identity plus the authorizing
/// signer for audit attribution.
#[derive(Debug)]
pub struct UploadOutcome {
    pub artifact: ValidatedArtifact,
    pub signer: TrustedSigningKey,
}

/// Runs the ingestion workflow end to end and returns the promoted artifact.
///
/// `archive_path` must be a private quarantine file the server wrote, not a
/// client-supplied path. Stages and their order are fixed by
/// [`PackageValidator`]; this function only sequences quarantine →
/// validation and emits the audit record.
pub fn run_upload_workflow(
    validator: &PackageValidator,
    archive_path: &Path,
    signature: &PackageSignature,
) -> Result<UploadOutcome, ValidationError> {
    let (artifact, signer) = validator.validate_with_signer(archive_path, signature)?;
    tracing::info!(
        module_id = artifact.module_id(),
        version = artifact.version(),
        digest = artifact.digest().to_hex(),
        signer_key_id = signer.key_id,
        "package validated"
    );
    Ok(UploadOutcome { artifact, signer })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::validate_package::PackageValidationBuilder;
    use crate::packages::policy::PackageValidationPolicy;
    use crate::packages::signature::{
        canonical_payload, ConfiguredTrustedKeys, SignatureAlgorithm,
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
            .expect("hashing must succeed")
            .try_into()
            .expect("SHA-256 is 32 bytes");
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
        assert_eq!(outcome.artifact.module_id(), "reporting-service");
        assert_eq!(outcome.signer.key_id, "k1");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

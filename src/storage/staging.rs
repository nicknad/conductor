//! Private staging directories: extraction with cleanup. Never makes
//! partially validated packages executable.
//!
//! [`extract_verified`] is the only extraction entry point. It re-hashes
//! the source over one open handle and compares against the validation
//! verdict — promotion and execution never trust a path across time — then
//! extracts into a private directory (owner-only permissions) while
//! hashing every decompressed stream exactly once. Manifest v2 per-file
//! integrity is enforced against the actual bytes; v1 packages retain
//! path-only agreement (set-equality was already proven at validation).
//!
//! The returned [`StagedPackage`] removes its directory on drop; call
//! [`StagedPackage::keep`] to hand the directory to an executor, which
//! should still re-verify the recorded digests at spawn time.

use std::io::Seek as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use thiserror::Error;

use crate::control_plane::validate_package::ValidatedPackage;
use crate::packages::archive::{
    ArchiveError, DeclaredIntegrity, ExtractedFile, ExtractedFiles, ExtractionTarget,
    QuarantinedFile, ZipArchiveReader,
};
use crate::packages::digest::{DigestError, Sha256DigestProvider};
use crate::packages::manifest::MANIFEST_FILE_NAME;
use crate::packages::policy::PackageValidationPolicy;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Extraction failures. `SourceChanged` is the outer-digest binding: the
/// bytes on disk are no longer the bytes that were validated.
#[derive(Debug, Error)]
pub enum StagingError {
    #[error("staged source changed since validation")]
    SourceChanged,
    #[error("source hashing failed: {0}")]
    Digest(#[from] DigestError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("staging I/O failed: {0}")]
    Io(String),
}

impl From<std::io::Error> for StagingError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// A private staging directory holding exactly the declared files. Removes
/// the directory on drop unless disarmed with [`keep`](Self::keep).
#[derive(Debug)]
pub struct StagedPackage {
    root: Option<PathBuf>,
    files: Vec<ExtractedFile>,
}

impl StagedPackage {
    /// Staging root; every file lives under it.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.as_deref().expect("root is present until kept")
    }

    /// Extracted files with actual size and SHA-256, in archive order.
    #[must_use]
    pub fn files(&self) -> &[ExtractedFile] {
        &self.files
    }

    /// Disarms cleanup and returns the directory for the executor to own.
    #[must_use]
    pub fn keep(mut self) -> PathBuf {
        self.root.take().expect("root is present until kept")
    }
}

impl Drop for StagedPackage {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// Verifies the source against the validation verdict and extracts the
/// declared files into a fresh private directory under `staging_root`.
///
/// `source` is the promoted artifact (or the quarantine file, pre-promotion);
/// either way it must hash to the verdict digest or extraction refuses to
/// run. On failure the partial directory is removed before returning.
pub fn extract_verified(
    staging_root: &Path,
    source: &Path,
    validated: &ValidatedPackage,
    policy: &PackageValidationPolicy,
) -> Result<StagedPackage, StagingError> {
    let mut file = QuarantinedFile::open(source)?;
    let expected = *validated.artifact().digest().as_bytes();
    let actual = Sha256DigestProvider.digest_stream(&mut file)?;
    if actual != expected {
        return Err(StagingError::SourceChanged);
    }
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|e| StagingError::Io(e.to_string()))?;

    // Declared payload files enforce v2 integrity where present; the
    // manifest itself is extracted alongside (the outer digest binds its
    // bytes, but executors may want it on disk).
    let mut targets: Vec<ExtractionTarget> = validated
        .manifest()
        .files
        .iter()
        .map(|file| ExtractionTarget {
            path: file.path.clone(),
            integrity: file.integrity.map(|integrity| DeclaredIntegrity {
                size: integrity.size,
                sha256: integrity.sha256,
            }),
        })
        .collect();
    targets.push(ExtractionTarget {
        path: MANIFEST_FILE_NAME.to_owned(),
        integrity: None,
    });

    let root = unique_staging_dir(staging_root);
    std::fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    }

    match ZipArchiveReader.extract_to(&mut file, &root, &targets, &policy.scan_config()) {
        Ok(ExtractedFiles { files }) => Ok(StagedPackage {
            root: Some(root),
            files,
        }),
        Err(err) => {
            let _ = std::fs::remove_dir_all(&root);
            Err(StagingError::Archive(err))
        }
    }
}

fn unique_staging_dir(root: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    root.join(format!("stage-{}-{nanos}-{count}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::validate_package::{PackageValidationBuilder, PackageValidator};
    use crate::packages::policy::PackageValidationPolicy;
    use crate::packages::signature::{
        canonical_payload, ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm,
        TrustedSigningKey, SUPPORTED_SIGNATURE_FORMAT_VERSION,
    };
    use std::io::Write as _;

    const PAYLOAD: &[u8] = b"not a real executable";

    fn validator() -> (PackageValidator, ed25519_dalek::SigningKey) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        )])
        .expect("test keys must build");
        let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
            .trusted_keys(keys)
            .build()
            .expect("validator must build");
        (validator, signing)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256DigestProvider
            .digest(bytes)
            .expect("hash")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Builds a v2 package with caller-controlled integrity declarations:
    /// `declared` is what the manifest claims; the archive always carries
    /// the real payload bytes.
    fn package_v2(declared_size: u64, declared_sha256: &str) -> Vec<u8> {
        let manifest = serde_json::json!({
            "manifest_version": 2,
            "module_id": "reporting-service",
            "version": "1.2.0",
            "runtime": "rust",
            "entrypoint": "payload/bin",
            "files": [{
                "path": "payload/bin",
                "size": declared_size,
                "sha256": declared_sha256,
            }],
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("manifest.json", options)
            .expect("manifest");
        writer
            .write_all(&serde_json::to_vec(&manifest).expect("serialize"))
            .expect("bytes");
        writer.start_file("payload/bin", options).expect("payload");
        writer.write_all(PAYLOAD).expect("bytes");
        writer.finish().expect("finalize");
        cursor.into_inner()
    }

    fn package_v1() -> Vec<u8> {
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "module_id": "reporting-service",
            "version": "1.2.0",
            "runtime": "rust",
            "entrypoint": "payload/bin",
            "files": ["payload/bin"],
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("manifest.json", options)
            .expect("manifest");
        writer
            .write_all(&serde_json::to_vec(&manifest).expect("serialize"))
            .expect("bytes");
        writer.start_file("payload/bin", options).expect("payload");
        writer.write_all(PAYLOAD).expect("bytes");
        writer.finish().expect("finalize");
        cursor.into_inner()
    }

    struct Fixture {
        dir: PathBuf,
        source: PathBuf,
        validated: ValidatedPackage,
    }

    fn fixture(bytes: &[u8], tag: &str) -> Fixture {
        use ed25519_dalek::Signer as _;

        let (validator, signing) = validator();
        let digest: [u8; 32] = Sha256DigestProvider.digest(bytes).expect("hash");
        let envelope = PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
            key_id: "k1".to_owned(),
            signature: signing
                .sign(&canonical_payload(&digest))
                .to_bytes()
                .to_vec(),
        };
        let dir = std::env::temp_dir().join(format!(
            "conductor-staging-{}-{tag}-{}",
            std::process::id(),
            bytes.len()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let source = dir.join("pkg.zip");
        std::fs::write(&source, bytes).expect("write");
        let mut handle = QuarantinedFile::open(&source).expect("open");
        let validated = validator.validate(&mut handle, &envelope).expect("valid");
        Fixture {
            dir,
            source,
            validated,
        }
    }

    #[test]
    fn v2_package_extracts_with_enforced_integrity() {
        let bytes = package_v2(PAYLOAD.len() as u64, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "v2-ok");
        let staging_root = fixture.dir.join("staging");
        let staged = extract_verified(
            &staging_root,
            &fixture.source,
            &fixture.validated,
            &PackageValidationPolicy::production(),
        )
        .expect("extraction must succeed");
        assert_eq!(
            std::fs::read(staged.root().join("payload/bin")).expect("payload must exist"),
            PAYLOAD
        );
        // manifest.json is staged alongside the declared payload.
        assert!(staged.root().join(MANIFEST_FILE_NAME).is_file());
        let payload = staged
            .files()
            .iter()
            .find(|f| f.path == "payload/bin")
            .expect("payload recorded");
        assert_eq!(payload.size, PAYLOAD.len() as u64);
        let expected: [u8; 32] = Sha256DigestProvider.digest(PAYLOAD).expect("hash");
        assert_eq!(payload.sha256, expected);
        // Dropping removes the directory.
        let root = staged.root().to_owned();
        drop(staged);
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn keep_disarms_cleanup() {
        let bytes = package_v2(PAYLOAD.len() as u64, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "keep");
        let staging_root = fixture.dir.join("staging");
        let staged = extract_verified(
            &staging_root,
            &fixture.source,
            &fixture.validated,
            &PackageValidationPolicy::production(),
        )
        .expect("extraction must succeed");
        let root = staged.keep();
        assert!(root.join("payload/bin").is_file());
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn lying_digest_declaration_fails_extraction() {
        // Signature is valid and inventory matches; only the manifest's
        // per-file digest is wrong. Extraction is where that is caught.
        let bytes = package_v2(PAYLOAD.len() as u64, &"aa".repeat(32));
        let fixture = fixture(&bytes, "lie-digest");
        let staging_root = fixture.dir.join("staging");
        let err = extract_verified(
            &staging_root,
            &fixture.source,
            &fixture.validated,
            &PackageValidationPolicy::production(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StagingError::Archive(ArchiveError::DigestMismatch { .. })
        ));
        // The partial directory was removed.
        assert!(!staging_root.join("stage").exists());
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn lying_size_declaration_fails_extraction() {
        let bytes = package_v2(PAYLOAD.len() as u64 + 1, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "lie-size");
        let staging_root = fixture.dir.join("staging");
        let err = extract_verified(
            &staging_root,
            &fixture.source,
            &fixture.validated,
            &PackageValidationPolicy::production(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StagingError::Archive(ArchiveError::SizeMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn swapped_source_after_validation_is_refused() {
        let bytes = package_v2(PAYLOAD.len() as u64, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "swap");
        std::fs::write(&fixture.source, b"entirely different bytes").expect("swap");
        let staging_root = fixture.dir.join("staging");
        let err = extract_verified(
            &staging_root,
            &fixture.source,
            &fixture.validated,
            &PackageValidationPolicy::production(),
        )
        .unwrap_err();
        assert!(matches!(err, StagingError::SourceChanged));
        assert!(!staging_root.join("stage").exists());
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn v1_package_extracts_with_path_agreement_only() {
        let bytes = package_v1();
        let fixture = fixture(&bytes, "v1");
        let staging_root = fixture.dir.join("staging");
        let staged = extract_verified(
            &staging_root,
            &fixture.source,
            &fixture.validated,
            &PackageValidationPolicy::production(),
        )
        .expect("v1 extraction must succeed");
        assert_eq!(
            std::fs::read(staged.root().join("payload/bin")).expect("payload"),
            PAYLOAD
        );
        // Actual digests are still recorded for the executor to verify.
        let payload = staged
            .files()
            .iter()
            .find(|f| f.path == "payload/bin")
            .expect("payload recorded");
        let expected: [u8; 32] = Sha256DigestProvider.digest(PAYLOAD).expect("hash");
        assert_eq!(payload.sha256, expected);
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }
}

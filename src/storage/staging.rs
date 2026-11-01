//! Private staging directories: extraction with cleanup. Never makes
//! partially validated packages executable.
//!
//! Two entry points share one extraction path:
//!
//! - [`extract_verified`] consumes a validation verdict (upload-time flow).
//! - [`extract_registered`] consumes a stored manifest plus its expected
//!   digest (execution-after-restart flow), so no archive is re-validated
//!   from registry state alone.
//!
//! Both re-hash the source over one open handle and compare against the
//! expected digest — promotion and execution never trust a path across
//! time — then extract into a private directory (owner-only permissions)
//! while hashing every decompressed stream exactly once. The stored
//! manifest supplies the declared files, their v2 per-file integrity, and
//! the entrypoint used by the executor; v1 packages retain path-only
//! agreement (set-equality was already proven at validation).
//!
//! The returned [`StagedPackage`] removes its directory on drop; call
//! [`StagedPackage::keep`] to hand the directory to an executor, which
//! should still re-verify the recorded digests at spawn time.

use std::io::Seek as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use thiserror::Error;

use crate::control_plane::validate_package::ValidatedPackage;
use crate::packages::archive::{
    ArchiveError, DeclaredIntegrity, ExtractedFile, ExtractedFiles, ExtractionTarget,
    QuarantinedFile, ZipArchiveReader,
};
use crate::packages::artifact::ArtifactDigest;
use crate::packages::digest::{DigestError, Sha256DigestProvider};
use crate::packages::manifest::{Manifest, MANIFEST_FILE_NAME};
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

/// Removes stale staging directories left by a crash or a kept hand-off that
/// was never cleaned up. Only directories directly under `dir` are
/// considered; symlinks, files, and the root itself are left alone. Returns
/// the number of directories removed; a missing root is not an error.
pub fn sweep_older_than(dir: &Path, max_age: Duration) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map(|modified| {
                modified
                    .elapsed()
                    .map(|age| is_older_than(age, max_age))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if stale && std::fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Strict age comparison: an entry exactly at the TTL is not stale yet.
fn is_older_than(age: Duration, max_age: Duration) -> bool {
    age > max_age
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
    extract_extraction(
        staging_root,
        source,
        validated.artifact().digest(),
        validated.manifest(),
        policy,
    )
}

/// Verifies the source against a registered artifact digest and extracts
/// the files declared by the stored manifest.
///
/// This is the execution-after-restart counterpart of
/// [`extract_verified`]: the caller has already resolved the registered
/// record, parsed its stored manifest with the package policy, and checked
/// the manifest identity against that record. This function still binds the
/// bytes: the source is re-hashed over the same handle that is extracted,
/// every declared path must be present, no undeclared path may appear, and
/// v2 per-file size/SHA-256 declarations are enforced against the actual
/// decompressed streams. On failure the partial directory is removed before
/// returning.
pub fn extract_registered(
    staging_root: &Path,
    source: &Path,
    expected_digest: &ArtifactDigest,
    manifest: &Manifest,
    policy: &PackageValidationPolicy,
) -> Result<StagedPackage, StagingError> {
    extract_extraction(staging_root, source, expected_digest, manifest, policy)
}

/// Shared extraction path: one open handle, one outer-digest check, then a
/// directed extraction driven by the manifest's declared files.
fn extract_extraction(
    staging_root: &Path,
    source: &Path,
    expected_digest: &ArtifactDigest,
    manifest: &Manifest,
    policy: &PackageValidationPolicy,
) -> Result<StagedPackage, StagingError> {
    let mut file = QuarantinedFile::open(source)?;
    let expected = *expected_digest.as_bytes();
    let actual = Sha256DigestProvider.digest_stream(&mut file)?;
    if actual != expected {
        return Err(StagingError::SourceChanged);
    }
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|e| StagingError::Io(e.to_string()))?;

    // Declared payload files enforce v2 integrity where present; the
    // manifest itself is extracted alongside (the outer digest binds its
    // bytes, but executors may want it on disk).
    let mut targets: Vec<ExtractionTarget> = manifest
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

    let root = create_staging_root(staging_root)?;

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

/// Number of distinct predicted names tried before giving up. Names are
/// process-unique (pid + monotonic counter + nanos), so collisions only
/// happen when something deliberately pre-created the path.
const MAX_STAGING_ATTEMPTS: usize = 16;

/// Creates the staging root if it does not exist, then atomically creates a
/// fresh private child directory.
///
/// `create_dir` (not `create_dir_all`) is the security boundary: it fails
/// with `AlreadyExists` instead of following a pre-created file or symlink
/// at the predicted path. A collision is retried with a new name; any other
/// failure is surfaced. On Unix the directory is created owner-only and
/// re-chmodded after creation so the umask cannot widen it.
fn create_staging_root(staging_root: &Path) -> Result<PathBuf, StagingError> {
    create_staging_root_with(staging_root, || unique_staging_dir(staging_root))
}

/// Collision-retry body, parameterized on the candidate generator so the
/// retry path is directly testable without guessing process-unique names.
fn create_staging_root_with(
    staging_root: &Path,
    mut next_name: impl FnMut() -> PathBuf,
) -> Result<PathBuf, StagingError> {
    std::fs::create_dir_all(staging_root)?;
    for _ in 0..MAX_STAGING_ATTEMPTS {
        let candidate = next_name();
        match create_private_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(StagingError::Io(err.to_string())),
        }
    }
    Err(StagingError::Io(
        "could not create a unique staging directory".to_owned(),
    ))
}

/// Atomic owner-only directory creation for one predicted stage path.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
            // Do not leave a partially configured directory behind.
            let _ = std::fs::remove_dir(path);
            return Err(err);
        }
    }
    Ok(())
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
    fn registered_extraction_uses_the_stored_manifest_and_expected_digest() {
        let bytes = package_v2(PAYLOAD.len() as u64, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "registered-ok");
        let manifest = fixture.validated.manifest().clone();
        let digest = *fixture.validated.artifact().digest();
        let staging_root = fixture.dir.join("staging");
        let staged = extract_registered(
            &staging_root,
            &fixture.source,
            &digest,
            &manifest,
            &PackageValidationPolicy::production(),
        )
        .expect("registered extraction must succeed");
        assert_eq!(
            std::fs::read(staged.root().join(&manifest.entrypoint)).expect("entrypoint"),
            PAYLOAD
        );
        assert!(
            staged.root().join(MANIFEST_FILE_NAME).is_file(),
            "the outer manifest must be staged for the executor"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn registered_extraction_refuses_a_source_that_no_longer_matches_the_digest() {
        let bytes = package_v2(PAYLOAD.len() as u64, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "registered-digest");
        let manifest = fixture.validated.manifest().clone();
        let wrong = ArtifactDigest::new([0u8; 32]);
        let staging_root = fixture.dir.join("staging");
        let err = extract_registered(
            &staging_root,
            &fixture.source,
            &wrong,
            &manifest,
            &PackageValidationPolicy::production(),
        )
        .unwrap_err();
        assert!(matches!(err, StagingError::SourceChanged));
        assert!(
            !staging_root.exists(),
            "a digest mismatch must not leave a staging directory"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn registered_extraction_rejects_files_outside_the_stored_manifest() {
        let bytes = package_v2(PAYLOAD.len() as u64, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "registered-files");
        let policy = PackageValidationPolicy::production();
        let stored = serde_json::json!({
            "manifest_version": 2,
            "module_id": "reporting-service",
            "version": "1.2.0",
            "runtime": "rust",
            "entrypoint": "payload/other",
            "files": [{
                "path": "payload/other",
                "size": PAYLOAD.len() as u64,
                "sha256": sha256_hex(PAYLOAD),
            }],
        });
        let manifest = Manifest::parse_with_policy(
            &serde_json::to_vec(&stored).expect("stored manifest must serialize"),
            &policy,
        )
        .expect("stored manifest must parse");
        let digest = *fixture.validated.artifact().digest();
        let staging_root = fixture.dir.join("staging");
        let err = extract_registered(&staging_root, &fixture.source, &digest, &manifest, &policy)
            .unwrap_err();
        assert!(matches!(
            err,
            StagingError::Archive(ArchiveError::UndeclaredEntry(path)) if path == "payload/bin"
        ));
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn registered_extraction_enforces_v2_file_integrity() {
        // The registered manifest claims a size the payload does not have;
        // extraction must catch the disagreement even though the outer
        // digest still matches the archive bytes.
        let bytes = package_v2(PAYLOAD.len() as u64 + 1, &sha256_hex(PAYLOAD));
        let fixture = fixture(&bytes, "registered-v2");
        let manifest = fixture.validated.manifest().clone();
        let digest = *fixture.validated.artifact().digest();
        let staging_root = fixture.dir.join("staging");
        let err = extract_registered(
            &staging_root,
            &fixture.source,
            &digest,
            &manifest,
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
        // The partial staging directory was removed; the root itself stays.
        assert!(staging_root.is_dir(), "the staging root must remain");
        assert_eq!(
            std::fs::read_dir(&staging_root)
                .expect("staging root must be readable")
                .count(),
            0,
            "a failed extraction must not leave a partial staging directory"
        );
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
        assert!(
            !staging_root.exists(),
            "a digest mismatch must refuse before creating a staging directory"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn failed_extraction_removes_the_partial_staging_directory() {
        // The archive is valid and its digest matches, but the v2 per-file
        // declaration does not. Extraction starts writing, then fails; the
        // already-created private directory must not survive.
        let bytes = package_v2(PAYLOAD.len() as u64, &"bb".repeat(32));
        let fixture = fixture(&bytes, "partial-cleanup");
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
        assert!(staging_root.is_dir(), "the staging root must remain");
        assert_eq!(
            std::fs::read_dir(&staging_root)
                .expect("staging root must be readable")
                .count(),
            0,
            "the failed stage directory must be removed completely"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_staging_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "conductor-staging-mode-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("parent must be creatable");
        let stage = dir.join("stage-mode");
        create_private_dir(&stage).expect("atomic private directory must be creatable");
        let mode = std::fs::metadata(&stage)
            .expect("staged dir must exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "staging directories must be owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_creation_retries_on_a_collision() {
        let dir = std::env::temp_dir().join(format!(
            "conductor-staging-collision-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("parent must be creatable");
        // A file (or symlink) already occupies the first predicted name.
        let collision = dir.join("stage-collision");
        std::fs::write(&collision, b"occupied").expect("collision file must be writable");
        let fresh = dir.join("stage-fresh");
        let mut names = vec![collision.clone(), fresh.clone()].into_iter();
        let created =
            create_staging_root_with(&dir, || names.next().expect("two names are queued"))
                .expect("a collision must be retried with a fresh name");

        assert_eq!(created, fresh);
        assert!(created.is_dir(), "the retry must create a real directory");
        assert!(
            collision.is_file(),
            "the pre-existing path must be left untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn staging_creation_never_follows_a_preexisting_symlink() {
        // A pre-created symlink at the predicted stage path must make atomic
        // creation fail with AlreadyExists, never redirect writes outside.
        let dir = std::env::temp_dir().join(format!(
            "conductor-staging-symlink-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).expect("outside dir must be creatable");
        let predicted = dir.join("stage-predicted");
        std::os::unix::fs::symlink(&outside, &predicted).expect("symlink must be creatable");

        let err = create_private_dir(&predicted).expect_err("an existing symlink must not be used");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            std::fs::symlink_metadata(&predicted)
                .expect("predicted path must still exist")
                .file_type()
                .is_symlink(),
            "the pre-existing symlink must be left untouched"
        );
        assert_eq!(
            std::fs::read_dir(&outside)
                .expect("outside dir must be readable")
                .count(),
            0,
            "creation must never write through the symlink"
        );
        let _ = std::fs::remove_dir_all(&dir);
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

    #[test]
    fn sweep_removes_only_directories_older_than_the_bound() {
        let root = std::env::temp_dir().join(format!(
            "conductor-staging-sweep-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let stale = root.join("stale");
        let fresh = root.join("fresh");
        std::fs::create_dir_all(stale.join("nested")).expect("stale dir");
        std::fs::create_dir_all(&fresh).expect("fresh dir");
        std::fs::write(stale.join("payload"), b"stale").expect("stale payload");

        let old = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        std::fs::File::open(&stale)
            .expect("stale dir must open")
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .expect("stale mtime must be set");
        let removed =
            sweep_older_than(&root, Duration::from_secs(60 * 60)).expect("sweep must succeed");

        assert_eq!(removed, 1);
        assert!(!stale.exists(), "stale staging dir must be removed");
        assert!(fresh.is_dir(), "fresh staging dir must survive");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sweep_treats_a_missing_root_as_empty() {
        let missing = std::env::temp_dir().join(format!(
            "conductor-staging-missing-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert_eq!(
            sweep_older_than(&missing, Duration::from_secs(1))
                .expect("missing root is not an error"),
            0
        );
    }

    #[test]
    fn sweep_reports_non_notfound_read_errors() {
        let path = std::env::temp_dir().join(format!(
            "conductor-staging-not-a-dir-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, b"not a directory").expect("fixture file");
        assert!(
            sweep_older_than(&path, Duration::from_secs(1)).is_err(),
            "a non-directory root must surface the read error"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn age_boundary_is_strictly_greater_than_the_ttl() {
        let ttl = Duration::from_secs(60);
        assert!(is_older_than(ttl + Duration::from_secs(1), ttl));
        assert!(!is_older_than(ttl, ttl), "exactly at the TTL is fresh");
        assert!(!is_older_than(ttl - Duration::from_secs(1), ttl));
    }
}

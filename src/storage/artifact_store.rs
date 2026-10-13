//! Promotes validated quarantine files to immutable artifact addresses.
//! Never overwrites an existing artifact version.
//!
//! Promotion is content-addressed and idempotent: the destination is
//! `artifacts/{module_id}/{version}/{digest_hex}.zip`, where `module_id`
//! and `version` come from a [`ValidatedPackage`](crate::application::validate_package::ValidatedPackage)
//! that only [`PackageValidator::validate`](crate::application::validate_package::PackageValidator::validate)
//! can mint, so path components are already path-safe. The quarantine file
//! is re-hashed before promotion and compared to the verdict digest —
//! validation and promotion never trust a path across time (TOCTOU).
//!
//! Destination files are created with `create_new`: an existing file with
//! the same digest is an identical re-upload (idempotent), and a file whose
//! bytes do not match its digest name can only be a crashed partial write,
//! so it is removed and rewritten. Distinct digests are distinct immutable
//! files; deciding *which* digest a module version means is the registry's
//! job, not the store's.

use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::application::validate_package::ValidatedPackage;
use crate::packages::digest::Sha256DigestProvider;

/// Promotion failures. Everything here is a server-side condition the
/// caller cannot retry into success blindly.
#[derive(Debug, Error)]
pub enum PromoteError {
    #[error("quarantine bytes changed after validation")]
    DigestMismatch,
    #[error("artifact promotion I/O failed: {0}")]
    Io(String),
}

/// Artifact address relative to the configured artifacts root:
/// `{module_id}/{version}/{digest_hex}.zip`. The layout lives here and
/// nowhere else; the registry stores this string so reconciliation does
/// not re-derive it.
#[must_use]
pub fn artifact_relative_path(validated: &ValidatedPackage) -> String {
    format!(
        "{}/{}/{}.zip",
        validated.artifact().module_id(),
        validated.artifact().version(),
        validated.artifact().digest().to_hex()
    )
}

/// Destination address for a validated package.
#[must_use]
pub fn artifact_path(artifacts: &Path, validated: &ValidatedPackage) -> PathBuf {
    artifacts.join(artifact_relative_path(validated))
}

/// Re-hashes the quarantine file, checks it still matches the validation
/// verdict, then copies it to its immutable address without overwriting
/// (a same-digest file is verified and treated as an identical re-upload).
///
/// On success the quarantine file is consumed. On failure the caller
/// discards it to bound disk use.
pub fn promote_quarantined(
    artifacts: &Path,
    quarantine: &Path,
    validated: &ValidatedPackage,
) -> Result<PathBuf, PromoteError> {
    let expected = *validated.artifact().digest().as_bytes();
    let mut src = std::fs::File::open(quarantine).map_err(|e| PromoteError::Io(e.to_string()))?;
    let actual = Sha256DigestProvider
        .digest_stream(&mut src)
        .map_err(|e| PromoteError::Io(e.to_string()))?;
    if actual != expected {
        return Err(PromoteError::DigestMismatch);
    }
    drop(src);

    let dest = artifact_path(artifacts, validated);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PromoteError::Io(e.to_string()))?;
    }

    // One retry: if a digest-named file exists with different bytes, it is
    // a partial write from a crash, never a legitimate artifact (a complete
    // artifact at this path always hashes to its name). Remove and rewrite.
    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
        {
            Ok(mut out) => {
                let mut input =
                    std::fs::File::open(quarantine).map_err(|e| PromoteError::Io(e.to_string()))?;
                if let Err(e) = std::io::copy(&mut input, &mut out) {
                    let _ = std::fs::remove_file(&dest);
                    return Err(PromoteError::Io(e.to_string()));
                }
                if let Err(e) = out.sync_all() {
                    let _ = std::fs::remove_file(&dest);
                    return Err(PromoteError::Io(e.to_string()));
                }
                drop(out);
                drop(input);
                crate::storage::quarantine::discard(quarantine);
                return Ok(dest);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let mut existing =
                    std::fs::File::open(&dest).map_err(|e| PromoteError::Io(e.to_string()))?;
                let existing_digest = Sha256DigestProvider
                    .digest_stream(&mut existing)
                    .map_err(|e| PromoteError::Io(e.to_string()))?;
                if existing_digest == expected {
                    // Identical re-upload: the artifact already exists.
                    crate::storage::quarantine::discard(quarantine);
                    return Ok(dest);
                }
                // Partial write from a crash: safe to replace (only a file
                // that hashes to its name is a legitimate artifact).
                std::fs::remove_file(&dest).map_err(|e| PromoteError::Io(e.to_string()))?;
            }
            Err(e) => return Err(PromoteError::Io(e.to_string())),
        }
    }
    Err(PromoteError::Io(
        "artifact path kept reappearing while promoting".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::validate_package::{PackageValidationBuilder, PackageValidator};
    use crate::packages::archive::QuarantinedFile;
    use crate::packages::policy::PackageValidationPolicy;
    use crate::packages::signature::{
        canonical_payload, ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm,
        TrustedSigningKey, SUPPORTED_SIGNATURE_FORMAT_VERSION,
    };
    use std::io::Write as _;

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

    fn package_bytes(module: &str, version: &str, payload: &[u8]) -> Vec<u8> {
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "module_id": module,
            "version": version,
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
            .expect("zip manifest");
        writer
            .write_all(&serde_json::to_vec(&manifest).expect("manifest serializes"))
            .expect("zip bytes");
        writer
            .start_file("payload/bin", options)
            .expect("zip payload");
        writer.write_all(payload).expect("zip bytes");
        writer.finish().expect("zip finalize");
        cursor.into_inner()
    }

    fn validated(bytes: &[u8], tag: &str) -> (ValidatedPackage, PathBuf, PathBuf) {
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
            "conductor-promote-{}-{tag}-{}",
            std::process::id(),
            bytes.len()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let q = dir.join("pkg.zip");
        std::fs::write(&q, bytes).expect("write");
        let mut handle = QuarantinedFile::open(&q).expect("quarantine open");
        let verdict = validator.validate(&mut handle, &envelope).expect("valid");
        (verdict, q, dir)
    }

    #[test]
    fn promotes_to_content_address_and_consumes_quarantine() {
        let bytes = package_bytes("reporting-service", "1.2.0", b"bin");
        let (verdict, qpath, dir) = validated(&bytes, "ok");
        let artifacts = dir.join("artifacts");
        let dest = promote_quarantined(&artifacts, &qpath, &verdict).expect("promote");
        assert!(dest.starts_with(&artifacts));
        assert!(dest.exists());
        assert!(!qpath.exists(), "quarantine must be consumed");
        assert_eq!(std::fs::read(&dest).expect("read"), bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_reupload_is_idempotent() {
        let bytes = package_bytes("reporting-service", "1.2.0", b"bin");
        let (verdict, qpath, dir) = validated(&bytes, "idem");
        let artifacts = dir.join("artifacts");
        let first = promote_quarantined(&artifacts, &qpath, &verdict).expect("first");
        let q2 = dir.join("pkg2.zip");
        std::fs::write(&q2, &bytes).expect("write");
        let second = promote_quarantined(&artifacts, &q2, &verdict).expect("second");
        assert_eq!(first, second);
        assert!(!q2.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn distinct_digests_coexist_and_never_overwrite() {
        let a = package_bytes("reporting-service", "1.2.0", b"bin-a");
        let b = package_bytes("reporting-service", "1.2.0", b"bin-b");
        assert_ne!(a, b);
        let (verdict_a, qpath_a, dir) = validated(&a, "coexist-a");
        let artifacts = dir.join("artifacts");
        let dest_a = promote_quarantined(&artifacts, &qpath_a, &verdict_a).expect("a");
        let (verdict_b, qpath_b, _) = validated(&b, "coexist-b");
        let qpath_b_shared = dir.join("pkg-b.zip");
        std::fs::write(&qpath_b_shared, &b).expect("write");
        let _ = std::fs::remove_file(&qpath_b);
        let dest_b =
            promote_quarantined(&artifacts, &qpath_b_shared, &verdict_b).expect("b promotes too");
        assert_ne!(dest_a, dest_b);
        assert_eq!(std::fs::read(&dest_a).expect("read a"), a);
        assert_eq!(std::fs::read(&dest_b).expect("read b"), b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_crash_remnant_at_digest_path_is_replaced() {
        let bytes = package_bytes("reporting-service", "1.2.0", b"bin");
        let (verdict, qpath, dir) = validated(&bytes, "partial");
        let artifacts = dir.join("artifacts");
        let dest = artifact_path(&artifacts, &verdict);
        std::fs::create_dir_all(dest.parent().expect("parent")).expect("dirs");
        std::fs::write(&dest, b"partial garbage").expect("remnant");
        let promoted = promote_quarantined(&artifacts, &qpath, &verdict).expect("promote");
        assert_eq!(promoted, dest);
        assert_eq!(std::fs::read(&dest).expect("read"), bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn swapped_quarantine_after_validation_is_rejected() {
        let bytes = package_bytes("reporting-service", "1.2.0", b"bin");
        let (verdict, qpath, dir) = validated(&bytes, "swap");
        std::fs::write(&qpath, b"different bytes").expect("swap");
        let artifacts = dir.join("artifacts");
        assert!(matches!(
            promote_quarantined(&artifacts, &qpath, &verdict).unwrap_err(),
            PromoteError::DigestMismatch
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_path_pins_the_storage_layout() {
        let bytes = package_bytes("reporting-service", "1.2.0", b"bin");
        let (verdict, _, dir) = validated(&bytes, "relpath");
        let expected = format!(
            "reporting-service/1.2.0/{}.zip",
            verdict.artifact().digest().to_hex()
        );
        assert_eq!(artifact_relative_path(&verdict), expected);
        #[cfg(unix)]
        assert_eq!(
            artifact_path(Path::new("/root/artifacts"), &verdict),
            Path::new(&format!("/root/artifacts/{expected}"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

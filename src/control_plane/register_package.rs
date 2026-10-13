//! Registers validated artifacts in the module registry.
//!
//! Registration is the bridge between a validation verdict and lasting
//! state: [`register`] consumes only the sealed
//! [`ValidatedPackage`] — artifact identity, validated manifest, and
//! authorizing signer — so no caller can register bytes that never passed
//! signature authentication. The archive is never re-opened: the verdict
//! already carries everything the registry records.
//!
//! Promotion (copying bytes into the artifact store) happens before
//! registration; the registry stores identity, not location. A registration
//! rejected for a version conflict leaves any promoted blob in the
//! content-addressed store unreferenced — harmless, immutable, and never
//! the source of truth.

use crate::control_plane::validate_package::ValidatedPackage;
use crate::modules::registry::{
    IntegrityState, ModuleRecord, ModuleRegistry, Registration, RegistryError,
};
use std::time::SystemTime;

/// Records a validated artifact as a registered module version.
///
/// Idempotent when the exact digest is re-registered for the same module
/// version; returns [`RegistryError::VersionConflict`] when a version would
/// change meaning. Only the sealed verdict can mint the record, so `digest`
/// and `signer_key_id` are trustworthy by construction.
///
/// `artifact_relpath` is the promoted artifact's address relative to the
/// configured artifacts root (see
/// [`artifact_relative_path`](crate::storage::artifact_store::artifact_relative_path)).
/// The registry stores it as reconciliation bookkeeping; it is never used
/// to load code. The artifact size comes from the verdict, which measured
/// the exact validated bytes.
pub fn register(
    registry: &ModuleRegistry,
    validated: &ValidatedPackage,
    artifact_relpath: &str,
) -> Result<Registration, RegistryError> {
    registry.record(ModuleRecord {
        module_id: validated.artifact().module_id().to_owned(),
        version: validated.artifact().version().to_owned(),
        digest: *validated.artifact().digest(),
        signer_key_id: validated.signer().key_id.clone(),
        runtime: validated.manifest().runtime.clone(),
        manifest_version: validated.manifest().manifest_version,
        manifest_json: validated.manifest_json().to_owned(),
        artifact_relpath: artifact_relpath.to_owned(),
        artifact_size: validated.artifact_size(),
        integrity_state: IntegrityState::Ok,
        registered_at: SystemTime::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::validate_package::{PackageValidationBuilder, PackageValidator};
    use crate::packages::archive::QuarantinedFile;
    use crate::packages::digest::Sha256DigestProvider;
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

    fn package_bytes(version: &str, payload: &[u8]) -> Vec<u8> {
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "module_id": "reporting-service",
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

    fn validated(bytes: &[u8], tag: &str) -> (ValidatedPackage, std::path::PathBuf) {
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
            "conductor-register-{}-{tag}-{}",
            std::process::id(),
            bytes.len()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("pkg.zip");
        std::fs::write(&path, bytes).expect("write");
        let mut handle = QuarantinedFile::open(&path).expect("open");
        let verdict = validator.validate(&mut handle, &envelope).expect("valid");
        (verdict, dir)
    }

    fn relpath(verdict: &ValidatedPackage) -> String {
        crate::storage::artifact_store::artifact_relative_path(verdict)
    }

    #[test]
    fn registers_verdict_identity_and_provenance() {
        let bytes = package_bytes("1.2.0", b"bin");
        let (verdict, dir) = validated(&bytes, "ok");
        let registry = ModuleRegistry::new();
        let relpath = relpath(&verdict);
        let outcome = register(&registry, &verdict, &relpath).expect("register");
        assert!(!outcome.already_registered);
        assert_eq!(outcome.record.module_id, "reporting-service");
        assert_eq!(outcome.record.version, "1.2.0");
        assert_eq!(outcome.record.digest, *verdict.artifact().digest());
        assert_eq!(outcome.record.signer_key_id, "k1");
        assert_eq!(outcome.record.runtime, "rust");
        assert_eq!(outcome.record.manifest_version, 1);
        assert_eq!(outcome.record.artifact_relpath, relpath);
        assert_eq!(outcome.record.artifact_size, bytes.len() as u64);
        // The exact validated manifest bytes are preserved, not a
        // reserialization.
        let stored: serde_json::Value =
            serde_json::from_str(&outcome.record.manifest_json).expect("stored manifest is JSON");
        assert_eq!(stored["module_id"], "reporting-service");
        assert_eq!(stored["manifest_version"].as_u64(), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_reupload_registers_idempotently() {
        let bytes = package_bytes("1.2.0", b"bin");
        let (verdict, dir) = validated(&bytes, "idem");
        let registry = ModuleRegistry::new();
        register(&registry, &verdict, &relpath(&verdict)).expect("first");
        let again = register(&registry, &verdict, &relpath(&verdict)).expect("second");
        assert!(again.already_registered);
        assert_eq!(registry.len().expect("len"), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_version_different_bytes_conflicts() {
        let a = package_bytes("1.2.0", b"bin-a");
        let b = package_bytes("1.2.0", b"bin-b");
        let (verdict_a, dir) = validated(&a, "conflict-a");
        let (verdict_b, _) = validated(&b, "conflict-b");
        let registry = ModuleRegistry::new();
        register(&registry, &verdict_a, &relpath(&verdict_a)).expect("first");
        let err = register(&registry, &verdict_b, &relpath(&verdict_b)).unwrap_err();
        assert!(matches!(err, RegistryError::VersionConflict { .. }));
        assert_eq!(
            registry
                .get("reporting-service", "1.2.0")
                .expect("lookup")
                .expect("kept")
                .digest,
            *verdict_a.artifact().digest()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

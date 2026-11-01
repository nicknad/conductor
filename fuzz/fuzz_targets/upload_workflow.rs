#![no_main]

use std::sync::atomic::{AtomicU64, Ordering};

use conductor::control_plane::upload_package::run_upload_workflow;
use conductor::control_plane::validate_package::PackageValidationBuilder;
use conductor::packages::artifact::ArtifactDigest;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    canonical_payload, ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm,
    TrustedSigningKey, SUPPORTED_SIGNATURE_FORMAT_VERSION,
};
use ed25519_dalek::{Signer as _, SigningKey};
use libfuzzer_sys::fuzz_target;

const SIGNING_KEY: [u8; 32] = [42u8; 32];

fn temp_path() -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "conductor-fuzz-upload-{}-{count}.zip",
        std::process::id()
    ))
}

fuzz_target!(|data: &[u8]| {
    let signing = SigningKey::from_bytes(&SIGNING_KEY);
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )])
    .expect("fixed test key must build");
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("fixed validator must build");

    let digest: [u8; 32] = Sha256DigestProvider
        .digest(data)
        .expect("in-memory hashing cannot fail");
    let signature = signing.sign(&canonical_payload(&digest));
    let envelope = PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "k1".to_owned(),
        signature: signature.to_bytes().to_vec(),
    };

    let path = temp_path();
    if std::fs::write(&path, data).is_err() {
        return;
    }
    if let Ok(validated) = run_upload_workflow(&validator, &path, &envelope) {
        // A verdict must describe exactly the bytes that were signed.
        assert_eq!(validated.artifact().digest(), &ArtifactDigest::new(digest));
        assert_eq!(validated.signer().key_id, "k1");
        assert!(!validated.manifest().module_id.is_empty());
        assert!(!validated.manifest().files.is_empty());
        assert!(validated
            .manifest()
            .files
            .iter()
            .any(|file| file.path == validated.manifest().entrypoint));
    }
    let _ = std::fs::remove_file(&path);
});

//! Pure property tests for the security boundaries the upload endpoint
//! relies on: bearer comparison, digest/hex canonicalization, signature
//! envelope shape, canonical payload framing, archive path confinement,
//! manifest bounds, and audit-detail bounding.
//!
//! These are deterministic (proptest with a fixed case budget), need no
//! I/O or network, and complement the example-based integration tests.

use conductor::api::uploads::ApiToken;
use conductor::audit::event::{RejectionEvent, RejectionStage, MAX_DETAIL_BYTES};
use conductor::packages::archive::{
    check_entry_path, check_no_duplicate_paths, MAX_ENTRY_PATH_LEN,
};
use conductor::packages::artifact::ArtifactDigest;
use conductor::packages::manifest::{Manifest, ManifestError};
use conductor::packages::signature::{
    canonical_payload, PackageSignature, SUPPORTED_SIGNATURE_FORMAT_VERSION,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn bearer_verification_is_exact_and_denies_an_empty_expected_token(
        expected in ".{0,64}",
        presented in ".{0,64}",
    ) {
        let token = ApiToken::new(expected.clone());
        prop_assert_eq!(
            token.verify(&presented),
            !expected.is_empty() && expected == presented
        );
    }

    #[test]
    fn token_debug_is_a_fixed_redaction(secret in ".{0,64}") {
        let token = ApiToken::new(secret);
        let debug = format!("{token:?}");
        // The whole value is replaced, so no secret (even a substring of
        // the literal "[redacted]") can leak.
        prop_assert_eq!(debug.as_str(), "[redacted]");
    }

    #[test]
    fn artifact_digest_hex_roundtrips(bytes in any::<[u8; 32]>()) {
        let digest = ArtifactDigest::new(bytes);
        let hex = digest.to_hex();
        prop_assert_eq!(hex.len(), 64);
        prop_assert!(hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        prop_assert_eq!(ArtifactDigest::from_hex(&hex), Some(digest));
    }

    #[test]
    fn artifact_digest_parsing_only_accepts_canonical_lowercase_hex(text in ".*") {
        if let Some(digest) = ArtifactDigest::from_hex(&text) {
            prop_assert_eq!(text.len(), 64);
            prop_assert!(text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            prop_assert_eq!(digest.to_hex(), text);
        }
    }

    #[test]
    fn canonical_payload_is_deterministic_and_domain_separated(
        left in any::<[u8; 32]>(),
        right in any::<[u8; 32]>(),
    ) {
        let payload = canonical_payload(&left);
        prop_assert!(payload.ends_with(&left));
        // Exactly three NUL field separators precede the raw digest.
        let header = &payload[..payload.len() - left.len()];
        prop_assert_eq!(header.iter().filter(|byte| **byte == 0).count(), 3);
        prop_assert_eq!(payload.clone(), canonical_payload(&left));
        if left != right {
            prop_assert_ne!(payload, canonical_payload(&right));
        }
    }

    #[test]
    fn accepted_entry_paths_are_confined_and_idempotent(name in ".{0,2000}") {
        if let Ok(path) = check_entry_path(&name, false) {
            prop_assert!(!path.starts_with('/'));
            prop_assert!(!path.contains('\\'));
            prop_assert!(!path.bytes().any(|byte| byte.is_ascii_control()));
            prop_assert!(!path.split('/').any(|part| part.is_empty() || part == "." || part == ".."));
            prop_assert!(path.len() <= MAX_ENTRY_PATH_LEN);
            prop_assert_eq!(check_entry_path(&path, false).ok(), Some(path.clone()));
        }
    }

    #[test]
    fn symlink_entries_are_always_rejected(name in ".{0,200}") {
        prop_assert!(check_entry_path(&name, true).is_err());
    }

    #[test]
    fn duplicate_path_detection_is_exact(paths in prop::collection::vec(".{0,32}", 0..12)) {
        let mut unique = std::collections::HashSet::new();
        let all_unique = paths.iter().all(|path| unique.insert(path.clone()));
        prop_assert_eq!(check_no_duplicate_paths(&paths).is_ok(), all_unique);
    }

    #[test]
    fn manifest_input_over_the_byte_bound_is_always_too_large(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
        max_bytes in 0usize..64,
    ) {
        let result = Manifest::parse_bounded(&bytes, max_bytes as u64, &[1, 2]);
        if bytes.len() > max_bytes {
            prop_assert!(matches!(result, Err(ManifestError::TooLarge)));
        }
    }

    #[test]
    fn manifest_version_must_be_allowlisted(
        version in prop_oneof![Just(1u32), Just(2u32), any::<u32>()],
        module_id in "[A-Za-z0-9]([A-Za-z0-9._+-]{0,18}[A-Za-z0-9])?",
        module_version in "[A-Za-z0-9]([A-Za-z0-9._+-]{0,18}[A-Za-z0-9])?",
    ) {
        let manifest = match version {
            1 => serde_json::json!({
                "manifest_version": 1,
                "module_id": module_id,
                "version": module_version,
                "runtime": "rust",
                "entrypoint": "payload/service",
                "files": ["payload/service"],
            }),
            2 => serde_json::json!({
                "manifest_version": 2,
                "module_id": module_id,
                "version": module_version,
                "runtime": "rust",
                "entrypoint": "payload/service",
                "files": [{
                    "path": "payload/service",
                    "size": 7,
                    "sha256": "00".repeat(32),
                }],
            }),
            other => serde_json::json!({
                "manifest_version": other,
                "module_id": module_id,
                "version": module_version,
                "runtime": "rust",
                "entrypoint": "payload/service",
                "files": ["payload/service"],
            }),
        };
        let bytes = serde_json::to_vec(&manifest).expect("manifest JSON must serialize");
        let allowed = &[1u32, 2u32][..];
        let result = Manifest::parse_bounded(&bytes, 1 << 20, allowed);
        if version == 1 || version == 2 {
            let parsed = result.expect("allowlisted shape must parse");
            prop_assert_eq!(parsed.manifest_version, version);
            prop_assert!(parsed.files.iter().any(|file| file.path == parsed.entrypoint));
            prop_assert_eq!(parsed.files[0].integrity.is_some(), version == 2);
        } else {
            prop_assert!(matches!(result, Err(ManifestError::UnsupportedVersion(seen)) if seen == version));
        }
    }

    #[test]
    fn envelope_acceptance_is_exactly_version_and_nonempty_fields(
        format_version in prop_oneof![Just(SUPPORTED_SIGNATURE_FORMAT_VERSION), any::<u16>()],
        key_id in ".{0,40}",
        signature in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let envelope = PackageSignature {
            format_version,
            key_id: key_id.clone(),
            signature: signature.clone(),
        };
        let expected = format_version == SUPPORTED_SIGNATURE_FORMAT_VERSION
            && !key_id.is_empty()
            && !signature.is_empty();
        prop_assert_eq!(envelope.check_envelope().is_ok(), expected);
    }

    #[test]
    fn rejection_detail_is_bounded_and_truncation_is_flagged(detail in ".{0,9000}") {
        let event = RejectionEvent::new(RejectionStage::Internal, "property", detail.clone());
        prop_assert!(event.detail.len() <= MAX_DETAIL_BYTES);
        prop_assert!(event.detail.is_char_boundary(event.detail.len()));
        prop_assert_eq!(event.detail_truncated, detail.len() > MAX_DETAIL_BYTES);
    }
}

/// Conventional anchor so the integration target always contains at least
/// one example-based test, plus a readable spec of the path forms rejected.
#[test]
fn path_policy_rejects_traversal_and_absolute_forms() {
    for bad in [
        "",
        "/absolute",
        "../escape",
        "a/../b",
        "a/./b",
        "a//b",
        "a\\b",
        ".",
        "..",
        "a\rb",
    ] {
        assert!(
            check_entry_path(bad, false).is_err(),
            "{bad:?} must be rejected"
        );
    }
    assert_eq!(
        check_entry_path("payload/service", false).expect("relative path must pass"),
        "payload/service"
    );
}

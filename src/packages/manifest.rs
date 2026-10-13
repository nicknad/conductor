//! Parses and validates the manifest schema. Never trusts hashes
//! without checking file bytes.
//!
//! Schema versions are runtime policy ([`PackageValidationPolicy`]
//! allowlist); parsing itself stays bounded by `max_manifest_bytes` before
//! any field is interpreted. The version gate runs before shape parsing,
//! so a v1 parser never sees a v2 document and vice versa.
//!
//! Schema v1 (`manifest.json` at the archive root) declares paths only:
//! ```json
//! {
//!   "manifest_version": 1,
//!   "module_id": "reporting-service",
//!   "version": "1.2.0",
//!   "runtime": "rust",
//!   "entrypoint": "payload/reporting-service",
//!   "files": ["payload/reporting-service"]
//! }
//! ```
//!
//! Schema v2 adds per-file integrity (byte size and lowercase-hex SHA-256):
//! ```json
//! {
//!   "manifest_version": 2,
//!   "module_id": "reporting-service",
//!   "version": "1.2.0",
//!   "runtime": "rust",
//!   "entrypoint": "payload/reporting-service",
//!   "files": [
//!     {
//!       "path": "payload/reporting-service",
//!       "size": 21,
//!       "sha256": "…64 hex…"
//!     }
//!   ]
//! }
//! ```
//!
//! `files` lists every payload file in the archive — everything except
//! `manifest.json` itself, which the validator requires separately. The
//! validator feeds these paths to inventory as [`DeclaredFile`]s, so path
//! confinement is enforced there; the manifest layer only checks shape,
//! version gating, integrity syntax, and cross-field consistency
//! (`entrypoint ∈ files`). Per-file byte agreement belongs to staged
//! extraction (`storage::staging`), where one stream feeds hashing and
//! writing and v2 declarations are enforced against actual bytes. v1
//! packages are set-equality only — operators who require byte agreement
//! pin `allowed_manifest_versions = [2]`.

use thiserror::Error;

use crate::packages::inventory::DeclaredFile;
use crate::packages::policy::PackageValidationPolicy;

/// Name of the manifest file at the archive root. Required in every
/// package; never listed in `files`.
pub const MANIFEST_FILE_NAME: &str = "manifest.json";

/// Parsed, validated manifest. All fields are opaque to this layer except
/// for the consistency checks in [`Manifest::parse_bounded`]; runtime
/// compatibility and lifecycle decisions belong to `application`/`modules`.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub manifest_version: u32,
    pub module_id: String,
    pub version: String,
    pub runtime: String,
    pub entrypoint: String,
    /// One entry per declared payload file, in declaration order.
    pub files: Vec<ManifestFile>,
}

/// One declared payload file. `integrity` is `Some` exactly for schema v2
/// packages (size and sha256 are required fields there) and `None` for
/// legacy v1 path-only declarations.
#[derive(Debug, Clone)]
pub struct ManifestFile {
    pub path: String,
    pub integrity: Option<FileIntegrity>,
}

/// Declared byte-level identity of one payload file. Staged extraction
/// enforces it against the actual decompressed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIntegrity {
    pub size: u64,
    pub sha256: [u8; 32],
}

/// Raw wire shape of schema v1. Unknown fields are rejected: a v1 parser
/// must not silently accept a shape it was never taught.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifestV1 {
    manifest_version: u32,
    module_id: String,
    version: String,
    runtime: String,
    entrypoint: String,
    files: Vec<String>,
}

/// Raw wire shape of schema v2.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifestV2 {
    manifest_version: u32,
    module_id: String,
    version: String,
    runtime: String,
    entrypoint: String,
    files: Vec<RawFileV2>,
}

/// One v2 file declaration. All three fields are required.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFileV2 {
    path: String,
    size: u64,
    sha256: String,
}

/// Fields common to every schema version, after shape-specific parsing.
struct ParsedFields {
    manifest_version: u32,
    module_id: String,
    version: String,
    runtime: String,
    entrypoint: String,
    files: Vec<ManifestFile>,
}

impl Manifest {
    /// Parses bounded input against the validation policy: byte bound and
    /// schema-version allowlist come from one policy snapshot so callers
    /// cannot mix mismatched bounds. Prefer this over [`Manifest::parse_bounded`]
    /// on the production path.
    pub fn parse_with_policy(
        bytes: &[u8],
        policy: &PackageValidationPolicy,
    ) -> Result<Self, ManifestError> {
        Self::parse_bounded(
            bytes,
            policy.max_manifest_bytes,
            &policy.allowed_manifest_versions,
        )
    }

    /// Parses bounded input, gates the schema version against the policy
    /// allowlist, then checks the shape of exactly that version. `module_id`
    /// and `version` are additionally constrained to path-safe identity
    /// components because downstream artifact-store paths are built from
    /// them. Path confinement of *declared files* is not checked here —
    /// declared paths are attacker-adjacent until the package signature
    /// verifies, and inventory runs them through the archive path policy.
    /// v2 `sha256` values must be well-formed lowercase hex, but they are
    /// only *checked* against bytes at staged extraction.
    pub fn parse_bounded(
        bytes: &[u8],
        max_bytes: u64,
        allowed_versions: &[u32],
    ) -> Result<Self, ManifestError> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err(ManifestError::TooLarge);
        }
        if bytes.is_empty() {
            return Err(ManifestError::Invalid("empty manifest".to_owned()));
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Invalid(e.to_string()))?;
        // Gate the version before shape parsing: an allowlisted version
        // selects exactly one wire shape.
        let version = value
            .get("manifest_version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ManifestError::Invalid("manifest_version must be an integer".to_owned())
            })?;
        let version = u32::try_from(version)
            .map_err(|_| ManifestError::Invalid("manifest_version out of range".to_owned()))?;
        if !allowed_versions.contains(&version) {
            return Err(ManifestError::UnsupportedVersion(version));
        }
        let parsed = match version {
            1 => {
                let raw: RawManifestV1 = serde_json::from_value(value)
                    .map_err(|e| ManifestError::Invalid(e.to_string()))?;
                ParsedFields {
                    manifest_version: raw.manifest_version,
                    module_id: raw.module_id,
                    version: raw.version,
                    runtime: raw.runtime,
                    entrypoint: raw.entrypoint,
                    files: raw
                        .files
                        .into_iter()
                        .map(|path| ManifestFile {
                            path,
                            integrity: None,
                        })
                        .collect(),
                }
            }
            2 => {
                let raw: RawManifestV2 = serde_json::from_value(value)
                    .map_err(|e| ManifestError::Invalid(e.to_string()))?;
                let mut files = Vec::with_capacity(raw.files.len());
                for file in raw.files {
                    files.push(ManifestFile {
                        path: file.path,
                        integrity: Some(FileIntegrity {
                            size: file.size,
                            sha256: parse_sha256_hex(&file.sha256)?,
                        }),
                    });
                }
                ParsedFields {
                    manifest_version: raw.manifest_version,
                    module_id: raw.module_id,
                    version: raw.version,
                    runtime: raw.runtime,
                    entrypoint: raw.entrypoint,
                    files,
                }
            }
            other => return Err(ManifestError::UnsupportedVersion(other)),
        };
        for (name, value) in [
            ("module_id", parsed.module_id.as_str()),
            ("version", parsed.version.as_str()),
            ("runtime", parsed.runtime.as_str()),
            ("entrypoint", parsed.entrypoint.as_str()),
        ] {
            if value.is_empty() {
                return Err(ManifestError::Invalid(format!("{name} must not be empty")));
            }
        }
        // module_id and version become path components in the artifact store
        // (`artifacts/{module_id}/{version}/…`) and registry keys, so their
        // shape is a security boundary, not cosmetics.
        for (name, value) in [
            ("module_id", parsed.module_id.as_str()),
            ("version", parsed.version.as_str()),
        ] {
            if !is_safe_identity(value) {
                return Err(ManifestError::Invalid(format!(
                    "{name} must be a path-safe identity component"
                )));
            }
        }
        if parsed.files.is_empty() {
            return Err(ManifestError::Invalid(
                "manifest must declare at least one file".to_owned(),
            ));
        }
        if !parsed
            .files
            .iter()
            .any(|file| file.path == parsed.entrypoint)
        {
            return Err(ManifestError::Invalid(
                "entrypoint must be one of the declared files".to_owned(),
            ));
        }
        Ok(Self {
            manifest_version: parsed.manifest_version,
            module_id: parsed.module_id,
            version: parsed.version,
            runtime: parsed.runtime,
            entrypoint: parsed.entrypoint,
            files: parsed.files,
        })
    }

    /// Declared payload files for the inventory stage.
    pub fn declared_files(&self) -> Vec<DeclaredFile> {
        self.files
            .iter()
            .map(|file| DeclaredFile::new(&file.path))
            .collect()
    }
}

/// Parses a schema-v2 `sha256` field: exactly 64 lowercase hex characters.
/// Uppercase, shorter, longer, or non-hex values fail closed at parse time
/// so extraction never compares against an ambiguous digest.
fn parse_sha256_hex(value: &str) -> Result<[u8; 32], ManifestError> {
    let invalid =
        || ManifestError::Invalid("sha256 must be 64 lowercase hex characters".to_owned());
    if value.len() != 64 {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    for (index, byte) in out.iter_mut().enumerate() {
        let hi = hex_digit(bytes[2 * index]).ok_or_else(invalid)?;
        let lo = hex_digit(bytes[2 * index + 1]).ok_or_else(invalid)?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Maximum accepted byte length of a path-forming identity field
/// (`module_id`, `version`).
const MAX_IDENTITY_BYTES: usize = 64;

/// Identity fields become path components in the artifact store
/// (`artifacts/{module_id}/{version}/…`) and registry keys. They must be
/// single portable path components: non-empty, bounded, no leading or
/// trailing dots, and only `[A-Za-z0-9._+-]` — so `reporting-service`,
/// `example.module_2`, and semver `1.2.3+build.7` all pass while
/// traversal, separators, control characters, and over-long values fail.
fn is_safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_BYTES
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest exceeds byte bound")]
    TooLarge,
    #[error("invalid manifest: {0}")]
    Invalid(String),
    #[error("unsupported manifest version: {0}")]
    UnsupportedVersion(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_json() -> Vec<u8> {
        br#"{
            "manifest_version": 1,
            "module_id": "reporting-service",
            "version": "1.2.0",
            "runtime": "rust",
            "entrypoint": "payload/reporting-service",
            "files": ["payload/reporting-service"]
        }"#
        .to_vec()
    }

    fn valid_json_v2() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "manifest_version": 2,
            "module_id": "reporting-service",
            "version": "1.2.0",
            "runtime": "rust",
            "entrypoint": "payload/reporting-service",
            "files": [{
                "path": "payload/reporting-service",
                "size": 21,
                "sha256": "aa".repeat(32),
            }],
        }))
        .expect("v2 manifest must serialize")
    }

    #[test]
    fn oversized_manifest_rejected_before_parsing() {
        let err = Manifest::parse_bounded(&[0u8; 8], 4, &[1]).unwrap_err();
        assert!(matches!(err, ManifestError::TooLarge));
    }

    #[test]
    fn exact_bound_parses_but_one_byte_over_does_not() {
        let json = valid_json();
        let len = u64::try_from(json.len()).expect("manifest fits in u64");
        Manifest::parse_bounded(&json, len, &[1]).expect("exact bound must parse");
        assert!(matches!(
            Manifest::parse_bounded(&json, len - 1, &[1]),
            Err(ManifestError::TooLarge)
        ));
    }

    #[test]
    fn empty_manifest_rejected() {
        let err = Manifest::parse_bounded(&[], 16, &[1]).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid(_)));
    }

    #[test]
    fn valid_v1_manifest_parses_without_integrity() {
        let manifest = Manifest::parse_bounded(&valid_json(), 1 << 20, &[1])
            .expect("valid manifest must parse");
        assert_eq!(manifest.manifest_version, 1);
        assert_eq!(manifest.module_id, "reporting-service");
        assert_eq!(manifest.version, "1.2.0");
        let declared = manifest.declared_files();
        assert_eq!(declared.len(), 1);
        assert_eq!(declared[0].path, "payload/reporting-service");
        assert!(manifest.files[0].integrity.is_none());
    }

    #[test]
    fn valid_v2_manifest_parses_with_integrity() {
        let manifest = Manifest::parse_bounded(&valid_json_v2(), 1 << 20, &[2])
            .expect("valid v2 manifest must parse");
        assert_eq!(manifest.manifest_version, 2);
        let integrity = manifest.files[0].integrity.expect("v2 declares integrity");
        assert_eq!(integrity.size, 21);
        assert_eq!(integrity.sha256, [0xAA; 32]);
    }

    #[test]
    fn version_gate_selects_shape_and_rejects_mismatches() {
        // A v2 document under a v1-only policy fails on version, not shape.
        assert!(matches!(
            Manifest::parse_bounded(&valid_json_v2(), 1 << 20, &[1]),
            Err(ManifestError::UnsupportedVersion(2))
        ));
        // A v1 document under a v2-only policy likewise.
        assert!(matches!(
            Manifest::parse_bounded(&valid_json(), 1 << 20, &[2]),
            Err(ManifestError::UnsupportedVersion(1))
        ));
        // Both allowed: each parses as its own shape.
        Manifest::parse_bounded(&valid_json(), 1 << 20, &[1, 2]).expect("v1 under [1,2]");
        Manifest::parse_bounded(&valid_json_v2(), 1 << 20, &[1, 2]).expect("v2 under [1,2]");
        // Version 2 with v1 string files is a shape error, not a fallback.
        let mixed = br#"{"manifest_version":2,"module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":["a"]}"#;
        assert!(matches!(
            Manifest::parse_bounded(mixed, 1 << 20, &[2]),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn malformed_json_missing_version_and_unknown_fields_rejected() {
        assert!(matches!(
            Manifest::parse_bounded(b"{not json", 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        // Wrong JSON types fail closed rather than coercing.
        let mistyped =
            br#"{"manifest_version":"1","module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":["a"]}"#;
        assert!(matches!(
            Manifest::parse_bounded(mistyped, 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        let missing =
            br#"{"module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":["a"]}"#;
        assert!(matches!(
            Manifest::parse_bounded(missing, 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        // Unknown fields fail closed rather than being silently ignored.
        let extra = br#"{"manifest_version":1,"module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":["a"],"signature":"00"}"#;
        assert!(matches!(
            Manifest::parse_bounded(extra, 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        let extra_v2 = serde_json::to_vec(&serde_json::json!({
            "manifest_version": 2,
            "module_id": "m",
            "version": "1",
            "runtime": "r",
            "entrypoint": "a",
            "files": [{"path": "a", "size": 1, "sha256": "aa".repeat(32), "mode": "0755"}],
        }))
        .expect("serialize");
        assert!(matches!(
            Manifest::parse_bounded(&extra_v2, 1 << 20, &[2]),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn v2_integrity_shape_is_bounded() {
        let doc = |sha256: &str, size: u64| {
            serde_json::to_vec(&serde_json::json!({
                "manifest_version": 2,
                "module_id": "m",
                "version": "1",
                "runtime": "r",
                "entrypoint": "a",
                "files": [{"path": "a", "size": size, "sha256": sha256}],
            }))
            .expect("serialize")
        };
        // Uppercase, short, long, and non-hex digests fail closed.
        for bad in [
            "AA".repeat(32),
            "aa".repeat(31),
            format!("{}a", "aa".repeat(32)),
            "zz".repeat(32),
        ] {
            assert!(
                matches!(
                    Manifest::parse_bounded(&doc(&bad, 1), 1 << 20, &[2]),
                    Err(ManifestError::Invalid(_))
                ),
                "sha256 {bad:?} must be rejected"
            );
        }
        // Missing size fails closed.
        let no_size = br#"{"manifest_version":2,"module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":[{"path":"a","sha256":"aa"}]}"#;
        assert!(matches!(
            Manifest::parse_bounded(no_size, 1 << 20, &[2]),
            Err(ManifestError::Invalid(_))
        ));
        // Zero size is legitimate (empty file).
        Manifest::parse_bounded(&doc(&"aa".repeat(32), 0), 1 << 20, &[2])
            .expect("zero size must parse");
    }

    #[test]
    fn path_unsafe_identity_fields_rejected() {
        let doc = |module_id: &str, version: &str| {
            serde_json::to_vec(&serde_json::json!({
                "manifest_version": 1,
                "module_id": module_id,
                "version": version,
                "runtime": "rust",
                "entrypoint": "payload/x",
                "files": ["payload/x"],
            }))
            .expect("manifest json must serialize")
        };

        for bad in [
            "../evil", "a/b", "a\\b", "..", ".", ".hidden", "a b", "a\u{0}b",
        ] {
            let bytes = doc(bad, "1.2.0");
            assert!(
                matches!(
                    Manifest::parse_bounded(&bytes, 1 << 20, &[1]),
                    Err(ManifestError::Invalid(message)) if message.contains("module_id")
                ),
                "module_id {bad:?} must be rejected"
            );
            let bytes = doc("module", bad);
            assert!(
                matches!(
                    Manifest::parse_bounded(&bytes, 1 << 20, &[1]),
                    Err(ManifestError::Invalid(message)) if message.contains("version")
                ),
                "version {bad:?} must be rejected"
            );
        }

        let too_long = "a".repeat(65);
        assert!(
            Manifest::parse_bounded(&doc(&too_long, "1.2.0"), 1 << 20, &[1]).is_err(),
            "over-long module_id must be rejected"
        );

        for (module_id, version) in [
            ("reporting-service", "1.2.0"),
            ("example.module_2", "1.2.3+build.7"),
            ("a", "0"),
        ] {
            Manifest::parse_bounded(&doc(module_id, version), 1 << 20, &[1])
                .expect("legitimate identity must parse");
        }
    }

    #[test]
    fn empty_fields_and_entrypoint_mismatch_rejected() {
        let no_id = br#"{"manifest_version":1,"module_id":"","version":"1","runtime":"r","entrypoint":"a","files":["a"]}"#;
        assert!(matches!(
            Manifest::parse_bounded(no_id, 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        let no_files = br#"{"manifest_version":1,"module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":[]}"#;
        assert!(matches!(
            Manifest::parse_bounded(no_files, 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        let bad_entry = br#"{"manifest_version":1,"module_id":"m","version":"1","runtime":"r","entrypoint":"missing","files":["a"]}"#;
        assert!(matches!(
            Manifest::parse_bounded(bad_entry, 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        // v2 entrypoint mismatch uses paths, not raw objects.
        let bad_entry_v2 = serde_json::to_vec(&serde_json::json!({
            "manifest_version": 2,
            "module_id": "m",
            "version": "1",
            "runtime": "r",
            "entrypoint": "missing",
            "files": [{"path": "a", "size": 1, "sha256": "aa".repeat(32)}],
        }))
        .expect("serialize");
        assert!(matches!(
            Manifest::parse_bounded(&bad_entry_v2, 1 << 20, &[2]),
            Err(ManifestError::Invalid(_))
        ));
    }
}

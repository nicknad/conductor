//! Parses and validates the manifest schema. Never trusts hashes
//! without checking file bytes.
//!
//! Schema versions are runtime policy ([`PackageValidationPolicy`]
//! allowlist); parsing itself stays bounded by `max_manifest_bytes` before
//! any field is interpreted.
//!
//! Schema v1 (`manifest.json` at the archive root):
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
//! `files` lists every payload file in the archive — everything except
//! `manifest.json` itself, which the validator requires separately. The
//! validator feeds these paths to inventory as [`DeclaredFile`]s, so path
//! confinement is enforced there; the manifest layer only checks shape,
//! version gating, and cross-field consistency (`entrypoint ∈ files`).
//! Per-file byte agreement (sizes, digests) belongs to staged extraction,
//! where one stream feeds hashing and writing.

use thiserror::Error;

use crate::packages::inventory::DeclaredFile;

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
    pub files: Vec<String>,
}

/// Raw wire shape. Unknown fields are rejected: a v1 parser must not
/// silently accept a shape it was never taught.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    manifest_version: u32,
    module_id: String,
    version: String,
    runtime: String,
    entrypoint: String,
    files: Vec<String>,
}

impl Manifest {
    /// Parses bounded input, gates the schema version against the policy
    /// allowlist, and checks required-field shape. Path confinement is
    /// *not* checked here — declared paths are attacker-adjacent until the
    /// package signature verifies, and inventory runs them through the
    /// archive path policy.
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
        let raw: RawManifest =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Invalid(e.to_string()))?;
        if !allowed_versions.contains(&raw.manifest_version) {
            return Err(ManifestError::UnsupportedVersion(raw.manifest_version));
        }
        for (name, value) in [
            ("module_id", raw.module_id.as_str()),
            ("version", raw.version.as_str()),
            ("runtime", raw.runtime.as_str()),
            ("entrypoint", raw.entrypoint.as_str()),
        ] {
            if value.is_empty() {
                return Err(ManifestError::Invalid(format!("{name} must not be empty")));
            }
        }
        if raw.files.is_empty() {
            return Err(ManifestError::Invalid(
                "manifest must declare at least one file".to_owned(),
            ));
        }
        if !raw.files.iter().any(|f| f == &raw.entrypoint) {
            return Err(ManifestError::Invalid(
                "entrypoint must be one of the declared files".to_owned(),
            ));
        }
        Ok(Self {
            manifest_version: raw.manifest_version,
            module_id: raw.module_id,
            version: raw.version,
            runtime: raw.runtime,
            entrypoint: raw.entrypoint,
            files: raw.files,
        })
    }

    /// Declared payload files for the inventory stage.
    pub fn declared_files(&self) -> Vec<DeclaredFile> {
        self.files.iter().map(DeclaredFile::new).collect()
    }
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

    #[test]
    fn oversized_manifest_rejected_before_parsing() {
        let err = Manifest::parse_bounded(&[0u8; 8], 4, &[1]).unwrap_err();
        assert!(matches!(err, ManifestError::TooLarge));
    }

    #[test]
    fn empty_manifest_rejected() {
        let err = Manifest::parse_bounded(&[], 16, &[1]).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid(_)));
    }

    #[test]
    fn valid_manifest_parses_and_declares_files() {
        let manifest = Manifest::parse_bounded(&valid_json(), 1 << 20, &[1])
            .expect("valid manifest must parse");
        assert_eq!(manifest.manifest_version, 1);
        assert_eq!(manifest.module_id, "reporting-service");
        assert_eq!(manifest.version, "1.2.0");
        let declared = manifest.declared_files();
        assert_eq!(declared.len(), 1);
        assert_eq!(declared[0].path, "payload/reporting-service");
    }

    #[test]
    fn malformed_json_unknown_version_and_shape_rejected() {
        assert!(matches!(
            Manifest::parse_bounded(b"{not json", 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
        let v2 = br#"{"manifest_version":2,"module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":["a"]}"#;
        assert!(matches!(
            Manifest::parse_bounded(v2, 1 << 20, &[1]),
            Err(ManifestError::UnsupportedVersion(2))
        ));
        // Unknown fields fail closed rather than being silently ignored.
        let extra = br#"{"manifest_version":1,"module_id":"m","version":"1","runtime":"r","entrypoint":"a","files":["a"],"signature":"00"}"#;
        assert!(matches!(
            Manifest::parse_bounded(extra, 1 << 20, &[1]),
            Err(ManifestError::Invalid(_))
        ));
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
    }
}

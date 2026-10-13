//! Parses and validates the manifest schema. Never trusts hashes
//! without checking file bytes.
//!
//! Schema versions are runtime policy ([`PackageValidationPolicy`]
//! allowlist); parsing itself stays bounded by `max_manifest_bytes` before
//! any field is interpreted.

use thiserror::Error;

/// Parsed manifest placeholder. Grows with the ported schema; the version
/// gate below ships first so format evolution stays explicit.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub schema_version: u32,
}

impl Manifest {
    /// Parses bounded input and rejects versions outside the policy
    /// allowlist. Body parsing is not ported yet, so supported versions
    /// fail closed until the schema lands.
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
        // Minimal probe: real schema parsing lands with the port. For now,
        // accept nothing so no package validates on placeholder logic.
        let _ = allowed_versions;
        Err(ManifestError::NotImplemented)
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
    #[error("manifest parsing not implemented yet")]
    NotImplemented,
}

/// Parses and validates the manifest from bounded input.
#[allow(dead_code)]
fn parse_manifest() {}

#[cfg(test)]
mod tests {
    use super::*;

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
}

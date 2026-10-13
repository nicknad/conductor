//! Validated artifact identity: the capability-like result of the
//! validation and promotion workflow.
//!
//! Fields are private and construction is crate-restricted: only the
//! validation/promotion path can mint a [`ValidatedArtifact`], never struct
//! literals or deserialized caller input. The Rust type alone is not the
//! security boundary — if the host persists an artifact reference, it must
//! still verify registration, availability, and activation authorization at
//! use time.

/// Content address of a promoted artifact: SHA-256 over the exact validated
/// bytes (the same bytes the detached signature authenticated).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactDigest([u8; 32]);

impl ArtifactDigest {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex for audit logs. Hand-rolled to avoid a formatting
    /// dependency for one conversion.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex digit"));
            out.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("hex digit"));
        }
        out
    }
}

/// A validated, promoted artifact. Minted only by the validation workflow;
/// read through accessors.
#[allow(dead_code)] // Scaffold: constructed once promotion lands; accessors define the read API.
#[derive(Debug, Clone)]
pub struct ValidatedArtifact {
    digest: ArtifactDigest,
    module_id: String,
    version: String,
}

impl ValidatedArtifact {
    // Scaffold: first call site lands with promotion; the unit test below
    // exercises construction in test builds only.
    #[allow(dead_code)]
    pub(crate) fn new(digest: ArtifactDigest, module_id: String, version: String) -> Self {
        Self {
            digest,
            module_id,
            version,
        }
    }

    #[must_use]
    pub fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_hex_is_lowercase_padded() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x0F;
        bytes[31] = 0xA0;
        let digest = ArtifactDigest::new(bytes);
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("0f"));
        assert!(hex.ends_with("a0"));
        assert_eq!(digest.as_bytes(), &bytes);
    }

    #[test]
    fn artifact_reads_through_accessors() {
        let artifact = ValidatedArtifact::new(
            ArtifactDigest::new([7u8; 32]),
            "example.module".to_owned(),
            "1.0.0".to_owned(),
        );
        assert_eq!(artifact.module_id(), "example.module");
        assert_eq!(artifact.version(), "1.0.0");
        assert_eq!(artifact.digest().as_bytes(), &[7u8; 32]);
    }
}

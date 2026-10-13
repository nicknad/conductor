//! Calculates and compares cryptographic hashes. Decides no
//! activation policy.
//!
//! One concrete backend ([`Sha256DigestProvider`]) behind the closed
//! [`DigestAlgorithm`] enum — no digest provider trait. Prefer streaming
//! interfaces for large files once real hashing lands — the current
//! `&[u8]` form is illustrative, not the final large-file contract.

use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Closed digest set. SHA-256 is the initial (and currently only)
/// file-integrity algorithm; artifact-store content addressing stays pinned
/// to it even if manifest agility is added later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
}

#[derive(Debug, Error)]
pub enum DigestError {
    #[error("digest algorithm not supported")]
    Unsupported,
    #[error("digest failure: {0}")]
    Failure(String),
}

/// The concrete digest backend: SHA-256 over the given bytes.
#[derive(Debug, Default)]
pub struct Sha256DigestProvider;

impl Sha256DigestProvider {
    #[must_use]
    pub fn algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }

    /// Hashes `bytes` and returns the 32-byte digest. Pure computation over
    /// caller-held bytes — no I/O, no time limits needed.
    pub fn digest(&self, bytes: &[u8]) -> Result<Vec<u8>, DigestError> {
        Ok(Sha256::digest(bytes).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_digest_is_sha256() {
        assert_eq!(Sha256DigestProvider.algorithm(), DigestAlgorithm::Sha256);
    }

    #[test]
    fn digest_matches_nist_vector() {
        // SHA-256("abc"), NIST FIPS 180-4.
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let actual: String = Sha256DigestProvider
            .digest(b"abc")
            .expect("hashing must succeed")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn digest_is_32_bytes_and_input_sensitive() {
        let one = Sha256DigestProvider
            .digest(b"a")
            .expect("hashing must succeed");
        let two = Sha256DigestProvider
            .digest(b"b")
            .expect("hashing must succeed");
        assert_eq!(one.len(), 32);
        assert_ne!(one, two);
    }
}

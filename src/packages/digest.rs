//! Calculates and compares cryptographic hashes. Decides no
//! activation policy.
//!
//! One concrete backend ([`Sha256DigestProvider`]) behind the closed
//! [`DigestAlgorithm`] enum — no digest provider trait. Prefer streaming
//! interfaces for large files once real hashing lands — the current
//! `&[u8]` form is illustrative, not the final large-file contract.

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
    #[error("digest backend not implemented yet")]
    NotImplemented,
}

/// The concrete digest backend. Reports [`DigestAlgorithm::Sha256`] but
/// fails closed on use until real hashing lands.
#[derive(Debug, Default)]
pub struct Sha256DigestProvider;

impl Sha256DigestProvider {
    #[must_use]
    pub fn algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }

    /// Hashes `bytes`. Fails closed until the backend lands.
    pub fn digest(&self, _bytes: &[u8]) -> Result<Vec<u8>, DigestError> {
        Err(DigestError::NotImplemented)
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
    fn digest_fails_closed_until_wired() {
        let err = Sha256DigestProvider.digest(b"bytes").unwrap_err();
        assert!(matches!(err, DigestError::NotImplemented));
    }
}

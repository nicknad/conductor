//! Calculates and compares cryptographic hashes. Decides no
//! activation policy.
//!
//! [`DigestProvider`] is injectable so tests can substitute vectors and
//! deployments could swap backends; the production algorithm stays
//! SHA-256 behind the closed [`DigestAlgorithm`] enum. Prefer streaming
//! interfaces for large files once real hashing lands — the current
//! `&[u8]` form is illustrative, not the final large-file contract.

use std::fmt;

/// Closed digest set. SHA-256 is the initial (and currently only)
/// file-integrity algorithm; artifact-store content addressing stays pinned
/// to it even if manifest agility is added later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
}

#[derive(Debug)]
pub enum DigestError {
    Unsupported,
    Failure(String),
    NotImplemented,
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "digest algorithm not supported"),
            Self::Failure(detail) => write!(f, "digest failure: {detail}"),
            Self::NotImplemented => write!(f, "digest backend not implemented yet"),
        }
    }
}

impl std::error::Error for DigestError {}

/// Injectable hash backend.
pub trait DigestProvider: Send + Sync {
    fn algorithm(&self) -> DigestAlgorithm;

    fn digest(&self, bytes: &[u8]) -> Result<Vec<u8>, DigestError>;
}

/// Initial production digest backend. Hashing is not wired yet, so it
/// reports [`DigestAlgorithm::Sha256`] but fails closed on use.
#[derive(Debug, Default)]
pub struct Sha256DigestProvider;

impl DigestProvider for Sha256DigestProvider {
    fn algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }

    fn digest(&self, _bytes: &[u8]) -> Result<Vec<u8>, DigestError> {
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

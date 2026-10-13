//! Verifies manifest signatures against configured trust keys. Never
//! loads or executes plugin code.
//!
//! [`SignatureVerifier`] and [`TrustedKeyProvider`] are the injectable
//! seams: key sourcing (config file, database, KMS) and verification
//! backends vary by deployment. The accepted algorithm set stays a closed
//! [`SignatureAlgorithm`] enum gated by policy — never whatever string the
//! uploaded package declares.

use std::fmt;

/// Closed set of accepted signature algorithms.
///
/// Deliberately an enum, not a free-form string: adding an algorithm is a
/// conscious migration, and verification must reject anything the trusted-key
/// record does not authorize.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}

/// A trusted signing key. The record — not the package — owns the algorithm
/// and permitted usage; verification rejects mismatches.
#[derive(Clone, Debug)]
pub struct TrustedSigningKey {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
}

impl TrustedSigningKey {
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        algorithm: SignatureAlgorithm,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            algorithm,
            public_key,
        }
    }
}

/// Signature verification failures. No silent fallback: every variant is an
/// error, never a downgrade to unsigned.
#[derive(Debug)]
pub enum SignatureError {
    UnknownKey(String),
    UnsupportedAlgorithm,
    VerificationFailed,
    ProviderFailure(String),
    NotImplemented,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(id) => write!(f, "unknown signing key: {id}"),
            Self::UnsupportedAlgorithm => write!(f, "signature algorithm not allowlisted"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::ProviderFailure(detail) => write!(f, "key provider failure: {detail}"),
            Self::NotImplemented => write!(f, "signature backend not implemented yet"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Injectable signature backend. Implementations vary (portable Rust,
/// HSM/KMS wrappers); the validator only sees this contract.
pub trait SignatureVerifier: Send + Sync {
    /// Verifies `signature` over `message` with `key`.
    /// Implementations must reject algorithm mismatches against
    /// `key.algorithm` rather than trusting package-declared metadata.
    fn verify(
        &self,
        key: &TrustedSigningKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError>;
}

/// Injectable trusted-key source: local config, database, or key-management
/// service. Runtime-configurable; the production validator requires one.
pub trait TrustedKeyProvider: Send + Sync {
    fn key(&self, key_id: &str) -> Option<TrustedSigningKey>;
}

/// Initial production verifier. Crypto is not wired yet, so verification
/// fails closed until a real Ed25519 backend lands.
#[derive(Debug, Default)]
pub struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn verify(
        &self,
        _key: &TrustedSigningKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), SignatureError> {
        Err(SignatureError::NotImplemented)
    }
}

/// In-memory key set, typically loaded from operator configuration at
/// startup. Each validation captures one immutable snapshot.
#[derive(Debug, Default)]
pub struct ConfiguredTrustedKeys {
    keys: Vec<TrustedSigningKey>,
}

impl ConfiguredTrustedKeys {
    #[must_use]
    pub fn new(keys: Vec<TrustedSigningKey>) -> Self {
        Self { keys }
    }
}

impl TrustedKeyProvider for ConfiguredTrustedKeys {
    fn key(&self, key_id: &str) -> Option<TrustedSigningKey> {
        self.keys.iter().find(|k| k.key_id == key_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_fails_closed_until_wired() {
        let verifier = Ed25519Verifier;
        let key = TrustedSigningKey::new("k1", SignatureAlgorithm::Ed25519, vec![0u8; 32]);
        let err = verifier.verify(&key, b"msg", b"sig").unwrap_err();
        assert!(matches!(err, SignatureError::NotImplemented));
    }

    #[test]
    fn configured_keys_resolve_by_id() {
        let provider = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            vec![],
        )]);
        assert!(provider.key("k1").is_some());
        assert!(provider.key("nope").is_none());
    }
}

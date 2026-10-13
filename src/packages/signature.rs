//! Verifies manifest signatures against configured trust keys. Never
//! loads or executes plugin code.
//!
//! One concrete verifier ([`Ed25519Verifier`]) and one concrete key source
//! ([`ConfiguredTrustedKeys`], typically loaded from operator configuration
//! at startup) — no cryptographic provider traits. The accepted algorithm
//! set stays a closed [`SignatureAlgorithm`] enum gated by policy — never
//! whatever string the uploaded package declares.

use thiserror::Error;

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

/// Supported detached-signature envelope versions. The envelope format is
/// versioned so signature parsing can evolve without ambiguous
/// interpretation; verifiers accept only listed versions.
pub const SUPPORTED_SIGNATURE_FORMAT_VERSION: u16 = 1;

/// Parsed detached-signature envelope: proves the exact package bytes match
/// what the holder of `key_id` signed. The envelope itself is validated —
/// arbitrary bytes are never treated as a signature.
///
/// The signature covers a canonical payload the signer and verifier must
/// construct byte-identically: a domain-separation prefix, the package
/// format/version, the digest-algorithm identifier, and the SHA-256 digest
/// of the exact archive bytes. Ed25519 ordinary signing and Ed25519ph are
/// not interchangeable here. If certificate-based interoperability is ever
/// required, prefer a standard detached format such as CMS over extending
/// this envelope.
#[derive(Clone, Debug)]
pub struct PackageSignature {
    pub format_version: u16,
    pub key_id: String,
    pub signature: Vec<u8>,
}

impl PackageSignature {
    /// Rejects unknown envelope versions and empty key/signature fields
    /// before any cryptographic work or key lookup happens.
    pub fn check_envelope(&self) -> Result<(), SignatureError> {
        if self.format_version != SUPPORTED_SIGNATURE_FORMAT_VERSION {
            return Err(SignatureError::InvalidEnvelope(format!(
                "unsupported signature format version: {}",
                self.format_version
            )));
        }
        if self.key_id.is_empty() {
            return Err(SignatureError::InvalidEnvelope(
                "signature envelope has empty key id".to_owned(),
            ));
        }
        if self.signature.is_empty() {
            return Err(SignatureError::InvalidEnvelope(
                "signature envelope has empty signature".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Signature verification failures. No silent fallback: every variant is an
/// error, never a downgrade to unsigned.
#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("invalid signature envelope: {0}")]
    InvalidEnvelope(String),
    #[error("unknown signing key: {0}")]
    UnknownKey(String),
    #[error("signature algorithm not allowlisted")]
    UnsupportedAlgorithm,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("key provider failure: {0}")]
    ProviderFailure(String),
    #[error("signature backend not implemented yet")]
    NotImplemented,
}

/// The concrete signature verifier. Must reject algorithm mismatches
/// against `key.algorithm` rather than trusting package-declared metadata.
///
/// Crypto is not wired yet, so verification fails closed until a real
/// Ed25519 backend lands. When positive-path tests need an accepting
/// verifier, the seam will be a `#[cfg(test)]` constructor here — never a
/// production `skip_verification` switch.
#[derive(Debug, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Verifies `signature` over `message` with `key`.
    pub fn verify(
        &self,
        _key: &TrustedSigningKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), SignatureError> {
        Err(SignatureError::NotImplemented)
    }
}

/// In-memory key set, typically loaded from operator configuration at
/// startup. Each validation captures one immutable snapshot. Tests
/// construct instances directly with test keys — the value, not a trait
/// object, is the test seam.
#[derive(Debug, Default)]
pub struct ConfiguredTrustedKeys {
    keys: Vec<TrustedSigningKey>,
}

impl ConfiguredTrustedKeys {
    #[must_use]
    pub fn new(keys: Vec<TrustedSigningKey>) -> Self {
        Self { keys }
    }

    #[must_use]
    pub fn key(&self, key_id: &str) -> Option<TrustedSigningKey> {
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

    fn valid_envelope() -> PackageSignature {
        PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
            key_id: "k1".to_owned(),
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn well_formed_envelope_passes_precheck() {
        valid_envelope()
            .check_envelope()
            .expect("supported version with key and signature must pass");
    }

    #[test]
    fn envelope_rejects_unknown_version_and_empty_fields() {
        let bad_version = PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION + 1,
            ..valid_envelope()
        };
        assert!(matches!(
            bad_version.check_envelope(),
            Err(SignatureError::InvalidEnvelope(_))
        ));
        for bad in [
            PackageSignature {
                key_id: String::new(),
                ..valid_envelope()
            },
            PackageSignature {
                signature: Vec::new(),
                ..valid_envelope()
            },
        ] {
            assert!(matches!(
                bad.check_envelope(),
                Err(SignatureError::InvalidEnvelope(_))
            ));
        }
    }
}

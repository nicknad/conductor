//! Verifies manifest signatures against configured trust keys. Never
//! loads or executes plugin code.
//!
//! One concrete verifier ([`Ed25519Verifier`]) and one concrete key source
//! ([`ConfiguredTrustedKeys`], typically loaded from operator configuration
//! at startup) — no cryptographic provider traits. The accepted algorithm
//! set stays a closed [`SignatureAlgorithm`] enum gated by policy — never
//! whatever string the uploaded package declares.

use ed25519_dalek::{
    Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519VerifyingKey,
};
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
/// The signature covers the [`canonical_payload`]: a domain-separation
/// prefix, the package format/version, the digest-algorithm identifier, and
/// the SHA-256 digest of the exact archive bytes. Ed25519 ordinary signing
/// and Ed25519ph are not interchangeable here. If certificate-based
/// interoperability is ever required, prefer a standard detached format
/// such as CMS over extending this envelope.
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

/// Domain-separation prefix for the canonical payload. Binds signatures to
/// this package format so a signature over unrelated data can never verify
/// as a package signature.
pub const SIGNATURE_DOMAIN: &[u8] = b"conductor/package-signature/v1";

/// Package format identifier covered by the signature. Bumping the archive
/// layout without bumping this invalidates old signatures by construction.
pub const SIGNATURE_FORMAT_ID: &[u8] = b"zip/v1";

/// Digest-algorithm identifier covered by the signature. Pinned to SHA-256
/// alongside the artifact store; algorithm agility needs a new format id.
pub const SIGNATURE_DIGEST_ID: &[u8] = b"sha256";

/// Builds the exact bytes the signer signs and the verifier checks:
/// `domain || 0x00 || format || 0x00 || digest-id || 0x00 || digest`.
/// NUL separators keep the fields unambiguous without length prefixes.
/// Single constructor shared by signer and verifier — never rebuilt ad hoc.
#[must_use]
pub fn canonical_payload(package_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SIGNATURE_DOMAIN.len() + SIGNATURE_FORMAT_ID.len() + SIGNATURE_DIGEST_ID.len() + 32 + 3,
    );
    out.extend_from_slice(SIGNATURE_DOMAIN);
    out.push(0);
    out.extend_from_slice(SIGNATURE_FORMAT_ID);
    out.push(0);
    out.extend_from_slice(SIGNATURE_DIGEST_ID);
    out.push(0);
    out.extend_from_slice(package_digest);
    out
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
}

/// The concrete signature verifier. Rejects algorithm mismatches against
/// `key.algorithm` rather than trusting package-declared metadata.
/// Malformed keys and signatures fail closed as [`SignatureError::VerificationFailed`]:
/// verification has exactly one success path and no diagnostic oracle.
#[derive(Debug, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Verifies `signature` over `message` with `key`. Pure computation —
    /// no I/O, no time limits needed.
    pub fn verify(
        &self,
        key: &TrustedSigningKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        if key.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(SignatureError::UnsupportedAlgorithm);
        }
        let public: [u8; 32] = key
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::VerificationFailed)?;
        let verifying = Ed25519VerifyingKey::from_bytes(&public)
            .map_err(|_| SignatureError::VerificationFailed)?;
        let bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| SignatureError::VerificationFailed)?;
        verifying
            .verify(message, &Ed25519Signature::from_bytes(&bytes))
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Full authentication of a detached signature over a package digest:
    /// envelope precheck → key lookup → policy allowlist → cryptographic
    /// verification. Returns the authorizing key record on success so the
    /// caller can attribute the package to its signer in the audit log.
    pub fn authenticate(
        &self,
        signature: &PackageSignature,
        package_digest: &[u8; 32],
        keys: &ConfiguredTrustedKeys,
        allowed_algorithms: &[SignatureAlgorithm],
    ) -> Result<TrustedSigningKey, SignatureError> {
        signature.check_envelope()?;
        let key = keys
            .key(&signature.key_id)
            .ok_or_else(|| SignatureError::UnknownKey(signature.key_id.clone()))?;
        if !allowed_algorithms.contains(&key.algorithm) {
            return Err(SignatureError::UnsupportedAlgorithm);
        }
        self.verify(
            &key,
            &canonical_payload(package_digest),
            &signature.signature,
        )?;
        Ok(key)
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
    fn verifier_accepts_genuine_signature() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let message = b"package bytes";
        let signature = signing.sign(message);
        let key = TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        );
        Ed25519Verifier
            .verify(&key, message, &signature.to_bytes())
            .expect("genuine signature must verify");
    }

    #[test]
    fn verifier_rejects_tampering_and_malformed_inputs() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let key = TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        );
        let signature = signing.sign(b"package bytes");
        for (message, sig) in [
            (&b"tampered bytes"[..], &signature.to_bytes()[..]),
            (&b"package bytes"[..], &b"too short"[..]),
            (&b"package bytes"[..], &[0u8; 64][..]),
        ] {
            assert!(matches!(
                Ed25519Verifier.verify(&key, message, sig),
                Err(SignatureError::VerificationFailed)
            ));
        }
        let short_key = TrustedSigningKey::new("k1", SignatureAlgorithm::Ed25519, vec![1u8; 4]);
        assert!(matches!(
            Ed25519Verifier.verify(&short_key, b"m", &signature.to_bytes()),
            Err(SignatureError::VerificationFailed)
        ));
    }

    #[test]
    fn canonical_payload_is_pinned_and_unambiguous() {
        let digest = [9u8; 32];
        let payload = canonical_payload(&digest);
        assert!(payload.starts_with(SIGNATURE_DOMAIN));
        assert!(payload.ends_with(&digest));
        // NUL separators: no field boundary is ambiguous.
        assert_eq!(payload.iter().filter(|b| **b == 0).count(), 3);
        // Different digests diverge; same digest is deterministic.
        assert_ne!(payload, canonical_payload(&[8u8; 32]));
        assert_eq!(payload, canonical_payload(&digest));
    }

    #[test]
    fn authenticate_roundtrip_attributes_the_signer() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let digest = [7u8; 32];
        let signature = signing.sign(&canonical_payload(&digest));
        let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        )]);
        let envelope = PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
            key_id: "k1".to_owned(),
            signature: signature.to_bytes().to_vec(),
        };
        let key = Ed25519Verifier
            .authenticate(&envelope, &digest, &keys, &[SignatureAlgorithm::Ed25519])
            .expect("genuine detached signature must authenticate");
        assert_eq!(key.key_id, "k1");
    }

    #[test]
    fn authenticate_rejects_unknown_key_tampered_digest_and_allowlist() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let digest = [7u8; 32];
        let signature = signing.sign(&canonical_payload(&digest));
        let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
            "k1",
            SignatureAlgorithm::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        )]);
        let envelope = PackageSignature {
            format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
            key_id: "k1".to_owned(),
            signature: signature.to_bytes().to_vec(),
        };
        // Tampered package bytes change the digest, which changes the payload.
        assert!(matches!(
            Ed25519Verifier.authenticate(
                &envelope,
                &[8u8; 32],
                &keys,
                &[SignatureAlgorithm::Ed25519]
            ),
            Err(SignatureError::VerificationFailed)
        ));
        // Unknown key id fails before any crypto.
        let unknown = PackageSignature {
            key_id: "nope".to_owned(),
            ..envelope.clone()
        };
        assert!(matches!(
            Ed25519Verifier.authenticate(&unknown, &digest, &keys, &[SignatureAlgorithm::Ed25519]),
            Err(SignatureError::UnknownKey(_))
        ));
        // Key algorithm outside the policy allowlist is rejected even though
        // the signature itself is genuine.
        assert!(matches!(
            Ed25519Verifier.authenticate(&envelope, &digest, &keys, &[]),
            Err(SignatureError::UnsupportedAlgorithm)
        ));
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

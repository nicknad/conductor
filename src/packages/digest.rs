//! Calculates and compares cryptographic hashes. Decides no
//! activation policy.
//!
//! One concrete backend ([`Sha256DigestProvider`]) behind the closed
//! [`DigestAlgorithm`] enum — no digest provider trait. Both entry points
//! hash exact bytes: [`Sha256DigestProvider::digest`] for caller-held
//! buffers, [`Sha256DigestProvider::digest_stream`] for files, so large
//! archives are never fully buffered to be hashed.

use std::io::Read;

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
    #[error("digest failure: {0}")]
    Failure(String),
}

/// The concrete digest backend: SHA-256 over the given bytes.
#[derive(Debug)]
pub struct Sha256DigestProvider;

impl Sha256DigestProvider {
    #[must_use]
    pub fn algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Sha256
    }

    /// Hashes `bytes` and returns the 32-byte digest. Pure computation over
    /// caller-held bytes — no I/O, no time limits needed.
    pub fn digest(&self, bytes: &[u8]) -> Result<[u8; 32], DigestError> {
        Ok(Sha256::digest(bytes).into())
    }

    /// Streams `reader` into SHA-256 and returns the 32-byte digest without
    /// buffering the whole input. This is the large-file entry point: the
    /// validator hashes the quarantined package through this while the
    /// archive is inspected from the same bytes.
    pub fn digest_stream(&self, mut reader: impl Read) -> Result<[u8; 32], DigestError> {
        let mut hasher = Sha256::new();
        std::io::copy(&mut reader, &mut hasher).map_err(|e| DigestError::Failure(e.to_string()))?;
        Ok(hasher.finalize().into())
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

    #[test]
    fn stream_io_failure_is_a_digest_failure() {
        struct Failing;

        impl Read for Failing {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }

        assert!(matches!(
            Sha256DigestProvider.digest_stream(Failing),
            Err(DigestError::Failure(_))
        ));
    }

    #[test]
    fn stream_matches_buffered_over_chunks() {
        use std::io::Cursor;

        // Capped reader proves no whole-input buffering assumption.
        struct Capped<'a> {
            inner: &'a [u8],
            cap: usize,
        }
        impl Read for Capped<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.len().min(buf.len()).min(self.cap);
                if n == 0 {
                    return Ok(0);
                }
                buf[..n].copy_from_slice(&self.inner[..n]);
                self.inner = &self.inner[n..];
                Ok(n)
            }
        }

        let bytes = b"package bytes over many chunks";
        let buffered = Sha256DigestProvider
            .digest(bytes)
            .expect("hashing must succeed");
        let streamed = Sha256DigestProvider
            .digest_stream(Capped {
                inner: bytes,
                cap: 7,
            })
            .expect("streaming must succeed");
        assert_eq!(buffered, streamed);
        let empty = Sha256DigestProvider
            .digest_stream(Cursor::new([]))
            .expect("empty stream must hash");
        assert_eq!(
            Sha256DigestProvider.digest(&[]).expect("empty digest"),
            empty
        );
    }
}

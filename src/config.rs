//! Host configuration. Placeholder values; nothing is stable yet.

use std::path::{Path, PathBuf};

/// Host configuration. Built once at startup and shared by value or by
/// reference; the upload API derives its quarantine directory, request
/// timeout, TLS identity, upload rate floor, and concurrency bound from
/// these fields plus the validation policy (which remains the authoritative
/// byte bound).
#[derive(Debug, Clone)]
pub struct Config {
    pub http_bind: String,
    pub storage_root: String,
    /// Per-request timeout in seconds, enforced by the HTTP timeout layer
    /// and the blocking validation task.
    pub request_timeout_secs: u64,
    /// PEM certificate and private key for the TLS-only listener. There is
    /// deliberately no plaintext option: this service never serves HTTP.
    pub tls_cert_path: String,
    pub tls_key_path: String,
    /// Minimum accepted body-upload speed in bytes per second, enforced
    /// after `rate_grace_secs` of transfer. Trickle (slow-loris) bodies
    /// are rejected with `408`.
    pub min_upload_bytes_per_sec: u64,
    /// Grace period in seconds before the rate floor applies, covering
    /// handshake and slow-start so small legitimate uploads never trip it.
    pub rate_grace_secs: u64,
    /// Maximum simultaneous upload validations. Excess uploads are
    /// rejected with `503` instead of queueing unbounded work.
    pub max_concurrent_uploads: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_bind: "127.0.0.1:8080".to_owned(),
            storage_root: "data".to_owned(),
            request_timeout_secs: 30,
            tls_cert_path: "tls/cert.pem".to_owned(),
            tls_key_path: "tls/key.pem".to_owned(),
            min_upload_bytes_per_sec: 8_192,
            rate_grace_secs: 5,
            max_concurrent_uploads: 8,
        }
    }
}

impl Config {
    /// Directory holding untrusted uploads awaiting validation. Created on
    /// demand by the quarantine layer; never served or executed from.
    #[must_use]
    pub fn quarantine_dir(&self) -> PathBuf {
        Path::new(&self.storage_root).join("quarantine")
    }

    /// Directory holding promoted immutable artifacts at
    /// `artifacts/{module_id}/{version}/{digest}.zip`. Written only by the
    /// artifact store via `create_new`; never overwritten.
    #[must_use]
    pub fn artifact_dir(&self) -> PathBuf {
        Path::new(&self.storage_root).join("artifacts")
    }
}

/// Loads host configuration from file and environment.
#[allow(dead_code)]
fn load_config() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_binds_loopback() {
        assert!(Config::default().http_bind.starts_with("127.0.0.1:"));
    }

    #[test]
    fn quarantine_lives_under_storage_root() {
        let config = Config::default();
        assert_eq!(
            config.quarantine_dir(),
            Path::new(&config.storage_root).join("quarantine")
        );
    }

    #[test]
    fn default_timeout_is_nonzero() {
        assert!(Config::default().request_timeout_secs > 0);
    }

    #[test]
    fn default_tls_paths_are_configured() {
        let config = Config::default();
        assert!(!config.tls_cert_path.is_empty());
        assert!(!config.tls_key_path.is_empty());
    }

    #[test]
    fn default_rate_floor_and_slots_are_nonzero() {
        let config = Config::default();
        assert!(config.min_upload_bytes_per_sec > 0);
        assert!(config.rate_grace_secs > 0);
        assert!(config.max_concurrent_uploads > 0);
    }
}

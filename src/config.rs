//! Host configuration. Placeholder values; nothing is stable yet.

use std::path::{Path, PathBuf};

/// Host configuration. Built once at startup and shared by value or by
/// reference; the upload API derives its quarantine directory, request
/// timeout, and body-limit headroom from these fields plus the validation
/// policy (which remains the authoritative byte bound).
#[derive(Debug, Clone)]
pub struct Config {
    pub http_bind: String,
    pub storage_root: String,
    /// Per-request timeout in seconds, enforced by the HTTP timeout layer
    /// and the blocking validation task.
    pub request_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_bind: "127.0.0.1:8080".to_owned(),
            storage_root: "data".to_owned(),
            request_timeout_secs: 30,
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
}

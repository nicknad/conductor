//! Host configuration. Placeholder values; nothing is stable yet.

#[derive(Debug, Clone)]
pub struct Config {
    pub http_bind: String,
    pub storage_root: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_bind: "127.0.0.1:8080".to_owned(),
            storage_root: "data".to_owned(),
        }
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
}

//! Host configuration.
//!
//! One immutable [`Config`] is assembled from defaults, an optional JSON
//! file, and `CONDUCTOR_*` environment variables (in that order: environment
//! wins over file values). Startup validates the result with
//! [`Config::validate_for_startup`]; missing or unusable security material is
//! a startup error, never a runtime ambiguity.
//!
//! Paths are used as given: relative paths resolve against the process
//! working directory, exactly like the defaults. Prefer absolute paths in
//! deployed configuration files.
//!
//! The API token is secret configuration. [`Config`] deliberately implements
//! `Debug` by hand so a log line or panic message can never carry it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::packages::signature::SignatureAlgorithm;

const ENV_CONFIG: &str = "CONDUCTOR_CONFIG";
const ENV_HTTP_BIND: &str = "CONDUCTOR_HTTP_BIND";
const ENV_STORAGE_ROOT: &str = "CONDUCTOR_STORAGE_ROOT";
const ENV_REQUEST_TIMEOUT_SECS: &str = "CONDUCTOR_REQUEST_TIMEOUT_SECS";
const ENV_TLS_CERT_PATH: &str = "CONDUCTOR_TLS_CERT_PATH";
const ENV_TLS_KEY_PATH: &str = "CONDUCTOR_TLS_KEY_PATH";
const ENV_MAX_CONCURRENT_UPLOADS: &str = "CONDUCTOR_MAX_CONCURRENT_UPLOADS";
// Environment variable names, not credentials.
// nosemgrep: generic.hardcoded-secret
const ENV_API_TOKEN: &str = "CONDUCTOR_API_TOKEN";
// nosemgrep: generic.hardcoded-secret
const ENV_API_TOKEN_FILE: &str = "CONDUCTOR_API_TOKEN_FILE";
const ENV_TRUSTED_KEYS_FILE: &str = "CONDUCTOR_TRUSTED_KEYS_FILE";

/// One trusted signing key as it appears in operator configuration.
///
/// `public_key_base64` is standard base64 over the raw public key bytes.
/// Key material is validated at the startup boundary (presence here;
/// algorithm-specific shape when the trust store is assembled).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKeyConfig {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key_base64: String,
}

/// Host configuration. Built once at startup and shared by value or by
/// reference; the upload API derives its quarantine directory, request
/// timeout, TLS identity, and concurrency bound from these fields plus the
/// validation policy (which remains the authoritative byte bound).
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub http_bind: String,
    pub storage_root: PathBuf,
    /// Per-request timeout in seconds, enforced by the HTTP timeout layer
    /// and the blocking validation task.
    pub request_timeout_secs: u64,
    /// PEM certificate and private key for the TLS-only listener. There is
    /// deliberately no plaintext option: this service never serves HTTP.
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    /// Maximum simultaneous upload validations. Excess uploads are
    /// rejected with `503` instead of queueing unbounded work.
    pub max_concurrent_uploads: usize,
    /// Operator bearer token. Secret: never logged, never serialized into
    /// error messages. `None` is only valid before startup validation.
    pub api_token: Option<String>,
    /// Signing keys accepted for package uploads. At least one is required
    /// before serving.
    pub trusted_keys: Vec<TrustedKeyConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_bind: "127.0.0.1:8080".to_owned(),
            storage_root: PathBuf::from("data"),
            request_timeout_secs: 30,
            tls_cert_path: PathBuf::from("tls/cert.pem"),
            tls_key_path: PathBuf::from("tls/key.pem"),
            max_concurrent_uploads: 8,
            api_token: None,
            trusted_keys: Vec::new(),
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("http_bind", &self.http_bind)
            .field("storage_root", &self.storage_root)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("max_concurrent_uploads", &self.max_concurrent_uploads)
            .field("api_token", &self.api_token.as_ref().map(|_| "[redacted]"))
            .field("trusted_keys", &self.trusted_keys)
            .finish()
    }
}

impl Config {
    /// Loads configuration for the running process: `--config <path>` first,
    /// then `CONDUCTOR_CONFIG`, then no file, with `CONDUCTOR_*` environment
    /// overrides applied on top.
    pub fn load() -> Result<Self, ConfigError> {
        let env = process_env()?;
        let path = parse_config_path(std::env::args_os().skip(1))?
            .or_else(|| env.get(ENV_CONFIG).map(PathBuf::from));
        Self::load_with(path.as_deref(), env)
    }

    /// Loads a specific file without consulting the process environment.
    /// Tests and embedding callers use this; production uses [`load`](Self::load).
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        Self::load_with(Some(path), std::iter::empty::<(String, String)>())
    }

    /// Testable loader: defaults, then `config_path` if present, then the
    /// supplied environment. Keeping the environment explicit lets tests
    /// assert precedence without mutating process-global state.
    pub fn load_with<I>(config_path: Option<&Path>, env: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let env: BTreeMap<String, String> = env.into_iter().collect();
        let mut config = Self::default();
        let mut file_token = None;
        let mut file_token_file = None;

        if let Some(path) = config_path {
            let text = read_text("config file", path)?;
            let file: ConfigFile = parse_json("config file", path, &text)?;
            if let Some(value) = file.http_bind {
                config.http_bind = value;
            }
            if let Some(value) = file.storage_root {
                config.storage_root = value;
            }
            if let Some(value) = file.request_timeout_secs {
                config.request_timeout_secs = value;
            }
            if let Some(value) = file.tls_cert_path {
                config.tls_cert_path = value;
            }
            if let Some(value) = file.tls_key_path {
                config.tls_key_path = value;
            }
            if let Some(value) = file.max_concurrent_uploads {
                config.max_concurrent_uploads = value;
            }
            if let Some(value) = file.trusted_keys {
                config.trusted_keys = value;
            }
            file_token = file.api_token;
            file_token_file = file.api_token_file;
        }

        if let Some(value) = env.get(ENV_HTTP_BIND) {
            config.http_bind = value.clone();
        }
        if let Some(value) = env.get(ENV_STORAGE_ROOT) {
            config.storage_root = PathBuf::from(value);
        }
        if let Some(value) = env_parse(&env, ENV_REQUEST_TIMEOUT_SECS)? {
            config.request_timeout_secs = value;
        }
        if let Some(value) = env.get(ENV_TLS_CERT_PATH) {
            config.tls_cert_path = PathBuf::from(value);
        }
        if let Some(value) = env.get(ENV_TLS_KEY_PATH) {
            config.tls_key_path = PathBuf::from(value);
        }
        if let Some(value) = env_parse(&env, ENV_MAX_CONCURRENT_UPLOADS)? {
            config.max_concurrent_uploads = value;
        }
        if let Some(path) = env.get(ENV_TRUSTED_KEYS_FILE) {
            let path = Path::new(path);
            let text = read_text("trusted-keys file", path)?;
            config.trusted_keys = parse_json("trusted-keys file", path, &text)?;
        }

        config.api_token = resolve_token(&env, file_token, file_token_file)?;
        Ok(config)
    }

    /// Startup gate: security material is present and the serving settings
    /// are usable. This is intentionally separate from [`load`](Self::load)
    /// so configuration can be inspected or tested without pretending to be
    /// servable.
    pub fn validate_for_startup(&self) -> Result<(), ConfigError> {
        if self.http_bind.parse::<SocketAddr>().is_err() {
            return Err(ConfigError::Invalid {
                field: "http_bind",
                reason: "must be a socket address such as 127.0.0.1:8443".to_owned(),
            });
        }
        if self.request_timeout_secs == 0 {
            return Err(ConfigError::Invalid {
                field: "request_timeout_secs",
                reason: "must be greater than zero".to_owned(),
            });
        }
        if self.max_concurrent_uploads == 0 {
            return Err(ConfigError::Invalid {
                field: "max_concurrent_uploads",
                reason: "must be greater than zero".to_owned(),
            });
        }
        if self.storage_root.as_os_str().is_empty() {
            return Err(ConfigError::Invalid {
                field: "storage_root",
                reason: "must not be empty".to_owned(),
            });
        }
        if self.tls_cert_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid {
                field: "tls_cert_path",
                reason: "must not be empty".to_owned(),
            });
        }
        if self.tls_key_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid {
                field: "tls_key_path",
                reason: "must not be empty".to_owned(),
            });
        }
        match self.api_token.as_deref() {
            None => return Err(ConfigError::Missing("api_token")),
            Some(token) if token.trim().is_empty() => {
                return Err(ConfigError::Invalid {
                    field: "api_token",
                    reason: "must not be empty".to_owned(),
                });
            }
            Some(_) => {}
        }
        if self.trusted_keys.is_empty() {
            return Err(ConfigError::Missing("trusted_keys"));
        }
        for key in &self.trusted_keys {
            if key.key_id.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    field: "trusted_keys.key_id",
                    reason: "must not be empty".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Directory holding untrusted uploads awaiting validation. Created on
    /// demand by the quarantine layer; never served or executed from.
    #[must_use]
    pub fn quarantine_dir(&self) -> PathBuf {
        self.storage_root.join("quarantine")
    }

    /// Directory holding promoted immutable artifacts at
    /// `artifacts/{module_id}/{version}/{digest}.zip`. Written only by the
    /// artifact store via `create_new`; never overwritten.
    #[must_use]
    pub fn artifact_dir(&self) -> PathBuf {
        self.storage_root.join("artifacts")
    }

    /// SQLite database path. The parent directory is created on demand by
    /// the database layer; migrations run at startup.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.storage_root.join("database").join("conductor.db")
    }
}

/// On-disk shape. Every field is optional: missing values fall back to
/// [`Config::default`], and unknown keys are rejected so typos cannot be
/// silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    http_bind: Option<String>,
    storage_root: Option<PathBuf>,
    request_timeout_secs: Option<u64>,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    max_concurrent_uploads: Option<usize>,
    api_token: Option<String>,
    api_token_file: Option<PathBuf>,
    trusted_keys: Option<Vec<TrustedKeyConfig>>,
}

/// Configuration failures. Every variant is a startup error; none is
/// recoverable at request time.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{what} {path}: {detail}")]
    Read {
        what: &'static str,
        path: String,
        detail: String,
    },
    #[error("{what} {path}: {detail}")]
    Parse {
        what: &'static str,
        path: String,
        detail: String,
    },
    #[error("missing required configuration: {0}")]
    Missing(&'static str),
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
}

/// Reads only `CONDUCTOR_*` variables from the process environment. A
/// non-UTF-8 value for one of our variables is a configuration error; other
/// variables are ignored rather than making startup depend on unrelated
/// process state.
fn process_env() -> Result<BTreeMap<String, String>, ConfigError> {
    let mut env = BTreeMap::new();
    for (key, value) in std::env::vars_os() {
        let Ok(key) = key.into_string() else {
            continue;
        };
        if !key.starts_with("CONDUCTOR_") {
            continue;
        }
        let value = value.into_string().map_err(|_| ConfigError::Invalid {
            field: "environment",
            reason: format!("{key} is not valid UTF-8"),
        })?;
        env.insert(key, value);
    }
    Ok(env)
}

fn parse_config_path<I>(args: I) -> Result<Option<PathBuf>, ConfigError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut config_path = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config") => {
                let value = args.next().ok_or(ConfigError::Invalid {
                    field: "argument",
                    reason: "--config requires a path".to_owned(),
                })?;
                if config_path.replace(PathBuf::from(value)).is_some() {
                    return Err(ConfigError::Invalid {
                        field: "argument",
                        reason: "--config may be supplied only once".to_owned(),
                    });
                }
            }
            Some(other) => {
                return Err(ConfigError::Invalid {
                    field: "argument",
                    reason: format!("unrecognized argument: {other}"),
                });
            }
            None => {
                return Err(ConfigError::Invalid {
                    field: "argument",
                    reason: "arguments must be valid UTF-8".to_owned(),
                });
            }
        }
    }
    Ok(config_path)
}

fn read_text(what: &'static str, path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|err| ConfigError::Read {
        what,
        path: path.display().to_string(),
        detail: err.to_string(),
    })
}

fn parse_json<T>(what: &'static str, path: &Path, text: &str) -> Result<T, ConfigError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(text).map_err(|err| ConfigError::Parse {
        what,
        path: path.display().to_string(),
        detail: err.to_string(),
    })
}

fn env_parse<T>(
    env: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    env.get(name)
        .map(|raw| {
            raw.parse::<T>().map_err(|err| ConfigError::Invalid {
                field: name,
                reason: err.to_string(),
            })
        })
        .transpose()
}

/// Resolves the token from the highest-precedence source: environment value,
/// environment file, file value, file path. A token file is trimmed; an empty
/// token file is a configuration error rather than an empty bearer token.
fn resolve_token(
    env: &BTreeMap<String, String>,
    file_token: Option<String>,
    file_token_file: Option<PathBuf>,
) -> Result<Option<String>, ConfigError> {
    if let Some(token) = env.get(ENV_API_TOKEN) {
        return Ok(Some(token.clone()));
    }
    if let Some(path) = env.get(ENV_API_TOKEN_FILE) {
        return read_token_file(Path::new(path)).map(Some);
    }
    if let Some(token) = file_token {
        return Ok(Some(token));
    }
    if let Some(path) = file_token_file {
        return read_token_file(&path).map(Some);
    }
    Ok(None)
}

fn read_token_file(path: &Path) -> Result<String, ConfigError> {
    let token = read_text("token file", path)?.trim().to_owned();
    if token.is_empty() {
        return Err(ConfigError::Invalid {
            field: "api_token",
            reason: "token file is empty".to_owned(),
        });
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "conductor-config-{}-{nanos}-{count}-{tag}",
            std::process::id()
        ))
    }

    fn write_temp(tag: &str, contents: &str) -> PathBuf {
        let path = temp_path(tag);
        std::fs::write(&path, contents).expect("temp file must be writable");
        path
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    fn startup_ready_config() -> Config {
        Config {
            api_token: Some("startup-token".to_owned()),
            trusted_keys: vec![TrustedKeyConfig {
                key_id: "k1".to_owned(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_base64: "GX9rI+FshTLGq8g4+s1ep4m+DHaykgM0A5v6iz02jWE=".to_owned(),
            }],
            ..Config::default()
        }
    }

    #[test]
    fn default_config_binds_loopback() {
        assert!(Config::default().http_bind.starts_with("127.0.0.1:"));
    }

    #[test]
    fn storage_directories_live_under_storage_root() {
        let config = Config::default();
        assert_eq!(
            config.quarantine_dir(),
            config.storage_root.join("quarantine")
        );
        assert_eq!(config.artifact_dir(), config.storage_root.join("artifacts"));
        assert_eq!(
            config.database_path(),
            config.storage_root.join("database").join("conductor.db")
        );
    }

    #[test]
    fn default_timeout_and_slots_are_nonzero() {
        let config = Config::default();
        assert!(config.request_timeout_secs > 0);
        assert!(config.max_concurrent_uploads > 0);
    }

    #[test]
    fn default_tls_paths_are_configured() {
        let config = Config::default();
        assert!(!config.tls_cert_path.as_os_str().is_empty());
        assert!(!config.tls_key_path.as_os_str().is_empty());
    }

    #[test]
    fn defaults_are_not_startup_ready() {
        assert!(matches!(
            Config::default().validate_for_startup(),
            Err(ConfigError::Missing("api_token"))
        ));
    }

    #[test]
    fn startup_ready_config_passes() {
        startup_ready_config()
            .validate_for_startup()
            .expect("token and one key must be sufficient");
    }

    #[test]
    fn config_file_parses_and_overrides_defaults() {
        let path = write_temp(
            "full.json",
            &serde_json::json!({
                "http_bind": "127.0.0.1:9443",
                "storage_root": "store",
                "request_timeout_secs": 7,
                "tls_cert_path": "cert.pem",
                "tls_key_path": "key.pem",
                "max_concurrent_uploads": 3,
                "api_token": "file-token",
                "trusted_keys": [{
                    "key_id": "file-key",
                    "algorithm": "ed25519",
                    "public_key_base64": "AAAA"
                }]
            })
            .to_string(),
        );

        let config = Config::from_file(&path).expect("valid config must load");
        assert_eq!(config.http_bind, "127.0.0.1:9443");
        assert_eq!(config.storage_root, PathBuf::from("store"));
        assert_eq!(config.request_timeout_secs, 7);
        assert_eq!(config.tls_cert_path, PathBuf::from("cert.pem"));
        assert_eq!(config.tls_key_path, PathBuf::from("key.pem"));
        assert_eq!(config.max_concurrent_uploads, 3);
        assert_eq!(config.api_token.as_deref(), Some("file-token"));
        assert_eq!(config.trusted_keys.len(), 1);
        assert_eq!(config.trusted_keys[0].key_id, "file-key");
        assert_eq!(
            config.trusted_keys[0].algorithm,
            SignatureAlgorithm::Ed25519
        );
        cleanup(&path);
    }

    #[test]
    fn example_config_parses_and_passes_startup_checks() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/conductor.example.json");
        let config = Config::from_file(&path).expect("example config must parse");
        config
            .validate_for_startup()
            .expect("example config must pass startup checks");
    }

    #[test]
    fn unknown_config_field_is_rejected() {
        let path = write_temp("unknown.json", r#"{"bogus": true}"#);
        assert!(matches!(
            Config::from_file(&path),
            Err(ConfigError::Parse { .. })
        ));
        cleanup(&path);
    }

    #[test]
    fn missing_config_file_is_reported() {
        let path = temp_path("missing.json");
        assert!(matches!(
            Config::from_file(&path),
            Err(ConfigError::Read { .. })
        ));
    }

    #[test]
    fn environment_overrides_file_values() {
        let path = write_temp(
            "env.json",
            r#"{"http_bind": "127.0.0.1:8000", "api_token": "file-token"}"#,
        );
        let config = Config::load_with(
            Some(&path),
            [
                (ENV_HTTP_BIND.to_owned(), "127.0.0.1:9000".to_owned()),
                (ENV_STORAGE_ROOT.to_owned(), "env-store".to_owned()),
                (ENV_API_TOKEN.to_owned(), "env-token".to_owned()),
            ],
        )
        .expect("environment overrides must load");

        assert_eq!(config.http_bind, "127.0.0.1:9000");
        assert_eq!(config.storage_root, PathBuf::from("env-store"));
        assert_eq!(config.api_token.as_deref(), Some("env-token"));
        cleanup(&path);
    }

    #[test]
    fn invalid_numeric_environment_value_is_reported() {
        let result = Config::load_with(
            None,
            [(ENV_REQUEST_TIMEOUT_SECS.to_owned(), "soon".to_owned())],
        );
        assert!(matches!(
            result,
            Err(ConfigError::Invalid {
                field: ENV_REQUEST_TIMEOUT_SECS,
                ..
            })
        ));
    }

    #[test]
    fn token_file_is_read_and_trimmed() {
        let token_path = write_temp("token.txt", "secret-token\n");
        let path = write_temp(
            "token-file.json",
            &serde_json::json!({ "api_token_file": token_path.display().to_string() }).to_string(),
        );

        let config = Config::from_file(&path).expect("token file config must load");
        assert_eq!(config.api_token.as_deref(), Some("secret-token"));
        cleanup(&path);
        cleanup(&token_path);
    }

    #[test]
    fn empty_token_file_is_rejected() {
        let token_path = write_temp("empty-token.txt", " \n");
        let path = write_temp(
            "empty-token-file.json",
            &serde_json::json!({ "api_token_file": token_path.display().to_string() }).to_string(),
        );

        assert!(matches!(
            Config::from_file(&path),
            Err(ConfigError::Invalid {
                field: "api_token",
                ..
            })
        ));
        cleanup(&path);
        cleanup(&token_path);
    }

    #[test]
    fn environment_token_wins_over_file_token() {
        let path = write_temp("token-precedence.json", r#"{"api_token": "file-token"}"#);
        let config = Config::load_with(
            Some(&path),
            [(ENV_API_TOKEN.to_owned(), "env-token".to_owned())],
        )
        .expect("token precedence must load");
        assert_eq!(config.api_token.as_deref(), Some("env-token"));
        cleanup(&path);
    }

    #[test]
    fn trusted_keys_file_replaces_config_keys() {
        let keys_path = write_temp(
            "keys.json",
            r#"[{"key_id":"env-key","algorithm":"ed25519","public_key_base64":"AAAA"}]"#,
        );
        let config = Config::load_with(
            None,
            [(
                ENV_TRUSTED_KEYS_FILE.to_owned(),
                keys_path.display().to_string(),
            )],
        )
        .expect("trusted-keys file must load");
        assert_eq!(config.trusted_keys.len(), 1);
        assert_eq!(config.trusted_keys[0].key_id, "env-key");
        cleanup(&keys_path);
    }

    #[test]
    fn debug_redacts_the_api_token() {
        let config = startup_ready_config();
        let debug = format!("{config:?}");
        assert!(!debug.contains("startup-token"), "{debug}");
        assert!(debug.contains("[redacted]"), "{debug}");
    }

    #[test]
    fn empty_token_is_rejected() {
        let config = Config {
            api_token: Some(String::new()),
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "api_token",
                ..
            })
        ));
    }

    #[test]
    fn empty_trusted_keys_are_rejected() {
        let config = Config {
            trusted_keys: Vec::new(),
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Missing("trusted_keys"))
        ));
    }

    #[test]
    fn empty_key_id_is_rejected() {
        let config = Config {
            trusted_keys: vec![TrustedKeyConfig {
                key_id: String::new(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_base64: "AAAA".to_owned(),
            }],
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "trusted_keys.key_id",
                ..
            })
        ));
    }

    #[test]
    fn invalid_bind_address_is_rejected() {
        let config = Config {
            http_bind: "not-an-address".to_owned(),
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "http_bind",
                ..
            })
        ));
    }

    #[test]
    fn zero_timeout_and_slots_are_rejected() {
        let config = Config {
            request_timeout_secs: 0,
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "request_timeout_secs",
                ..
            })
        ));

        let config = Config {
            max_concurrent_uploads: 0,
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "max_concurrent_uploads",
                ..
            })
        ));
    }

    #[test]
    fn parses_the_config_flag() {
        let args = vec![OsString::from("--config"), OsString::from("host.json")];
        assert_eq!(
            parse_config_path(args).expect("valid argument"),
            Some(PathBuf::from("host.json"))
        );
    }

    #[test]
    fn rejects_malformed_config_arguments() {
        for args in [
            vec![OsString::from("--config")],
            vec![
                OsString::from("--config"),
                OsString::from("a.json"),
                OsString::from("--config"),
                OsString::from("b.json"),
            ],
            vec![OsString::from("--help")],
        ] {
            assert!(matches!(
                parse_config_path(args),
                Err(ConfigError::Invalid {
                    field: "argument",
                    ..
                })
            ));
        }
    }
}

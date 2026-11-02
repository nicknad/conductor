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

use base64::prelude::*;
use serde::Deserialize;

use crate::packages::signature::{
    ConfiguredTrustedKeys, SignatureAlgorithm, TrustStoreError, TrustedSigningKey, MAX_KEY_ID_BYTES,
};

const ENV_CONFIG: &str = "CONDUCTOR_CONFIG";
const ENV_HTTP_BIND: &str = "CONDUCTOR_HTTP_BIND";
const ENV_STORAGE_ROOT: &str = "CONDUCTOR_STORAGE_ROOT";
const ENV_REQUEST_TIMEOUT_SECS: &str = "CONDUCTOR_REQUEST_TIMEOUT_SECS";
const ENV_TLS_CERT_PATH: &str = "CONDUCTOR_TLS_CERT_PATH";
const ENV_TLS_KEY_PATH: &str = "CONDUCTOR_TLS_KEY_PATH";
const ENV_MAX_CONCURRENT_UPLOADS: &str = "CONDUCTOR_MAX_CONCURRENT_UPLOADS";
const ENV_QUARANTINE_TTL_SECS: &str = "CONDUCTOR_QUARANTINE_TTL_SECS";
const ENV_STAGING_TTL_SECS: &str = "CONDUCTOR_STAGING_TTL_SECS";
const ENV_ALLOWED_RUNTIMES: &str = "CONDUCTOR_ALLOWED_RUNTIMES";
const ENV_MAX_EXECUTION_DEADLINE_SECS: &str = "CONDUCTOR_MAX_EXECUTION_DEADLINE_SECS";
const ENV_MAX_CONCURRENT_EXECUTIONS: &str = "CONDUCTOR_MAX_CONCURRENT_EXECUTIONS";
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

impl TrustedKeyConfig {
    /// Converts the operator-facing record into the runtime key type.
    /// The key id is trimmed to the same form the HTTP `key_id` field is
    /// trimmed to, so a configured key can always be selected and
    /// whitespace cannot create a duplicate-looking id that is unreachable.
    /// It must be non-empty and fit [`MAX_KEY_ID_BYTES`]; the public key must
    /// be standard base64 over exactly 32 raw bytes (the Ed25519 key size),
    /// and the algorithm is the closed [`SignatureAlgorithm`] enum. Failures
    /// include the offending field but never echo key material.
    fn to_signing_key(&self) -> Result<TrustedSigningKey, ConfigError> {
        let key_id = self.key_id.trim();
        if key_id.is_empty() {
            return Err(ConfigError::Invalid {
                field: "trusted_keys.key_id",
                reason: "must not be empty".to_owned(),
            });
        }
        if key_id.len() > MAX_KEY_ID_BYTES {
            return Err(ConfigError::Invalid {
                field: "trusted_keys.key_id",
                reason: format!("must be at most {MAX_KEY_ID_BYTES} bytes"),
            });
        }
        let public_key = BASE64_STANDARD
            .decode(self.public_key_base64.trim())
            .map_err(|err| ConfigError::Invalid {
                field: "trusted_keys.public_key_base64",
                reason: format!("must be standard base64: {err}"),
            })?;
        if public_key.len() != 32 {
            return Err(ConfigError::Invalid {
                field: "trusted_keys.public_key_base64",
                reason: format!(
                    "Ed25519 public key must be 32 bytes, got {}",
                    public_key.len()
                ),
            });
        }
        Ok(TrustedSigningKey::new(
            key_id.to_owned(),
            self.algorithm,
            public_key,
        ))
    }
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
    /// and the blocking validation task. It includes request preparation as
    /// well as the worker run, and must exceed
    /// `max_execution_deadline_secs` plus the worker termination grace so a
    /// request cannot time out while its worker is still being reaped.
    pub request_timeout_secs: u64,
    /// PEM certificate and private key for the TLS-only listener. There is
    /// deliberately no plaintext option: this service never serves HTTP.
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    /// Maximum simultaneous upload validations. Excess uploads are
    /// rejected with `503` instead of queueing unbounded work.
    pub max_concurrent_uploads: usize,
    /// Age after which a leftover quarantine upload is removed at startup.
    pub quarantine_ttl_secs: u64,
    /// Age after which a leftover staging directory is removed at startup.
    pub staging_ttl_secs: u64,
    /// Runtime names that activation and execution may run. Non-empty
    /// metadata filter, not a sandbox; checked again by `ActivationPolicy`
    /// when the host assembles.
    pub allowed_runtimes: Vec<String>,
    /// Host ceiling for any requested execution deadline. An omitted request
    /// deadline defaults to 30 seconds clamped down to this value.
    pub max_execution_deadline_secs: u64,
    /// Maximum simultaneous worker processes. Excess requests fail fast
    /// with `503` instead of queueing.
    pub max_concurrent_executions: usize,
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
            request_timeout_secs: 360,
            tls_cert_path: PathBuf::from("tls/cert.pem"),
            tls_key_path: PathBuf::from("tls/key.pem"),
            max_concurrent_uploads: 8,
            quarantine_ttl_secs: 60 * 60,
            staging_ttl_secs: 60 * 60,
            allowed_runtimes: vec!["rust".to_owned()],
            max_execution_deadline_secs: 300,
            max_concurrent_executions: 4,
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
            .field("quarantine_ttl_secs", &self.quarantine_ttl_secs)
            .field("staging_ttl_secs", &self.staging_ttl_secs)
            .field("allowed_runtimes", &self.allowed_runtimes)
            .field(
                "max_execution_deadline_secs",
                &self.max_execution_deadline_secs,
            )
            .field("max_concurrent_executions", &self.max_concurrent_executions)
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
            if let Some(value) = file.quarantine_ttl_secs {
                config.quarantine_ttl_secs = value;
            }
            if let Some(value) = file.staging_ttl_secs {
                config.staging_ttl_secs = value;
            }
            if let Some(value) = file.allowed_runtimes {
                config.allowed_runtimes = normalize_runtimes(value);
            }
            if let Some(value) = file.max_execution_deadline_secs {
                config.max_execution_deadline_secs = value;
            }
            if let Some(value) = file.max_concurrent_executions {
                config.max_concurrent_executions = value;
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
        if let Some(value) = env_parse(&env, ENV_QUARANTINE_TTL_SECS)? {
            config.quarantine_ttl_secs = value;
        }
        if let Some(value) = env_parse(&env, ENV_STAGING_TTL_SECS)? {
            config.staging_ttl_secs = value;
        }
        if let Some(value) = env.get(ENV_ALLOWED_RUNTIMES) {
            config.allowed_runtimes = parse_runtime_env(value);
        }
        if let Some(value) = env_parse(&env, ENV_MAX_EXECUTION_DEADLINE_SECS)? {
            config.max_execution_deadline_secs = value;
        }
        if let Some(value) = env_parse(&env, ENV_MAX_CONCURRENT_EXECUTIONS)? {
            config.max_concurrent_executions = value;
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
        if self.quarantine_ttl_secs == 0 {
            return Err(ConfigError::Invalid {
                field: "quarantine_ttl_secs",
                reason: "must be greater than zero".to_owned(),
            });
        }
        if self.staging_ttl_secs == 0 {
            return Err(ConfigError::Invalid {
                field: "staging_ttl_secs",
                reason: "must be greater than zero".to_owned(),
            });
        }
        if self.allowed_runtimes.is_empty() {
            return Err(ConfigError::Invalid {
                field: "allowed_runtimes",
                reason: "must not be empty".to_owned(),
            });
        }
        if self
            .allowed_runtimes
            .iter()
            .any(|runtime| runtime.trim().is_empty())
        {
            return Err(ConfigError::Invalid {
                field: "allowed_runtimes",
                reason: "must not contain empty runtime names".to_owned(),
            });
        }
        if self.max_execution_deadline_secs == 0 {
            return Err(ConfigError::Invalid {
                field: "max_execution_deadline_secs",
                reason: "must be greater than zero".to_owned(),
            });
        }
        // A request must be able to run its worker to the configured deadline
        // and then reap the process group inside the termination grace before
        // the HTTP timeout cancels the request. Requiring a strict margin also
        // keeps the default request deadline (`deadline_secs` omitted) usable.
        let termination_grace_secs = crate::executions::executor::ExecutionLimits::default()
            .terminate_grace
            .as_secs();
        let minimum_timeout_secs = self
            .max_execution_deadline_secs
            .saturating_add(termination_grace_secs)
            .saturating_add(1);
        if self.request_timeout_secs < minimum_timeout_secs {
            return Err(ConfigError::Invalid {
                field: "max_execution_deadline_secs",
                reason: format!(
                    "must be less than request_timeout_secs minus the {termination_grace_secs}s \
                     worker termination grace (request_timeout_secs must be at least \
                     {minimum_timeout_secs})"
                ),
            });
        }
        if self.max_concurrent_executions == 0 {
            return Err(ConfigError::Invalid {
                field: "max_concurrent_executions",
                reason: "must be greater than zero".to_owned(),
            });
        }
        // Same fail-closed rule as upload slots: a value above the
        // semaphore ceiling is a startup error, not a runtime panic.
        if self.max_concurrent_executions > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConfigError::Invalid {
                field: "max_concurrent_executions",
                reason: format!(
                    "must be at most {} (semaphore permit ceiling)",
                    tokio::sync::Semaphore::MAX_PERMITS
                ),
            });
        }
        // `Semaphore::new` panics above its own permit ceiling; keep an
        // absurd configuration value a startup error instead of a panic.
        if self.max_concurrent_uploads > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConfigError::Invalid {
                field: "max_concurrent_uploads",
                reason: format!(
                    "must be at most {} (semaphore permit ceiling)",
                    tokio::sync::Semaphore::MAX_PERMITS
                ),
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
        self.trust_store()?;
        Ok(())
    }

    /// Builds the runtime trust store from the configured key records.
    /// Validates standard-base64 encoding, the 32-byte Ed25519 key size, and
    /// non-empty unique key ids, so startup never proceeds with a key that
    /// cannot verify or a lookup that could resolve ambiguously.
    pub fn trust_store(&self) -> Result<ConfiguredTrustedKeys, ConfigError> {
        let keys = self
            .trusted_keys
            .iter()
            .map(TrustedKeyConfig::to_signing_key)
            .collect::<Result<Vec<_>, _>>()?;
        ConfiguredTrustedKeys::new(keys).map_err(|err| match err {
            TrustStoreError::EmptyKeyId => ConfigError::Invalid {
                field: "trusted_keys.key_id",
                reason: "must not be empty".to_owned(),
            },
            TrustStoreError::DuplicateKeyId(key_id) => ConfigError::Invalid {
                field: "trusted_keys.key_id",
                reason: format!("duplicate key id: {key_id}"),
            },
        })
    }

    /// Creates and tightens the managed storage layout: the storage root,
    /// `quarantine/`, `artifacts/`, `database/`, and `staging/`. Directories
    /// are created if missing and set to owner-only (`0700`) on Unix,
    /// including directories that already exist. Idempotent; any I/O failure
    /// is fatal at startup.
    pub fn ensure_layout(&self) -> Result<(), ConfigError> {
        for path in [
            self.storage_root.clone(),
            self.quarantine_dir(),
            self.artifact_dir(),
            self.database_dir(),
            self.staging_dir(),
        ] {
            create_private_dir(&path)?;
        }
        Ok(())
    }

    /// Directory holding untrusted uploads awaiting validation. Created by
    /// [`ensure_layout`](Self::ensure_layout); never served or executed from.
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

    /// Owner-only staging root for verified extraction
    /// ([`extract_verified`](crate::storage::staging::extract_verified)).
    #[must_use]
    pub fn staging_dir(&self) -> PathBuf {
        self.storage_root.join("staging")
    }

    /// Directory holding the SQLite database.
    #[must_use]
    pub fn database_dir(&self) -> PathBuf {
        self.storage_root.join("database")
    }

    /// SQLite database path. Migrations run at startup over the one
    /// process-wide connection.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.database_dir().join("conductor.db")
    }
}

/// Creates `path` and makes it owner-only on Unix. Existing directories are
/// tightened too: storage roots hold untrusted uploads and immutable
/// artifacts, so a permissive umask must not weaken them.
fn create_private_dir(path: &Path) -> Result<(), ConfigError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(ConfigError::Layout {
                    path: path.display().to_string(),
                    detail: "must not be a symlink".to_owned(),
                });
            }
            if !metadata.is_dir() {
                return Err(ConfigError::Layout {
                    path: path.display().to_string(),
                    detail: "must be a directory".to_owned(),
                });
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                // A world-writable existing root may already be shared with
                // other users; tightening it silently would not make the
                // bytes that were there before private.
                if metadata.permissions().mode() & 0o002 != 0 {
                    return Err(ConfigError::Layout {
                        path: path.display().to_string(),
                        detail: "must not be world-writable".to_owned(),
                    });
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(ConfigError::Layout {
                path: path.display().to_string(),
                detail: err.to_string(),
            });
        }
    }
    std::fs::create_dir_all(path).map_err(|err| ConfigError::Layout {
        path: path.display().to_string(),
        detail: err.to_string(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
            ConfigError::Layout {
                path: path.display().to_string(),
                detail: err.to_string(),
            }
        })?;
    }
    Ok(())
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
    quarantine_ttl_secs: Option<u64>,
    staging_ttl_secs: Option<u64>,
    allowed_runtimes: Option<Vec<String>>,
    max_execution_deadline_secs: Option<u64>,
    max_concurrent_executions: Option<usize>,
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
    #[error("storage layout {path}: {detail}")]
    Layout { path: String, detail: String },
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

/// Normalizes a JSON runtime list: surrounding whitespace is removed and
/// empty entries are dropped. An all-empty list then fails startup validation
/// instead of silently allowing nothing.
fn normalize_runtimes(runtimes: Vec<String>) -> Vec<String> {
    runtimes
        .into_iter()
        .map(|runtime| runtime.trim().to_owned())
        .filter(|runtime| !runtime.is_empty())
        .collect()
}

/// Parses the comma-separated `CONDUCTOR_ALLOWED_RUNTIMES` form. Empty
/// entries are ignored, matching the JSON normalization above; the result is
/// still subject to startup validation.
fn parse_runtime_env(raw: &str) -> Vec<String> {
    normalize_runtimes(raw.split(',').map(ToOwned::to_owned).collect())
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

    const VALID_PUBLIC_KEY_BASE64: &str = "GX9rI+FshTLGq8g4+s1ep4m+DHaykgM0A5v6iz02jWE=";

    fn startup_ready_config() -> Config {
        Config {
            api_token: Some("startup-token".to_owned()),
            trusted_keys: vec![TrustedKeyConfig {
                key_id: "k1".to_owned(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_base64: VALID_PUBLIC_KEY_BASE64.to_owned(),
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
        assert_eq!(config.staging_dir(), config.storage_root.join("staging"));
        assert_eq!(config.database_dir(), config.storage_root.join("database"));
        assert_eq!(
            config.database_path(),
            config.storage_root.join("database").join("conductor.db")
        );
    }

    #[test]
    fn ensure_layout_creates_owner_only_storage_dirs() {
        let root = temp_path("layout");
        let config = Config {
            storage_root: root.clone(),
            ..Config::default()
        };
        config.ensure_layout().expect("layout must be created");

        for dir in [
            config.storage_root.clone(),
            config.quarantine_dir(),
            config.artifact_dir(),
            config.database_dir(),
            config.staging_dir(),
        ] {
            assert!(dir.is_dir(), "{} must be a directory", dir.display());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&dir)
                    .expect("directory metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o700, "{} must be owner-only", dir.display());
            }
        }

        config
            .ensure_layout()
            .expect("layout creation is idempotent");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_layout_tightens_an_existing_storage_root() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp_path("layout-existing");
        std::fs::create_dir_all(&root).expect("root must be created");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("root permissions must be relaxed for the test");

        let config = Config {
            storage_root: root.clone(),
            ..Config::default()
        };
        config.ensure_layout().expect("layout must be tightened");

        let mode = std::fs::metadata(&root)
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "existing root must become owner-only");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_layout_rejects_a_world_writable_existing_root() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp_path("layout-world-writable");
        std::fs::create_dir_all(&root).expect("root must be created");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777))
            .expect("root permissions must be widened for the test");
        let config = Config {
            storage_root: root.clone(),
            ..Config::default()
        };

        assert!(matches!(
            config.ensure_layout(),
            Err(ConfigError::Layout { ref detail, .. })
                if detail.contains("world-writable")
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_layout_rejects_a_symlinked_root() {
        let target = temp_path("layout-symlink-target");
        let link = temp_path("layout-symlink-link");
        std::fs::create_dir_all(&target).expect("target must be created");
        std::os::unix::fs::symlink(&target, &link).expect("symlink must be created");

        let config = Config {
            storage_root: link.clone(),
            ..Config::default()
        };
        assert!(matches!(
            config.ensure_layout(),
            Err(ConfigError::Layout { ref detail, .. })
                if detail.contains("symlink")
        ));
        assert!(target.is_dir(), "the symlink target must not be touched");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn ensure_layout_reports_an_unusable_storage_root() {
        let root = temp_path("layout-file");
        std::fs::write(&root, b"not a directory").expect("blocking file must be written");
        let config = Config {
            storage_root: root.clone(),
            ..Config::default()
        };
        assert!(matches!(
            config.ensure_layout(),
            Err(ConfigError::Layout { .. })
        ));
        cleanup(&root);
    }

    #[test]
    fn default_timeout_slots_and_ttls_are_nonzero() {
        let config = Config::default();
        assert!(config.request_timeout_secs > 0);
        assert!(config.max_concurrent_uploads > 0);
        assert!(config.quarantine_ttl_secs > 0);
        assert!(config.staging_ttl_secs > 0);
    }

    #[test]
    fn execution_defaults_are_safe_and_nonzero() {
        let config = Config::default();
        assert_eq!(config.allowed_runtimes, vec!["rust".to_owned()]);
        assert_eq!(config.max_execution_deadline_secs, 300);
        assert_eq!(config.max_concurrent_executions, 4);
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Missing("api_token"))
        ));
    }

    #[test]
    fn empty_allowed_runtimes_are_rejected() {
        let config = Config {
            allowed_runtimes: Vec::new(),
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "allowed_runtimes",
                ..
            })
        ));
    }

    #[test]
    fn zero_execution_deadline_is_rejected() {
        let config = Config {
            max_execution_deadline_secs: 0,
            ..startup_ready_config()
        };
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "max_execution_deadline_secs",
                ..
            })
        ));
    }

    #[test]
    fn execution_deadline_must_fit_inside_the_request_timeout() {
        let grace = crate::executions::executor::ExecutionLimits::default()
            .terminate_grace
            .as_secs();

        let invalid = Config {
            max_execution_deadline_secs: 300,
            request_timeout_secs: 30,
            ..startup_ready_config()
        };
        assert!(matches!(
            invalid.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "max_execution_deadline_secs",
                ref reason,
            }) if reason.contains("request_timeout_secs")
        ));

        // The boundary is strict: deadline + grace must be less than the
        // request timeout, because teardown needs the remaining second.
        let boundary = Config {
            max_execution_deadline_secs: 30,
            request_timeout_secs: 30 + grace,
            ..startup_ready_config()
        };
        assert!(matches!(
            boundary.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "max_execution_deadline_secs",
                ..
            })
        ));

        let accepted = Config {
            max_execution_deadline_secs: 30,
            request_timeout_secs: 30 + grace + 1,
            ..startup_ready_config()
        };
        accepted
            .validate_for_startup()
            .expect("one second beyond the grace boundary must be accepted");
    }

    #[test]
    fn default_execution_deadline_has_room_for_grace_and_request_teardown() {
        let config = Config {
            api_token: Some("startup-token".to_owned()),
            trusted_keys: startup_ready_config().trusted_keys,
            ..Config::default()
        };
        config
            .validate_for_startup()
            .expect("default execution deadline and request timeout must agree");
    }

    #[test]
    fn execution_slots_outside_the_semaphore_range_are_rejected() {
        for value in [0, tokio::sync::Semaphore::MAX_PERMITS.saturating_add(1)] {
            let config = Config {
                max_concurrent_executions: value,
                ..startup_ready_config()
            };
            assert!(matches!(
                config.validate_for_startup(),
                Err(ConfigError::Invalid {
                    field: "max_concurrent_executions",
                    ..
                })
            ));
        }

        let config = Config {
            max_concurrent_executions: tokio::sync::Semaphore::MAX_PERMITS,
            ..startup_ready_config()
        };
        config
            .validate_for_startup()
            .expect("the semaphore ceiling itself is valid");
    }

    #[test]
    fn zero_workspace_ttls_are_rejected() {
        for config in [
            Config {
                quarantine_ttl_secs: 0,
                ..startup_ready_config()
            },
            Config {
                staging_ttl_secs: 0,
                ..startup_ready_config()
            },
        ] {
            assert!(matches!(
                config.validate_for_startup(),
                Err(ConfigError::Invalid {
                    field: "quarantine_ttl_secs" | "staging_ttl_secs",
                    ..
                })
            ));
        }
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
    fn trust_store_converts_and_validates_configured_keys() {
        let config = startup_ready_config();
        let store = config.trust_store().expect("valid key must build");
        let key = store.key("k1").expect("configured key must resolve");
        assert_eq!(key.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(key.public_key.len(), 32);
        assert_eq!(
            key.public_key,
            BASE64_STANDARD
                .decode(VALID_PUBLIC_KEY_BASE64)
                .expect("test constant must be valid base64")
        );
    }

    #[test]
    fn invalid_base64_key_material_is_rejected() {
        let mut config = startup_ready_config();
        config.trusted_keys[0].public_key_base64 = "not base64!".to_owned();
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "trusted_keys.public_key_base64",
                ..
            })
        ));
    }

    #[test]
    fn wrong_length_ed25519_key_material_is_rejected() {
        let mut config = startup_ready_config();
        config.trusted_keys[0].public_key_base64 = BASE64_STANDARD.encode([1u8; 31]);
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "trusted_keys.public_key_base64",
                ..
            })
        ));
    }

    #[test]
    fn whitespace_padded_key_ids_are_trimmed_to_the_http_selectable_form() {
        let mut config = startup_ready_config();
        config.trusted_keys[0].key_id = "  k1 \n".to_owned();

        let store = config
            .trust_store()
            .expect("surrounding whitespace must not make the key unusable");
        assert!(
            store.key("k1").is_some(),
            "the HTTP key_id is trimmed before lookup"
        );
        assert!(store.key("  k1 \n").is_none());
    }

    #[test]
    fn whitespace_variants_of_one_key_id_are_duplicates_after_trimming() {
        let mut config = startup_ready_config();
        let mut duplicate = config.trusted_keys[0].clone();
        duplicate.key_id = " k1 ".to_owned();
        config.trusted_keys.push(duplicate);

        assert!(matches!(
            config.trust_store(),
            Err(ConfigError::Invalid {
                field: "trusted_keys.key_id",
                ref reason,
            }) if reason.contains("duplicate")
        ));
    }

    #[test]
    fn overlong_key_ids_are_rejected_at_startup() {
        let mut config = startup_ready_config();
        config.trusted_keys[0].key_id = "k".repeat(MAX_KEY_ID_BYTES + 1);

        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "trusted_keys.key_id",
                ..
            })
        ));
    }

    #[test]
    fn key_id_at_the_byte_bound_is_accepted() {
        let mut config = startup_ready_config();
        config.trusted_keys[0].key_id = "k".repeat(MAX_KEY_ID_BYTES);

        config
            .validate_for_startup()
            .expect("exactly MAX_KEY_ID_BYTES is selectable through the HTTP field");
    }

    #[test]
    fn duplicate_trusted_key_ids_are_rejected() {
        let mut config = startup_ready_config();
        let mut duplicate = config.trusted_keys[0].clone();
        duplicate.public_key_base64 = BASE64_STANDARD.encode([2u8; 32]);
        config.trusted_keys.push(duplicate);
        assert!(matches!(
            config.validate_for_startup(),
            Err(ConfigError::Invalid {
                field: "trusted_keys.key_id",
                ref reason,
            }) if reason.contains("duplicate")
        ));
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
                "quarantine_ttl_secs": 5,
                "staging_ttl_secs": 6,
                "allowed_runtimes": ["rust", "python"],
                "max_execution_deadline_secs": 90,
                "max_concurrent_executions": 2,
                "api_token": "file-token",
                "trusted_keys": [{
                    "key_id": "file-key",
                    "algorithm": "ed25519",
                    "public_key_base64": VALID_PUBLIC_KEY_BASE64
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
        assert_eq!(config.quarantine_ttl_secs, 5);
        assert_eq!(config.staging_ttl_secs, 6);
        assert_eq!(
            config.allowed_runtimes,
            vec!["rust".to_owned(), "python".to_owned()]
        );
        assert_eq!(config.max_execution_deadline_secs, 90);
        assert_eq!(config.max_concurrent_executions, 2);
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
    fn environment_parses_execution_settings() {
        let config = Config::load_with(
            None,
            [
                (
                    ENV_ALLOWED_RUNTIMES.to_owned(),
                    " rust, python ,,".to_owned(),
                ),
                (ENV_MAX_EXECUTION_DEADLINE_SECS.to_owned(), "45".to_owned()),
                (ENV_MAX_CONCURRENT_EXECUTIONS.to_owned(), "2".to_owned()),
            ],
        )
        .expect("execution environment overrides must load");

        assert_eq!(
            config.allowed_runtimes,
            vec!["rust".to_owned(), "python".to_owned()]
        );
        assert_eq!(config.max_execution_deadline_secs, 45);
        assert_eq!(config.max_concurrent_executions, 2);
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
    fn invalid_numeric_execution_environment_value_is_reported() {
        let result = Config::load_with(
            None,
            [(ENV_MAX_CONCURRENT_EXECUTIONS.to_owned(), "many".to_owned())],
        );
        assert!(matches!(
            result,
            Err(ConfigError::Invalid {
                field: ENV_MAX_CONCURRENT_EXECUTIONS,
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
            &serde_json::json!([{
                "key_id": "env-key",
                "algorithm": "ed25519",
                "public_key_base64": VALID_PUBLIC_KEY_BASE64
            }])
            .to_string(),
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
                public_key_base64: VALID_PUBLIC_KEY_BASE64.to_owned(),
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
    fn upload_slots_above_the_semaphore_ceiling_are_rejected() {
        let config = Config {
            max_concurrent_uploads: tokio::sync::Semaphore::MAX_PERMITS.saturating_add(1),
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
    fn upload_slots_at_the_semaphore_ceiling_are_accepted() {
        let config = Config {
            max_concurrent_uploads: tokio::sync::Semaphore::MAX_PERMITS,
            ..startup_ready_config()
        };

        config
            .validate_for_startup()
            .expect("the semaphore ceiling itself is valid");
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

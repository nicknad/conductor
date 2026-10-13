//! Versioned stdin/stdout IPC protocol between the host and worker
//! processes.
//!
//! One execution is one worker process. The host writes exactly one
//! [`ExecutionRequest`] line to the worker's stdin and then closes it; the
//! worker writes exactly one [`ExecutionResponse`] line to stdout. stderr
//! is diagnostics and never protocol. Lines are newline-delimited JSON —
//! one message per line, no embedded newlines — and their size, along with
//! stderr volume and wall time, is bounded by the executor
//! (`executor::ExecutionLimits`), not by this module.
//!
//! Secrets travel only inside the `secrets` map of the request, over the
//! private stdin pipe: never in command-line arguments, and never in the
//! worker environment. [`ExecutionRequest`]'s `Debug` redacts secret values
//! so a request can be logged or dumped without leaking them.
//!
//! The protocol version gate is explicit in both directions: a message
//! from another version is rejected, not best-effort parsed.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire version of the stdin/stdout protocol. Bumped only for incompatible
/// message-shape changes; this host refuses messages from any other version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum accepted byte length of an identity field (`execution_id`,
/// `module_id`, `version`, `function`, and secret names) in a request.
pub const MAX_FIELD_BYTES: usize = 256;

/// Identity of the invocation the request describes. Built by whoever
/// resolves the execution (registry/control_plane); the executor only
/// transports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub execution_id: String,
    pub module_id: String,
    pub version: String,
    /// Lowercase hex of the artifact digest (64 characters): pins the
    /// execution to exact bytes for audit.
    pub digest_hex: String,
    pub function: String,
}

/// One host-to-worker execution request, serialized as a single JSON line
/// on stdin.
///
/// `configuration` is job configuration (never secrets); `secrets` carries
/// exactly the values this execution needs and nothing else.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub protocol_version: u32,
    pub execution_id: String,
    pub module_id: String,
    pub version: String,
    pub digest_hex: String,
    pub function: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub configuration: serde_json::Value,
    /// Execution-time bound in milliseconds from request receipt. The
    /// executor enforces the same duration on the host side.
    pub deadline_ms: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

impl ExecutionRequest {
    /// Builds a request with the current protocol version and no secrets.
    /// `deadline` is converted to whole milliseconds (never below 1 for a
    /// non-zero duration); [`validate`](Self::validate) rejects a zero
    /// deadline.
    #[must_use]
    pub fn new(
        invocation: Invocation,
        configuration: serde_json::Value,
        deadline: Duration,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            execution_id: invocation.execution_id,
            module_id: invocation.module_id,
            version: invocation.version,
            digest_hex: invocation.digest_hex,
            function: invocation.function,
            configuration,
            deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            secrets: BTreeMap::new(),
        }
    }

    /// Attaches the secrets required by this execution. They ride only the
    /// request: not argv, not the environment.
    #[must_use]
    pub fn with_secrets(mut self, secrets: BTreeMap<String, String>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Checks the request is well-shaped before anything is spawned: the
    /// version matches, identity fields are present and bounded, the
    /// digest is lowercase hex, and the deadline is at least one
    /// millisecond.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                found: self.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }
        for (name, value) in [
            ("execution_id", self.execution_id.as_str()),
            ("module_id", self.module_id.as_str()),
            ("version", self.version.as_str()),
            ("function", self.function.as_str()),
        ] {
            if value.is_empty() {
                return Err(ProtocolError::Invalid(format!("{name} must not be empty")));
            }
            if value.len() > MAX_FIELD_BYTES {
                return Err(ProtocolError::Invalid(format!(
                    "{name} exceeds the {MAX_FIELD_BYTES} byte bound"
                )));
            }
        }
        if !is_lowercase_hex_64(&self.digest_hex) {
            return Err(ProtocolError::Invalid(
                "digest_hex must be 64 lowercase hex characters".to_owned(),
            ));
        }
        if self.deadline_ms == 0 {
            return Err(ProtocolError::Invalid(
                "deadline_ms must be at least 1".to_owned(),
            ));
        }
        if self
            .secrets
            .keys()
            .any(|name| name.is_empty() || name.len() > MAX_FIELD_BYTES)
        {
            return Err(ProtocolError::Invalid(
                "secret names must be non-empty and bounded".to_owned(),
            ));
        }
        Ok(())
    }

    /// Encodes the request as exactly one newline-terminated JSON line.
    pub fn to_line(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut line =
            serde_json::to_vec(self).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
        line.push(b'\n');
        Ok(line)
    }
}

impl fmt::Debug for ExecutionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionRequest")
            .field("protocol_version", &self.protocol_version)
            .field("execution_id", &self.execution_id)
            .field("module_id", &self.module_id)
            .field("version", &self.version)
            .field("digest_hex", &self.digest_hex)
            .field("function", &self.function)
            .field("configuration", &self.configuration)
            .field("deadline_ms", &self.deadline_ms)
            .field(
                "secrets",
                &format_args!("[{} redacted]", self.secrets.len()),
            )
            .finish()
    }
}

/// One worker-to-host response, parsed from a single stdout line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionResponse {
    /// The function ran and returned a JSON result (`null` for none).
    Ok { result: serde_json::Value },
    /// The function failed; `message` is the sanitized reason.
    Failed { message: String },
}

/// Raw wire shape of a response. Parsed fail-closed, then validated into
/// [`ExecutionResponse`] so status and payload cannot contradict.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponse {
    protocol_version: u32,
    status: String,
    #[serde(default)]
    result: serde_json::Value,
    #[serde(default)]
    message: Option<String>,
}

/// Parses one response line (without its trailing newline). Unknown
/// versions, unknown fields, unknown statuses, and contradictory shapes
/// (`ok` with a message, `failed` without one) are protocol errors.
pub fn decode_response(bytes: &[u8]) -> Result<ExecutionResponse, ProtocolError> {
    let raw: RawResponse = serde_json::from_slice(bytes)
        .map_err(|e| ProtocolError::Invalid(format!("malformed response: {e}")))?;
    if raw.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            found: raw.protocol_version,
            supported: PROTOCOL_VERSION,
        });
    }
    match raw.status.as_str() {
        "ok" => {
            if raw.message.is_some() {
                return Err(ProtocolError::Invalid(
                    "ok response must not carry a message".to_owned(),
                ));
            }
            Ok(ExecutionResponse::Ok { result: raw.result })
        }
        "failed" => {
            let message = raw
                .message
                .filter(|message| !message.is_empty())
                .ok_or_else(|| {
                    ProtocolError::Invalid(
                        "failed response must carry a non-empty message".to_owned(),
                    )
                })?;
            if !raw.result.is_null() {
                return Err(ProtocolError::Invalid(
                    "failed response must not carry a result".to_owned(),
                ));
            }
            Ok(ExecutionResponse::Failed { message })
        }
        other => Err(ProtocolError::Invalid(format!(
            "unknown response status {other:?}"
        ))),
    }
}

/// Exactly 64 lowercase hex characters, matching `ArtifactDigest::to_hex`.
fn is_lowercase_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version {found} (supported: {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("invalid protocol message: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> Invocation {
        Invocation {
            execution_id: "exec-1".to_owned(),
            module_id: "reporting-service".to_owned(),
            version: "1.2.0".to_owned(),
            digest_hex: "ab".repeat(32),
            function: "report".to_owned(),
        }
    }

    fn request() -> ExecutionRequest {
        ExecutionRequest::new(
            invocation(),
            serde_json::json!({"batch": 7}),
            Duration::from_millis(1500),
        )
    }

    #[test]
    fn request_round_trips_through_one_line() {
        let request =
            request().with_secrets(BTreeMap::from([("db".to_owned(), "hunter2".to_owned())]));
        request.validate().expect("request must be valid");
        let line = request.to_line().expect("request must encode");
        assert!(line.ends_with(b"\n"), "line must be newline-terminated");
        assert_eq!(
            line.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "one message is exactly one line"
        );
        let decoded: ExecutionRequest =
            serde_json::from_slice(&line).expect("request line must decode");
        assert_eq!(decoded, request);
        assert_eq!(decoded.configuration["batch"], 7);
        // Secrets do reach the worker — over stdin, the sanctioned channel.
        assert_eq!(decoded.secrets["db"], "hunter2");
    }

    #[test]
    fn request_debug_redacts_secret_values() {
        let request =
            request().with_secrets(BTreeMap::from([("db".to_owned(), "hunter2".to_owned())]));
        let debug = format!("{request:?}");
        assert!(debug.contains("[1 redacted]"));
        assert!(!debug.contains("hunter2"));
    }

    #[test]
    fn request_validation_rejects_out_of_shape_fields() {
        let mutate = |edit: &dyn Fn(&mut ExecutionRequest)| {
            let mut request = request();
            edit(&mut request);
            request.validate()
        };
        assert!(matches!(
            mutate(&|request| request.protocol_version = 2),
            Err(ProtocolError::UnsupportedVersion { found: 2, .. })
        ));
        assert!(mutate(&|request| request.execution_id = String::new()).is_err());
        assert!(mutate(&|request| request.module_id = "m".repeat(MAX_FIELD_BYTES + 1)).is_err());
        assert!(mutate(&|request| request.version = String::new()).is_err());
        assert!(mutate(&|request| request.function = String::new()).is_err());
        assert!(mutate(&|request| request.digest_hex = "AB".repeat(32)).is_err());
        assert!(mutate(&|request| request.digest_hex = "ab".repeat(31)).is_err());
        assert!(mutate(&|request| request.deadline_ms = 0).is_err());
        assert!(mutate(&|request| {
            request.secrets.insert(String::new(), "value".to_owned());
        })
        .is_err());
    }

    #[test]
    fn responses_decode_ok_and_failed() {
        let ok = decode_response(br#"{"protocol_version":1,"status":"ok","result":{"rows":3}}"#)
            .expect("ok response must decode");
        assert_eq!(
            ok,
            ExecutionResponse::Ok {
                result: serde_json::json!({"rows": 3}),
            }
        );
        // A result-less ok is a null result, not an error.
        let bare = decode_response(br#"{"protocol_version":1,"status":"ok"}"#)
            .expect("result-less ok must decode");
        assert_eq!(
            bare,
            ExecutionResponse::Ok {
                result: serde_json::Value::Null,
            }
        );
        let failed =
            decode_response(br#"{"protocol_version":1,"status":"failed","message":"bad input"}"#)
                .expect("failed response must decode");
        assert_eq!(
            failed,
            ExecutionResponse::Failed {
                message: "bad input".to_owned(),
            }
        );
    }

    #[test]
    fn responses_reject_wrong_version_shape_and_junk() {
        for bad in [
            br#"{"protocol_version":2,"status":"ok"}"#.as_slice(),
            br#"{"protocol_version":1,"status":"maybe"}"#.as_slice(),
            br#"{"protocol_version":1,"status":"ok","message":"nope"}"#.as_slice(),
            br#"{"protocol_version":1,"status":"failed"}"#.as_slice(),
            br#"{"protocol_version":1,"status":"failed","message":""}"#.as_slice(),
            br#"{"protocol_version":1,"status":"failed","message":"x","result":1}"#.as_slice(),
            br#"{"protocol_version":1,"status":"ok","extra":true}"#.as_slice(),
            br#"{"status":"ok"}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            assert!(
                decode_response(bad).is_err(),
                "must reject {}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}

//! Rejection event taxonomy.
//!
//! One event describes one refused package upload: where the pipeline
//! stopped (`stage`), the stable code surfaced to the caller (`code`), and
//! the internal reason operators need (`detail`). Attribution fields
//! (`key_id`, module identity, digest, byte count) are populated only when
//! the rejection happened after that fact was established, so they double
//! as evidence of how far the pipeline got.

use std::time::SystemTime;

/// Event schema version. Bumped only for incompatible field changes so
/// stored records stay interpretable.
pub const REJECTION_EVENT_VERSION: u16 = 1;

/// Longest retained `detail`. Longer reasons are truncated on a character
/// boundary and flagged with [`RejectionEvent::detail_truncated`].
pub const MAX_DETAIL_BYTES: usize = 4096;

/// Where the upload pipeline stopped. `Transport` covers responses
/// produced by transport layers (auth, headers, timeouts, body limits) that
/// never reached the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionStage {
    Transport,
    Multipart,
    Streaming,
    Policy,
    Archive,
    Digest,
    Signature,
    Manifest,
    Inventory,
    Promotion,
    Registration,
    Internal,
}

impl RejectionStage {
    /// Stable lowercase wire name; also used in structured logs.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Multipart => "multipart",
            Self::Streaming => "streaming",
            Self::Policy => "policy",
            Self::Archive => "archive",
            Self::Digest => "digest",
            Self::Signature => "signature",
            Self::Manifest => "manifest",
            Self::Inventory => "inventory",
            Self::Promotion => "promotion",
            Self::Registration => "registration",
            Self::Internal => "internal",
        }
    }
}

/// One refusal of one upload. Built at the rejection site and recorded once
/// via the tracing-only recorder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectionEvent {
    pub event_version: u16,
    pub occurred_at: SystemTime,
    /// Server-issued request id (`x-request-id`), for incident correlation.
    pub request_id: Option<String>,
    pub stage: RejectionStage,
    /// Stable machine code; matches the response body's `code`.
    pub code: &'static str,
    /// Internal reason, bounded to [`MAX_DETAIL_BYTES`].
    pub detail: String,
    pub detail_truncated: bool,
    /// Claimed signer key id, recorded for audit attribution only.
    pub key_id: Option<String>,
    pub module_id: Option<String>,
    pub version: Option<String>,
    /// Hex digest, set once the digest stage was reached.
    pub digest: Option<String>,
    /// Package bytes received before the rejection, when streaming began.
    pub byte_count: Option<u64>,
}

impl RejectionEvent {
    #[must_use]
    pub fn new(stage: RejectionStage, code: &'static str, detail: impl Into<String>) -> Self {
        let (detail, detail_truncated) = bound_detail(detail.into());
        Self {
            event_version: REJECTION_EVENT_VERSION,
            occurred_at: SystemTime::now(),
            request_id: None,
            stage,
            code,
            detail,
            detail_truncated,
            key_id: None,
            module_id: None,
            version: None,
            digest: None,
            byte_count: None,
        }
    }

    #[must_use]
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    #[must_use]
    pub fn with_key_id(mut self, key_id: Option<String>) -> Self {
        self.key_id = key_id;
        self
    }

    #[must_use]
    pub fn with_module_id(mut self, module_id: Option<String>) -> Self {
        self.module_id = module_id;
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: Option<String>) -> Self {
        self.version = version;
        self
    }

    #[must_use]
    pub fn with_digest(mut self, digest: Option<String>) -> Self {
        self.digest = digest;
        self
    }

    #[must_use]
    pub fn with_byte_count(mut self, byte_count: Option<u64>) -> Self {
        self.byte_count = byte_count;
        self
    }
}

/// Truncates detail to the event bound on a character boundary, reporting
/// whether anything was dropped.
fn bound_detail(mut detail: String) -> (String, bool) {
    if detail.len() <= MAX_DETAIL_BYTES {
        return (detail, false);
    }
    let mut end = MAX_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    (detail, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_wire_names_are_stable() {
        for (stage, name) in [
            (RejectionStage::Transport, "transport"),
            (RejectionStage::Multipart, "multipart"),
            (RejectionStage::Streaming, "streaming"),
            (RejectionStage::Policy, "policy"),
            (RejectionStage::Archive, "archive"),
            (RejectionStage::Digest, "digest"),
            (RejectionStage::Signature, "signature"),
            (RejectionStage::Manifest, "manifest"),
            (RejectionStage::Inventory, "inventory"),
            (RejectionStage::Promotion, "promotion"),
            (RejectionStage::Registration, "registration"),
            (RejectionStage::Internal, "internal"),
        ] {
            assert_eq!(stage.as_str(), name);
        }
    }

    #[test]
    fn short_detail_is_not_truncated() {
        let event = RejectionEvent::new(RejectionStage::Archive, "archive_rejected", "bad zip");
        assert_eq!(event.detail, "bad zip");
        assert!(!event.detail_truncated);
        assert_eq!(event.event_version, REJECTION_EVENT_VERSION);
    }

    #[test]
    fn long_detail_truncates_on_a_character_boundary() {
        // A multi-byte character straddling the bound must not be split.
        let mut detail = "a".repeat(MAX_DETAIL_BYTES - 1);
        detail.push('é'); // two bytes; byte MAX arrives mid-character
        detail.push_str("tail");
        let event = RejectionEvent::new(RejectionStage::Manifest, "manifest_rejected", detail);
        assert!(event.detail_truncated);
        assert_eq!(event.detail.len(), MAX_DETAIL_BYTES - 1);
        assert!(event.detail.is_char_boundary(event.detail.len()));
    }

    #[test]
    fn builders_attach_attribution_fields() {
        let event = RejectionEvent::new(
            RejectionStage::Signature,
            "signature_verification_failed",
            "x",
        )
        .with_request_id(Some("req-1".to_owned()))
        .with_key_id(Some("k9".to_owned()))
        .with_module_id(Some("reporting-service".to_owned()))
        .with_version(Some("1.2.0".to_owned()))
        .with_digest(Some("ab".repeat(32)))
        .with_byte_count(Some(42));
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
        assert_eq!(event.key_id.as_deref(), Some("k9"));
        assert_eq!(event.module_id.as_deref(), Some("reporting-service"));
        assert_eq!(event.version.as_deref(), Some("1.2.0"));
        assert_eq!(event.digest.as_deref().expect("digest").len(), 64);
        assert_eq!(event.byte_count, Some(42));
    }
}

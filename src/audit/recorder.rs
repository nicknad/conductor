//! Emits rejection events as structured `tracing` records.
//!
//! The recorder is the single emission point for package rejections; the
//! persistence phase adds a durable sink (SQLite rows) behind the same
//! `record` call. Recording is best-effort by contract: it must never
//! change a response or propagate a failure.

use crate::audit::event::RejectionEvent;

/// Stateless in this phase; held by value behind an `Arc` in the app state
/// so durable-state sinks can arrive later without reshaping call sites.
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectionRecorder;

impl RejectionRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Records one rejection event. Emits the `conductor::audit`
    /// `package_rejected` tracing record with every event field.
    pub fn record(&self, event: &RejectionEvent) {
        tracing::warn!(
            target: "conductor::audit",
            package_event = "package_rejected",
            event_version = event.event_version,
            stage = event.stage.as_str(),
            code = event.code,
            detail = %event.detail,
            detail_truncated = event.detail_truncated,
            request_id = event.request_id.as_deref(),
            key_id = event.key_id.as_deref(),
            module_id = event.module_id.as_deref(),
            version = event.version.as_deref(),
            digest = event.digest.as_deref(),
            byte_count = event.byte_count,
            "package rejected"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::RejectionStage;
    use std::sync::{Arc, Mutex};

    /// `io::Write` sink shared with the test so the emitted record can be
    /// asserted on without touching global tracing state.
    #[derive(Clone)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture lock must not poison")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture(event: &RejectionEvent) -> String {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CaptureWriter(Arc::clone(&buffer)))
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || RejectionRecorder.record(event));
        let captured = buffer.lock().expect("capture lock").clone();
        String::from_utf8(captured).expect("utf8 output")
    }

    #[test]
    fn records_the_event_name_stage_code_and_reason() {
        let event = RejectionEvent::new(
            RejectionStage::Signature,
            "signature_verification_failed",
            "unknown signing key: k9",
        )
        .with_request_id(Some("req-1".to_owned()));
        let output = capture(&event);
        assert!(
            output.contains("package rejected"),
            "missing event name: {output}"
        );
        assert!(
            output.contains("stage=\"signature\""),
            "missing stage: {output}"
        );
        assert!(
            output.contains("code=\"signature_verification_failed\""),
            "missing code: {output}"
        );
        assert!(
            output.contains("detail=unknown signing key: k9"),
            "missing internal detail: {output}"
        );
    }

    #[test]
    fn records_none_fields_without_failing() {
        let event = RejectionEvent::new(RejectionStage::Transport, "server_busy", "busy");
        let output = capture(&event);
        assert!(
            output.contains("stage=\"transport\""),
            "missing stage: {output}"
        );
        assert!(
            output.contains("code=\"server_busy\""),
            "missing code: {output}"
        );
    }
}

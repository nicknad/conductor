//! Emits rejection events as structured `tracing` records and, when a
//! store is attached, as durable SQLite rows.
//!
//! The recorder is the single emission point for package rejections: one
//! rejection produces one tracing event plus at most one row. Recording is
//! best-effort by contract: it must never change a response or propagate
//! a failure. A locked database or full disk is therefore invisible to
//! callers — the tracing event is always emitted, the row insert is
//! attempted synchronously in one bounded transaction, and any store
//! failure is swallowed after a `tracing::error!`.

use std::sync::Arc;

use crate::audit::event::RejectionEvent;
use crate::audit::store::RejectionStore;

/// Rejection emission point. Tracing-only via [`new`](Self::new);
/// tracing plus a durable row via [`with_store`](Self::with_store). Held
/// by value behind an `Arc` in the app state.
#[derive(Debug, Clone, Default)]
pub struct RejectionRecorder {
    store: Option<Arc<RejectionStore>>,
}

impl RejectionRecorder {
    /// Tracing-only recorder. Existing call sites keep compiling; no row
    /// is written.
    #[must_use]
    pub fn new() -> Self {
        Self { store: None }
    }

    /// Recorder with a durable sink: every recorded event is also
    /// inserted into `package_rejections`, best-effort.
    #[must_use]
    pub fn with_store(store: Arc<RejectionStore>) -> Self {
        Self { store: Some(store) }
    }

    /// Attached durable sink, if any. Integration tests read rows back
    /// through this handle.
    #[must_use]
    pub fn store(&self) -> Option<&Arc<RejectionStore>> {
        self.store.as_ref()
    }

    /// Records one rejection event. Always emits the `conductor::audit`
    /// `package_rejected` tracing record with every event field; then, if
    /// a store is attached, attempts the row insert and swallows any
    /// failure after logging it. Never panics, never propagates, never
    /// alters the response.
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
        if let Some(store) = &self.store {
            if let Err(err) = store.record(event) {
                tracing::error!(error = %err, "rejection row write failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::RejectionStage;
    use crate::storage::database::Database;
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

    fn capture(recorder: &RejectionRecorder, event: &RejectionEvent) -> String {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CaptureWriter(Arc::clone(&buffer)))
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || recorder.record(event));
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
        let output = capture(&RejectionRecorder::new(), &event);
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
        let output = capture(&RejectionRecorder::new(), &event);
        assert!(
            output.contains("stage=\"transport\""),
            "missing stage: {output}"
        );
        assert!(
            output.contains("code=\"server_busy\""),
            "missing code: {output}"
        );
    }

    #[test]
    fn store_backed_record_emits_tracing_and_writes_one_row() {
        let store = Arc::new(RejectionStore::open_in_memory().expect("store must open"));
        let recorder = RejectionRecorder::with_store(Arc::clone(&store));
        let event = RejectionEvent::new(
            RejectionStage::Registration,
            "version_conflict",
            "version taken",
        )
        .with_module_id(Some("reporting-service".to_owned()));
        let output = capture(&recorder, &event);
        assert!(output.contains("package rejected"), "{output}");
        let rows = store.list().expect("rows must read");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].stage, "registration");
        assert_eq!(rows[0].code, "version_conflict");
        assert_eq!(rows[0].module_id.as_deref(), Some("reporting-service"));
    }

    #[test]
    fn store_failure_is_invisible_to_callers_but_tracing_survives() {
        // Failure injection: a database that was never migrated has no
        // `package_rejections` table, so every insert fails like a locked
        // database or full disk would.
        let database = Database::open_in_memory().expect("database must open");
        let store = Arc::new(RejectionStore::new(Arc::new(database)));
        let event = RejectionEvent::new(RejectionStage::Transport, "server_busy", "busy");
        assert!(
            store.record(&event).is_err(),
            "the injected failure must be real"
        );
        let recorder = RejectionRecorder::with_store(store);
        // Must return normally (no panic, no Result to propagate).
        let output = capture(&recorder, &event);
        assert!(
            output.contains("package rejected"),
            "tracing must survive store failure: {output}"
        );
        assert!(
            output.contains("stage=\"transport\""),
            "missing stage: {output}"
        );
    }
}

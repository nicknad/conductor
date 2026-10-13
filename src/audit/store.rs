//! Durable sink for package rejection events.
//!
//! [`RejectionStore`] owns the `INSERT INTO package_rejections` over the
//! shared [`Database`](crate::storage::database::Database) connection. One
//! event becomes at most one row, mapped 1:1 from
//! [`RejectionEvent`](crate::audit::event::RejectionEvent): the stage via
//! `as_str()`, `detail_truncated` as `0`/`1`, timestamps as unix millis via
//! the shared [`to_millis`](crate::storage::database::to_millis)
//! convention, and `byte_count` saturating at `i64::MAX` like the
//! registry's size columns.
//!
//! The event shape is already free of PII, secrets, signature bytes, and
//! package contents (key id, module identity, digest, and byte count are
//! audit attribution only); this sink adds no fields, so nothing new can
//! leak into rows.
//!
//! Writes run synchronously as a single-row immediate transaction on the
//! existing mutex connection — no new threads or pools. Callers (see
//! [`RejectionRecorder`](crate::audit::recorder::RejectionRecorder)) treat
//! failures as best-effort: logged, never propagated.

use std::sync::Arc;

use rusqlite::params;

use crate::audit::event::RejectionEvent;
use crate::storage::database::{from_millis, to_millis, Database, DatabaseError};

/// Durable rejection sink. Thread-safe via the underlying [`Database`];
/// always shared behind an [`Arc`].
#[derive(Debug)]
pub struct RejectionStore {
    database: Arc<Database>,
}

/// One persisted rejection row, read back with [`RejectionStore::list`].
/// Field types mirror the event shape; `occurred_at` is the
/// millis-truncated event time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRejection {
    pub id: i64,
    pub occurred_at: std::time::SystemTime,
    pub event_version: u16,
    pub request_id: Option<String>,
    pub stage: String,
    pub code: String,
    pub detail: String,
    pub detail_truncated: bool,
    pub key_id: Option<String>,
    pub module_id: Option<String>,
    pub version: Option<String>,
    pub digest: Option<String>,
    pub byte_count: Option<u64>,
}

const SELECT_REJECTIONS: &str = "SELECT id, occurred_at, event_version, request_id, \
     stage, code, detail, detail_truncated, key_id, module_id, version, digest, byte_count \
     FROM package_rejections";

impl RejectionStore {
    /// Wraps an already-migrated database handle.
    #[must_use]
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }

    /// Private in-memory store with the real storage semantics and no
    /// files. For tests and ephemeral hosts.
    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let database = Database::open_in_memory()?;
        database.migrate()?;
        Ok(Self::new(Arc::new(database)))
    }

    /// Persists one event as one row. One immediate transaction, bounded
    /// to a single insert.
    pub fn record(&self, event: &RejectionEvent) -> Result<(), DatabaseError> {
        let truncated: i64 = if event.detail_truncated { 1 } else { 0 };
        let byte_count = event
            .byte_count
            .map(|b| i64::try_from(b).unwrap_or(i64::MAX));
        self.database.with_write_tx(|tx| {
            tx.execute(
                "INSERT INTO package_rejections (
                    occurred_at, event_version, request_id, stage, code,
                    detail, detail_truncated, key_id, module_id, version,
                    digest, byte_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    to_millis(event.occurred_at),
                    i64::from(event.event_version),
                    event.request_id.as_deref(),
                    event.stage.as_str(),
                    event.code,
                    event.detail,
                    truncated,
                    event.key_id.as_deref(),
                    event.module_id.as_deref(),
                    event.version.as_deref(),
                    event.digest.as_deref(),
                    byte_count,
                ],
            )?;
            Ok(())
        })
    }

    /// Every persisted row, ordered by insertion id.
    pub fn list(&self) -> Result<Vec<StoredRejection>, DatabaseError> {
        self.database.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!("{SELECT_REJECTIONS} ORDER BY id"))
                .map_err(DatabaseError::from)?;
            let rows = statement
                .query_map([], row_to_rejection)
                .map_err(DatabaseError::from)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(DatabaseError::from)?);
            }
            Ok(out)
        })
    }
}

fn row_to_rejection(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRejection> {
    let event_version: i64 = row.get(2)?;
    let truncated: i64 = row.get(7)?;
    let byte_count: Option<i64> = row.get(12)?;
    Ok(StoredRejection {
        id: row.get(0)?,
        occurred_at: from_millis(row.get(1)?),
        event_version: u16::try_from(event_version).unwrap_or(0),
        request_id: row.get(3)?,
        stage: row.get(4)?,
        code: row.get(5)?,
        detail: row.get(6)?,
        detail_truncated: truncated != 0,
        key_id: row.get(8)?,
        module_id: row.get(9)?,
        version: row.get(10)?,
        digest: row.get(11)?,
        byte_count: byte_count.map(|b| u64::try_from(b).unwrap_or(0)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::RejectionStage;

    fn event_for(stage: RejectionStage, code: &'static str) -> RejectionEvent {
        RejectionEvent::new(stage, code, format!("{code} at {}", stage.as_str()))
            .with_request_id(Some("req-1".to_owned()))
            .with_key_id(Some("k1".to_owned()))
            .with_module_id(Some("reporting-service".to_owned()))
            .with_version(Some("1.2.0".to_owned()))
            .with_digest(Some("ab".repeat(32)))
            .with_byte_count(Some(128))
    }

    fn assert_row_matches_event(row: &StoredRejection, event: &RejectionEvent) {
        assert_eq!(row.event_version, event.event_version);
        assert_eq!(
            to_millis(row.occurred_at),
            to_millis(event.occurred_at),
            "millis-truncated time must round-trip"
        );
        assert_eq!(row.request_id, event.request_id);
        assert_eq!(row.stage, event.stage.as_str());
        assert_eq!(row.code, event.code);
        assert_eq!(row.detail, event.detail);
        assert_eq!(row.detail_truncated, event.detail_truncated);
        assert_eq!(row.key_id, event.key_id);
        assert_eq!(row.module_id, event.module_id);
        assert_eq!(row.version, event.version);
        assert_eq!(row.digest, event.digest);
        assert_eq!(row.byte_count, event.byte_count);
    }

    #[test]
    fn round_trip_covers_every_stage_truncation_and_missing_attribution() {
        let store = RejectionStore::open_in_memory().expect("in-memory store must open");
        // One stable code per stage; distinct so rows cannot be confused.
        const CODES: [&str; 12] = [
            "transport_rejected",
            "multipart_rejected",
            "streaming_rejected",
            "policy_rejected",
            "archive_rejected",
            "digest_rejected",
            "signature_rejected",
            "manifest_rejected",
            "inventory_rejected",
            "promotion_rejected",
            "registration_rejected",
            "internal_rejected",
        ];
        let stages = [
            RejectionStage::Transport,
            RejectionStage::Multipart,
            RejectionStage::Streaming,
            RejectionStage::Policy,
            RejectionStage::Archive,
            RejectionStage::Digest,
            RejectionStage::Signature,
            RejectionStage::Manifest,
            RejectionStage::Inventory,
            RejectionStage::Promotion,
            RejectionStage::Registration,
            RejectionStage::Internal,
        ];
        let mut events = Vec::new();
        for (i, stage) in stages.iter().enumerate() {
            events.push(event_for(*stage, CODES[i]));
        }
        // Truncation-flagged detail: over the 4 KiB bound, flagged.
        let long = RejectionEvent::new(
            RejectionStage::Manifest,
            "manifest_rejected",
            "x".repeat(crate::audit::event::MAX_DETAIL_BYTES + 8),
        );
        assert!(long.detail_truncated);
        events.push(long);
        // No attribution at all: early-transport refusal.
        events.push(RejectionEvent::new(
            RejectionStage::Transport,
            "server_busy",
            "busy",
        ));
        for event in &events {
            store.record(event).expect("insert must succeed");
        }
        let rows = store.list().expect("rows must read");
        assert_eq!(rows.len(), events.len());
        for (row, event) in rows.iter().zip(events.iter()) {
            assert_row_matches_event(row, event);
        }
        // Ids are insertion-ordered.
        for window in rows.windows(2) {
            assert!(window[0].id < window[1].id);
        }
    }
}

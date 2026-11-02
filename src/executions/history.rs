//! Durable execution metadata history.
//!
//! [`ExecutionHistoryStore`] owns the `INSERT INTO executions` and the
//! read queries over the shared [`Database`](crate::storage::database::Database)
//! connection. One completed worker execution becomes one row: the stable
//! registry identity, function name, stable outcome name, and timing. It
//! deliberately stores no stdout, stderr, configuration, or secrets — history
//! is metadata only.
//!
//! There is intentionally no foreign key to `module_versions`: execution
//! history must survive a future version removal. Rows are inserted in one
//! immediate transaction; timestamps use the shared
//! [`to_millis`](crate::storage::database::to_millis) /
//! [`from_millis`](crate::storage::database::from_millis) convention and
//! `duration_ms` saturates at `i64::MAX` like the other integer columns.
//!
//! Listing is newest first (`ORDER BY id DESC`) with parameterized
//! `LIMIT`/`OFFSET`. [`MAX_LIST_LIMIT`] is enforced here rather than only in
//! the HTTP layer so a direct caller cannot request an unbounded result set.

use std::sync::Arc;
use std::time::SystemTime;

use rusqlite::{params, OptionalExtension};

use crate::executions::executor::ExecutionOutcome;
use crate::executions::protocol::MAX_FIELD_BYTES;
use crate::storage::database::{from_millis, to_millis, Database, DatabaseError};

/// Hard upper bound on rows returned by [`ExecutionHistoryStore::list`].
/// Callers choose their own default; the store never returns more than this.
pub const MAX_LIST_LIMIT: usize = 200;

/// Bound on a server-generated execution id. Shared by the HTTP detail route
/// and the persisted-row validator so they cannot drift.
pub const MAX_EXECUTION_ID_BYTES: usize = 128;

const SELECT_EXECUTIONS: &str = "SELECT execution_id, module_id, version, digest, \
     function, outcome, started_at, finished_at, duration_ms FROM executions";

/// Durable execution history sink. Thread-safe via the underlying
/// [`Database`]; shared behind an [`Arc`] by the execution service.
#[derive(Debug)]
pub struct ExecutionHistoryStore {
    database: Arc<Database>,
}

/// One persisted execution receipt. `digest` is lowercase hex and `outcome`
/// is the stable lowercase name exposed by the API; `started_at`/`finished_at`
/// are millis-truncated wall-clock times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecord {
    pub execution_id: String,
    pub module_id: String,
    pub version: String,
    pub digest: String,
    pub function: String,
    pub outcome: String,
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
    pub duration_ms: u64,
}

impl ExecutionHistoryStore {
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

    /// Persists one execution receipt. One immediate transaction, bounded to
    /// a single insert. A duplicate `execution_id` is a UNIQUE violation and
    /// is returned as an error rather than overwriting the earlier row.
    pub fn record(&self, record: &ExecutionRecord) -> Result<(), DatabaseError> {
        let duration_ms = i64::try_from(record.duration_ms).unwrap_or(i64::MAX);
        self.database.with_write_tx(|tx| {
            tx.execute(
                "INSERT INTO executions (
                    execution_id, module_id, version, digest, function, outcome,
                    started_at, finished_at, duration_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record.execution_id,
                    record.module_id,
                    record.version,
                    record.digest,
                    record.function,
                    record.outcome,
                    to_millis(record.started_at),
                    to_millis(record.finished_at),
                    duration_ms,
                ],
            )?;
            Ok(())
        })
    }

    /// Looks up one receipt by its server-generated execution id.
    pub fn get(&self, execution_id: &str) -> Result<Option<ExecutionRecord>, DatabaseError> {
        self.database.with_connection(|conn| {
            conn.query_row(
                &format!("{SELECT_EXECUTIONS} WHERE execution_id = ?1"),
                params![execution_id],
                row_to_record,
            )
            .optional()
            .map_err(DatabaseError::from)
        })
    }

    /// Newest-first page of persisted receipts. `limit` is clamped to
    /// [`MAX_LIST_LIMIT`] so a caller cannot request unbounded rows;
    /// `offset` is converted with saturation.
    pub fn list(&self, limit: usize, offset: usize) -> Result<Vec<ExecutionRecord>, DatabaseError> {
        let limit = i64::try_from(limit.min(MAX_LIST_LIMIT)).unwrap_or(i64::MAX);
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        self.database.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "{SELECT_EXECUTIONS} ORDER BY id DESC LIMIT ?1 OFFSET ?2"
                ))
                .map_err(DatabaseError::from)?;
            let rows = statement
                .query_map(params![limit, offset], row_to_record)
                .map_err(DatabaseError::from)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(DatabaseError::from)?);
            }
            Ok(out)
        })
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExecutionRecord> {
    let execution_id: String = row.get(0)?;
    let module_id: String = row.get(1)?;
    let version: String = row.get(2)?;
    let digest: String = row.get(3)?;
    let function: String = row.get(4)?;
    let outcome: String = row.get(5)?;
    let started_at: i64 = row.get(6)?;
    let finished_at: i64 = row.get(7)?;
    let duration_ms: i64 = row.get(8)?;
    let record = ExecutionRecord {
        execution_id,
        module_id,
        version,
        digest,
        function,
        outcome,
        started_at: from_millis(started_at),
        finished_at: from_millis(finished_at),
        duration_ms: u64::try_from(duration_ms).unwrap_or(0),
    };
    // The schema CHECKs are a first line of defence. A row can still be
    // tampered after insert, or come from an older unconstrained v2 database,
    // so re-check the invariants here and fail closed instead of serving it.
    validate_record(&record, started_at, finished_at, duration_ms).map_err(invalid_row)?;
    Ok(record)
}

/// Maps a corrupt-row invariant failure into a `rusqlite` error so both `get`
/// and `list` surface it as a [`DatabaseError::Query`].
fn invalid_row(message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message,
        )),
    )
}

/// The invariants the v2 schema enforces, re-applied to a row read back.
/// `started_at`/`finished_at`/`duration_ms` are the raw stored integers so a
/// negative value is refused rather than clamped to the epoch.
fn validate_record(
    record: &ExecutionRecord,
    started_at: i64,
    finished_at: i64,
    duration_ms: i64,
) -> Result<(), String> {
    if !bounded_non_empty(&record.execution_id, MAX_EXECUTION_ID_BYTES) {
        return Err("execution_id is empty or over the byte bound".to_owned());
    }
    for (name, value) in [
        ("module_id", &record.module_id),
        ("version", &record.version),
        ("function", &record.function),
    ] {
        if !bounded_non_empty(value, MAX_FIELD_BYTES) {
            return Err(format!("{name} is empty or over the byte bound"));
        }
    }
    if !is_lowercase_hex_digest(&record.digest) {
        return Err("digest is not 64 lowercase hex characters".to_owned());
    }
    if !ExecutionOutcome::is_name(&record.outcome) {
        return Err("outcome is not a stable execution outcome name".to_owned());
    }
    if started_at < 0 || finished_at < 0 || duration_ms < 0 {
        return Err("timestamps and duration must not be negative".to_owned());
    }
    Ok(())
}

fn bounded_non_empty(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

fn is_lowercase_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    fn record(execution_id: &str, module_id: &str, version: &str) -> ExecutionRecord {
        ExecutionRecord {
            execution_id: execution_id.to_owned(),
            module_id: module_id.to_owned(),
            version: version.to_owned(),
            digest: "ab".repeat(32),
            function: "run".to_owned(),
            outcome: "succeeded".to_owned(),
            started_at: UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
            finished_at: UNIX_EPOCH + Duration::from_millis(1_700_000_000_456),
            duration_ms: 333,
        }
    }

    /// A raw row inserted with `PRAGMA ignore_check_constraints = ON`.
    /// Simulates a row tampered after insert, or one left by an older
    /// unconstrained v2 database.
    struct RawRow {
        execution_id: String,
        module_id: String,
        version: String,
        digest: String,
        function: String,
        outcome: String,
        started_at: i64,
        finished_at: i64,
        duration_ms: i64,
    }

    impl RawRow {
        fn valid() -> Self {
            Self {
                execution_id: "exec-tamper".to_owned(),
                module_id: "module".to_owned(),
                version: "1.0.0".to_owned(),
                digest: "ab".repeat(32),
                function: "run".to_owned(),
                outcome: "succeeded".to_owned(),
                started_at: 1_700_000_000_123,
                finished_at: 1_700_000_000_456,
                duration_ms: 333,
            }
        }
    }

    const INSERT_EXECUTION: &str = "INSERT INTO executions (
        execution_id, module_id, version, digest, function, outcome,
        started_at, finished_at, duration_ms
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

    fn insert_raw(
        store: &ExecutionHistoryStore,
        row: &RawRow,
        ignore_checks: bool,
    ) -> Result<(), DatabaseError> {
        store.database.with_connection(|conn| {
            if ignore_checks {
                conn.execute_batch("PRAGMA ignore_check_constraints = ON")?;
            }
            let inserted = conn.execute(
                INSERT_EXECUTION,
                params![
                    row.execution_id,
                    row.module_id,
                    row.version,
                    row.digest,
                    row.function,
                    row.outcome,
                    row.started_at,
                    row.finished_at,
                    row.duration_ms,
                ],
            );
            if ignore_checks {
                conn.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
            }
            inserted?;
            Ok(())
        })
    }

    fn insert_unchecked(store: &ExecutionHistoryStore, row: &RawRow) {
        insert_raw(store, row, true)
            .expect("tampered insert must succeed with check constraints disabled");
    }

    #[test]
    fn every_stable_outcome_name_is_accepted_by_the_schema() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");
        for (index, outcome) in [
            ExecutionOutcome::Succeeded {
                result: serde_json::Value::Null,
            },
            ExecutionOutcome::Failed {
                message: String::new(),
            },
            ExecutionOutcome::TimedOut {
                deadline: Duration::from_secs(1),
            },
            ExecutionOutcome::Cancelled {
                reason: String::new(),
            },
            ExecutionOutcome::WorkerError {
                detail: String::new(),
            },
            ExecutionOutcome::ProtocolViolation {
                detail: String::new(),
            },
        ]
        .iter()
        .enumerate()
        {
            let mut row = record(&format!("exec-outcome-{index}"), "module", "1.0.0");
            row.outcome = outcome.as_str().to_owned();
            store
                .record(&row)
                .expect("a stable outcome name must satisfy the v2 CHECK");
        }
    }

    #[test]
    fn schema_check_constraints_refuse_invalid_rows() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");

        let mut invalid_outcome = record("exec-schema-outcome", "module", "1.0.0");
        invalid_outcome.outcome = "pwned".to_owned();
        assert!(
            store.record(&invalid_outcome).is_err(),
            "the v2 outcome CHECK must refuse an unknown outcome"
        );

        let mut non_hex_digest = record("exec-schema-digest", "module", "1.0.0");
        non_hex_digest.digest = "zz".repeat(32);
        assert!(
            store.record(&non_hex_digest).is_err(),
            "the v2 digest CHECK must refuse non-hex bytes"
        );

        let mut uppercase_digest = record("exec-schema-uppercase", "module", "1.0.0");
        uppercase_digest.digest = "AB".repeat(32);
        assert!(
            store.record(&uppercase_digest).is_err(),
            "the v2 digest CHECK must refuse uppercase hex"
        );
    }

    #[test]
    fn schema_check_constraints_refuse_out_of_range_fields() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");

        let mut overlong_execution_id = RawRow::valid();
        overlong_execution_id.execution_id = "e".repeat(MAX_EXECUTION_ID_BYTES + 1);

        let mut empty_execution_id = RawRow::valid();
        empty_execution_id.execution_id = String::new();

        let mut overlong_module = RawRow::valid();
        overlong_module.execution_id = "exec-check-module".to_owned();
        overlong_module.module_id = "m".repeat(MAX_FIELD_BYTES + 1);

        let mut empty_module = RawRow::valid();
        empty_module.execution_id = "exec-check-empty-module".to_owned();
        empty_module.module_id = String::new();

        let mut overlong_version = RawRow::valid();
        overlong_version.execution_id = "exec-check-version".to_owned();
        overlong_version.version = "v".repeat(MAX_FIELD_BYTES + 1);

        let mut overlong_function = RawRow::valid();
        overlong_function.execution_id = "exec-check-function".to_owned();
        overlong_function.function = "f".repeat(MAX_FIELD_BYTES + 1);

        let mut empty_function = RawRow::valid();
        empty_function.execution_id = "exec-check-empty-function".to_owned();
        empty_function.function = String::new();

        let mut negative_started = RawRow::valid();
        negative_started.execution_id = "exec-check-started".to_owned();
        negative_started.started_at = -1;

        let mut negative_finished = RawRow::valid();
        negative_finished.execution_id = "exec-check-finished".to_owned();
        negative_finished.finished_at = -1;

        let mut negative_duration = RawRow::valid();
        negative_duration.execution_id = "exec-check-duration".to_owned();
        negative_duration.duration_ms = -1;

        for (label, row) in [
            ("overlong execution_id", overlong_execution_id),
            ("empty execution_id", empty_execution_id),
            ("overlong module_id", overlong_module),
            ("empty module_id", empty_module),
            ("overlong version", overlong_version),
            ("overlong function", overlong_function),
            ("empty function", empty_function),
            ("negative started_at", negative_started),
            ("negative finished_at", negative_finished),
            ("negative duration_ms", negative_duration),
        ] {
            assert!(
                insert_raw(&store, &row, false).is_err(),
                "the v2 CHECK must refuse a {label}"
            );
        }
    }

    #[test]
    fn tampered_rows_fail_closed_on_get() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");

        let mut cases = Vec::new();
        let mut push = |mut row: RawRow| {
            row.execution_id = format!("exec-tamper-{}", cases.len());
            cases.push(row);
        };

        let mut invalid_outcome = RawRow::valid();
        invalid_outcome.outcome = "pwned".to_owned();
        push(invalid_outcome);

        let mut non_hex_digest = RawRow::valid();
        non_hex_digest.digest = "zz".repeat(32);
        push(non_hex_digest);

        let mut uppercase_digest = RawRow::valid();
        uppercase_digest.digest = "AB".repeat(32);
        push(uppercase_digest);

        let mut short_digest = RawRow::valid();
        short_digest.digest = "ab".repeat(31);
        push(short_digest);

        let mut negative_started = RawRow::valid();
        negative_started.started_at = -1;
        push(negative_started);

        let mut negative_finished = RawRow::valid();
        negative_finished.finished_at = -1;
        push(negative_finished);

        let mut negative_duration = RawRow::valid();
        negative_duration.duration_ms = -1;
        push(negative_duration);

        let mut empty_module = RawRow::valid();
        empty_module.module_id = String::new();
        push(empty_module);

        let mut overlong_module = RawRow::valid();
        overlong_module.module_id = "m".repeat(MAX_FIELD_BYTES + 1);
        push(overlong_module);

        let mut overlong_version = RawRow::valid();
        overlong_version.version = "v".repeat(MAX_FIELD_BYTES + 1);
        push(overlong_version);

        let mut overlong_function = RawRow::valid();
        overlong_function.function = "f".repeat(MAX_FIELD_BYTES + 1);
        push(overlong_function);

        let mut overlong_id = RawRow::valid();
        overlong_id.execution_id = "e".repeat(MAX_EXECUTION_ID_BYTES + 1);
        cases.push(overlong_id);

        for row in &cases {
            insert_unchecked(&store, row);
        }
        for row in &cases {
            assert!(
                store.get(&row.execution_id).is_err(),
                "tampered row {:?} must fail closed",
                row.execution_id
            );
        }
    }

    #[test]
    fn tampered_rows_fail_closed_on_list() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");
        store
            .record(&record("exec-valid", "module", "1.0.0"))
            .expect("valid insert must succeed");

        let mut tampered = RawRow::valid();
        tampered.execution_id = "exec-tampered-list".to_owned();
        tampered.outcome = "pwned".to_owned();
        insert_unchecked(&store, &tampered);

        let err = store
            .list(10, 0)
            .expect_err("a tampered row must not be served from a list");
        assert!(
            matches!(err, DatabaseError::Query(_)),
            "expected a store error, got {err:?}"
        );
    }

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "conductor-history-{}-{nanos}-{tag}",
            std::process::id()
        ))
    }

    #[test]
    fn record_and_get_round_trip_every_field() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");
        let expected = record("exec-1", "reporting-service", "1.2.0");

        store.record(&expected).expect("insert must succeed");
        let stored = store
            .get("exec-1")
            .expect("lookup must succeed")
            .expect("record must exist");

        assert_eq!(stored, expected);
        assert_eq!(to_millis(stored.started_at), 1_700_000_000_123);
        assert_eq!(to_millis(stored.finished_at), 1_700_000_000_456);
    }

    #[test]
    fn list_is_newest_first_and_paginates() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");
        for index in 0..5 {
            store
                .record(&record(&format!("exec-{index}"), "module", "1.0.0"))
                .expect("insert must succeed");
        }

        let all = store.list(10, 0).expect("list must read");
        let ids: Vec<&str> = all.iter().map(|row| row.execution_id.as_str()).collect();
        assert_eq!(ids, ["exec-4", "exec-3", "exec-2", "exec-1", "exec-0"]);

        let page = store.list(2, 1).expect("page must read");
        let ids: Vec<&str> = page.iter().map(|row| row.execution_id.as_str()).collect();
        assert_eq!(ids, ["exec-3", "exec-2"]);

        let past_end = store.list(2, 99).expect("offset past the end must read");
        assert!(past_end.is_empty());
    }

    #[test]
    fn missing_id_returns_none() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");
        assert_eq!(
            store.get("exec-missing").expect("lookup must succeed"),
            None
        );
    }

    #[test]
    fn duplicate_id_is_refused_without_overwriting() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");
        store
            .record(&record("exec-dup", "module-one", "1.0.0"))
            .expect("first insert must succeed");

        let mut replacement = record("exec-dup", "module-two", "2.0.0");
        replacement.outcome = "failed".to_owned();
        let err = store
            .record(&replacement)
            .expect_err("a duplicate execution id must be refused");
        assert!(
            matches!(err, DatabaseError::Query(_)),
            "expected a UNIQUE failure, got {err:?}"
        );

        let stored = store
            .get("exec-dup")
            .expect("lookup must succeed")
            .expect("the original row must remain");
        assert_eq!(stored.module_id, "module-one");
        assert_eq!(stored.version, "1.0.0");
        assert_eq!(stored.outcome, "succeeded");
    }

    #[test]
    fn records_survive_reopening_the_database_file() {
        let dir = temp_path("persist");
        std::fs::create_dir_all(&dir).expect("temp dir must be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("temp dir must be owner-only");
        }
        let path = dir.join("conductor.db");
        let expected = record("exec-persist", "module", "1.0.0");
        {
            let database = Database::open(&path).expect("database must open");
            database.migrate().expect("database must migrate");
            ExecutionHistoryStore::new(Arc::new(database))
                .record(&expected)
                .expect("insert must succeed");
        }

        let database = Database::open(&path).expect("database must reopen");
        database.migrate().expect("reopen must be idempotent");
        let stored = ExecutionHistoryStore::new(Arc::new(database))
            .get("exec-persist")
            .expect("lookup must succeed")
            .expect("record must survive a reopen");
        assert_eq!(stored, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_clamps_to_the_store_maximum() {
        let store = ExecutionHistoryStore::open_in_memory().expect("store must open");
        let total = MAX_LIST_LIMIT + 25;
        for index in 0..total {
            store
                .record(&record(&format!("exec-{index}"), "module", "1.0.0"))
                .expect("insert must succeed");
        }

        let rows = store
            .list(usize::MAX, 0)
            .expect("an unbounded request must be clamped");
        assert_eq!(rows.len(), MAX_LIST_LIMIT);
        assert_eq!(rows[0].execution_id, format!("exec-{}", total - 1));
    }
}

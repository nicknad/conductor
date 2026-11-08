//! SQLite connection policy and forward-only schema migrations.
//!
//! One process-wide connection behind a mutex: WAL journaling, foreign-key
//! enforcement, and a bounded busy timeout are applied at open, and every
//! migration runs in its own transaction with the applied version recorded
//! in `PRAGMA user_version`. A crash mid-migration therefore resumes
//! cleanly on the next start, and a database written by a newer binary is
//! refused instead of misread.
//!
//! This module owns the schema DDL; repositories (`modules::registry`,
//! `audit::store`) own the queries and share one `Arc<Database>` so all
//! writes use the same WAL/pragma policy.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use rusqlite::{Connection, Transaction, TransactionBehavior};
use thiserror::Error;

/// Schema version this build produces. Bump alongside a new entry in
/// `MIGRATIONS`; never edit an entry that has shipped.
pub const SCHEMA_VERSION: i64 = 3;

/// Forward-only migrations; index `n` applies version `n + 1`, each string
/// one statement. The v1 schema backs the module registry, activation, and
/// rejection records. The v2 schema adds durable execution metadata.
const MIGRATIONS: &[&[&str]] = &[
    &[
        "CREATE TABLE modules (
        module_id  TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL
     )",
        "CREATE TABLE module_versions (
        module_id        TEXT NOT NULL REFERENCES modules(module_id) ON DELETE CASCADE,
        version          TEXT NOT NULL,
        digest           TEXT NOT NULL CHECK (length(digest) = 64),
        signer_key_id    TEXT NOT NULL,
        runtime          TEXT NOT NULL,
        manifest_version INTEGER NOT NULL,
        manifest_json    TEXT NOT NULL,
        artifact_relpath TEXT NOT NULL,
        artifact_size    INTEGER NOT NULL,
        integrity_state  TEXT NOT NULL DEFAULT 'ok',
        registered_at    INTEGER NOT NULL,
        PRIMARY KEY (module_id, version)
     )",
        "CREATE TABLE active_versions (
        module_id    TEXT PRIMARY KEY REFERENCES modules(module_id) ON DELETE CASCADE,
        version      TEXT NOT NULL,
        activated_at INTEGER NOT NULL,
        FOREIGN KEY (module_id, version)
            REFERENCES module_versions(module_id, version)
     )",
        "CREATE TABLE package_rejections (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at      INTEGER NOT NULL,
        event_version    INTEGER NOT NULL,
        request_id       TEXT,
        stage            TEXT NOT NULL,
        code             TEXT NOT NULL,
        detail           TEXT NOT NULL,
        detail_truncated INTEGER NOT NULL DEFAULT 0,
        key_id           TEXT,
        module_id        TEXT,
        version          TEXT,
        digest           TEXT,
        byte_count       INTEGER
     )",
        "CREATE INDEX idx_rejections_occurred_at ON package_rejections(occurred_at)",
    ],
    &[
        // Bounded, non-empty identity fields and a strict outcome/digest
        // vocabulary. `length(CAST(... AS BLOB))` counts bytes, matching the
        // Rust-side `MAX_FIELD_BYTES`/execution-id bounds. Negative timing
        // values and the outcome set are refused at insert time; reads
        // re-validate so a row tampered afterwards still fails closed.
        "CREATE TABLE executions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id TEXT NOT NULL UNIQUE
                         CHECK (length(CAST(execution_id AS BLOB)) BETWEEN 1 AND 128),
            module_id    TEXT NOT NULL
                         CHECK (length(CAST(module_id AS BLOB)) BETWEEN 1 AND 256),
            version      TEXT NOT NULL
                         CHECK (length(CAST(version AS BLOB)) BETWEEN 1 AND 256),
            digest       TEXT NOT NULL
                         CHECK (length(digest) = 64
                                AND digest NOT GLOB '*[^0-9a-f]*'),
            function     TEXT NOT NULL
                         CHECK (length(CAST(function AS BLOB)) BETWEEN 1 AND 256),
            outcome      TEXT NOT NULL
                         CHECK (outcome IN (
                             'succeeded', 'failed', 'timed_out', 'cancelled',
                             'worker_error', 'protocol_violation'
                         )),
            started_at   INTEGER NOT NULL CHECK (started_at >= 0),
            finished_at  INTEGER NOT NULL CHECK (finished_at >= 0),
            duration_ms  INTEGER NOT NULL CHECK (duration_ms >= 0)
         )",
        "CREATE INDEX idx_executions_started_at ON executions(started_at)",
        "CREATE INDEX idx_executions_module_version ON executions(module_id, version)",
    ],
    &[
        // Durable job definitions and the run queue. `job_runs.state` is the
        // queue: a queued row is pending dispatch, a running row is claimed,
        // and terminal rows are history. Trigger fields are closed and
        // cross-checked so a row cannot describe two trigger kinds.
        "CREATE TABLE jobs (
            job_id        TEXT PRIMARY KEY
                          CHECK (length(CAST(job_id AS BLOB)) BETWEEN 1 AND 128),
            module_id     TEXT NOT NULL
                          CHECK (length(CAST(module_id AS BLOB)) BETWEEN 1 AND 256),
            version       TEXT NOT NULL
                          CHECK (length(CAST(version AS BLOB)) BETWEEN 1 AND 256),
            function      TEXT NOT NULL
                          CHECK (length(CAST(function AS BLOB)) BETWEEN 1 AND 256),
            trigger_kind  TEXT NOT NULL
                          CHECK (trigger_kind IN ('manual','interval','cron')),
            interval_secs INTEGER
                          CHECK (interval_secs IS NULL OR interval_secs > 0),
            cron_expr     TEXT
                          CHECK (cron_expr IS NULL
                                 OR length(CAST(cron_expr AS BLOB)) BETWEEN 1 AND 256),
            timezone      TEXT NOT NULL DEFAULT 'UTC'
                          CHECK (timezone = 'UTC'),
            payload_json  TEXT NOT NULL DEFAULT '{}'
                          CHECK (length(CAST(payload_json AS BLOB)) <= 65536),
            enabled       INTEGER NOT NULL CHECK (enabled IN (0,1)),
            next_run_at   INTEGER
                          CHECK (next_run_at IS NULL OR next_run_at >= 0),
            created_at    INTEGER NOT NULL CHECK (created_at >= 0),
            updated_at    INTEGER NOT NULL CHECK (updated_at >= 0),
            CHECK (
                (trigger_kind = 'manual'   AND interval_secs IS NULL AND cron_expr IS NULL) OR
                (trigger_kind = 'interval' AND interval_secs IS NOT NULL AND cron_expr IS NULL) OR
                (trigger_kind = 'cron'     AND cron_expr IS NOT NULL AND interval_secs IS NULL)
            ),
            CHECK (
                (next_run_at IS NULL AND (trigger_kind = 'manual' OR enabled = 0)) OR
                (next_run_at IS NOT NULL AND trigger_kind IN ('interval','cron') AND enabled = 1)
            )
         )",
        "CREATE TABLE job_runs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id           TEXT NOT NULL UNIQUE
                             CHECK (length(CAST(run_id AS BLOB)) BETWEEN 1 AND 128),
            job_id           TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT,
            attempt_no       INTEGER NOT NULL DEFAULT 1 CHECK (attempt_no >= 1),
            trigger_kind     TEXT NOT NULL
                             CHECK (trigger_kind IN ('manual','interval','cron')),
            scheduled_for    INTEGER NOT NULL CHECK (scheduled_for >= 0),
            state            TEXT NOT NULL
                             CHECK (state IN (
                                 'queued','running','succeeded','failed','refused','interrupted'
                             )),
            claimed_by       TEXT
                             CHECK (claimed_by IS NULL
                                    OR length(CAST(claimed_by AS BLOB)) BETWEEN 1 AND 128),
            lease_expires_at INTEGER
                             CHECK (lease_expires_at IS NULL OR lease_expires_at >= 0),
            execution_id     TEXT
                             CHECK (execution_id IS NULL
                                    OR length(CAST(execution_id AS BLOB)) BETWEEN 1 AND 128),
            outcome          TEXT
                             CHECK (outcome IS NULL OR outcome IN (
                                 'succeeded','failed','timed_out','cancelled',
                                 'worker_error','protocol_violation'
                             )),
            failure_code     TEXT
                             CHECK (failure_code IS NULL OR failure_code IN (
                                 'module_not_found','module_not_active','artifact_not_intact',
                                 'runtime_not_allowed','execution_not_permitted',
                                 'deadline_exceeded','server_busy','artifact_integrity_failed',
                                 'legacy_manifest','manifest_invalid','archive_invalid',
                                 'package_invalid','history_write_failed','job_disabled',
                                 'invalid_job_definition','internal','interrupted'
                             )),
            created_at       INTEGER NOT NULL CHECK (created_at >= 0),
            started_at       INTEGER CHECK (started_at IS NULL OR started_at >= 0),
            finished_at      INTEGER CHECK (finished_at IS NULL OR finished_at >= 0)
         )",
        "CREATE INDEX idx_job_runs_state ON job_runs(state, scheduled_for)",
        "CREATE INDEX idx_job_runs_job ON job_runs(job_id, created_at)",
        "CREATE UNIQUE INDEX idx_job_runs_execution
             ON job_runs(execution_id) WHERE execution_id IS NOT NULL",
        "CREATE UNIQUE INDEX idx_job_runs_tick
             ON job_runs(job_id, trigger_kind, scheduled_for, attempt_no)
             WHERE trigger_kind IN ('interval','cron')",
    ],
];

/// Storage failures. All variants are server-side conditions; callers
/// decide whether they are fatal (startup) or a rejected request.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database open failed: {0}")]
    Open(String),
    #[error("database migration failed: {0}")]
    Migration(String),
    #[error("database holds schema v{found}, but this binary supports v{supported}")]
    NewerSchema { found: i64, supported: i64 },
    #[error("database operation failed: {0}")]
    Query(String),
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(err: rusqlite::Error) -> Self {
        if is_busy_or_locked(&err) {
            crate::metrics::record_db_busy_error();
        }
        Self::Query(err.to_string())
    }
}

/// True when SQLite refused because another writer held a lock. The global
/// metrics handle (if a host installed one) records the classification.
pub(crate) fn is_busy_or_locked(err: &rusqlite::Error) -> bool {
    matches!(
        err.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

/// One process-wide SQLite connection behind a mutex. Cloning is not
/// possible: every caller shares the same handle.
#[derive(Debug)]
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Opens (creating if missing) the database at `path`, creating missing
    /// parent directories, and applies the connection pragmas. Call
    /// [`migrate`](Self::migrate) before use.
    pub fn open(path: &Path) -> Result<Self, DatabaseError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| DatabaseError::Open(format!("{}: {e}", parent.display())))?;
            }
        }
        let conn = Connection::open(path)
            .map_err(|e| DatabaseError::Open(format!("{}: {e}", path.display())))?;
        Self::from_connection(conn)
    }

    /// Opens a private in-memory database: the real storage semantics with
    /// no files. Call [`migrate`](Self::migrate) before use.
    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let conn = Connection::open_in_memory().map_err(|e| DatabaseError::Open(e.to_string()))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, DatabaseError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = NORMAL;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Recovers the connection from a poisoned lock: SQLite rolls back the
    /// interrupted transaction itself, so the connection stays usable. Lock
    /// wait is recorded through the process-global metrics handle when a host
    /// installed one; absent a host, this is a no-op.
    fn lock(&self) -> MutexGuard<'_, Connection> {
        let started = Instant::now();
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        crate::metrics::record_db_lock_wait(started.elapsed());
        guard
    }

    /// Readiness probe: the database must be at the schema version this
    /// binary produces and answer `SELECT 1`. Any error (including an
    /// unmigrated in-memory database) is reported as not ready; callers must
    /// not expose the error detail.
    pub fn check_ready(&self) -> Result<(), DatabaseError> {
        let conn = self.lock();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(DatabaseError::from)?;
        if version != SCHEMA_VERSION {
            return Err(DatabaseError::Query(
                "database schema is not at the current version".to_owned(),
            ));
        }
        let one: i64 = conn
            .query_row("SELECT 1", [], |row| row.get(0))
            .map_err(DatabaseError::from)?;
        if one == 1 {
            Ok(())
        } else {
            Err(DatabaseError::Query(
                "readiness query returned an unexpected value".to_owned(),
            ))
        }
    }

    /// Applies pending migrations, each in its own transaction, recording
    /// the applied version in `user_version` inside the same transaction.
    /// Idempotent; refuses a database from a newer binary.
    pub fn migrate(&self) -> Result<(), DatabaseError> {
        let mut conn = self.lock();
        let current: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| DatabaseError::Migration(e.to_string()))?;
        if current > SCHEMA_VERSION {
            return Err(DatabaseError::NewerSchema {
                found: current,
                supported: SCHEMA_VERSION,
            });
        }
        for (index, statements) in MIGRATIONS.iter().enumerate() {
            let version = index as i64 + 1;
            if version <= current {
                continue;
            }
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| DatabaseError::Migration(e.to_string()))?;
            for statement in *statements {
                tx.execute_batch(statement)
                    .map_err(|e| DatabaseError::Migration(format!("v{version}: {e}")))?;
            }
            tx.pragma_update(None, "user_version", version)
                .map_err(|e| DatabaseError::Migration(e.to_string()))?;
            tx.commit()
                .map_err(|e| DatabaseError::Migration(e.to_string()))?;
        }
        Ok(())
    }

    /// Runs `f` with a shared reference to the connection (reads).
    pub fn with_connection<T, E>(&self, f: impl FnOnce(&Connection) -> Result<T, E>) -> Result<T, E>
    where
        E: From<DatabaseError>,
    {
        let conn = self.lock();
        f(&conn)
    }

    /// Runs `f` inside one immediate write transaction: commits on `Ok`,
    /// rolls back on `Err`, so no caller can leave partial rows behind.
    pub fn with_write_tx<T, E>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<DatabaseError>,
    {
        let mut conn = self.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(DatabaseError::from)
            .map_err(E::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(DatabaseError::from).map_err(E::from)?;
        Ok(out)
    }
}

/// Unix millis for a `SystemTime`, saturating at the `i64` bound and
/// falling back to the epoch for pre-epoch times. Shared by every table
/// that stores timestamps so rows stay comparable.
pub(crate) fn to_millis(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Inverse of [`to_millis`]: negative stored values clamp to the epoch
/// rather than panicking.
pub(crate) fn from_millis(millis: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(u64::try_from(millis).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("conductor-db-{}-{nanos}-{tag}", std::process::id()))
    }

    #[test]
    fn migrate_creates_the_schema_and_is_idempotent() {
        let db = Database::open_in_memory().expect("in-memory database must open");
        db.migrate().expect("first migration");
        db.migrate().expect("second migration must be a no-op");

        let version: i64 = db
            .with_connection(|conn| {
                conn.pragma_query_value(None, "user_version", |row| row.get(0))
                    .map_err(DatabaseError::from)
            })
            .expect("schema version must read");
        assert_eq!(version, SCHEMA_VERSION);

        // Every schema table is usable at the current version.
        for table in [
            "modules",
            "module_versions",
            "active_versions",
            "package_rejections",
            "executions",
            "jobs",
            "job_runs",
        ] {
            let count: i64 = db
                .with_connection(|conn| {
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .map_err(DatabaseError::from)
                })
                .expect("table must exist");
            assert_eq!(count, 0);
        }

        // Both v2 indexes exist after migration.
        let indexes: Vec<String> = db
            .with_connection(|conn| {
                let mut statement = conn
                    .prepare(
                        "SELECT name FROM sqlite_master
                         WHERE type = 'index' AND name LIKE 'idx_executions_%'
                         ORDER BY name",
                    )
                    .map_err(DatabaseError::from)?;
                let rows = statement
                    .query_map([], |row| row.get(0))
                    .map_err(DatabaseError::from)?;
                let mut names = Vec::new();
                for row in rows {
                    names.push(row.map_err(DatabaseError::from)?);
                }
                Ok::<_, DatabaseError>(names)
            })
            .expect("execution indexes must read");
        assert_eq!(
            indexes,
            [
                "idx_executions_module_version".to_owned(),
                "idx_executions_started_at".to_owned(),
            ]
        );
    }

    #[test]
    fn migrate_upgrades_a_v1_schema_preserving_existing_rows() {
        use rusqlite::params;

        let db = Database::open_in_memory().expect("in-memory database must open");
        let digest = "a".repeat(64);
        // Build the shipped v1 schema and rows exactly as an older binary
        // would have left them, then run the current migration.
        db.with_connection(|conn| {
            for statement in MIGRATIONS[0] {
                conn.execute_batch(statement)?;
            }
            conn.pragma_update(None, "user_version", 1)?;
            conn.execute(
                "INSERT INTO modules (module_id, created_at) VALUES ('reporting-service', 100)",
                [],
            )?;
            conn.execute(
                "INSERT INTO module_versions (
                    module_id, version, digest, signer_key_id, runtime,
                    manifest_version, manifest_json, artifact_relpath,
                    artifact_size, integrity_state, registered_at
                 ) VALUES ('reporting-service', '1.2.0', ?1, 'k1', 'rust',
                    2, '{}', 'reporting-service/1.2.0/pkg.zip', 123, 'ok', 200)",
                params![digest],
            )?;
            conn.execute(
                "INSERT INTO active_versions (module_id, version, activated_at)
                 VALUES ('reporting-service', '1.2.0', 300)",
                [],
            )?;
            conn.execute(
                "INSERT INTO package_rejections (
                    occurred_at, event_version, stage, code, detail
                 ) VALUES (400, 1, 'transport', 'denied', 'kept')",
                [],
            )?;
            Ok::<(), DatabaseError>(())
        })
        .expect("v1 schema and rows must be written");

        db.migrate().expect("v1 database must upgrade to v2");

        let version: i64 = db
            .with_connection(|conn| {
                conn.pragma_query_value(None, "user_version", |row| row.get(0))
                    .map_err(DatabaseError::from)
            })
            .expect("schema version must read");
        assert_eq!(version, SCHEMA_VERSION);

        let counts: (i64, i64, i64, i64, i64) = db
            .with_connection(|conn| {
                let count = |table: &str| -> rusqlite::Result<i64> {
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                };
                Ok::<_, DatabaseError>((
                    count("modules")?,
                    count("module_versions")?,
                    count("active_versions")?,
                    count("package_rejections")?,
                    count("executions")?,
                ))
            })
            .expect("upgraded table counts must read");
        assert_eq!(counts, (1, 1, 1, 1, 0));

        let stored: (String, String, String, String) = db
            .with_connection(|conn| {
                let digest: String = conn.query_row(
                    "SELECT digest FROM module_versions
                     WHERE module_id = 'reporting-service' AND version = '1.2.0'",
                    [],
                    |row| row.get(0),
                )?;
                let signer: String = conn.query_row(
                    "SELECT signer_key_id FROM module_versions
                     WHERE module_id = 'reporting-service' AND version = '1.2.0'",
                    [],
                    |row| row.get(0),
                )?;
                let active: String = conn.query_row(
                    "SELECT version FROM active_versions WHERE module_id = 'reporting-service'",
                    [],
                    |row| row.get(0),
                )?;
                let detail: String = conn.query_row(
                    "SELECT detail FROM package_rejections WHERE code = 'denied'",
                    [],
                    |row| row.get(0),
                )?;
                Ok::<_, DatabaseError>((digest, signer, active, detail))
            })
            .expect("existing rows must survive the upgrade");
        assert_eq!(stored.0, "a".repeat(64));
        assert_eq!(stored.1, "k1");
        assert_eq!(stored.2, "1.2.0");
        assert_eq!(stored.3, "kept");
    }

    #[test]
    fn migrate_upgrades_a_v2_schema_without_touching_execution_history() {
        use rusqlite::params;

        let db = Database::open_in_memory().expect("in-memory database must open");
        db.with_connection(|conn| {
            for statement in MIGRATIONS[0] {
                conn.execute_batch(statement)?;
            }
            for statement in MIGRATIONS[1] {
                conn.execute_batch(statement)?;
            }
            conn.pragma_update(None, "user_version", 2)?;
            conn.execute(
                "INSERT INTO executions (
                    execution_id, module_id, version, digest, function, outcome,
                    started_at, finished_at, duration_ms
                 ) VALUES ('exec-v2', 'module', '1.0.0', ?1, 'run', 'succeeded', 10, 20, 10)",
                params!["ab".repeat(32)],
            )?;
            Ok::<(), DatabaseError>(())
        })
        .expect("v2 schema and row must be written");

        db.migrate().expect("v2 database must upgrade to v3");

        let (version, execution_count, job_count, run_count): (i64, i64, i64, i64) = db
            .with_connection(|conn| {
                let version = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
                let execution_count =
                    conn.query_row("SELECT COUNT(*) FROM executions", [], |row| row.get(0))?;
                let job_count =
                    conn.query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))?;
                let run_count =
                    conn.query_row("SELECT COUNT(*) FROM job_runs", [], |row| row.get(0))?;
                Ok::<_, DatabaseError>((version, execution_count, job_count, run_count))
            })
            .expect("upgraded schema must read");

        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(execution_count, 1, "v2 history must survive the upgrade");
        assert_eq!(job_count, 0);
        assert_eq!(run_count, 0);
    }

    #[test]
    fn migrate_refuses_a_newer_schema() {
        let db = Database::open_in_memory().expect("in-memory database must open");
        db.with_connection(|conn| {
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .map_err(DatabaseError::from)
        })
        .expect("version must bump");
        let err = db.migrate().unwrap_err();
        assert!(matches!(
            err,
            DatabaseError::NewerSchema { found, supported }
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ));
    }

    #[test]
    fn write_transaction_rolls_back_on_error() {
        let db = Database::open_in_memory().expect("in-memory database must open");
        db.migrate().expect("migrate");
        let result: Result<(), DatabaseError> = db.with_write_tx(|tx| {
            tx.execute(
                "INSERT INTO modules (module_id, created_at) VALUES ('m', 1)",
                [],
            )?;
            Err(DatabaseError::Query("abort on purpose".to_owned()))
        });
        assert!(result.is_err());
        let count: i64 = db
            .with_connection(|conn| {
                conn.query_row("SELECT COUNT(*) FROM modules", [], |row| row.get(0))
                    .map_err(DatabaseError::from)
            })
            .expect("count must read");
        assert_eq!(count, 0, "an aborted write transaction must leave no rows");
    }

    #[test]
    fn busy_and_locked_errors_are_classified() {
        for code in [5, 6] {
            let error = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert!(
                is_busy_or_locked(&error),
                "SQLite code {code} must classify as busy/locked"
            );
        }
        for code in [1, 11, 19] {
            let error = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert!(
                !is_busy_or_locked(&error),
                "SQLite code {code} must not classify as busy/locked"
            );
        }
        assert!(!is_busy_or_locked(&rusqlite::Error::QueryReturnedNoRows));
    }

    #[test]
    fn readiness_requires_a_migrated_database() {
        let db = Database::open_in_memory().expect("in-memory database must open");
        assert!(
            db.check_ready().is_err(),
            "an unmigrated database must not be ready"
        );
        db.migrate().expect("migrate");
        db.check_ready().expect("a migrated database must be ready");
    }

    #[test]
    fn open_creates_missing_parent_directories() {
        let dir = temp_path("nested");
        let path = dir.join("database").join("conductor.db");
        let db = Database::open(&path).expect("open must create parents");
        db.migrate().expect("migrate");
        assert!(path.exists());
        // Reopening the same file keeps the migrated schema.
        let reopened = Database::open(&path).expect("reopen");
        reopened.migrate().expect("migrate is idempotent on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

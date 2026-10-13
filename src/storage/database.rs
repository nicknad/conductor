//! SQLite connection policy and forward-only schema migrations.
//!
//! One process-wide connection behind a mutex: WAL journaling, foreign-key
//! enforcement, and a bounded busy timeout are applied at open, and every
//! migration runs in its own transaction with the applied version recorded
//! in `PRAGMA user_version`. A crash mid-migration therefore resumes
//! cleanly on the next start, and a database written by a newer binary is
//! refused instead of misread.
//!
//! This module owns the schema DDL; repositories (starting with
//! `modules::registry`) own the queries. Later phases add the rejection
//! sink and startup reconciliation over the same connection.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use rusqlite::{Connection, Transaction, TransactionBehavior};
use thiserror::Error;

/// Schema version this build produces. Bump alongside a new entry in
/// `MIGRATIONS`; never edit an entry that has shipped.
pub const SCHEMA_VERSION: i64 = 1;

/// Forward-only migrations; index `n` applies version `n + 1`, each string
/// one statement. The v1 schema backs the module registry, activation, and
/// rejection records.
const MIGRATIONS: &[&[&str]] = &[&[
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
]];

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
        Self::Query(err.to_string())
    }
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
    /// interrupted transaction itself, so the connection stays usable.
    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
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

        // The v1 tables are usable.
        for table in [
            "modules",
            "module_versions",
            "active_versions",
            "package_rejections",
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

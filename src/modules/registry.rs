//! Tracks registered module versions.
//!
//! The registry is the authority on which artifact digest a
//! `(module_id, version)` pair means. Registration is idempotent for the
//! exact same digest and conflicts when a version is re-registered with
//! different bytes — a version never silently changes meaning.
//!
//! Two backends, one API: an in-memory map for tests and ephemeral hosts,
//! and SQLite ([`ModuleRegistry::open`], migrations applied on
//! construction), which makes registrations survive a restart. The
//! registry stores records, never code and never a path it will open:
//! activation consumes registry state plus policy and must not re-open
//! archives. `artifact_relpath` is reconciliation bookkeeping, not an
//! execution input.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use rusqlite::{params, OptionalExtension};
use thiserror::Error;

use crate::modules::activation::ActiveVersion;
use crate::packages::artifact::ArtifactDigest;
use crate::storage::database::{from_millis, to_millis, Database, DatabaseError};

/// One registered module version. Identity, provenance, the exact
/// validated manifest bytes, and the promoted artifact's location and size
/// — everything activation, audit, and reconciliation need without
/// touching the archive again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleRecord {
    pub module_id: String,
    pub version: String,
    pub digest: ArtifactDigest,
    /// Key id that authorized the upload (from the validation verdict).
    pub signer_key_id: String,
    /// Declared runtime from the validated manifest.
    pub runtime: String,
    /// Manifest schema version of the validated manifest.
    pub manifest_version: u32,
    /// Exact validated manifest bytes, as read from the archive.
    pub manifest_json: String,
    /// Artifact path relative to the configured artifacts root.
    pub artifact_relpath: String,
    /// Size in bytes of the immutable artifact.
    pub artifact_size: u64,
    /// Reconciliation state: whether the promoted artifact was last seen
    /// intact on disk. New registrations are always `Ok`; reconciliation
    /// moves rows to `Missing`/`Mismatch`.
    pub integrity_state: IntegrityState,
    pub registered_at: SystemTime,
}

/// Reconciliation state of a registered version's promoted artifact.
/// Stored as text in `module_versions.integrity_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IntegrityState {
    #[default]
    Ok,
    Missing,
    Mismatch,
}

impl IntegrityState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Mismatch => "mismatch",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "ok" => Some(Self::Ok),
            "missing" => Some(Self::Missing),
            "mismatch" => Some(Self::Mismatch),
            _ => None,
        }
    }
}

impl std::fmt::Display for IntegrityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of one registration attempt.
#[derive(Clone, Debug)]
pub struct Registration {
    pub record: ModuleRecord,
    /// True when this exact digest was already registered for the same
    /// module version — an identical re-upload, not a new registration.
    pub already_registered: bool,
}

/// Registration failures. A version conflict is the caller's error: well
/// formed bytes, but they would change what an existing version means.
/// Storage failures are server-side and must not be conflated with one.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(
        "module {module_id} version {version} is already registered with a different digest \
         (registered={existing:?}, attempted={attempted:?})"
    )]
    VersionConflict {
        module_id: String,
        version: String,
        existing: ArtifactDigest,
        attempted: ArtifactDigest,
    },
    #[error("registry storage failure: {0}")]
    Storage(#[from] DatabaseError),
}

impl From<rusqlite::Error> for RegistryError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Storage(DatabaseError::from(err))
    }
}

/// Module version records. Thread-safe; memory mutations are one locked
/// insert, and every SQLite mutation is one immediate transaction.
#[derive(Debug)]
pub struct ModuleRegistry {
    pub(crate) store: Store,
}

#[derive(Debug, Default)]
pub(crate) struct MemoryState {
    pub(crate) versions: HashMap<(String, String), ModuleRecord>,
    pub(crate) active: HashMap<String, ActiveVersion>,
}

#[derive(Debug)]
pub(crate) enum Store {
    Memory(Mutex<MemoryState>),
    Sqlite(Database),
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

const SELECT_VERSION: &str = "SELECT module_id, version, digest, signer_key_id, runtime, \
     manifest_version, manifest_json, artifact_relpath, artifact_size, integrity_state, registered_at \
     FROM module_versions";

impl ModuleRegistry {
    /// In-memory registry: registrations live for the process lifetime.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Store::Memory(Mutex::new(MemoryState::default())),
        }
    }

    /// Opens (or creates) the SQLite-backed registry at `path` and applies
    /// pending migrations. Registrations survive restarts.
    pub fn open(path: &Path) -> Result<Self, RegistryError> {
        let database = Database::open(path)?;
        database.migrate()?;
        Ok(Self {
            store: Store::Sqlite(database),
        })
    }

    /// SQLite-backed registry over a private in-memory database: the real
    /// storage semantics with no files.
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        let database = Database::open_in_memory()?;
        database.migrate()?;
        Ok(Self {
            store: Store::Sqlite(database),
        })
    }

    /// Registers a module version. Idempotent for the identical digest;
    /// rejects a different digest for an already-registered version.
    pub fn record(&self, record: ModuleRecord) -> Result<Registration, RegistryError> {
        match &self.store {
            Store::Memory(state) => record_in_memory(state, record),
            Store::Sqlite(database) => record_sqlite(database, record),
        }
    }

    /// Looks up a registered module version. Storage failures are errors,
    /// never silently "not registered".
    pub fn get(
        &self,
        module_id: &str,
        version: &str,
    ) -> Result<Option<ModuleRecord>, RegistryError> {
        match &self.store {
            Store::Memory(state) => {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                Ok(state
                    .versions
                    .get(&(module_id.to_owned(), version.to_owned()))
                    .cloned())
            }
            Store::Sqlite(database) => database.with_connection(|conn| {
                conn.query_row(
                    &format!("{SELECT_VERSION} WHERE module_id = ?1 AND version = ?2"),
                    params![module_id, version],
                    row_to_record,
                )
                .optional()
                .map_err(RegistryError::from)
            }),
        }
    }

    /// Lists every registered version of one module, ordered by version
    /// string.
    pub fn list_versions(&self, module_id: &str) -> Result<Vec<ModuleRecord>, RegistryError> {
        match &self.store {
            Store::Memory(state) => {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                let mut records: Vec<ModuleRecord> = state
                    .versions
                    .values()
                    .filter(|record| record.module_id == module_id)
                    .cloned()
                    .collect();
                records.sort_by(|a, b| a.version.cmp(&b.version));
                Ok(records)
            }
            Store::Sqlite(database) => database.with_connection(|conn| {
                let mut statement = conn
                    .prepare(&format!(
                        "{SELECT_VERSION} WHERE module_id = ?1 ORDER BY version"
                    ))
                    .map_err(RegistryError::from)?;
                let rows = statement
                    .query_map(params![module_id], row_to_record)
                    .map_err(RegistryError::from)?;
                let mut records = Vec::new();
                for row in rows {
                    records.push(row.map_err(RegistryError::from)?);
                }
                Ok(records)
            }),
        }
    }

    /// Lists every registered version across all modules, ordered by
    /// `(module_id, version)`. Reconciliation entry point: scan rows and
    /// stat each artifact without SQL outside this module.
    pub fn all_versions(&self) -> Result<Vec<ModuleRecord>, RegistryError> {
        match &self.store {
            Store::Memory(state) => {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                let mut records: Vec<ModuleRecord> = state.versions.values().cloned().collect();
                records.sort_by(|a, b| (&a.module_id, &a.version).cmp(&(&b.module_id, &b.version)));
                Ok(records)
            }
            Store::Sqlite(database) => database.with_connection(|conn| {
                let mut statement = conn
                    .prepare(&format!("{SELECT_VERSION} ORDER BY module_id, version"))
                    .map_err(RegistryError::from)?;
                let rows = statement
                    .query_map([], row_to_record)
                    .map_err(RegistryError::from)?;
                let mut records = Vec::new();
                for row in rows {
                    records.push(row.map_err(RegistryError::from)?);
                }
                Ok(records)
            }),
        }
    }

    /// Lists every module id with at least one registered version, ordered
    /// by module id.
    pub fn list_modules(&self) -> Result<Vec<String>, RegistryError> {
        match &self.store {
            Store::Memory(state) => {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                let mut modules: Vec<String> = state
                    .versions
                    .values()
                    .map(|record| record.module_id.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();
                modules.sort();
                Ok(modules)
            }
            Store::Sqlite(database) => database.with_connection(|conn| {
                let mut statement = conn
                    .prepare("SELECT DISTINCT module_id FROM module_versions ORDER BY module_id")
                    .map_err(RegistryError::from)?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(RegistryError::from)?;
                let mut modules = Vec::new();
                for row in rows {
                    modules.push(row.map_err(RegistryError::from)?);
                }
                Ok(modules)
            }),
        }
    }

    /// Reads the reconciliation state of one registered version. `Ok(None)`
    /// when the version is not registered; storage failures are errors.
    pub fn get_integrity_state(
        &self,
        module_id: &str,
        version: &str,
    ) -> Result<Option<IntegrityState>, RegistryError> {
        Ok(self
            .get(module_id, version)?
            .map(|record| record.integrity_state))
    }

    /// Marks the reconciliation state of one registered version. Returns
    /// `false` when the version is not registered. One immediate
    /// transaction on SQLite; one locked mutation in memory.
    pub fn set_integrity_state(
        &self,
        module_id: &str,
        version: &str,
        state: IntegrityState,
    ) -> Result<bool, RegistryError> {
        match &self.store {
            Store::Memory(memory) => {
                let mut guard = memory.lock().unwrap_or_else(|e| e.into_inner());
                match guard
                    .versions
                    .get_mut(&(module_id.to_owned(), version.to_owned()))
                {
                    Some(record) => {
                        record.integrity_state = state;
                        Ok(true)
                    }
                    None => Ok(false),
                }
            }
            Store::Sqlite(database) => database.with_write_tx(|tx| {
                let updated = tx.execute(
                    "UPDATE module_versions SET integrity_state = ?1 \
                     WHERE module_id = ?2 AND version = ?3",
                    params![state.as_str(), module_id, version],
                )?;
                Ok(updated > 0)
            }),
        }
    }

    /// Number of registered module versions.
    pub fn len(&self) -> Result<usize, RegistryError> {
        match &self.store {
            Store::Memory(state) => {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                Ok(state.versions.len())
            }
            Store::Sqlite(database) => database.with_connection(|conn| {
                conn.query_row("SELECT COUNT(*) FROM module_versions", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map(|count| usize::try_from(count).unwrap_or(usize::MAX))
                .map_err(RegistryError::from)
            }),
        }
    }

    /// True when no module version is registered.
    pub fn is_empty(&self) -> Result<bool, RegistryError> {
        Ok(self.len()? == 0)
    }
}

fn record_in_memory(
    state: &Mutex<MemoryState>,
    record: ModuleRecord,
) -> Result<Registration, RegistryError> {
    let key = (record.module_id.clone(), record.version.clone());
    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
    match state.versions.get(&key) {
        Some(existing) if existing.digest == record.digest => Ok(Registration {
            record: existing.clone(),
            already_registered: true,
        }),
        Some(existing) => Err(RegistryError::VersionConflict {
            module_id: key.0,
            version: key.1,
            existing: existing.digest,
            attempted: record.digest,
        }),
        None => {
            let registration = Registration {
                record: record.clone(),
                already_registered: false,
            };
            state.versions.insert(key, record);
            Ok(registration)
        }
    }
}

fn record_sqlite(database: &Database, record: ModuleRecord) -> Result<Registration, RegistryError> {
    let key = (record.module_id.clone(), record.version.clone());
    database.with_write_tx(|tx| {
        tx.execute(
            "INSERT OR IGNORE INTO modules (module_id, created_at) VALUES (?1, ?2)",
            params![record.module_id, to_millis(record.registered_at)],
        )?;
        let existing = tx
            .query_row(
                &format!("{SELECT_VERSION} WHERE module_id = ?1 AND version = ?2"),
                params![record.module_id, record.version],
                row_to_record,
            )
            .optional()?;
        match existing {
            Some(existing) if existing.digest == record.digest => Ok(Registration {
                record: existing,
                already_registered: true,
            }),
            Some(existing) => Err(RegistryError::VersionConflict {
                module_id: key.0,
                version: key.1,
                existing: existing.digest,
                attempted: record.digest,
            }),
            None => {
                tx.execute(
                    "INSERT INTO module_versions (
                        module_id, version, digest, signer_key_id, runtime,
                        manifest_version, manifest_json, artifact_relpath,
                        artifact_size, integrity_state, registered_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        record.module_id,
                        record.version,
                        record.digest.to_hex(),
                        record.signer_key_id,
                        record.runtime,
                        record.manifest_version,
                        record.manifest_json,
                        record.artifact_relpath,
                        i64::try_from(record.artifact_size).unwrap_or(i64::MAX),
                        record.integrity_state.as_str(),
                        to_millis(record.registered_at),
                    ],
                )?;
                Ok(Registration {
                    record,
                    already_registered: false,
                })
            }
        }
    })
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ModuleRecord> {
    let digest_hex: String = row.get(2)?;
    let digest = ArtifactDigest::from_hex(&digest_hex).ok_or_else(|| {
        rusqlite::Error::InvalidColumnType(2, "digest".to_owned(), rusqlite::types::Type::Text)
    })?;
    // SQLite INTEGER is signed; sizes are stored as i64 and read back as
    // the u64 the registry deals in.
    let artifact_size: i64 = row.get(8)?;
    let integrity_text: String = row.get(9)?;
    let integrity_state = IntegrityState::from_str(&integrity_text).ok_or_else(|| {
        rusqlite::Error::InvalidColumnType(
            9,
            "integrity_state".to_owned(),
            rusqlite::types::Type::Text,
        )
    })?;
    Ok(ModuleRecord {
        module_id: row.get(0)?,
        version: row.get(1)?,
        digest,
        signer_key_id: row.get(3)?,
        runtime: row.get(4)?,
        manifest_version: row.get(5)?,
        manifest_json: row.get(6)?,
        artifact_relpath: row.get(7)?,
        artifact_size: u64::try_from(artifact_size).unwrap_or(0),
        integrity_state,
        registered_at: from_millis(row.get(10)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn record(module: &str, version: &str, byte: u8) -> ModuleRecord {
        ModuleRecord {
            module_id: module.to_owned(),
            version: version.to_owned(),
            digest: ArtifactDigest::new([byte; 32]),
            signer_key_id: "k1".to_owned(),
            runtime: "rust".to_owned(),
            manifest_version: 2,
            manifest_json: format!("{{\"module_id\":\"{module}\",\"version\":\"{version}\"}}"),
            artifact_relpath: format!("{module}/{version}/pkg.zip"),
            artifact_size: 123,
            integrity_state: IntegrityState::Ok,
            registered_at: SystemTime::now(),
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "conductor-registry-{}-{nanos}-{tag}",
            std::process::id()
        ))
    }

    /// The registration contract every backend must honor.
    fn assert_backend_semantics(registry: &ModuleRegistry) {
        assert!(registry.is_empty().expect("empty"));
        let outcome = registry
            .record(record("reporting", "1.0.0", 7))
            .expect("record");
        assert!(!outcome.already_registered);
        assert_eq!(registry.len().expect("len"), 1);

        let found = registry
            .get("reporting", "1.0.0")
            .expect("lookup")
            .expect("registered");
        assert_eq!(found.digest, ArtifactDigest::new([7u8; 32]));
        assert_eq!(found.manifest_version, 2);
        assert!(found.manifest_json.contains("reporting"));
        assert_eq!(found.artifact_relpath, "reporting/1.0.0/pkg.zip");
        assert_eq!(found.artifact_size, 123);
        assert_eq!(found.integrity_state, IntegrityState::Ok);
        assert!(registry
            .get("reporting", "2.0.0")
            .expect("lookup")
            .is_none());
        assert!(registry.get("other", "1.0.0").expect("lookup").is_none());
        assert_eq!(
            registry
                .get_integrity_state("reporting", "1.0.0")
                .expect("state"),
            Some(IntegrityState::Ok)
        );
        assert_eq!(
            registry
                .get_integrity_state("reporting", "9.9.9")
                .expect("state"),
            None
        );

        let again = registry
            .record(record("reporting", "1.0.0", 7))
            .expect("idempotent");
        assert!(again.already_registered);
        assert_eq!(again.record, found);
        assert_eq!(registry.len().expect("len"), 1);

        let err = registry
            .record(record("reporting", "1.0.0", 8))
            .unwrap_err();
        assert!(matches!(err, RegistryError::VersionConflict { .. }));
        assert_eq!(
            registry
                .get("reporting", "1.0.0")
                .expect("lookup")
                .expect("kept")
                .digest,
            ArtifactDigest::new([7u8; 32])
        );

        registry
            .record(record("reporting", "1.1.0", 8))
            .expect("v2");
        registry
            .record(record("billing", "1.0.0", 9))
            .expect("other");
        assert_eq!(registry.len().expect("len"), 3);
        let versions = registry.list_versions("reporting").expect("list");
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "1.1.0");
        assert!(registry.list_versions("missing").expect("list").is_empty());

        // P1 reconciliation reads: full scan and module list, both ordered.
        let all = registry.all_versions().expect("all");
        assert_eq!(all.len(), 3);
        assert_eq!(
            all.iter()
                .map(|r| (r.module_id.as_str(), r.version.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("billing", "1.0.0"),
                ("reporting", "1.0.0"),
                ("reporting", "1.1.0"),
            ]
        );
        assert_eq!(
            registry.list_modules().expect("modules"),
            vec!["billing".to_owned(), "reporting".to_owned()]
        );

        // Integrity marking round-trips through get().
        assert!(registry
            .set_integrity_state("reporting", "1.0.0", IntegrityState::Missing)
            .expect("mark"));
        assert_eq!(
            registry
                .get_integrity_state("reporting", "1.0.0")
                .expect("state"),
            Some(IntegrityState::Missing)
        );
        assert_eq!(
            registry
                .get("reporting", "1.0.0")
                .expect("lookup")
                .expect("kept")
                .integrity_state,
            IntegrityState::Missing
        );
        // Idempotent re-registration preserves the stored state, not the
        // caller's default.
        let again = registry
            .record(record("reporting", "1.0.0", 7))
            .expect("idempotent");
        assert!(again.already_registered);
        assert_eq!(again.record.integrity_state, IntegrityState::Missing);
        assert!(registry
            .set_integrity_state("reporting", "1.0.0", IntegrityState::Mismatch)
            .expect("mark"));
        assert!(!registry
            .set_integrity_state("reporting", "9.9.9", IntegrityState::Missing)
            .expect("missing version marks nothing"));
    }

    #[test]
    fn in_memory_backend_semantics() {
        assert_backend_semantics(&ModuleRegistry::new());
    }

    #[test]
    fn sqlite_in_memory_backend_matches_semantics() {
        assert_backend_semantics(&ModuleRegistry::open_in_memory().expect("open"));
    }

    #[test]
    fn sqlite_registrations_survive_reopen() {
        let dir = temp_path("reopen");
        let path = dir.join("database").join("conductor.db");
        let before = {
            let registry = ModuleRegistry::open(&path).expect("open");
            registry
                .record(record("reporting", "1.2.0", 7))
                .expect("record");
            registry
                .get("reporting", "1.2.0")
                .expect("lookup")
                .expect("registered")
        };
        let reopened = ModuleRegistry::open(&path).expect("reopen");
        let after = reopened
            .get("reporting", "1.2.0")
            .expect("lookup")
            .expect("registered");
        assert_eq!(after, before, "the record must survive a restart unchanged");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

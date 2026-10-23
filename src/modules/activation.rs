//! Persisted active versions and version removal.
//!
//! Version rows live in [`ModuleRegistry`](crate::modules::registry::ModuleRegistry);
//! this module owns the `active_versions` pointer on top of the same
//! store: one `Mutex` mutation in memory, one immediate transaction on
//! SQLite. Activation state never auto-creates: pointing at an
//! unregistered or non-`ok` version is the caller's error, and removing
//! the active version is refused so the pointer can never dangle.
//!
//! Removal deletes the `module_versions` row (and the `modules` parent
//! when its last version goes) but never touches artifact bytes: the
//! promoted blob is left orphaned for artifact-store GC, per the
//! no-destructive-delete rule.

use std::time::SystemTime;

use rusqlite::{params, OptionalExtension};
use thiserror::Error;

use crate::modules::registry::{IntegrityState, ModuleRegistry, RegistryError, Store};
use crate::storage::database::{from_millis, to_millis};

/// The version currently marked active for one module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveVersion {
    pub module_id: String,
    pub version: String,
    pub activated_at: SystemTime,
}

/// Failures when pointing a module at a version. Unregistered and
/// non-intact targets are caller errors; storage failures are server-side.
#[derive(Debug, Error)]
pub enum ActiveError {
    #[error("module version is not registered: {module_id} {version}")]
    NotRegistered { module_id: String, version: String },
    #[error("module version artifact is not intact ({state}): {module_id} {version}")]
    Integrity {
        module_id: String,
        version: String,
        state: IntegrityState,
    },
    #[error("activation storage failure: {0}")]
    Storage(#[from] RegistryError),
}

impl From<rusqlite::Error> for ActiveError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Storage(RegistryError::from(err))
    }
}

impl From<crate::storage::database::DatabaseError> for ActiveError {
    fn from(err: crate::storage::database::DatabaseError) -> Self {
        Self::Storage(RegistryError::Storage(err))
    }
}

/// Failures when removing a registered version. Removing the active
/// version is refused; everything else is storage failure.
#[derive(Debug, Error)]
pub enum RemoveError {
    #[error("module version is active and cannot be removed: {module_id} {version}")]
    IsActive { module_id: String, version: String },
    #[error("removal storage failure: {0}")]
    Storage(#[from] RegistryError),
}

impl From<rusqlite::Error> for RemoveError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Storage(RegistryError::from(err))
    }
}

impl From<crate::storage::database::DatabaseError> for RemoveError {
    fn from(err: crate::storage::database::DatabaseError) -> Self {
        Self::Storage(RegistryError::Storage(err))
    }
}

impl ModuleRegistry {
    /// Marks `version` as the active version of `module_id`. Verifies the
    /// target exists and is intact, then upserts the pointer with a fresh
    /// timestamp. Never auto-creates a version row.
    pub fn set_active(&self, module_id: &str, version: &str) -> Result<ActiveVersion, ActiveError> {
        match &self.store {
            Store::Memory(memory) => {
                let mut guard = memory.lock().unwrap_or_else(|e| e.into_inner());
                let record = guard
                    .versions
                    .get(&(module_id.to_owned(), version.to_owned()))
                    .ok_or_else(|| ActiveError::NotRegistered {
                        module_id: module_id.to_owned(),
                        version: version.to_owned(),
                    })?;
                if record.integrity_state != IntegrityState::Ok {
                    return Err(ActiveError::Integrity {
                        module_id: module_id.to_owned(),
                        version: version.to_owned(),
                        state: record.integrity_state,
                    });
                }
                let active = ActiveVersion {
                    module_id: module_id.to_owned(),
                    version: version.to_owned(),
                    activated_at: SystemTime::now(),
                };
                guard.active.insert(module_id.to_owned(), active.clone());
                Ok(active)
            }
            Store::Sqlite(database) => database.with_write_tx(|tx| {
                let state: Option<String> = tx
                    .query_row(
                        "SELECT integrity_state FROM module_versions \
                         WHERE module_id = ?1 AND version = ?2",
                        params![module_id, version],
                        |row| row.get(0),
                    )
                    .optional()?;
                let state = state.ok_or_else(|| ActiveError::NotRegistered {
                    module_id: module_id.to_owned(),
                    version: version.to_owned(),
                })?;
                if state != IntegrityState::Ok.as_str() {
                    let parsed =
                        IntegrityState::from_str(&state).unwrap_or(IntegrityState::Mismatch);
                    return Err(ActiveError::Integrity {
                        module_id: module_id.to_owned(),
                        version: version.to_owned(),
                        state: parsed,
                    });
                }
                let now = SystemTime::now();
                tx.execute(
                    "INSERT INTO active_versions (module_id, version, activated_at) \
                     VALUES (?1, ?2, ?3) \
                     ON CONFLICT (module_id) DO UPDATE SET \
                       version = excluded.version, \
                       activated_at = excluded.activated_at",
                    params![module_id, version, to_millis(now)],
                )?;
                Ok(ActiveVersion {
                    module_id: module_id.to_owned(),
                    version: version.to_owned(),
                    activated_at: now,
                })
            }),
        }
    }

    /// Reads the active version pointer for one module. `Ok(None)` when
    /// no version is marked active.
    pub fn get_active(&self, module_id: &str) -> Result<Option<ActiveVersion>, RegistryError> {
        match &self.store {
            Store::Memory(memory) => {
                let guard = memory.lock().unwrap_or_else(|e| e.into_inner());
                Ok(guard.active.get(module_id).cloned())
            }
            Store::Sqlite(database) => database.with_connection(|conn| {
                conn.query_row(
                    "SELECT version, activated_at FROM active_versions WHERE module_id = ?1",
                    params![module_id],
                    |row| {
                        let version: String = row.get(0)?;
                        let activated_at: i64 = row.get(1)?;
                        Ok(ActiveVersion {
                            module_id: module_id.to_owned(),
                            version,
                            activated_at: from_millis(activated_at),
                        })
                    },
                )
                .optional()
                .map_err(RegistryError::from)
            }),
        }
    }

    /// Clears the active version pointer. Returns `false` when no version
    /// was marked active.
    pub fn clear_active(&self, module_id: &str) -> Result<bool, RegistryError> {
        match &self.store {
            Store::Memory(memory) => {
                let mut guard = memory.lock().unwrap_or_else(|e| e.into_inner());
                Ok(guard.active.remove(module_id).is_some())
            }
            Store::Sqlite(database) => database.with_write_tx(|tx| {
                let removed = tx.execute(
                    "DELETE FROM active_versions WHERE module_id = ?1",
                    params![module_id],
                )?;
                Ok(removed > 0)
            }),
        }
    }

    /// Removes a registered version. Refused when the version is the
    /// module's active pointer; the caller must clear or repoint first.
    /// Deletes the `modules` parent row when its last version goes.
    /// Artifact bytes are untouched (orphaned for GC). Returns `false`
    /// when the version was not registered.
    pub fn remove_version(&self, module_id: &str, version: &str) -> Result<bool, RemoveError> {
        match &self.store {
            Store::Memory(memory) => {
                let mut guard = memory.lock().unwrap_or_else(|e| e.into_inner());
                if guard
                    .active
                    .get(module_id)
                    .is_some_and(|active| active.version == version)
                {
                    return Err(RemoveError::IsActive {
                        module_id: module_id.to_owned(),
                        version: version.to_owned(),
                    });
                }
                Ok(guard
                    .versions
                    .remove(&(module_id.to_owned(), version.to_owned()))
                    .is_some())
            }
            Store::Sqlite(database) => database.with_write_tx(|tx| {
                let active: Option<String> = tx
                    .query_row(
                        "SELECT version FROM active_versions WHERE module_id = ?1",
                        params![module_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if active.as_deref() == Some(version) {
                    return Err(RemoveError::IsActive {
                        module_id: module_id.to_owned(),
                        version: version.to_owned(),
                    });
                }
                let removed = tx.execute(
                    "DELETE FROM module_versions WHERE module_id = ?1 AND version = ?2",
                    params![module_id, version],
                )?;
                if removed == 0 {
                    return Ok(false);
                }
                tx.execute(
                    "DELETE FROM modules WHERE module_id = ?1 \
                     AND NOT EXISTS \
                       (SELECT 1 FROM module_versions WHERE module_id = ?1)",
                    params![module_id],
                )?;
                Ok(true)
            }),
        }
    }
}

/// Locks the memory store for tests in this module.
#[cfg(test)]
fn lock_for_test(
    registry: &ModuleRegistry,
) -> std::sync::MutexGuard<'_, crate::modules::registry::MemoryState> {
    match &registry.store {
        Store::Memory(memory) => memory.lock().unwrap_or_else(|e| e.into_inner()),
        Store::Sqlite(_) => panic!("test helper needs the memory backend"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::registry::{IntegrityState, ModuleRecord};
    use crate::packages::artifact::ArtifactDigest;

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

    /// The activation contract every backend must honor.
    fn assert_activation_semantics(registry: &ModuleRegistry) {
        assert!(registry.get_active("reporting").expect("lookup").is_none());
        assert!(!registry.clear_active("reporting").expect("clear"));

        // Unregistered targets never activate.
        let err = registry.set_active("reporting", "1.0.0").unwrap_err();
        assert!(matches!(err, ActiveError::NotRegistered { .. }));

        registry
            .record(record("reporting", "1.0.0", 7))
            .expect("record");
        registry
            .record(record("reporting", "1.1.0", 8))
            .expect("record");

        // Set -> get -> repoint -> clear.
        let first = registry.set_active("reporting", "1.0.0").expect("activate");
        assert_eq!(first.version, "1.0.0");
        assert_eq!(
            registry
                .get_active("reporting")
                .expect("lookup")
                .expect("active")
                .version,
            "1.0.0"
        );
        let second = registry.set_active("reporting", "1.1.0").expect("repoint");
        assert_eq!(second.version, "1.1.0");
        assert_eq!(
            registry
                .get_active("reporting")
                .expect("lookup")
                .expect("active")
                .version,
            "1.1.0"
        );
        assert!(registry.clear_active("reporting").expect("clear"));
        assert!(registry.get_active("reporting").expect("lookup").is_none());
        assert!(!registry.clear_active("reporting").expect("clear again"));

        // Non-intact targets never activate.
        registry
            .set_integrity_state("reporting", "1.0.0", IntegrityState::Missing)
            .expect("mark");
        let err = registry.set_active("reporting", "1.0.0").unwrap_err();
        assert!(matches!(err, ActiveError::Integrity { .. }));
        assert!(registry.get_active("reporting").expect("lookup").is_none());
    }

    /// The removal contract every backend must honor.
    fn assert_removal_semantics(registry: &ModuleRegistry) {
        assert!(!registry
            .remove_version("reporting", "9.9.9")
            .expect("missing removes nothing"));

        registry
            .record(record("reporting", "1.0.0", 7))
            .expect("record");
        registry
            .record(record("reporting", "1.1.0", 8))
            .expect("record");
        registry.set_active("reporting", "1.1.0").expect("activate");

        // Active version is refused; inactive removes fine.
        let err = registry.remove_version("reporting", "1.1.0").unwrap_err();
        assert!(matches!(err, RemoveError::IsActive { .. }));
        assert!(registry
            .get("reporting", "1.1.0")
            .expect("lookup")
            .is_some());
        assert!(registry
            .remove_version("reporting", "1.0.0")
            .expect("remove inactive"));
        assert!(registry
            .get("reporting", "1.0.0")
            .expect("lookup")
            .is_none());
        assert!(!registry
            .remove_version("reporting", "1.0.0")
            .expect("second remove is idempotent"));

        // Repoint then remove the old active version.
        registry.set_active("reporting", "1.1.0").expect("repoint");
        registry.clear_active("reporting").expect("clear");
        assert!(registry
            .remove_version("reporting", "1.1.0")
            .expect("remove after clear"));
        assert!(registry
            .list_versions("reporting")
            .expect("list")
            .is_empty());
    }

    #[test]
    fn memory_activation_and_removal() {
        let registry = ModuleRegistry::new();
        assert_activation_semantics(&registry);
        let registry = ModuleRegistry::new();
        assert_removal_semantics(&registry);
    }

    #[test]
    fn sqlite_activation_and_removal_matches() {
        let registry = ModuleRegistry::open_in_memory().expect("open");
        assert_activation_semantics(&registry);
        let registry = ModuleRegistry::open_in_memory().expect("open");
        assert_removal_semantics(&registry);
    }

    #[test]
    fn memory_module_parent_needs_no_cleanup_row() {
        // Memory derives modules from versions; removing the last version
        // must drop the module from list_modules.
        let registry = ModuleRegistry::new();
        registry.record(record("solo", "1.0.0", 7)).expect("record");
        assert_eq!(registry.list_modules().expect("modules"), vec!["solo"]);
        assert!(registry.remove_version("solo", "1.0.0").expect("remove"));
        assert!(registry.list_modules().expect("modules").is_empty());
    }

    #[test]
    fn sqlite_active_pointer_and_parent_cleanup_survive_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "conductor-active-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let path = dir.join("database").join("conductor.db");
        {
            let registry = ModuleRegistry::open(&path).expect("open");
            registry
                .record(record("reporting", "1.0.0", 7))
                .expect("record");
            registry
                .record(record("reporting", "1.1.0", 8))
                .expect("record");
            registry.set_active("reporting", "1.1.0").expect("activate");
            registry
                .remove_version("reporting", "1.0.0")
                .expect("remove");
        }
        let reopened = ModuleRegistry::open(&path).expect("reopen");
        assert_eq!(
            reopened
                .get_active("reporting")
                .expect("lookup")
                .expect("active survives")
                .version,
            "1.1.0"
        );
        assert!(reopened
            .get("reporting", "1.0.0")
            .expect("lookup")
            .is_none());
        assert!(reopened
            .get("reporting", "1.1.0")
            .expect("lookup")
            .is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sqlite_parent_row_goes_with_last_version() {
        let registry = ModuleRegistry::open_in_memory().expect("open");
        registry.record(record("solo", "1.0.0", 7)).expect("record");
        assert!(registry.remove_version("solo", "1.0.0").expect("remove"));
        assert!(registry.list_modules().expect("modules").is_empty());
        // A fresh registration of the same module still works: the parent
        // row is recreated, not left dangling.
        registry.record(record("solo", "2.0.0", 8)).expect("record");
        assert!(registry.get("solo", "2.0.0").expect("lookup").is_some());
    }

    #[test]
    fn memory_helper_sees_shared_state() {
        let registry = ModuleRegistry::new();
        registry
            .record(record("reporting", "1.0.0", 7))
            .expect("record");
        assert!(lock_for_test(&registry)
            .versions
            .contains_key(&("reporting".to_owned(), "1.0.0".to_owned())));
    }
}

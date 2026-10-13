//! Tracks registered module versions in memory.
//!
//! The registry is the authority on which artifact digest a
//! `(module_id, version)` pair means. Registration is idempotent for the
//! exact same digest and conflicts when a version is re-registered with
//! different bytes — a version never silently changes meaning. Persistence
//! is future work: entries live for the process lifetime.
//!
//! The registry stores records, never code and never paths: activation
//! consumes registry state plus policy and must not re-open archives.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;
use thiserror::Error;

use crate::packages::artifact::ArtifactDigest;

/// One registered module version. Identity, provenance, and registration
/// time — everything activation and audit need without touching disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleRecord {
    pub module_id: String,
    pub version: String,
    pub digest: ArtifactDigest,
    /// Key id that authorized the upload (from the validation verdict).
    pub signer_key_id: String,
    /// Declared runtime from the validated manifest.
    pub runtime: String,
    pub registered_at: SystemTime,
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
}

/// In-memory registry of module versions. Thread-safe; one lock covers the
/// whole map, and every mutation is a single insert, so a panic mid-record
/// cannot leave partial state (poisoned locks are recovered, not raced).
#[derive(Debug, Default)]
pub struct ModuleRegistry {
    entries: Mutex<HashMap<(String, String), ModuleRecord>>,
}

impl ModuleRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a module version. Idempotent for the identical digest;
    /// rejects a different digest for an already-registered version.
    pub fn record(&self, record: ModuleRecord) -> Result<Registration, RegistryError> {
        let key = (record.module_id.clone(), record.version.clone());
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(&key) {
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
                entries.insert(key, record);
                Ok(registration)
            }
        }
    }

    /// Looks up a registered module version.
    #[must_use]
    pub fn get(&self, module_id: &str, version: &str) -> Option<ModuleRecord> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(&(module_id.to_owned(), version.to_owned()))
            .cloned()
    }

    /// Number of registered module versions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(module: &str, version: &str, byte: u8) -> ModuleRecord {
        ModuleRecord {
            module_id: module.to_owned(),
            version: version.to_owned(),
            digest: ArtifactDigest::new([byte; 32]),
            signer_key_id: "k1".to_owned(),
            runtime: "rust".to_owned(),
            registered_at: SystemTime::now(),
        }
    }

    #[test]
    fn records_and_resolves_by_module_version() {
        let registry = ModuleRegistry::new();
        assert!(registry.is_empty());
        let outcome = registry
            .record(record("reporting", "1.0.0", 7))
            .expect("record");
        assert!(!outcome.already_registered);
        assert_eq!(registry.len(), 1);
        let found = registry.get("reporting", "1.0.0").expect("registered");
        assert_eq!(found.digest, ArtifactDigest::new([7u8; 32]));
        assert!(registry.get("reporting", "2.0.0").is_none());
        assert!(registry.get("other", "1.0.0").is_none());
    }

    #[test]
    fn identical_digest_is_idempotent() {
        let registry = ModuleRegistry::new();
        registry
            .record(record("reporting", "1.0.0", 7))
            .expect("first");
        let again = registry
            .record(record("reporting", "1.0.0", 7))
            .expect("idempotent");
        assert!(again.already_registered);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn different_digest_for_same_version_conflicts() {
        let registry = ModuleRegistry::new();
        registry
            .record(record("reporting", "1.0.0", 7))
            .expect("first");
        let err = registry
            .record(record("reporting", "1.0.0", 8))
            .unwrap_err();
        assert!(matches!(err, RegistryError::VersionConflict { .. }));
        // The registered digest is untouched.
        assert_eq!(
            registry.get("reporting", "1.0.0").expect("kept").digest,
            ArtifactDigest::new([7u8; 32])
        );
    }

    #[test]
    fn distinct_versions_coexist() {
        let registry = ModuleRegistry::new();
        registry
            .record(record("reporting", "1.0.0", 7))
            .expect("v1");
        registry
            .record(record("reporting", "1.1.0", 8))
            .expect("v2");
        registry
            .record(record("billing", "1.0.0", 9))
            .expect("other module");
        assert_eq!(registry.len(), 3);
    }
}

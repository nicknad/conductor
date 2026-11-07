//! Classifies registered versions against their artifact bytes. It never
//! parses, extracts, executes, repairs, or deletes. Determinate findings are
//! persisted; indeterminate I/O aborts. All rows are classified before any are
//! persisted, so a fatal read writes nothing.

use std::path::Path;

use thiserror::Error;
use tracing::{info, warn};

use crate::modules::registry::{IntegrityState, ModuleRecord, ModuleRegistry, RegistryError};
use crate::storage::artifact_verify::{
    preflight_artifact_root, resolve_registered_artifact, verify_open_artifact, ArtifactPathError,
    ArtifactRootError, ArtifactVerifyError,
};

/// One reconciliation pass's classification counts. Every scanned row lands in
/// exactly one of `ok`, `missing`, or `mismatch`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub scanned: usize,
    pub ok: usize,
    pub missing: usize,
    pub mismatch: usize,
}

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    ArtifactRoot(#[from] ArtifactRootError),
    #[error("artifact read failed for {module_id} {version}: {detail}")]
    ArtifactRead {
        module_id: String,
        version: String,
        detail: String,
    },
}

trait RegistryAccess {
    fn all_versions(&self) -> Result<Vec<ModuleRecord>, RegistryError>;
    fn set_integrity_state(
        &self,
        module_id: &str,
        version: &str,
        state: IntegrityState,
    ) -> Result<bool, RegistryError>;
}

impl RegistryAccess for ModuleRegistry {
    fn all_versions(&self) -> Result<Vec<ModuleRecord>, RegistryError> {
        ModuleRegistry::all_versions(self)
    }

    fn set_integrity_state(
        &self,
        module_id: &str,
        version: &str,
        state: IntegrityState,
    ) -> Result<bool, RegistryError> {
        ModuleRegistry::set_integrity_state(self, module_id, version, state)
    }
}

/// Classifies every registered version's artifact and persists the result.
///
/// There is no production caller yet; a later slice runs this during host
/// assembly. The run is idempotent: the same rows and bytes produce the same
/// states on every pass.
pub fn reconcile_registry(
    registry: &ModuleRegistry,
    artifact_root: &Path,
    max_artifact_bytes: u64,
) -> Result<ReconciliationReport, ReconcileError> {
    reconcile_with(registry, artifact_root, max_artifact_bytes)
}

fn reconcile_with<R: RegistryAccess + ?Sized>(
    registry: &R,
    artifact_root: &Path,
    max_artifact_bytes: u64,
) -> Result<ReconciliationReport, ReconcileError> {
    let canonical_root = preflight_artifact_root(artifact_root)?;
    let records = registry.all_versions()?;
    let mut report = ReconciliationReport::default();
    let mut classifications = Vec::with_capacity(records.len());

    for record in records {
        report.scanned += 1;
        classifications.push((
            classify(&canonical_root, &record, max_artifact_bytes)?,
            record,
        ));
    }

    for (classification, record) in classifications {
        if let Some(reason) = &classification.reason {
            warn!(
                module_id = %bounded_identity(&record.module_id),
                version = %bounded_identity(&record.version),
                reason = %bounded_reason(reason),
                "registered artifact is not intact"
            );
        }

        match registry.set_integrity_state(&record.module_id, &record.version, classification.state)
        {
            Ok(true) => {}
            Ok(false) => {
                warn!(
                    module_id = %bounded_identity(&record.module_id),
                    version = %bounded_identity(&record.version),
                    "reconciliation could not persist integrity state; row is gone"
                );
            }
            Err(err) => return Err(ReconcileError::Registry(err)),
        }

        match classification.state {
            IntegrityState::Ok => report.ok += 1,
            IntegrityState::Missing => report.missing += 1,
            IntegrityState::Mismatch => report.mismatch += 1,
        }
    }

    info!(
        scanned = report.scanned,
        ok = report.ok,
        missing = report.missing,
        mismatch = report.mismatch,
        "artifact reconciliation complete"
    );
    Ok(report)
}

struct Classification {
    state: IntegrityState,
    reason: Option<String>,
}

impl Classification {
    fn intact() -> Self {
        Self {
            state: IntegrityState::Ok,
            reason: None,
        }
    }

    fn unhealthy(state: IntegrityState, reason: String) -> Self {
        Self {
            state,
            reason: Some(reason),
        }
    }
}

fn classify(
    canonical_root: &Path,
    record: &ModuleRecord,
    max_artifact_bytes: u64,
) -> Result<Classification, ReconcileError> {
    let path = match resolve_registered_artifact(
        canonical_root,
        &record.module_id,
        &record.version,
        &record.digest,
        &record.artifact_relpath,
    ) {
        Ok(path) => path,
        Err(err) => return path_failure(record, err),
    };

    match verify_open_artifact(
        &path,
        record.artifact_size,
        &record.digest,
        max_artifact_bytes,
    ) {
        Ok(()) => Ok(Classification::intact()),
        Err(err) => verify_failure(record, err),
    }
}

fn path_failure(
    record: &ModuleRecord,
    err: ArtifactPathError,
) -> Result<Classification, ReconcileError> {
    let reason = err.to_string();
    match err {
        ArtifactPathError::Missing => {
            Ok(Classification::unhealthy(IntegrityState::Missing, reason))
        }
        ArtifactPathError::Io(detail) => Err(ReconcileError::ArtifactRead {
            module_id: bounded_identity(&record.module_id).to_owned(),
            version: bounded_identity(&record.version).to_owned(),
            detail,
        }),
        ArtifactPathError::NonCanonical
        | ArtifactPathError::ParentEscape
        | ArtifactPathError::Symlink
        | ArtifactPathError::NotRegular => {
            Ok(Classification::unhealthy(IntegrityState::Mismatch, reason))
        }
    }
}

fn verify_failure(
    record: &ModuleRecord,
    err: ArtifactVerifyError,
) -> Result<Classification, ReconcileError> {
    let reason = err.to_string();
    match err {
        ArtifactVerifyError::Missing => {
            Ok(Classification::unhealthy(IntegrityState::Missing, reason))
        }
        ArtifactVerifyError::Io(detail) => Err(ReconcileError::ArtifactRead {
            module_id: bounded_identity(&record.module_id).to_owned(),
            version: bounded_identity(&record.version).to_owned(),
            detail,
        }),
        ArtifactVerifyError::Symlink
        | ArtifactVerifyError::NotRegular
        | ArtifactVerifyError::Size { .. }
        | ArtifactVerifyError::Oversized { .. }
        | ArtifactVerifyError::Digest => {
            Ok(Classification::unhealthy(IntegrityState::Mismatch, reason))
        }
    }
}

/// Keeps DB-controlled identity fields from bloating a log event or error.
fn bounded_identity(identity: &str) -> &str {
    truncate_on_char_boundary(identity, 128)
}

/// Keeps DB-controlled or OS-supplied detail from bloating a log event.
fn bounded_reason(reason: &str) -> &str {
    truncate_on_char_boundary(reason, 200)
}

fn truncate_on_char_boundary(value: &str, max: usize) -> &str {
    let mut end = max.min(value.len());
    // A UTF-8 character is at most 4 bytes; three steps reach a boundary.
    for _ in 0..4 {
        if value.is_char_boundary(end) {
            break;
        }
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::artifact::ArtifactDigest;
    use crate::packages::digest::Sha256DigestProvider;
    use crate::storage::artifact_store::canonical_artifact_relpath;
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;
    use std::time::SystemTime;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("conductor-reconcile-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct FakeRegistry {
        records: RefCell<Vec<ModuleRecord>>,
        updates: RefCell<Vec<(String, String, IntegrityState)>>,
        read_error: bool,
        write_error: bool,
        write_returns_false: bool,
    }

    impl RegistryAccess for FakeRegistry {
        fn all_versions(&self) -> Result<Vec<ModuleRecord>, RegistryError> {
            if self.read_error {
                return Err(registry_error());
            }
            Ok(self.records.borrow().clone())
        }

        fn set_integrity_state(
            &self,
            module_id: &str,
            version: &str,
            state: IntegrityState,
        ) -> Result<bool, RegistryError> {
            if self.write_error {
                return Err(registry_error());
            }
            self.updates
                .borrow_mut()
                .push((module_id.to_owned(), version.to_owned(), state));
            Ok(!self.write_returns_false)
        }
    }

    fn registry_error() -> RegistryError {
        RegistryError::InvalidArtifactPath {
            relpath: "stored".to_owned(),
            expected: "expected".to_owned(),
        }
    }

    fn artifact_root(temp: &TempDir) -> PathBuf {
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("artifact root");
        root
    }

    fn record(module_id: &str, version: &str, bytes: &[u8]) -> ModuleRecord {
        let digest = ArtifactDigest::new(Sha256DigestProvider.digest(bytes).expect("hash"));
        ModuleRecord {
            module_id: module_id.to_owned(),
            version: version.to_owned(),
            digest,
            signer_key_id: "k1".to_owned(),
            runtime: "rust".to_owned(),
            manifest_version: 1,
            manifest_json: "{}".to_owned(),
            artifact_relpath: canonical_artifact_relpath(module_id, version, &digest),
            artifact_size: bytes.len() as u64,
            integrity_state: IntegrityState::Ok,
            registered_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn write_artifact(root: &Path, record: &ModuleRecord, bytes: &[u8]) {
        let relpath =
            canonical_artifact_relpath(&record.module_id, &record.version, &record.digest);
        let path = root.join(relpath);
        fs::create_dir_all(path.parent().expect("artifact parent")).expect("artifact dir");
        fs::write(path, bytes).expect("write artifact");
    }

    fn registry_with(records: Vec<ModuleRecord>) -> FakeRegistry {
        FakeRegistry {
            records: RefCell::new(records),
            ..FakeRegistry::default()
        }
    }

    fn update_calls(registry: &FakeRegistry) -> Vec<(String, String, IntegrityState)> {
        registry.updates.borrow().clone()
    }

    #[test]
    fn intact_row_is_ok_and_persisted() {
        let temp = TempDir::new("intact-row");
        let root = artifact_root(&temp);
        let record = record("mod", "1.0.0", b"intact bytes");
        write_artifact(&root, &record, b"intact bytes");
        let registry = registry_with(vec![record]);

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(
            report,
            ReconciliationReport {
                scanned: 1,
                ok: 1,
                missing: 0,
                mismatch: 0
            }
        );
        assert_eq!(
            update_calls(&registry),
            vec![("mod".to_owned(), "1.0.0".to_owned(), IntegrityState::Ok)]
        );
    }

    #[test]
    fn missing_row_is_missing_and_persisted() {
        let temp = TempDir::new("missing-row");
        let root = artifact_root(&temp);
        let record = record("mod", "1.0.0", b"absent bytes");
        let registry = registry_with(vec![record]);

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(report.missing, 1);
        assert_eq!(report.ok, 0);
        assert_eq!(
            update_calls(&registry),
            vec![(
                "mod".to_owned(),
                "1.0.0".to_owned(),
                IntegrityState::Missing
            )]
        );
    }

    #[test]
    fn tampered_row_is_mismatch_and_persisted() {
        let temp = TempDir::new("tampered-row");
        let root = artifact_root(&temp);
        let record = record("mod", "1.0.0", b"expected");
        write_artifact(&root, &record, b"tampered");
        let registry = registry_with(vec![record]);

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(report.mismatch, 1);
        assert_eq!(
            update_calls(&registry),
            vec![(
                "mod".to_owned(),
                "1.0.0".to_owned(),
                IntegrityState::Mismatch
            )]
        );
    }

    #[test]
    fn missing_row_does_not_stop_a_later_intact_row() {
        let temp = TempDir::new("mixed-rows");
        let root = artifact_root(&temp);
        let missing = record("a-missing", "1.0.0", b"absent");
        let intact = record("b-intact", "2.0.0", b"present");
        write_artifact(&root, &intact, b"present");
        let registry = registry_with(vec![missing, intact]);

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(
            report,
            ReconciliationReport {
                scanned: 2,
                ok: 1,
                missing: 1,
                mismatch: 0
            }
        );
        assert_eq!(update_calls(&registry).len(), 2);
    }

    #[test]
    fn empty_registry_reports_zero_counts() {
        let temp = TempDir::new("empty-registry");
        let root = artifact_root(&temp);
        let registry = FakeRegistry::default();

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(report, ReconciliationReport::default());
        assert!(update_calls(&registry).is_empty());
    }

    #[test]
    fn registry_read_failure_is_registry_error() {
        let temp = TempDir::new("read-failure");
        let root = artifact_root(&temp);
        let registry = FakeRegistry {
            read_error: true,
            ..FakeRegistry::default()
        };

        let result = reconcile_with(&registry, &root, 1024);

        assert!(matches!(result, Err(ReconcileError::Registry(_))));
    }

    #[test]
    fn persistence_failure_is_registry_error() {
        let temp = TempDir::new("write-failure");
        let root = artifact_root(&temp);
        let record = record("mod", "1.0.0", b"present");
        write_artifact(&root, &record, b"present");
        let registry = FakeRegistry {
            records: RefCell::new(vec![record]),
            write_error: true,
            ..FakeRegistry::default()
        };

        let result = reconcile_with(&registry, &root, 1024);

        assert!(matches!(result, Err(ReconcileError::Registry(_))));
    }

    #[test]
    fn false_persistence_result_still_counts_the_row() {
        let temp = TempDir::new("write-false");
        let root = artifact_root(&temp);
        let record = record("mod", "1.0.0", b"present");
        write_artifact(&root, &record, b"present");
        let registry = FakeRegistry {
            records: RefCell::new(vec![record]),
            write_returns_false: true,
            ..FakeRegistry::default()
        };

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(report.scanned, 1);
        assert_eq!(report.ok, 1);
        assert_eq!(update_calls(&registry).len(), 1);
    }

    #[test]
    fn legacy_non_canonical_row_is_mismatch() {
        let temp = TempDir::new("legacy-relpath");
        let root = artifact_root(&temp);
        let mut record = record("mod", "1.0.0", b"present");
        record.artifact_relpath = "mod/1.0.0/legacy-name.zip".to_owned();
        let registry = registry_with(vec![record]);

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(report.mismatch, 1);
        assert_eq!(update_calls(&registry)[0].2, IntegrityState::Mismatch);
    }

    #[test]
    fn unsafe_identity_row_is_mismatch() {
        let temp = TempDir::new("unsafe-row");
        let root = artifact_root(&temp);
        let record = record("../..", "1.0.0", b"outside bytes");
        let registry = registry_with(vec![record]);

        let report = reconcile_with(&registry, &root, 1024).expect("reconcile");

        assert_eq!(report.mismatch, 1);
        assert_eq!(report.ok, 0);
    }

    #[test]
    fn regular_file_artifact_root_is_artifact_root_error() {
        let temp = TempDir::new("root-file");
        let root = temp.path().join("artifacts");
        fs::write(&root, b"not a directory").expect("root file");
        let registry = FakeRegistry::default();

        let result = reconcile_with(&registry, &root, 1024);

        assert!(matches!(result, Err(ReconcileError::ArtifactRoot(_))));
    }

    #[test]
    fn non_directory_parent_is_artifact_read_error() {
        let temp = TempDir::new("enotdir-row");
        let root = artifact_root(&temp);
        fs::write(root.join("mod"), b"not a directory").expect("file parent");
        let record = record("mod", "1.0.0", b"present");
        let registry = registry_with(vec![record]);

        let result = reconcile_with(&registry, &root, 1024);

        assert!(matches!(result, Err(ReconcileError::ArtifactRead { .. })));
    }

    #[test]
    fn reconciliation_does_not_modify_artifact_bytes() {
        let temp = TempDir::new("bytes-unchanged");
        let root = artifact_root(&temp);
        let record = record("mod", "1.0.0", b"immutable bytes");
        write_artifact(&root, &record, b"immutable bytes");
        let path = root.join(canonical_artifact_relpath(
            &record.module_id,
            &record.version,
            &record.digest,
        ));
        let before = fs::read(&path).expect("read before");
        let registry = registry_with(vec![record]);

        reconcile_with(&registry, &root, 1024).expect("reconcile");

        let after = fs::read(&path).expect("read after");
        assert_eq!(before, after);
    }

    #[test]
    fn fatal_read_leaves_no_partial_writes() {
        let temp = TempDir::new("fatal-read-no-writes");
        let root = artifact_root(&temp);
        let intact = record("a-intact", "1.0.0", b"present");
        let unreadable = record("mod", "1.0.0", b"present");
        write_artifact(&root, &intact, b"present");
        fs::write(root.join("mod"), b"not a directory").expect("file parent");
        let registry = registry_with(vec![intact, unreadable]);

        let result = reconcile_with(&registry, &root, 1024);

        assert!(matches!(result, Err(ReconcileError::ArtifactRead { .. })));
        assert!(update_calls(&registry).is_empty());
    }

    #[test]
    fn reconcile_registry_classifies_real_rows() {
        let temp = TempDir::new("real-registry");
        let root = artifact_root(&temp);
        let registry = ModuleRegistry::open_in_memory().expect("in-memory registry");
        let intact = record("a-intact", "1.0.0", b"intact bytes");
        let missing = record("b-missing", "1.0.0", b"missing bytes");
        let tampered = record("c-tampered", "1.0.0", b"expected bytes");
        write_artifact(&root, &intact, b"intact bytes");
        write_artifact(&root, &tampered, b"tampered bytes");
        registry.record(intact).expect("record intact");
        registry.record(missing).expect("record missing");
        registry.record(tampered).expect("record tampered");

        let report = reconcile_registry(&registry, &root, 1024).expect("reconcile");

        assert_eq!(
            report,
            ReconciliationReport {
                scanned: 3,
                ok: 1,
                missing: 1,
                mismatch: 1
            }
        );
        assert_eq!(
            registry
                .get_integrity_state("a-intact", "1.0.0")
                .expect("state"),
            Some(IntegrityState::Ok)
        );
        assert_eq!(
            registry
                .get_integrity_state("b-missing", "1.0.0")
                .expect("state"),
            Some(IntegrityState::Missing)
        );
        assert_eq!(
            registry
                .get_integrity_state("c-tampered", "1.0.0")
                .expect("state"),
            Some(IntegrityState::Mismatch)
        );
    }

    #[test]
    fn bounded_identity_truncates_on_char_boundary() {
        // The one-byte prefix puts byte 128 inside a multi-byte character, so
        // truncation must walk back to a boundary instead of slicing at 128.
        let long = format!("a{}", "é".repeat(100));
        let bounded = bounded_identity(&long);
        assert!(long.starts_with(bounded));
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(bounded.len(), 127);
    }

    #[test]
    fn bounded_identity_truncates_a_three_byte_character() {
        // "€" is three bytes, so byte 128 falls inside a character. The prefix
        // must stop at the previous boundary (126) instead of slicing at 128.
        let long = "€".repeat(100);
        let bounded = bounded_identity(&long);
        assert!(long.starts_with(bounded));
        assert_eq!(bounded, "€".repeat(42).as_str());
        assert_eq!(bounded.len(), 126);
        assert!(bounded.is_char_boundary(bounded.len()));
    }

    #[test]
    fn bounded_reason_truncates_on_char_boundary() {
        let long = format!("a{}", "é".repeat(150));
        let bounded = bounded_reason(&long);
        assert!(long.starts_with(bounded));
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(bounded.len(), 199);
    }

    #[test]
    fn bounded_reason_truncates_a_three_byte_character() {
        // 200 is one byte inside a three-byte character, so the prefix ends at
        // the previous boundary (198).
        let long = "€".repeat(100);
        let bounded = bounded_reason(&long);
        assert!(long.starts_with(bounded));
        assert_eq!(bounded.len(), 198);
        assert!(bounded.is_char_boundary(bounded.len()));
    }
}

//! Compares declared files against actual archive entries. Persists
//! no lifecycle state.
//!
//! Set comparison only: every manifest-declared file must be present in
//! the archive, and no undeclared file may be present — extras could smuggle
//! payloads past review. Byte-level agreement (sizes, digests) is checked
//! during staged extraction, where the same stream feeds hashing and
//! writing. Declared paths pass through the same [`check_entry_path`]
//! confinement policy as archive entries: the manifest is attacker-adjacent
//! input until the signature over the package verifies.

use thiserror::Error;

use super::archive::{check_entry_path, ArchiveError, InspectedArchive};

/// A file the manifest declares must be in the package. Sourced from
/// manifest parsing once the schema lands; defined here because inventory
/// is its first consumer.
#[derive(Debug, Clone)]
pub struct DeclaredFile {
    pub path: String,
}

impl DeclaredFile {
    #[must_use]
    pub fn new(path: impl AsRef<str>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("declared file missing from archive: {0}")]
    MissingFile(String),
    #[error("archive contains undeclared file: {0}")]
    UnexpectedFile(String),
    #[error("manifest declares file twice: {0}")]
    DuplicateDeclaration(String),
    #[error("invalid declared path: {0}")]
    DeclaredPath(#[from] ArchiveError),
}

/// Compares manifest-declared files against one inspection run. Takes the
/// [`InspectedArchive`] itself — not a detached file list — so the
/// inventory can only run against normalized output of the archive stage.
/// Prefer this on the production path; [`check_inventory`] remains for
/// unit tests over synthetic listings.
pub fn check_against_inspected(
    declared: &[DeclaredFile],
    inspected: &InspectedArchive,
) -> Result<(), InventoryError> {
    check_inventory(declared, &inspected.files)
}

/// Compares manifest-declared files against normalized actual archive
/// entries. `actual` must already be normalized (each entry accepted by
/// [`check_entry_path`]); declared paths are validated here. Duplicate
/// detection belongs to [`check_no_duplicate_paths`](super::archive::check_no_duplicate_paths),
/// which runs first.
pub fn check_inventory(declared: &[DeclaredFile], actual: &[String]) -> Result<(), InventoryError> {
    use std::collections::HashSet;

    let mut wanted = HashSet::new();
    for file in declared {
        let normalized = check_entry_path(&file.path, false)?;
        if !wanted.insert(normalized) {
            return Err(InventoryError::DuplicateDeclaration(file.path.clone()));
        }
    }
    let have: HashSet<&str> = actual.iter().map(String::as_str).collect();
    for path in &wanted {
        if !have.contains(path.as_str()) {
            return Err(InventoryError::MissingFile(path.clone()));
        }
    }
    // `actual` entries are already normalized by the archive stage, so a
    // direct set difference is exact — no second normalization pass.
    for path in have {
        if !wanted.contains(path) {
            return Err(InventoryError::UnexpectedFile(path.to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(paths: &[&str]) -> Vec<DeclaredFile> {
        paths.iter().map(DeclaredFile::new).collect()
    }

    fn actual(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matching_sets_pass() {
        check_inventory(
            &declared(&["manifest.json", "bin/plugin.dll"]),
            &actual(&["manifest.json", "bin/plugin.dll"]),
        )
        .expect("matching sets must pass");
        check_inventory(&declared(&[]), &actual(&[])).expect("empty package passes this layer");
    }

    #[test]
    fn missing_and_extra_files_rejected() {
        assert!(matches!(
            check_inventory(&declared(&["a", "b"]), &actual(&["a"])),
            Err(InventoryError::MissingFile(_))
        ));
        assert!(matches!(
            check_inventory(&declared(&["a"]), &actual(&["a", "evil.dll"])),
            Err(InventoryError::UnexpectedFile(_))
        ));
    }

    #[test]
    fn declared_traversal_rejected_through_archive_policy() {
        assert!(matches!(
            check_inventory(&declared(&["../evil"]), &actual(&["../evil"])),
            Err(InventoryError::DeclaredPath(_))
        ));
    }

    #[test]
    fn duplicate_declarations_rejected() {
        assert!(matches!(
            check_inventory(&declared(&["a", "a"]), &actual(&["a"])),
            Err(InventoryError::DuplicateDeclaration(_))
        ));
    }
}

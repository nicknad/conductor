//! ZIP mechanics and extraction safety: entry limits, path normalization,
//! bounded extraction into a controlled staging directory while hashing.
//! Decides no validation outcome on its own.
//!
//! [`ArchiveReader`] is the injectable seam (real ZIP backend vs. test
//! doubles). [`ArchiveLimits`] and [`CompressionMethod`] are runtime policy,
//! bounded by hard implementation maxima. Path-traversal, duplicate-path,
//! and symlink rejection are fixed invariants — never operator options.

use std::fmt;
use std::path::Path;

/// Hard implementation ceilings. Operator-configured [`ArchiveLimits`] must
/// fit inside these; raising them requires a code change, not a config edit.
pub const HARD_MAX_ENTRIES: usize = 100_000;
pub const HARD_MAX_COMPRESSED_BYTES: u64 = 1 << 31;
pub const HARD_MAX_UNCOMPRESSED_BYTES: u64 = 1 << 33;
pub const HARD_MAX_ENTRY_BYTES: u64 = 1 << 31;

/// Bounds applied before reading or decompressing anything.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    pub max_compressed_bytes: u64,
    pub max_uncompressed_bytes: u64,
    pub max_entry_bytes: u64,
}

impl ArchiveLimits {
    /// Rejects zero, unreasonable, or internally inconsistent bounds.
    pub fn validate(&self) -> Result<(), ArchiveError> {
        if self.max_entries == 0
            || self.max_compressed_bytes == 0
            || self.max_uncompressed_bytes == 0
            || self.max_entry_bytes == 0
        {
            return Err(ArchiveError::LimitExceeded(
                "archive limits must be non-zero",
            ));
        }
        if self.max_entries > HARD_MAX_ENTRIES
            || self.max_compressed_bytes > HARD_MAX_COMPRESSED_BYTES
            || self.max_uncompressed_bytes > HARD_MAX_UNCOMPRESSED_BYTES
            || self.max_entry_bytes > HARD_MAX_ENTRY_BYTES
        {
            return Err(ArchiveError::LimitExceeded(
                "archive limits exceed implementation maxima",
            ));
        }
        if self.max_entry_bytes > self.max_uncompressed_bytes {
            return Err(ArchiveError::LimitExceeded(
                "per-entry bound cannot exceed total uncompressed bound",
            ));
        }
        Ok(())
    }
}

/// Explicit compression-method allowlist. Unsupported or unexpected methods
/// are rejected, never attempted opportunistically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMethod {
    Stored,
    Deflate,
}

/// Outcome of structural inspection: entry counts and size bounds before any
/// payload bytes are trusted.
#[derive(Debug, Clone)]
pub struct InspectedArchive {
    pub entry_count: usize,
}

impl InspectedArchive {
    #[must_use]
    pub fn new(entry_count: usize) -> Self {
        Self { entry_count }
    }
}

#[derive(Debug)]
pub enum ArchiveError {
    LimitExceeded(&'static str),
    InvalidArchive(String),
    PathRejected(&'static str),
    UnsupportedCompression(String),
    Io(String),
    /// Scaffold-only: the ZIP backend is not wired yet. Removed once a real
    /// reader lands; never produced for policy violations.
    NotImplemented,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(detail) => write!(f, "archive limit exceeded: {detail}"),
            Self::InvalidArchive(detail) => write!(f, "invalid archive: {detail}"),
            Self::PathRejected(detail) => write!(f, "archive path rejected: {detail}"),
            Self::UnsupportedCompression(detail) => {
                write!(f, "unsupported compression method: {detail}")
            }
            Self::Io(detail) => write!(f, "archive I/O failure: {detail}"),
            Self::NotImplemented => write!(f, "archive backend not implemented yet"),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Injectable archive backend. The validator drives inspection first;
/// extraction (directed by `storage::staging`) only runs against a verified
/// inventory — never as a casual `unzip(path, destination)` utility.
pub trait ArchiveReader: Send + Sync {
    fn inspect(
        &self,
        archive: &Path,
        limits: &ArchiveLimits,
    ) -> Result<InspectedArchive, ArchiveError>;
}

/// Initial production reader. The ZIP backend is not wired yet, so
/// inspection validates limits then fails closed.
#[derive(Debug, Default)]
pub struct ZipArchiveReader;

impl ArchiveReader for ZipArchiveReader {
    fn inspect(
        &self,
        _archive: &Path,
        limits: &ArchiveLimits,
    ) -> Result<InspectedArchive, ArchiveError> {
        limits.validate()?;
        Err(ArchiveError::NotImplemented)
    }
}

/// Maximum accepted entry-name length in bytes. Bounds attacker-controlled
/// strings before any allocation or filesystem contact.
pub const MAX_ENTRY_PATH_LEN: usize = 1_024;

/// Pure entry-path policy: the fixed archive-safety invariant, testable
/// without I/O. Rejects absolute paths, Windows drive prefixes, `.` / `..`
/// components, empty segments, backslashes, over-long names, and symlink
/// entries. A single trailing `/` (explicit directory entry) is stripped —
/// directories carry no payload and are recreated from file parents during
/// extraction. Returns the normalized relative path, confined by
/// construction: no caller can obtain an escaping path from this function.
pub fn check_entry_path(entry: &str, is_symlink: bool) -> Result<String, ArchiveError> {
    if is_symlink {
        return Err(ArchiveError::PathRejected(
            "symlink entries are never extracted",
        ));
    }
    if entry.is_empty() {
        return Err(ArchiveError::PathRejected("empty entry name"));
    }
    if entry.len() > MAX_ENTRY_PATH_LEN {
        return Err(ArchiveError::PathRejected(
            "entry name exceeds length bound",
        ));
    }
    if entry.contains('\\') {
        return Err(ArchiveError::PathRejected(
            "backslashes are never accepted in entry names",
        ));
    }
    if entry.starts_with('/') {
        return Err(ArchiveError::PathRejected("absolute paths are rejected"));
    }
    let bytes = entry.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(ArchiveError::PathRejected(
            "drive-prefixed paths are rejected",
        ));
    }
    let stripped = entry.strip_suffix('/').unwrap_or(entry);
    if stripped.is_empty() {
        return Err(ArchiveError::PathRejected("empty entry name"));
    }
    let mut normalized = Vec::new();
    for component in stripped.split('/') {
        match component {
            "" => {
                return Err(ArchiveError::PathRejected(
                    "empty path segments are rejected",
                ));
            }
            "." | ".." => {
                return Err(ArchiveError::PathRejected("dot segments are rejected"));
            }
            _ => normalized.push(component),
        }
    }
    Ok(normalized.join("/"))
}

/// Rejects exact-duplicate paths and case-fold collisions within one
/// archive listing. The second check matters because staging may sit on a
/// case-insensitive filesystem, where `Bin/x` and `bin/x` would collapse
/// into a single file and break inventory accounting.
pub fn check_no_duplicate_paths(paths: &[impl AsRef<str>]) -> Result<(), ArchiveError> {
    use std::collections::HashSet;
    let mut seen: HashSet<&str> = HashSet::new();
    let mut folded: HashSet<String> = HashSet::new();
    for path in paths {
        let entry = path.as_ref();
        if !seen.insert(entry) {
            return Err(ArchiveError::PathRejected("duplicate archive paths"));
        }
        if !folded.insert(entry.to_lowercase()) {
            return Err(ArchiveError::PathRejected("case-colliding archive paths"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sane_limits() -> ArchiveLimits {
        ArchiveLimits {
            max_entries: 1,
            max_compressed_bytes: 1,
            max_uncompressed_bytes: 1,
            max_entry_bytes: 1,
        }
    }

    #[test]
    fn limits_carry_all_bounds() {
        let limits = sane_limits();
        assert_eq!(limits.max_entries, 1);
        assert_eq!(limits.max_compressed_bytes, 1);
        assert_eq!(limits.max_uncompressed_bytes, 1);
        assert_eq!(limits.max_entry_bytes, 1);
    }

    #[test]
    fn zero_limits_rejected() {
        let limits = ArchiveLimits {
            max_entries: 0,
            ..sane_limits()
        };
        assert!(matches!(
            limits.validate(),
            Err(ArchiveError::LimitExceeded(_))
        ));
    }

    #[test]
    fn limits_above_hard_maxima_rejected() {
        let limits = ArchiveLimits {
            max_entries: HARD_MAX_ENTRIES + 1,
            ..sane_limits()
        };
        assert!(matches!(
            limits.validate(),
            Err(ArchiveError::LimitExceeded(_))
        ));
    }

    #[test]
    fn per_entry_above_total_rejected() {
        let limits = ArchiveLimits {
            max_uncompressed_bytes: 1,
            max_entry_bytes: 2,
            ..sane_limits()
        };
        assert!(matches!(
            limits.validate(),
            Err(ArchiveError::LimitExceeded(_))
        ));
    }

    #[test]
    fn production_reader_fails_closed_after_limit_check() {
        let reader = ZipArchiveReader;
        let bad = ArchiveLimits {
            max_entries: 0,
            ..sane_limits()
        };
        assert!(matches!(
            reader.inspect(Path::new("pkg.zip"), &bad),
            Err(ArchiveError::LimitExceeded(_))
        ));
        assert!(matches!(
            reader.inspect(Path::new("pkg.zip"), &sane_limits()),
            Err(ArchiveError::NotImplemented)
        ));
    }

    #[test]
    fn confined_paths_normalize() {
        assert_eq!(
            check_entry_path("manifest.json", false).expect("plain file"),
            "manifest.json"
        );
        assert_eq!(
            check_entry_path("bin/plugin.dll", false).expect("nested file"),
            "bin/plugin.dll"
        );
        assert_eq!(check_entry_path("docs/", false).expect("dir entry"), "docs");
    }

    #[test]
    fn escaping_paths_rejected() {
        for hostile in [
            "",
            "/",
            "/etc/passwd",
            "C:/windows/evil",
            "c:evil",
            "..",
            "../evil",
            "a/../../b",
            "a/./b",
            ".",
            "./b",
            "a//b",
            "/a/b",
            "a\\b",
            "..\\evil",
        ] {
            assert!(
                matches!(
                    check_entry_path(hostile, false),
                    Err(ArchiveError::PathRejected(_))
                ),
                "must reject {hostile:?}"
            );
        }
    }

    #[test]
    fn symlinks_and_overlong_names_rejected() {
        assert!(matches!(
            check_entry_path("manifest.json", true),
            Err(ArchiveError::PathRejected(_))
        ));
        let long = "a".repeat(MAX_ENTRY_PATH_LEN + 1);
        assert!(matches!(
            check_entry_path(&long, false),
            Err(ArchiveError::PathRejected(_))
        ));
        assert!(check_entry_path(&"a".repeat(MAX_ENTRY_PATH_LEN), false).is_ok());
    }

    #[test]
    fn duplicate_and_colliding_paths_rejected() {
        assert!(check_no_duplicate_paths(&["a".to_owned(), "b".to_owned()]).is_ok());
        assert!(matches!(
            check_no_duplicate_paths(&["a".to_owned(), "a".to_owned()]),
            Err(ArchiveError::PathRejected(_))
        ));
        assert!(matches!(
            check_no_duplicate_paths(&["Bin/x".to_owned(), "bin/x".to_owned()]),
            Err(ArchiveError::PathRejected(_))
        ));
    }
}

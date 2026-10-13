//! ZIP mechanics and extraction safety: entry limits, path normalization,
//! bounded extraction into a controlled staging directory while hashing.
//! Decides no validation outcome on its own.
//!
//! One concrete reader ([`ZipArchiveReader`]); no pluggable archive-engine
//! trait. [`ArchiveLimits`] and [`CompressionMethod`] are runtime policy,
//! bounded by hard implementation maxima. Path-traversal, duplicate-path,
//! and symlink rejection are fixed invariants — never operator options.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

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
/// payload bytes are trusted. `files` holds the normalized paths of every
/// non-directory entry, in listing order — the inventory stage compares this
/// against the manifest's declared files.
#[derive(Debug, Clone)]
pub struct InspectedArchive {
    pub entry_count: usize,
    pub files: Vec<String>,
}

impl InspectedArchive {
    #[must_use]
    pub fn new(entry_count: usize, files: Vec<String>) -> Self {
        Self { entry_count, files }
    }
}

/// What one inspection run enforces. Borrowed from the validation policy
/// ([`PackageValidationPolicy::scan_config`](super::policy::PackageValidationPolicy::scan_config));
/// bundling the parameters here keeps the dependency direction
/// policy → archive instead of a module cycle.
#[derive(Debug, Clone, Copy)]
pub struct ScanConfig<'a> {
    pub limits: &'a ArchiveLimits,
    pub allowed_methods: &'a [CompressionMethod],
    pub max_compression_ratio: u32,
    pub max_nesting_depth: usize,
}

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("archive limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("invalid archive: {0}")]
    InvalidArchive(String),
    #[error("archive path rejected: {0}")]
    PathRejected(&'static str),
    #[error("unsupported compression method: {0}")]
    UnsupportedCompression(String),
    #[error("archive I/O failure: {0}")]
    Io(String),
}

/// Unix file-type bits for symlinks (`S_IFLNK`), masked with `S_IFMT`.
/// The threat is in entry metadata, not the name: a `link` entry passes the
/// path policy, so every entry's mode bits are consulted.
const UNIX_SYMLINK_MASK: u32 = 0o170_000;
const UNIX_SYMLINK_TYPE: u32 = 0o120_000;

/// The concrete archive backend. Inspection first; extraction (directed
/// by `storage::staging`) only runs against a verified inventory — never
/// as a casual `unzip(path, destination)` utility.
#[derive(Debug, Default)]
pub struct ZipArchiveReader;

impl ZipArchiveReader {
    /// Inspects ZIP structure and entry limits without trusting payload
    /// bytes. Validates limits before touching the archive, so a zeroed
    /// config against a missing file reports `LimitExceeded`, never I/O.
    pub fn inspect(
        &self,
        archive: &Path,
        config: &ScanConfig<'_>,
    ) -> Result<InspectedArchive, ArchiveError> {
        config.limits.validate()?;
        let mut file = File::open(archive).map_err(|e| ArchiveError::Io(e.to_string()))?;
        self.inspect_file(&mut file, config)
    }

    /// Same inspection over an already-open handle. The validator hashes
    /// and inspects one open file through this, so hashing and inspection
    /// can never diverge onto different bytes (TOCTOU).
    pub fn inspect_file(
        &self,
        file: &mut File,
        config: &ScanConfig<'_>,
    ) -> Result<InspectedArchive, ArchiveError> {
        config.limits.validate()?;
        let mut zip =
            zip::ZipArchive::new(file).map_err(|e| ArchiveError::InvalidArchive(e.to_string()))?;
        self.scan_entries(&mut zip, config)
    }

    /// Bounded read of one entry's bytes. `max_bytes` is enforced during
    /// the read (metadata `size` is only an early hint — a lying
    /// central directory cannot force over-allocation). Used for
    /// `manifest.json`; general extraction lives in `storage::staging`.
    pub fn read_file(
        &self,
        archive: &Path,
        name: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, ArchiveError> {
        let mut file = File::open(archive).map_err(|e| ArchiveError::Io(e.to_string()))?;
        self.read_file_from(&mut file, name, max_bytes)
    }

    /// Same bounded read over an already-open handle (see
    /// [`inspect_file`](Self::inspect_file)).
    pub fn read_file_from(
        &self,
        file: &mut File,
        name: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, ArchiveError> {
        let mut zip =
            zip::ZipArchive::new(file).map_err(|e| ArchiveError::InvalidArchive(e.to_string()))?;
        let entry = zip
            .by_name(name)
            .map_err(|_| ArchiveError::InvalidArchive(format!("{name} not found in archive")))?;
        if entry.is_dir() {
            return Err(ArchiveError::InvalidArchive(format!(
                "{name} is a directory"
            )));
        }
        if entry.size() > max_bytes {
            return Err(ArchiveError::LimitExceeded("file exceeds read bound"));
        }
        let mut buf = Vec::new();
        entry
            .take(max_bytes + 1)
            .read_to_end(&mut buf)
            .map_err(|e| ArchiveError::Io(e.to_string()))?;
        if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err(ArchiveError::LimitExceeded("file exceeds read bound"));
        }
        Ok(buf)
    }

    /// Entry-by-entry enforcement over an open archive. Central-directory
    /// sizes are treated as hints for early rejection; authoritative byte
    /// counting over actual decompressed output happens at extraction.
    fn scan_entries(
        &self,
        zip: &mut zip::ZipArchive<&mut File>,
        config: &ScanConfig<'_>,
    ) -> Result<InspectedArchive, ArchiveError> {
        let entry_count = zip.len();
        if entry_count > config.limits.max_entries {
            return Err(ArchiveError::LimitExceeded(
                "archive entry count exceeds bound",
            ));
        }
        let mut compressed_total: u64 = 0;
        let mut uncompressed_total: u64 = 0;
        let mut files = Vec::new();
        for index in 0..entry_count {
            let entry = zip
                .by_index(index)
                .map_err(|e| ArchiveError::InvalidArchive(e.to_string()))?;
            if entry.encrypted() {
                return Err(ArchiveError::InvalidArchive(
                    "encrypted entries are not accepted".to_owned(),
                ));
            }
            let method = match entry.compression() {
                zip::CompressionMethod::Stored => CompressionMethod::Stored,
                zip::CompressionMethod::Deflated => CompressionMethod::Deflate,
                other => {
                    return Err(ArchiveError::UnsupportedCompression(format!("{other:?}")));
                }
            };
            if !config.allowed_methods.contains(&method) {
                return Err(ArchiveError::UnsupportedCompression(format!("{method:?}")));
            }
            let is_symlink = entry
                .unix_mode()
                .is_some_and(|mode| mode & UNIX_SYMLINK_MASK == UNIX_SYMLINK_TYPE);
            let normalized = check_entry_path(entry.name(), is_symlink)?;
            if entry.is_dir() {
                continue;
            }
            if normalized.split('/').count() > config.max_nesting_depth {
                return Err(ArchiveError::LimitExceeded(
                    "entry nesting depth exceeds bound",
                ));
            }
            if entry.size() > config.limits.max_entry_bytes {
                return Err(ArchiveError::LimitExceeded(
                    "archive entry exceeds per-entry bound",
                ));
            }
            compressed_total = compressed_total
                .checked_add(entry.compressed_size())
                .ok_or(ArchiveError::LimitExceeded("archive size total overflow"))?;
            uncompressed_total = uncompressed_total
                .checked_add(entry.size())
                .ok_or(ArchiveError::LimitExceeded("archive size total overflow"))?;
            files.push(normalized);
        }
        if compressed_total > config.limits.max_compressed_bytes
            || uncompressed_total > config.limits.max_uncompressed_bytes
        {
            return Err(ArchiveError::LimitExceeded(
                "archive size totals exceed bounds",
            ));
        }
        if compressed_total == 0 {
            if uncompressed_total > 0 {
                return Err(ArchiveError::LimitExceeded(
                    "compression ratio exceeds bound",
                ));
            }
        } else if uncompressed_total > u64::from(config.max_compression_ratio) * compressed_total {
            return Err(ArchiveError::LimitExceeded(
                "compression ratio exceeds bound",
            ));
        }
        check_no_duplicate_paths(&files)?;
        Ok(InspectedArchive::new(entry_count, files))
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

    fn sane_config(limits: &ArchiveLimits) -> ScanConfig<'_> {
        ScanConfig {
            limits,
            allowed_methods: &[CompressionMethod::Stored, CompressionMethod::Deflate],
            max_compression_ratio: 100,
            max_nesting_depth: 32,
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
    fn limits_are_checked_before_backend_touches_disk() {
        let reader = ZipArchiveReader;
        let bad = ArchiveLimits {
            max_entries: 0,
            ..sane_limits()
        };
        let bad_config = sane_config(&bad);
        assert!(matches!(
            reader.inspect(Path::new("pkg.zip"), &bad_config),
            Err(ArchiveError::LimitExceeded(_))
        ));
    }

    #[test]
    fn missing_file_is_io_not_policy() {
        let reader = ZipArchiveReader;
        let limits = sane_limits();
        let config = sane_config(&limits);
        assert!(matches!(
            reader.inspect(Path::new("pkg.zip"), &config),
            Err(ArchiveError::Io(_))
        ));
    }

    #[test]
    fn missing_entry_read_is_invalid_not_found() {
        let reader = ZipArchiveReader;
        assert!(matches!(
            reader.read_file(Path::new("pkg.zip"), "manifest.json", 16),
            Err(ArchiveError::Io(_))
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

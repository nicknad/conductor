//! ZIP mechanics and extraction safety: entry limits, path normalization,
//! bounded extraction into a controlled staging directory while hashing.
//! Decides no validation outcome on its own.
//!
//! One concrete reader ([`ZipArchiveReader`]); no pluggable archive-engine
//! trait. [`ArchiveLimits`] and [`CompressionMethod`] are runtime policy,
//! bounded by hard implementation maxima. Path-traversal, duplicate-path,
//! and symlink rejection are fixed invariants — never operator options.

use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write as _};
use std::path::Path;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

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
#[derive(Debug)]
pub struct ScanConfig<'a> {
    pub limits: &'a ArchiveLimits,
    pub allowed_methods: &'a [CompressionMethod],
    pub max_compression_ratio: u32,
    pub max_nesting_depth: usize,
}

/// Declared byte-level identity for one extraction target: the actual
/// decompressed stream must match both. Mirrors the manifest's v2 integrity
/// declaration without creating a module cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredIntegrity {
    pub size: u64,
    pub sha256: [u8; 32],
}

/// One file the caller requires to be extracted. `integrity` is `None`
/// for legacy (v1) declarations, which fall back to path-only agreement.
#[derive(Debug, Clone)]
pub struct ExtractionTarget {
    pub path: String,
    pub integrity: Option<DeclaredIntegrity>,
}

/// One extracted file with its actual byte size and SHA-256.
#[derive(Debug, Clone)]
pub struct ExtractedFile {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// Outcome of one extraction run: every declared target, in archive order,
/// with the actual bytes' size and digest.
#[derive(Debug, Clone)]
pub struct ExtractedFiles {
    pub files: Vec<ExtractedFile>,
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
    #[error("undeclared archive entry: {0}")]
    UndeclaredEntry(String),
    #[error("declared entry missing from archive: {0}")]
    MissingEntry(String),
    #[error("declared size mismatch for {path}: declared {declared}, wrote {actual}")]
    SizeMismatch {
        path: String,
        declared: u64,
        actual: u64,
    },
    #[error("declared digest mismatch for {path}")]
    DigestMismatch { path: String },
}

/// Unix file-type bits (`S_IFMT`) and the types a package may contain:
/// regular files and directories. The threat is in entry metadata, not the
/// name: a `link` — or a FIFO/device/socket — passes the path policy, so
/// every entry's mode bits are consulted.
const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;
const UNIX_SYMLINK_TYPE: u32 = 0o120_000;
const UNIX_REGULAR_TYPE: u32 = 0o100_000;
const UNIX_DIRECTORY_TYPE: u32 = 0o040_000;

/// Classification of an entry's Unix file-type bits (`S_IFMT`). `Regular`
/// covers type-less modes, regular files, and directories; `Forbidden`
/// covers FIFOs, devices, and sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryFileType {
    Regular,
    Symlink,
    Forbidden,
}

/// Classifies central-directory mode bits. Shared by inspection and
/// extraction so both consult file types the same way.
#[must_use]
pub fn entry_file_type(mode: Option<u32>) -> EntryFileType {
    match mode.map_or(0, |mode| mode & UNIX_FILE_TYPE_MASK) {
        UNIX_SYMLINK_TYPE => EntryFileType::Symlink,
        0 | UNIX_REGULAR_TYPE | UNIX_DIRECTORY_TYPE => EntryFileType::Regular,
        _ => EntryFileType::Forbidden,
    }
}

/// End-of-central-directory magic (`PK\x05\x06`), ZIP64 locator magic
/// (`PK\x06\x07`), and ZIP64 end magic (`PK\x06\x06`).
const EOCD_MAGIC: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const ZIP64_LOCATOR_MAGIC: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
const ZIP64_EOCD_MAGIC: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
/// Fixed EOCD size without comment; comments cap at 64 KiB.
const EOCD_FIXED_LEN: u64 = 22;
const EOCD_MAX_COMMENT: u64 = 0xFFFF;

/// The concrete archive backend. Inspection first; extraction (directed
/// by `storage::staging`) only runs against a verified inventory — never
/// as a casual `unzip(path, destination)` utility.
///
/// All multi-stage callers must thread one [`QuarantinedFile`] handle
/// through hashing, inspection, and manifest reads. The one-shot
/// [`ZipArchiveReader::inspect`] opens the path once internally and is
/// safe for standalone inspection, but production validation must never
/// hash one open and inspect another path.
#[derive(Debug)]
pub struct ZipArchiveReader;

/// A private quarantine file opened once for reading. Hashing, inspection,
/// and manifest reads all borrow `&mut self`, so the compiler forces every
/// stage onto the same OS handle — the same bytes the signature
/// authenticated. Construct with [`QuarantinedFile::open`]; access the
/// handle only through the reader/digest stages.
#[derive(Debug)]
pub struct QuarantinedFile {
    file: File,
}

impl QuarantinedFile {
    /// Opens `path` for validation. `path` must be a private quarantine
    /// file the server wrote, never a client-supplied path.
    pub fn open(path: &Path) -> Result<Self, ArchiveError> {
        File::open(path)
            .map(|file| Self { file })
            .map_err(|e| ArchiveError::Io(e.to_string()))
    }

    /// On-disk length without parsing. Used as the pre-hash size gate.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> std::io::Result<u64> {
        self.file.metadata().map(|m| m.len())
    }
}

impl Read for QuarantinedFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for QuarantinedFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl ZipArchiveReader {
    /// One-shot inspection of the archive at `path`. Opens the file once
    /// and inspects that same handle, so this single call is atomic.
    ///
    /// Production validation must NOT combine this with a separate hash of
    /// the same path (two opens can diverge under replacement). Thread one
    /// [`QuarantinedFile`] through [`ZipArchiveReader::inspect_file`] and
    /// [`ZipArchiveReader::read_file_from`] instead.
    pub fn inspect(
        &self,
        archive: &Path,
        config: &ScanConfig<'_>,
    ) -> Result<InspectedArchive, ArchiveError> {
        config.limits.validate()?;
        let mut quarantined = QuarantinedFile::open(archive)?;
        self.inspect_file(&mut quarantined, config)
    }

    /// Inspection over an already-open quarantine handle. The validator
    /// hashes and inspects one [`QuarantinedFile`] through this, so hashing
    /// and inspection can never diverge onto different bytes (TOCTOU).
    pub fn inspect_file(
        &self,
        file: &mut QuarantinedFile,
        config: &ScanConfig<'_>,
    ) -> Result<InspectedArchive, ArchiveError> {
        config.limits.validate()?;
        // The backend indexes entries by name, silently collapsing duplicate
        // records. Cross-check its view against the authoritative EOCD
        // record count first: any disagreement means ambiguous names.
        let records = Self::central_directory_count(file)?;
        // Enforce the count bound *before* the backend parses: parsing
        // allocates per-record data for every declared entry, so a crafted
        // archive could force memory proportional to the declared (not the
        // allowed) entry count. Limits are cheap; backend work is not.
        if records > config.limits.max_entries {
            return Err(ArchiveError::LimitExceeded(
                "archive entry count exceeds bound",
            ));
        }
        let mut zip =
            zip::ZipArchive::new(file).map_err(|e| ArchiveError::InvalidArchive(e.to_string()))?;
        if zip.len() != records {
            return Err(ArchiveError::PathRejected("duplicate archive paths"));
        }
        self.scan_entries(&mut zip, config)
    }

    /// Reads the authoritative central-directory record count from the
    /// End-of-Central-Directory (classic or ZIP64) record. Independent of
    /// the name-indexed view the backend builds, so duplicates the backend
    /// collapses are still caught. Fails closed whenever the EOCD cannot be
    /// located and verified.
    fn central_directory_count(file: &mut (impl Read + Seek)) -> Result<usize, ArchiveError> {
        use std::io::SeekFrom;

        let invalid = |msg: &str| ArchiveError::InvalidArchive(msg.to_owned());
        let len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| ArchiveError::Io(e.to_string()))?;
        if len < EOCD_FIXED_LEN {
            return Err(invalid("file too small to be a ZIP archive"));
        }
        let tail_len = len.min(EOCD_FIXED_LEN + EOCD_MAX_COMMENT);
        file.seek(SeekFrom::Start(len - tail_len))
            .map_err(|e| ArchiveError::Io(e.to_string()))?;
        let mut tail = vec![0u8; tail_len as usize];
        file.read_exact(&mut tail)
            .map_err(|e| ArchiveError::Io(e.to_string()))?;
        // The EOCD is the last structure; a comment may follow it. Scan
        // backwards and accept the candidate whose comment length lands
        // exactly on EOF, so magic bytes inside payloads cannot spoof it.
        let mut eocd_at = None;
        for i in (0..=tail.len() - EOCD_FIXED_LEN as usize).rev() {
            if tail[i..i + 4] == EOCD_MAGIC {
                let comment = u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize;
                if i + EOCD_FIXED_LEN as usize + comment == tail.len() {
                    eocd_at = Some(i);
                    break;
                }
            }
        }
        let at = eocd_at.ok_or_else(|| invalid("end-of-central-directory not found"))?;
        let u16_at = |off: usize| u16::from_le_bytes([tail[at + off], tail[at + off + 1]]);
        if u16_at(4) != 0 || u16_at(6) != 0 {
            return Err(invalid("multi-disk archives are not accepted"));
        }
        if u16_at(8) != u16_at(10) {
            return Err(invalid("central-directory disk counts disagree"));
        }
        let total = u16_at(10);
        if total != 0xFFFF {
            return Ok(usize::from(total));
        }
        // ZIP64: the locator sits immediately before the EOCD and points at
        // the ZIP64 end record holding the real 64-bit counts.
        if at < 20 || tail[at - 20..at - 16] != ZIP64_LOCATOR_MAGIC {
            return Err(invalid("ZIP64 end locator not found"));
        }
        let cd_offset = u64::from_le_bytes(
            tail[at - 12..at - 4]
                .try_into()
                .map_err(|_| invalid("truncated ZIP64 locator"))?,
        );
        file.seek(SeekFrom::Start(cd_offset))
            .map_err(|e| ArchiveError::Io(e.to_string()))?;
        let mut header = [0u8; 40];
        file.read_exact(&mut header)
            .map_err(|_| invalid("truncated ZIP64 end record"))?;
        if header[0..4] != ZIP64_EOCD_MAGIC {
            return Err(invalid("ZIP64 end record not found"));
        }
        let total64 = u64::from_le_bytes(
            header[32..40]
                .try_into()
                .map_err(|_| invalid("truncated ZIP64 end record"))?,
        );
        usize::try_from(total64).map_err(|_| invalid("ZIP64 entry count out of range"))
    }

    /// Bounded read of one entry's bytes over the same quarantined handle
    /// (see [`inspect_file`](Self::inspect_file)). `max_bytes` is enforced
    /// during the read (metadata `size` is only an early hint — a lying
    /// central directory cannot force over-allocation). Used for
    /// `manifest.json`; general extraction lives in `storage::staging`.
    /// Takes `&mut QuarantinedFile` — not a generic seekable — so the
    /// manifest can only come from the inspected handle.
    pub fn read_file_from(
        &self,
        file: &mut QuarantinedFile,
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
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| ArchiveError::Io(e.to_string()))?;
        if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err(ArchiveError::LimitExceeded("file exceeds read bound"));
        }
        Ok(buf)
    }

    /// Bounded extraction of every non-directory entry into `dest_root`,
    /// directed by `declared` targets, hashing each stream exactly once —
    /// the same bytes feed the hasher and the file writer, so what was
    /// verified is what was written.
    ///
    /// Mechanics only: the caller owns the destination directory (creation,
    /// permissions, cleanup) and has already validated the package
    /// signature on this same handle. Every archive entry must be declared
    /// (`UndeclaredEntry` otherwise); every declared target must appear
    /// (`MissingEntry` otherwise). Declared paths pass the same confinement
    /// policy as entries before any filesystem contact. Targets carrying
    /// [`DeclaredIntegrity`] are enforced against the actual decompressed
    /// stream. On `Err`, `dest_root` may contain partial files; the caller
    /// removes it.
    ///
    /// Takes `&mut QuarantinedFile` for the same reason as
    /// [`inspect_file`](Self::inspect_file): extraction can only run over
    /// the handle that was hashed and authenticated.
    pub fn extract_to(
        &self,
        file: &mut QuarantinedFile,
        dest_root: &Path,
        declared: &[ExtractionTarget],
        config: &ScanConfig<'_>,
    ) -> Result<ExtractedFiles, ArchiveError> {
        use std::collections::HashMap;

        config.limits.validate()?;
        // Normalize declared paths through the same confinement policy as
        // archive entries; a target that cannot produce a confined path
        // condemns the extraction before any filesystem contact. Duplicate
        // targets would make "every target written" ambiguous.
        let mut wanted: HashMap<String, Option<DeclaredIntegrity>> = HashMap::new();
        for target in declared {
            let normalized = check_entry_path(&target.path, false)?;
            if wanted.insert(normalized, target.integrity).is_some() {
                return Err(ArchiveError::PathRejected("duplicate extraction targets"));
            }
        }
        let mut zip =
            zip::ZipArchive::new(file).map_err(|e| ArchiveError::InvalidArchive(e.to_string()))?;
        let entry_count = zip.len();
        if entry_count > config.limits.max_entries {
            return Err(ArchiveError::LimitExceeded(
                "archive entry count exceeds bound",
            ));
        }
        let mut total_written: u64 = 0;
        let mut extracted = Vec::new();
        for index in 0..entry_count {
            let mut entry = zip
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
            let file_type = entry_file_type(entry.unix_mode());
            if file_type == EntryFileType::Forbidden {
                return Err(ArchiveError::PathRejected(
                    "non-regular entries are never extracted",
                ));
            }
            let normalized = check_entry_path(entry.name(), file_type == EntryFileType::Symlink)?;
            if entry.is_dir() {
                // Directories carry no payload; they are recreated from
                // file parents below.
                continue;
            }
            if normalized.split('/').count() > config.max_nesting_depth {
                return Err(ArchiveError::LimitExceeded(
                    "entry nesting depth exceeds bound",
                ));
            }
            let Some(integrity) = wanted.remove(&normalized) else {
                return Err(ArchiveError::UndeclaredEntry(normalized));
            };
            // `normalized` is confined by construction: no absolute paths,
            // dot segments, separators, or colons — joining it under
            // `dest_root` cannot escape.
            let dest = dest_root.join(&normalized);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| ArchiveError::Io(e.to_string()))?;
            }
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)
                .map_err(|e| ArchiveError::Io(e.to_string()))?;
            let mut hasher = Sha256::new();
            let mut wrote: u64 = 0;
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = entry
                    .read(&mut buf)
                    .map_err(|e| ArchiveError::Io(e.to_string()))?;
                if n == 0 {
                    break;
                }
                wrote += n as u64;
                // Authoritative counts over actual decompressed output; the
                // central-directory sizes were only hints at inspection.
                if wrote > config.limits.max_entry_bytes {
                    return Err(ArchiveError::LimitExceeded(
                        "entry exceeds per-entry bound during extraction",
                    ));
                }
                total_written += n as u64;
                if total_written > config.limits.max_uncompressed_bytes {
                    return Err(ArchiveError::LimitExceeded(
                        "archive exceeds uncompressed bound during extraction",
                    ));
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n])
                    .map_err(|e| ArchiveError::Io(e.to_string()))?;
            }
            out.flush().map_err(|e| ArchiveError::Io(e.to_string()))?;
            let digest: [u8; 32] = hasher.finalize().into();
            if let Some(declared) = integrity {
                if declared.size != wrote {
                    return Err(ArchiveError::SizeMismatch {
                        path: normalized,
                        declared: declared.size,
                        actual: wrote,
                    });
                }
                if declared.sha256 != digest {
                    return Err(ArchiveError::DigestMismatch { path: normalized });
                }
            }
            extracted.push(ExtractedFile {
                path: normalized,
                size: wrote,
                sha256: digest,
            });
        }
        if let Some((missing, _)) = wanted.into_iter().next() {
            return Err(ArchiveError::MissingEntry(missing));
        }
        Ok(ExtractedFiles { files: extracted })
    }

    /// Entry-by-entry enforcement over an open archive. Central-directory
    /// sizes are treated as hints for early rejection; authoritative byte
    /// counting over actual decompressed output happens at extraction.
    fn scan_entries<R: Read + Seek>(
        &self,
        zip: &mut zip::ZipArchive<R>,
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
            let file_type = entry_file_type(entry.unix_mode());
            if file_type == EntryFileType::Forbidden {
                return Err(ArchiveError::PathRejected(
                    "non-regular entries are never extracted",
                ));
            }
            let normalized = check_entry_path(entry.name(), file_type == EntryFileType::Symlink)?;
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
        // A zero-byte total passes trivially: every entry that contributes
        // content occupies at least one compressed byte, so an empty
        // archive cannot smuggle amplification past this check.
        if uncompressed_total > u64::from(config.max_compression_ratio) * compressed_total {
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
/// without I/O. Rejects absolute paths, any colon (drive prefixes and NTFS
/// alternate data streams), ASCII control characters, `.` / `..`
/// components, empty segments, backslashes, over-long names, components
/// with trailing dots or spaces (Windows strips them, collapsing distinct
/// entries), Windows reserved device names, and symlink entries. A single
/// trailing `/` (explicit directory entry) is stripped — directories carry
/// no payload and are recreated from file parents during extraction.
/// Returns the relative path normalized to Unicode NFC, confined by
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
    if entry.contains(':') {
        return Err(ArchiveError::PathRejected(
            "colon-bearing names are rejected (drive prefixes, NTFS data streams)",
        ));
    }
    if entry.bytes().any(|b| b.is_ascii_control()) {
        return Err(ArchiveError::PathRejected(
            "control characters are never accepted in entry names",
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
            _ => {}
        }
        if component.ends_with(['.', ' ']) {
            return Err(ArchiveError::PathRejected(
                "components with trailing dots or spaces are rejected",
            ));
        }
        if is_windows_reserved_name(component) {
            return Err(ArchiveError::PathRejected(
                "Windows reserved device names are rejected",
            ));
        }
        normalized.push(component);
    }
    Ok(normalized.join("/").nfc().collect())
}

/// Windows treats `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, and
/// `LPT1`-`LPT9` as reserved device names in every directory, with the
/// extension ignored: `CON.txt` names the console just like `CON`. A
/// cross-platform package must never contain one.
fn is_windows_reserved_name(component: &str) -> bool {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = component.split('.').next().unwrap_or_default();
    RESERVED.iter().any(|name| stem.eq_ignore_ascii_case(name))
}

/// Rejects exact-duplicate paths and collisions under Unicode NFC
/// normalization plus case folding within one archive listing. Both
/// matter because staging may sit on a case-insensitive and/or
/// normalization-insensitive filesystem, where `Bin/x` / `bin/x` or
/// NFC/NFD forms of the same name would collapse into a single file and
/// break inventory accounting.
pub fn check_no_duplicate_paths(paths: &[impl AsRef<str>]) -> Result<(), ArchiveError> {
    use std::collections::HashSet;
    let mut seen: HashSet<&str> = HashSet::new();
    let mut folded: HashSet<String> = HashSet::new();
    for path in paths {
        let entry = path.as_ref();
        if !seen.insert(entry) {
            return Err(ArchiveError::PathRejected("duplicate archive paths"));
        }
        let fold_key: String = entry.nfc().collect::<String>().to_lowercase();
        if !folded.insert(fold_key) {
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

    /// Builds a Stored archive in memory. Private-API tests stay hermetic:
    /// no temp files, no fixture drift.
    fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            writer
                .start_file(*name, options)
                .expect("test zip must build");
            writer.write_all(data).expect("test zip must build");
        }
        writer.finish().expect("test zip must finalize");
        cursor.into_inner()
    }

    /// Builds a one-entry Stored archive carrying explicit Unix file-type
    /// bits in the central directory's external attributes. The writer
    /// masks `unix_permissions` to `0o777` and always ORs in `S_IFREG`, so
    /// hostile type bits are injected at the byte level — exactly as a
    /// hostile producer would emit them.
    fn stored_zip_with_mode(name: &str, mode: u32) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        writer
            .start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("test zip must build");
        writer.write_all(b"x").expect("test zip must build");
        writer.finish().expect("test zip must finalize");
        let mut bytes = cursor.into_inner();

        let cd = bytes
            .windows(4)
            .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
            .expect("central directory record must exist");
        bytes[cd + 5] = 3; // host system: Unix, so `unix_mode` is honored
        bytes[cd + 38..cd + 42].copy_from_slice(&(mode << 16).to_le_bytes());
        bytes
    }

    /// Sets the general-purpose "encrypted" flag (bit 0) in both the local
    /// and central headers of a single-entry archive.
    fn set_encryption_flag(mut bytes: Vec<u8>) -> Vec<u8> {
        let local = bytes
            .windows(4)
            .position(|w| w == [0x50, 0x4b, 0x03, 0x04])
            .expect("local header must exist");
        let central = bytes
            .windows(4)
            .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
            .expect("central header must exist");
        let local_flags = u16::from_le_bytes([bytes[local + 6], bytes[local + 7]]) | 1;
        bytes[local + 6..local + 8].copy_from_slice(&local_flags.to_le_bytes());
        let central_flags = u16::from_le_bytes([bytes[central + 8], bytes[central + 9]]) | 1;
        bytes[central + 8..central + 10].copy_from_slice(&central_flags.to_le_bytes());
        bytes
    }

    fn scan_bytes(bytes: &[u8], config: &ScanConfig<'_>) -> Result<InspectedArchive, ArchiveError> {
        let mut cursor = std::io::Cursor::new(bytes);
        let mut zip = zip::ZipArchive::new(&mut cursor).expect("test zip must parse");
        ZipArchiveReader.scan_entries(&mut zip, config)
    }

    fn read_bytes(bytes: &[u8], name: &str, max: u64) -> Result<Vec<u8>, ArchiveError> {
        let path = std::env::temp_dir().join(format!(
            "conductor-read-test-{}-{}.zip",
            std::process::id(),
            bytes.len()
        ));
        std::fs::write(&path, bytes).expect("temp archive must be writable");
        let mut quarantined = QuarantinedFile::open(&path)?;
        let out = ZipArchiveReader.read_file_from(&mut quarantined, name, max);
        let _ = std::fs::remove_file(&path);
        out
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
    fn bounded_reads_reject_missing_directory_and_oversize() {
        let bytes = stored_zip(&[("manifest.json", b"{}"), ("payload/x", b"data")]);
        assert_eq!(
            read_bytes(&bytes, "manifest.json", 16).expect("small read must succeed"),
            b"{}"
        );
        assert!(matches!(
            read_bytes(&bytes, "absent.json", 16),
            Err(ArchiveError::InvalidArchive(_))
        ));
        // The metadata size is an early hint: a 4-byte entry against a
        // 2-byte bound fails without trusting the stream.
        assert!(matches!(
            read_bytes(&bytes, "payload/x", 2),
            Err(ArchiveError::LimitExceeded(_))
        ));

        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        writer
            .add_directory(
                "docs/",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("test zip must build");
        writer.finish().expect("test zip must finalize");
        let dir_bytes = cursor.into_inner();
        assert!(matches!(
            read_bytes(&dir_bytes, "docs/", 16),
            Err(ArchiveError::InvalidArchive(_))
        ));
    }

    #[test]
    fn max_read_bound_does_not_overflow() {
        // `u64::MAX` means "effectively unbounded", not "wrap to zero":
        // debug builds must not panic and release builds must not return
        // a silently truncated (here: empty) buffer.
        let bytes = stored_zip(&[("x.dat", b"data")]);
        assert_eq!(
            read_bytes(&bytes, "x.dat", u64::MAX)
                .expect("u64::MAX is an unbounded request, not an overflow"),
            b"data"
        );
    }

    #[test]
    fn scan_enforces_per_entry_and_total_bounds() {
        let limits = ArchiveLimits {
            max_entries: 16,
            max_compressed_bytes: 1 << 20,
            max_uncompressed_bytes: 1 << 20,
            max_entry_bytes: 2,
        };
        let config = sane_config(&limits);
        let bytes = stored_zip(&[("big.dat", b"1234")]);
        assert!(matches!(
            scan_bytes(&bytes, &config),
            Err(ArchiveError::LimitExceeded(_))
        ));

        let totals = ArchiveLimits {
            max_entries: 16,
            max_compressed_bytes: 6,
            max_uncompressed_bytes: 1 << 20,
            max_entry_bytes: 1 << 20,
        };
        let totals_config = sane_config(&totals);
        let bytes = stored_zip(&[("a", b"1234"), ("b", b"5678")]);
        assert!(matches!(
            scan_bytes(&bytes, &totals_config),
            Err(ArchiveError::LimitExceeded(_))
        ));
    }

    #[test]
    fn scan_enforces_ratio_and_depth() {
        let ratio = ArchiveLimits {
            max_entries: 16,
            max_compressed_bytes: 1 << 20,
            max_uncompressed_bytes: 1 << 20,
            max_entry_bytes: 1 << 20,
        };
        let mut config = sane_config(&ratio);
        config.max_compression_ratio = 1;
        // 1,000 zero bytes deflate to a handful: ratio ~50:1 trips a
        // max-ratio-1 policy while every byte bound passes.
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        writer
            .start_file(
                "zeros.dat",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .expect("test zip must build");
        writer.write_all(&[0u8; 1000]).expect("test zip must build");
        writer.finish().expect("test zip must finalize");
        let bytes = cursor.into_inner();
        assert!(matches!(
            scan_bytes(&bytes, &config),
            Err(ArchiveError::LimitExceeded(_))
        ));

        let depth = ArchiveLimits {
            max_entries: 16,
            max_compressed_bytes: 1 << 20,
            max_uncompressed_bytes: 1 << 20,
            max_entry_bytes: 1 << 20,
        };
        let mut deep_config = sane_config(&depth);
        deep_config.max_nesting_depth = 2;
        let bytes = stored_zip(&[("a/b/c", b"x")]);
        assert!(matches!(
            scan_bytes(&bytes, &deep_config),
            Err(ArchiveError::LimitExceeded(_))
        ));
        deep_config.max_nesting_depth = 3;
        let inspected = scan_bytes(&bytes, &deep_config).expect("depth boundary must pass");
        assert_eq!(inspected.files, vec!["a/b/c".to_owned()]);
    }

    #[test]
    fn scan_rejects_disallowed_method_encrypted_and_lists_dirs() {
        // Deflate is decodable but not allowlisted here: capability must not
        // imply permission.
        let limits = ArchiveLimits {
            max_entries: 16,
            max_compressed_bytes: 1 << 20,
            max_uncompressed_bytes: 1 << 20,
            max_entry_bytes: 1 << 20,
        };
        let stored_only = ScanConfig {
            limits: &limits,
            allowed_methods: &[CompressionMethod::Stored],
            max_compression_ratio: 100,
            max_nesting_depth: 32,
        };
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        writer
            .start_file(
                "z.dat",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .expect("test zip must build");
        writer.write_all(b"data").expect("test zip must build");
        writer.finish().expect("test zip must finalize");
        assert!(matches!(
            scan_bytes(&cursor.into_inner(), &stored_only),
            Err(ArchiveError::UnsupportedCompression(_))
        ));

        // Encrypted entries are rejected before any payload handling. The
        // writer cannot emit encrypted entries without the (deliberately
        // uncompiled) AES feature, so set the general-purpose encryption
        // bit at the byte level — exactly what a hostile producer emits.
        let encrypted = set_encryption_flag(stored_zip(&[("secret.dat", b"data")]));
        let config = sane_config(&limits);
        assert!(matches!(
            scan_bytes(&encrypted, &config),
            Err(ArchiveError::InvalidArchive(_))
        ));

        // Directory entries count toward the entry total but carry no
        // payload: they never reach the file inventory.
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut cursor);
        writer
            .add_directory(
                "docs/",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("test zip must build");
        writer
            .start_file(
                "docs/note.txt",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("test zip must build");
        writer.write_all(b"hi").expect("test zip must build");
        writer.finish().expect("test zip must finalize");
        let inspected = scan_bytes(&cursor.into_inner(), &config).expect("dirs must scan cleanly");
        assert_eq!(inspected.entry_count, 2);
        assert_eq!(inspected.files, vec!["docs/note.txt".to_owned()]);
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
    fn scan_rejects_non_regular_file_types_not_only_symlinks() {
        let limits = ArchiveLimits {
            max_entries: 16,
            max_compressed_bytes: 1 << 20,
            max_uncompressed_bytes: 1 << 20,
            max_entry_bytes: 1 << 20,
        };
        let config = sane_config(&limits);

        // FIFO mode bits (S_IFIFO) with otherwise ordinary permissions: the
        // name policy passes, so only the file-type check can condemn it.
        let fifo = stored_zip_with_mode("pipe", 0o010644);
        assert!(matches!(
            scan_bytes(&fifo, &config),
            Err(ArchiveError::PathRejected(_))
        ));

        // Regular-file and type-less modes must stay accepted.
        let regular = stored_zip_with_mode("bin/tool", 0o100755);
        let inspected = scan_bytes(&regular, &config).expect("regular mode must pass");
        assert_eq!(inspected.files, vec!["bin/tool".to_owned()]);
        let untyped = stored_zip_with_mode("plain.dat", 0o600);
        scan_bytes(&untyped, &config).expect("type-less mode must pass");
    }

    #[test]
    fn windows_unsafe_names_rejected() {
        for hostile in [
            "C:/windows/evil",
            "c:evil",
            "payload/file:stream",
            "stream:name",
            "aux",
            "AUX.txt",
            "con",
            "nul.log",
            "COM1",
            "lpt9.bin",
            "dir/COM1.txt",
            "trailing.",
            "trailing ",
            "dir/trailing. ",
            "with\nnewline",
            "with\ttab",
            "\u{7f}",
        ] {
            assert!(
                matches!(
                    check_entry_path(hostile, false),
                    Err(ArchiveError::PathRejected(_))
                ),
                "must reject {hostile:?}"
            );
        }
        for accepted in [
            "conifer.txt",
            "console/err.log",
            "com10.txt",
            "lpt0.dat",
            "nulled/readme",
            ".gitignore",
            "internal space.txt",
            "payload/report.2024",
        ] {
            assert!(
                check_entry_path(accepted, false).is_ok(),
                "must accept {accepted:?}"
            );
        }
    }

    #[test]
    fn unicode_equivalents_normalize_and_collide() {
        let nfc = "caf\u{e9}/r\u{e9}sum\u{e9}.txt";
        let nfd = "cafe\u{301}/re\u{301}sume\u{301}.txt";
        assert_eq!(
            check_entry_path(nfc, false).expect("NFC must be accepted"),
            check_entry_path(nfd, false).expect("NFD must be accepted"),
            "equivalent forms must normalize to one canonical path"
        );
        assert!(matches!(
            check_no_duplicate_paths(&[nfc.to_owned(), nfd.to_owned()]),
            Err(ArchiveError::PathRejected(_))
        ));
        assert!(matches!(
            check_no_duplicate_paths(&["CAF\u{c9}.TXT".to_owned(), "caf\u{e9}.txt".to_owned()]),
            Err(ArchiveError::PathRejected(_))
        ));
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

    fn classic_eocd(count: u16) -> Vec<u8> {
        // Decoy magic up front: the scanner must skip it because its
        // comment length does not land on EOF.
        let mut buf = vec![0xAAu8; 6];
        buf.extend_from_slice(&EOCD_MAGIC);
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&EOCD_MAGIC);
        buf.extend_from_slice(&[0, 0]); // disk
        buf.extend_from_slice(&[0, 0]); // cd disk
        buf.extend_from_slice(&count.to_le_bytes()); // this disk
        buf.extend_from_slice(&count.to_le_bytes()); // total
        buf.extend_from_slice(&[0; 8]); // sizes
        buf.extend_from_slice(&[0, 0]); // comment len
        buf
    }

    #[test]
    fn eocd_count_reads_classic_records() {
        use std::io::Cursor;

        let mut cursor = Cursor::new(classic_eocd(3));
        assert_eq!(
            ZipArchiveReader::central_directory_count(&mut cursor).expect("classic EOCD"),
            3
        );
        let mut empty = Cursor::new(b"too small".to_vec());
        assert!(matches!(
            ZipArchiveReader::central_directory_count(&mut empty),
            Err(ArchiveError::InvalidArchive(_))
        ));
    }

    #[test]
    fn eocd_count_follows_zip64_locator() {
        use std::io::Cursor;

        let mut buf = vec![0xBBu8; 8];
        let zip64_at = buf.len() as u64;
        // Minimal ZIP64 end record: magic + 44-byte size + fields, with the
        // total-entries u64 at offset 32.
        buf.extend_from_slice(&ZIP64_EOCD_MAGIC);
        buf.extend_from_slice(&44u64.to_le_bytes());
        buf.extend_from_slice(&[0; 20]);
        buf.extend_from_slice(&7u64.to_le_bytes()); // entries this disk
        buf.extend_from_slice(&7u64.to_le_bytes()); // total entries
        buf.extend_from_slice(&[0; 12]);
        // Locator immediately before the classic EOCD.
        buf.extend_from_slice(&ZIP64_LOCATOR_MAGIC);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&zip64_at.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        // Classic EOCD with placeholder counts.
        buf.extend_from_slice(&EOCD_MAGIC);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf.extend_from_slice(&[0xFF; 8]);
        buf.extend_from_slice(&[0, 0]);
        let mut cursor = Cursor::new(buf);
        assert_eq!(
            ZipArchiveReader::central_directory_count(&mut cursor).expect("ZIP64 EOCD"),
            7
        );
    }

    #[test]
    fn eocd_count_rejects_multidisk() {
        use std::io::Cursor;

        let mut buf = classic_eocd(1);
        let disk_off = buf.len() - 22 + 4;
        buf[disk_off] = 1; // nonzero disk number
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            ZipArchiveReader::central_directory_count(&mut cursor),
            Err(ArchiveError::InvalidArchive(_))
        ));
    }

    #[test]
    fn eocd_count_rejects_disagreeing_disk_counts() {
        use std::io::Cursor;

        let mut buf = classic_eocd(2);
        let this_disk_off = buf.len() - 22 + 8;
        buf[this_disk_off] = 1; // this-disk 1 vs total 2 on disk 0
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            ZipArchiveReader::central_directory_count(&mut cursor),
            Err(ArchiveError::InvalidArchive(_))
        ));
    }

    #[test]
    fn eocd_count_rejects_zip64_without_locator() {
        use std::io::Cursor;

        // Placeholder counts but no locator immediately before the EOCD.
        let mut buf = vec![0xCCu8; 30];
        buf.extend_from_slice(&EOCD_MAGIC);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf.extend_from_slice(&[0xFF; 8]);
        buf.extend_from_slice(&[0, 0]);
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            ZipArchiveReader::central_directory_count(&mut cursor),
            Err(ArchiveError::InvalidArchive(_))
        ));
    }

    #[test]
    fn eocd_count_rejects_broken_zip64_records() {
        use std::io::Cursor;

        // Locator points at zeros: not a ZIP64 end record.
        let mut buf = vec![0u8; 64];
        buf.extend_from_slice(&ZIP64_LOCATOR_MAGIC);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // points at zeros
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&EOCD_MAGIC);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf.extend_from_slice(&[0xFF; 8]);
        buf.extend_from_slice(&[0, 0]);
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            ZipArchiveReader::central_directory_count(&mut cursor),
            Err(ArchiveError::InvalidArchive(_))
        ));

        // Locator points past EOF: truncated record.
        let mut buf = vec![0u8; 8];
        buf.extend_from_slice(&ZIP64_LOCATOR_MAGIC);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&u64::MAX.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&EOCD_MAGIC);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf.extend_from_slice(&[0xFF; 8]);
        buf.extend_from_slice(&[0, 0]);
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            ZipArchiveReader::central_directory_count(&mut cursor),
            Err(ArchiveError::InvalidArchive(_))
        ));
    }

    #[test]
    fn eocd_count_honors_comments() {
        use std::io::Cursor;

        let mut buf = classic_eocd(4);
        let comment_off = buf.len() - 2;
        buf.extend_from_slice(b"hello");
        buf[comment_off] = 5;
        buf[comment_off + 1] = 0;
        let mut cursor = Cursor::new(buf);
        assert_eq!(
            ZipArchiveReader::central_directory_count(&mut cursor).expect("commented EOCD"),
            4
        );
    }
}

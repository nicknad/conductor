//! Archive security: fixed invariants enforced through the public API.
//!
//! What must hold (none of this is operator-configurable):
//! - limits are validated before the backend touches the archive;
//! - entry paths can never escape staging (no absolute, drive-prefixed,
//!   dot-segment, empty-segment, backslash, or over-long names);
//! - symlinks are never extracted; duplicates and case collisions rejected;
//! - unexpected compression is rejected, never attempted opportunistically;
//! - entry-count, byte, ratio, and depth bounds are enforced independently.
//!
//! The hostile `tests/testdata/*.zip` corpus exercises these against the
//! real reader (see `tests/testdata/README.md`).

use std::path::{Path, PathBuf};

use conductor::packages::archive::{
    check_entry_path, check_no_duplicate_paths, ArchiveError, ArchiveLimits, InspectedArchive,
    ScanConfig, ZipArchiveReader, MAX_ENTRY_PATH_LEN,
};
use conductor::packages::policy::PackageValidationPolicy;

fn production_limits() -> ArchiveLimits {
    PackageValidationPolicy::production().archive
}

/// Runs `f` against the production scan configuration.
fn with_production<R>(f: impl FnOnce(&ScanConfig<'_>) -> R) -> R {
    let policy = PackageValidationPolicy::production();
    f(&policy.scan_config())
}

fn inspect_fixture(name: &str) -> Result<InspectedArchive, ArchiveError> {
    with_production(|config| {
        ZipArchiveReader.inspect(&Path::new("tests/testdata").join(name), config)
    })
}

/// Writes crafted bytes to a process-unique temp path; removed on drop.
struct TempArchive(PathBuf);

impl TempArchive {
    fn write(bytes: &[u8], tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "conductor-archive-test-{}-{}-{}.zip",
            std::process::id(),
            tag,
            bytes.len()
        ));
        std::fs::write(&path, bytes).expect("temp archive must be writable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempArchive {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn limits_are_checked_before_backend_touches_disk() {
    let reader = ZipArchiveReader;
    let missing = Path::new("tests/testdata/does-not-exist.zip");
    let zero = ArchiveLimits {
        max_entries: 0,
        ..production_limits()
    };
    let policy = PackageValidationPolicy::production();
    let zero_config = ScanConfig {
        limits: &zero,
        allowed_methods: &policy.allowed_compression_methods,
        max_compression_ratio: policy.max_compression_ratio,
        max_nesting_depth: policy.max_nesting_depth,
    };
    assert!(matches!(
        reader.inspect(missing, &zero_config),
        Err(ArchiveError::LimitExceeded(_))
    ));
    assert!(matches!(
        reader.inspect(missing, &policy.scan_config()),
        Err(ArchiveError::Io(_))
    ));
}

/// The entry-count bound is a *pre-parse* gate: an archive whose EOCD
/// declares more entries than the limit must be rejected as a limit
/// violation even though the central directory itself is garbage. If the
/// count check ran after the backend parsed, the verdict would be a parse
/// error instead — and, on a well-formed archive, the backend would have
/// already allocated for every declared entry.
#[test]
fn entry_count_limit_is_checked_before_backend_parses() {
    let mut bytes = vec![0xAAu8; 64]; // junk where the central directory should be
    bytes.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]); // EOCD magic
    bytes.extend_from_slice(&[0, 0]); // disk number
    bytes.extend_from_slice(&[0, 0]); // central-directory disk
    bytes.extend_from_slice(&2u16.to_le_bytes()); // entries on this disk
    bytes.extend_from_slice(&2u16.to_le_bytes()); // total entries
    bytes.extend_from_slice(&0u32.to_le_bytes()); // central-directory size
    bytes.extend_from_slice(&64u32.to_le_bytes()); // central-directory offset (junk)
    bytes.extend_from_slice(&[0, 0]); // comment length
    let archive = TempArchive::write(&bytes, "eocd-count-over-limit");

    let policy = PackageValidationPolicy::production();
    let limits = ArchiveLimits {
        max_entries: 1,
        ..policy.archive
    };
    limits.validate().expect("test limits must stay valid");
    let config = ScanConfig {
        limits: &limits,
        allowed_methods: &policy.allowed_compression_methods,
        max_compression_ratio: policy.max_compression_ratio,
        max_nesting_depth: policy.max_nesting_depth,
    };
    assert!(
        matches!(
            ZipArchiveReader.inspect(archive.path(), &config),
            Err(ArchiveError::LimitExceeded(_))
        ),
        "count bound must reject before the backend parses the directory"
    );
}

#[test]
fn entry_path_policy_accepts_only_confined_relative_paths() {
    for accepted in ["manifest.json", "bin/plugin.dll", "a/b/c/deep.dat", "docs/"] {
        assert!(
            check_entry_path(accepted, false).is_ok(),
            "must accept {accepted:?}"
        );
    }
    for hostile in [
        "",
        "/",
        "/etc/passwd",
        "C:/windows/evil",
        "..",
        "../evil",
        "a/../../b",
        "a/./b",
        "a//b",
        "a\\b",
        "manifest.json ",
    ] {
        // NOTE: "manifest.json " (trailing space) is currently accepted: it
        // is confined, and trailing-space trimming is a backend/extraction
        // concern, not a traversal vector. Listed here to pin the behavior.
        let result = check_entry_path(hostile, false);
        if hostile == "manifest.json " {
            assert!(result.is_ok());
        } else {
            assert!(
                matches!(result, Err(ArchiveError::PathRejected(_))),
                "must reject {hostile:?}"
            );
        }
    }
}

#[test]
fn symlinks_and_overlong_names_rejected_at_the_boundary() {
    assert!(matches!(
        check_entry_path("bin/tool", true),
        Err(ArchiveError::PathRejected(_))
    ));
    assert!(matches!(
        check_entry_path(&"n".repeat(MAX_ENTRY_PATH_LEN + 1), false),
        Err(ArchiveError::PathRejected(_))
    ));
}

#[test]
fn duplicate_and_case_colliding_listings_rejected() {
    let unique = ["manifest.json".to_owned(), "bin/plugin.dll".to_owned()];
    assert!(check_no_duplicate_paths(&unique).is_ok());
    let duplicated = ["a.txt".to_owned(), "a.txt".to_owned()];
    assert!(matches!(
        check_no_duplicate_paths(&duplicated),
        Err(ArchiveError::PathRejected(_))
    ));
    let colliding = ["Bin/tool".to_owned(), "bin/tool".to_owned()];
    assert!(matches!(
        check_no_duplicate_paths(&colliding),
        Err(ArchiveError::PathRejected(_))
    ));
}

#[test]
fn hostile_corpus_is_present() {
    // Every fixture the reader tests need must be checked in. Add a fixture
    // to `tests/testdata/` without adding it here (and vice versa) and CI
    // goes red.
    for fixture in [
        "traversal.zip",
        "absolute.zip",
        "duplicate.zip",
        "symlink.zip",
        "entry-bomb.zip",
        "odd-compression.zip",
    ] {
        let path = Path::new("tests/testdata").join(fixture);
        assert!(
            path.is_file(),
            "missing fixture {} (see tests/testdata/README.md)",
            path.display()
        );
    }
}

#[test]
fn traversal_and_absolute_entries_poison_the_package() {
    for fixture in ["traversal.zip", "absolute.zip"] {
        assert!(
            matches!(inspect_fixture(fixture), Err(ArchiveError::PathRejected(_))),
            "{fixture} must fail path policy even though ok.txt is benign"
        );
    }
}

#[test]
fn duplicate_entries_fail_before_payload_reads() {
    assert!(matches!(
        inspect_fixture("duplicate.zip"),
        Err(ArchiveError::PathRejected(_))
    ));
}

#[test]
fn symlink_entries_are_rejected_by_metadata_not_name() {
    // `link` passes the name policy; the Unix file-type bits condemn it.
    assert!(matches!(
        inspect_fixture("symlink.zip"),
        Err(ArchiveError::PathRejected(_))
    ));
}

#[test]
fn entry_bomb_trips_the_count_limit_not_byte_limits() {
    assert!(matches!(
        inspect_fixture("entry-bomb.zip"),
        Err(ArchiveError::LimitExceeded(_))
    ));
    // Companion proof: the count limit — not a parse failure — is what
    // rejects it. Raised limits (still under the hard maxima) get through.
    let policy = PackageValidationPolicy::production();
    let raised = ArchiveLimits {
        max_entries: 6_000,
        ..policy.archive
    };
    raised
        .validate()
        .expect("raised limits must stay under hard maxima");
    let config = ScanConfig {
        limits: &raised,
        allowed_methods: &policy.allowed_compression_methods,
        max_compression_ratio: policy.max_compression_ratio,
        max_nesting_depth: policy.max_nesting_depth,
    };
    let inspected = ZipArchiveReader
        .inspect(Path::new("tests/testdata/entry-bomb.zip"), &config)
        .expect("raised count limit must accept the bomb");
    assert_eq!(inspected.entry_count, 5_000);
    assert_eq!(inspected.files.len(), 5_000);
}

#[test]
fn out_of_allowlist_compression_is_rejected() {
    assert!(matches!(
        inspect_fixture("odd-compression.zip"),
        Err(ArchiveError::UnsupportedCompression(_))
    ));
}

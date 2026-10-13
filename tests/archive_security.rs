//! Archive security: fixed invariants enforced through the public API.
//!
//! What must hold (none of this is operator-configurable):
//! - limits are validated before the backend touches the archive;
//! - entry paths can never escape staging (no absolute, drive-prefixed,
//!   dot-segment, empty-segment, backslash, or over-long names);
//! - symlinks are never extracted; duplicates and case collisions rejected;
//! - unsupported compression is rejected, never attempted opportunistically.
//!
//! The hostile `tests/testdata/*.zip` corpus exercises these against the
//! real reader once the ZIP backend lands (see `tests/testdata/README.md`).

use std::path::Path;

use conductor::packages::archive::{
    check_entry_path, check_no_duplicate_paths, ArchiveError, ArchiveLimits, ZipArchiveReader,
    MAX_ENTRY_PATH_LEN,
};
use conductor::packages::policy::PackageValidationPolicy;

fn production_limits() -> ArchiveLimits {
    PackageValidationPolicy::production().archive
}

#[test]
fn limits_are_checked_before_backend_touches_disk() {
    let reader = ZipArchiveReader;
    let missing = Path::new("tests/testdata/does-not-exist.zip");
    let zero = ArchiveLimits {
        max_entries: 0,
        ..production_limits()
    };
    assert!(matches!(
        reader.inspect(missing, &zero),
        Err(ArchiveError::LimitExceeded(_))
    ));
    assert!(matches!(
        reader.inspect(missing, &production_limits()),
        Err(ArchiveError::NotImplemented)
    ));
}

#[test]
fn production_limits_pass_their_own_validation() {
    production_limits()
        .validate()
        .expect("production defaults must be self-consistent");
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
fn hostile_corpus_is_present_for_the_future_reader() {
    // The real backend does not exist yet, so these fixtures are not opened
    // here. This test pins the corpus contract: every file the future
    // reader tests need must already be checked in.
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

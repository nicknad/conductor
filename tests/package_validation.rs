//! Scaffold: package validation workflow is not implemented yet.

use conductor::config::Config;
use conductor::packages::archive::ArchiveLimits;

#[test]
fn scaffold_modules_are_wired() {
    let config = Config::default();
    assert!(!config.http_bind.is_empty());
    let limits = ArchiveLimits {
        max_entries: 1,
        max_compressed_bytes: 1,
        max_uncompressed_bytes: 1,
        max_entry_bytes: 1,
    };
    assert_eq!(limits.max_entries, 1);
}

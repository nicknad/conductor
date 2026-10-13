//! Scaffold: archive security checks are not implemented yet.

use conductor::packages::archive::ArchiveLimits;

#[test]
fn archive_limits_carry_all_bounds() {
    let limits = ArchiveLimits {
        max_entries: 10,
        max_compressed_bytes: 10,
        max_uncompressed_bytes: 10,
        max_entry_bytes: 10,
    };
    assert_eq!(limits.max_uncompressed_bytes, 10);
    assert_eq!(limits.max_entry_bytes, 10);
}

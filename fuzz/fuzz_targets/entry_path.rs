#![no_main]

use conductor::packages::archive::{
    check_entry_path, check_no_duplicate_paths, MAX_ENTRY_PATH_LEN,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(name) = std::str::from_utf8(data) else {
        return;
    };

    // Symlink entries are never extractable, whatever the name.
    assert!(check_entry_path(name, true).is_err());

    if let Ok(path) = check_entry_path(name, false) {
        assert!(!path.is_empty());
        assert!(!path.starts_with('/'));
        assert!(!path.contains('\\'));
        assert!(!path.bytes().any(|byte| byte.is_ascii_control()));
        assert!(path.len() <= MAX_ENTRY_PATH_LEN);
        assert!(!path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".."));

        // Normalization is idempotent and duplicate detection is exact.
        assert_eq!(
            check_entry_path(&path, false).ok().as_deref(),
            Some(path.as_str())
        );
        assert!(check_no_duplicate_paths(&[path.as_str(), path.as_str()]).is_err());
        assert!(check_no_duplicate_paths(&[path.as_str()]).is_ok());
    }
});

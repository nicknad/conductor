#![no_main]

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use conductor::packages::archive::{check_entry_path, QuarantinedFile, ZipArchiveReader};
use conductor::packages::policy::PackageValidationPolicy;
use libfuzzer_sys::fuzz_target;

fn temp_path() -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "conductor-fuzz-archive-{}-{count}.zip",
        std::process::id()
    ))
}

fuzz_target!(|data: &[u8]| {
    let path = temp_path();
    if std::fs::write(&path, data).is_err() {
        return;
    }

    let policy = PackageValidationPolicy::production();
    let config = policy.scan_config();
    if let Ok(mut file) = QuarantinedFile::open(&path) {
        if let Ok(inspected) = ZipArchiveReader.inspect_file(&mut file, &config) {
            // Every accepted listing is bounded, duplicate-free, and stored in
            // its confined normalized form.
            assert!(inspected.files.len() <= inspected.entry_count);
            let mut seen = HashSet::new();
            for entry in &inspected.files {
                assert!(seen.insert(entry.clone()), "duplicate accepted entry");
                assert_eq!(
                    check_entry_path(entry, false).ok().as_deref(),
                    Some(entry.as_str()),
                    "accepted entry is not normalized"
                );
            }
        }
    }

    let _ = std::fs::remove_file(&path);
});

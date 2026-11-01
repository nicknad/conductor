#![no_main]

use conductor::packages::manifest::{Manifest, MAX_IDENTITY_BYTES};
use conductor::packages::policy::PackageValidationPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let policy = PackageValidationPolicy::production();
    if let Ok(manifest) = Manifest::parse_with_policy(data, &policy) {
        // A successful parse must produce a usable, confined identity and a
        // non-empty inventory whose entrypoint is actually declared.
        assert!(!manifest.module_id.is_empty());
        assert!(!manifest.version.is_empty());
        assert!(!manifest.runtime.is_empty());
        assert!(!manifest.files.is_empty());
        assert!(manifest
            .files
            .iter()
            .any(|file| file.path == manifest.entrypoint));
        assert!(manifest.module_id.len() <= MAX_IDENTITY_BYTES);
        assert!(manifest.version.len() <= MAX_IDENTITY_BYTES);
        assert!(!manifest.module_id.starts_with('.'));
        assert!(!manifest.module_id.ends_with('.'));
        assert!(!manifest.version.starts_with('.'));
        assert!(!manifest.version.ends_with('.'));
    }
});

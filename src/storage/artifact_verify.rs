//! Filesystem primitives for startup reconciliation.
//!
//! These functions only classify a registered artifact. They never extract,
//! execute, rewrite, or delete bytes. The registry's stored locator is audit
//! data, never a path: the address is re-derived from the record identity and
//! the stored string must equal it exactly.
//!
//! Residuals:
//!
//! - Resolution and open are separate path operations. `O_NOFOLLOW` protects
//!   only the final component, so a same-UID writer can swap an intermediate
//!   directory between parent confinement and open. Execution independently
//!   re-verifies before spawn, so reconciliation is detection, not
//!   authorization. Dirfd-based opening is future hardening.
//! - `O_NOFOLLOW`/`O_NONBLOCK` are Unix-only. Non-Unix targets follow symlinks
//!   on open.
//! - Startup work is proportional to every registered artifact. There is no
//!   per-run byte or time budget yet.
//! - `Oversized` is a policy-bound refusal and is persisted as `Mismatch`. The
//!   caller must pass `PackageValidationPolicy::archive.max_compressed_bytes`.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::packages::archive::check_entry_path;
use crate::packages::artifact::ArtifactDigest;
use crate::packages::digest::Sha256DigestProvider;
use crate::storage::artifact_store::canonical_artifact_relpath;

/// The configured artifact root cannot be used for reconciliation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactRootError {
    #[error("artifact root is unusable: {0}")]
    Unusable(String),
}

/// A registered artifact address is missing, unsafe, or not a regular file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactPathError {
    #[error("artifact is missing")]
    Missing,
    #[error("stored artifact path is not the canonical address")]
    NonCanonical,
    #[error("artifact parent directory escapes the artifact root")]
    ParentEscape,
    #[error("artifact path is a symlink")]
    Symlink,
    #[error("artifact path is not a regular file")]
    NotRegular,
    #[error("artifact path I/O failed: {0}")]
    Io(String),
}

/// An opened artifact's bytes do not match its registry record.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactVerifyError {
    #[error("artifact is missing")]
    Missing,
    #[error("artifact path is a symlink")]
    Symlink,
    #[error("artifact path is not a regular file")]
    NotRegular,
    #[error("artifact size mismatch: expected {expected} bytes, found {actual}")]
    Size { expected: u64, actual: u64 },
    #[error("artifact exceeds the policy bound: {size} bytes, maximum {maximum}")]
    Oversized { size: u64, maximum: u64 },
    #[error("artifact digest does not match the registry record")]
    Digest,
    #[error("artifact read failed: {0}")]
    Io(String),
}

/// Validates the artifact root once and returns its canonical form.
///
/// The root must already exist, be a real directory (not a symlink a later
/// writer could retarget), and not be group- or world-writable. The raw path is
/// checked for a trailing separator and for `.`/`..` components before
/// `symlink_metadata`: on Linux both a trailing slash and a final `/.` follow a
/// symlinked directory, so the metadata call would report the target as a real
/// directory and hide the link.
pub fn preflight_artifact_root(path: &Path) -> Result<PathBuf, ArtifactRootError> {
    if has_trailing_separator(path) {
        return Err(ArtifactRootError::Unusable(
            "artifact root must not end with a path separator".to_owned(),
        ));
    }
    if has_dot_or_parent_component(path) {
        return Err(ArtifactRootError::Unusable(
            "artifact root must not contain . or .. components".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        ArtifactRootError::Unusable(format!("artifact root is not readable: {err}"))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ArtifactRootError::Unusable(
            "artifact root must not be a symlink".to_owned(),
        ));
    }
    if !metadata.is_dir() {
        return Err(ArtifactRootError::Unusable(
            "artifact root must be a directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ArtifactRootError::Unusable(
                "artifact root must not be group-writable or world-writable".to_owned(),
            ));
        }
    }
    path.canonicalize().map_err(|err| {
        ArtifactRootError::Unusable(format!("artifact root cannot be canonicalized: {err}"))
    })
}

/// True when the raw path text ends in a separator. `Path` normalizes trailing
/// separators away for most operations, so this inspects the OS string.
fn has_trailing_separator(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().last() == Some(&b'/')
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().ends_with(std::path::MAIN_SEPARATOR)
    }
}

/// True when the raw path contains a `.` or `..` component.
///
/// `Path::components` normalizes `.` away except at the start of the path, so
/// `link/.` yields only `link`. The raw suffix check catches that case before
/// `symlink_metadata` can follow the linked directory.
fn has_dot_or_parent_component(path: &Path) -> bool {
    use std::path::Component;

    path.components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || has_dot_slash_suffix(path)
}

fn has_dot_slash_suffix(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().ends_with(b"/.")
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy()
            .ends_with(&format!("{}.", std::path::MAIN_SEPARATOR))
    }
}

/// Resolves a registry row to the artifact file it names.
///
/// `stored_relpath` is validated and then discarded. The returned path is
/// built from the canonical address so an untrusted stored string can never
/// become a filesystem path. The final component is inspected with
/// `symlink_metadata` rather than canonicalized, which keeps a final symlink
/// visible instead of silently following it.
pub fn resolve_registered_artifact(
    canonical_root: &Path,
    module_id: &str,
    version: &str,
    digest: &ArtifactDigest,
    stored_relpath: &str,
) -> Result<PathBuf, ArtifactPathError> {
    let expected = canonical_artifact_relpath(module_id, version, digest);
    if stored_relpath != expected {
        return Err(ArtifactPathError::NonCanonical);
    }
    if check_entry_path(stored_relpath, false).is_err() {
        return Err(ArtifactPathError::NonCanonical);
    }

    let candidate = canonical_root.join(&expected);
    let parent = candidate.parent().ok_or(ArtifactPathError::NonCanonical)?;
    let resolved_parent = match parent.canonicalize() {
        Ok(resolved) => resolved,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(ArtifactPathError::Missing);
        }
        Err(err) => return Err(ArtifactPathError::Io(err.to_string())),
    };
    if !resolved_parent.starts_with(canonical_root) {
        return Err(ArtifactPathError::ParentEscape);
    }
    if !resolved_parent.is_dir() {
        return Err(ArtifactPathError::NotRegular);
    }

    let metadata = match fs::symlink_metadata(&candidate) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(ArtifactPathError::Missing);
        }
        Err(err) => return Err(ArtifactPathError::Io(err.to_string())),
    };
    if metadata.file_type().is_symlink() {
        return Err(ArtifactPathError::Symlink);
    }
    if !metadata.is_file() {
        return Err(ArtifactPathError::NotRegular);
    }
    Ok(candidate)
}

/// Opens an already-resolved artifact and checks its size and digest.
///
/// The size policy bound is checked before opening. On Unix the open uses
/// `O_NOFOLLOW` so a symlink raced into place after resolution is rejected,
/// and `O_NONBLOCK` so a FIFO can never block the caller. Only
/// `expected_size + 1` bytes are hashed, which detects a file that grew after
/// the metadata check without reading an unbounded stream.
pub fn verify_open_artifact(
    path: &Path,
    expected_size: u64,
    expected_digest: &ArtifactDigest,
    max_artifact_bytes: u64,
) -> Result<(), ArtifactVerifyError> {
    if expected_size > max_artifact_bytes {
        return Err(ArtifactVerifyError::Oversized {
            size: expected_size,
            maximum: max_artifact_bytes,
        });
    }

    #[cfg(unix)]
    let file = open_no_follow(path)?;
    #[cfg(not(unix))]
    let file = open_following_symlinks(path)?;
    let metadata = file
        .metadata()
        .map_err(|err| ArtifactVerifyError::Io(err.to_string()))?;
    if !metadata.is_file() {
        return Err(ArtifactVerifyError::NotRegular);
    }
    let actual = metadata.len();
    if actual != expected_size {
        return Err(ArtifactVerifyError::Size {
            expected: expected_size,
            actual,
        });
    }

    let digest = hash_bounded(file, expected_size.saturating_add(1))?;
    if digest != *expected_digest.as_bytes() {
        return Err(ArtifactVerifyError::Digest);
    }
    Ok(())
}

fn hash_bounded(reader: impl Read, limit: u64) -> Result<[u8; 32], ArtifactVerifyError> {
    Sha256DigestProvider
        .digest_stream(reader.take(limit))
        .map_err(|err| ArtifactVerifyError::Io(err.to_string()))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, ArtifactVerifyError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .read(true)
        // Distinct flag bits, so addition matches OR without creating an
        // OR-to-XOR equivalent-mutant survivor.
        .custom_flags(libc::O_NOFOLLOW + libc::O_NONBLOCK)
        .open(path)
        .map_err(map_open_error)
}

#[cfg(any(not(unix), test))]
fn open_following_symlinks(path: &Path) -> Result<File, ArtifactVerifyError> {
    File::open(path).map_err(map_open_error)
}

fn map_open_error(err: std::io::Error) -> ArtifactVerifyError {
    if err.kind() == std::io::ErrorKind::NotFound {
        return ArtifactVerifyError::Missing;
    }
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ELOOP) {
        return ArtifactVerifyError::Symlink;
    }
    ArtifactVerifyError::Io(err.to_string())
}

/// Creates a FIFO at `path` for the non-regular-file tests.
#[cfg(all(test, unix))]
#[allow(unsafe_code)]
fn test_make_fifo(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let c_path = CString::new(path.as_os_str().as_bytes()).expect("c path");
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the
    // call, and `mkfifo` only reads it. Callers pass a path under a test temp
    // dir whose parent already exists.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo must succeed");
}

/// True when the test process runs with effective uid 0.
#[cfg(all(test, unix))]
#[allow(unsafe_code)]
fn test_is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and only reads the process's
    // effective uid; it cannot fail or touch memory.
    unsafe { libc::geteuid() == 0 }
}

/// Pins the root probe to the OS answer so a misreporting helper fails here.
#[cfg(all(test, unix))]
#[test]
#[allow(unsafe_code)]
fn test_is_root_matches_effective_uid() {
    // SAFETY: `geteuid` takes no arguments and only reads the process's
    // effective uid; it cannot fail or touch memory.
    let effective_root = unsafe { libc::geteuid() == 0 };
    assert_eq!(test_is_root(), effective_root);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::artifact_store::canonical_artifact_relpath;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "conductor-artifact-verify-{}-{tag}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    struct RestoreMode {
        path: PathBuf,
        mode: u32,
    }

    #[cfg(unix)]
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
        }
    }

    fn digest(bytes: &[u8]) -> ArtifactDigest {
        ArtifactDigest::new(Sha256DigestProvider.digest(bytes).expect("hash"))
    }

    fn write_artifact(
        root: &Path,
        module_id: &str,
        version: &str,
        bytes: &[u8],
    ) -> (ArtifactDigest, String, PathBuf) {
        let digest = digest(bytes);
        let relpath = canonical_artifact_relpath(module_id, version, &digest);
        let path = root.join(&relpath);
        fs::create_dir_all(path.parent().expect("artifact parent")).expect("artifact dir");
        fs::write(&path, bytes).expect("write artifact");
        (digest, relpath, path)
    }

    #[test]
    fn canonical_intact_artifact_resolves_and_verifies() {
        let temp = TempDir::new("intact");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let bytes = b"module bytes";
        let (digest, relpath, expected_path) =
            write_artifact(&root, "reporting-service", "1.2.0", bytes);
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        let resolved = resolve_registered_artifact(
            &canonical_root,
            "reporting-service",
            "1.2.0",
            &digest,
            &relpath,
        )
        .expect("resolve");
        assert_eq!(resolved, expected_path);
        assert_eq!(
            verify_open_artifact(&resolved, bytes.len() as u64, &digest, 1024),
            Ok(())
        );
    }

    #[test]
    fn non_canonical_stored_relpath_is_rejected() {
        let temp = TempDir::new("noncanonical");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let bytes = b"bytes";
        let (digest, _relpath, _) = write_artifact(&root, "mod", "1.0.0", bytes);
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        let wrong = "mod/1.0.0/not-the-digest.zip";
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, wrong),
            Err(ArtifactPathError::NonCanonical)
        );
    }

    #[test]
    fn unsafe_identity_is_rejected_without_reading_outside_root() {
        let temp = TempDir::new("unsafe-identity");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let bytes = b"outside bytes";
        let digest = digest(bytes);
        let outside = temp.path().join("outside");
        fs::create_dir_all(&outside).expect("outside dir");
        fs::write(outside.join("artifact.zip"), bytes).expect("outside artifact");
        let relpath = canonical_artifact_relpath("../..", "1.0.0", &digest);
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "../..", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::NonCanonical)
        );
    }

    #[test]
    fn missing_parent_is_missing() {
        let temp = TempDir::new("missing-parent");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let digest = digest(b"bytes");
        let relpath = canonical_artifact_relpath("mod", "1.0.0", &digest);
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::Missing)
        );
    }

    #[cfg(unix)]
    #[test]
    fn final_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("final-symlink");
        let root = temp.path().join("artifacts");
        let bytes = b"real bytes";
        let (digest, relpath, path) = write_artifact(&root, "mod", "1.0.0", bytes);
        let moved = root.join("real.zip");
        fs::rename(&path, &moved).expect("move real file");
        symlink(&moved, &path).expect("symlink artifact");
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::Symlink)
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_escaping_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("parent-symlink");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(root.join("mod")).expect("module dir");
        let outside = temp.path().join("outside").join("mod").join("1.0.0");
        fs::create_dir_all(&outside).expect("outside dir");
        let bytes = b"outside bytes";
        let digest = digest(bytes);
        let relpath = canonical_artifact_relpath("mod", "1.0.0", &digest);
        fs::write(outside.join(format!("{}.zip", digest.to_hex())), bytes).expect("artifact");
        symlink(&outside, root.join("mod").join("1.0.0")).expect("parent symlink");
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::ParentEscape)
        );
    }

    #[test]
    fn directory_at_artifact_path_is_not_regular() {
        let temp = TempDir::new("directory-artifact");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let bytes = b"bytes";
        let digest = digest(bytes);
        let relpath = canonical_artifact_relpath("mod", "1.0.0", &digest);
        let path = root.join(&relpath);
        fs::create_dir_all(&path).expect("directory artifact path");
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::NotRegular)
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_at_artifact_path_is_not_regular_without_blocking() {
        let temp = TempDir::new("fifo-artifact");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let bytes = b"bytes";
        let digest = digest(bytes);
        let relpath = canonical_artifact_relpath("mod", "1.0.0", &digest);
        let path = root.join(&relpath);
        fs::create_dir_all(path.parent().expect("parent")).expect("artifact dir");
        test_make_fifo(&path);
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::NotRegular)
        );
    }

    #[test]
    fn non_directory_parent_is_io() {
        let temp = TempDir::new("enotdir-parent");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join("mod"), b"not a directory").expect("file parent");
        let digest = digest(b"bytes");
        let relpath = canonical_artifact_relpath("mod", "1.0.0", &digest);
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert!(matches!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_is_io() {
        use std::os::unix::fs::PermissionsExt as _;

        if test_is_root() {
            // Root bypasses permission bits, so the scenario cannot exist here.
            return;
        }

        let temp = TempDir::new("permission-denied");
        let root = temp.path().join("artifacts");
        let bytes = b"bytes";
        let (digest, _, path) = write_artifact(&root, "mod", "1.0.0", bytes);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");
        let result = verify_open_artifact(&path, bytes.len() as u64, &digest, 1024);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore chmod");
        assert!(matches!(result, Err(ArtifactVerifyError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn unsearchable_version_directory_is_io() {
        use std::os::unix::fs::PermissionsExt as _;

        if test_is_root() {
            // Root bypasses permission bits, so the scenario cannot exist here.
            return;
        }

        let temp = TempDir::new("unsearchable-version");
        let root = temp.path().join("artifacts");
        let bytes = b"bytes";
        let (digest, relpath, path) = write_artifact(&root, "mod", "1.0.0", bytes);
        let version_dir = path.parent().expect("version dir").to_path_buf();
        // Read+write without execute: the version directory itself still
        // canonicalizes, but statting the artifact inside it fails with EACCES.
        fs::set_permissions(&version_dir, fs::Permissions::from_mode(0o600)).expect("chmod");
        let _restore = RestoreMode {
            path: version_dir.clone(),
            mode: 0o700,
        };
        assert!(version_dir.canonicalize().is_ok());
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert!(matches!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::Io(_))
        ));
    }

    #[test]
    fn size_mismatch_is_reported() {
        let temp = TempDir::new("size-mismatch");
        let path = temp.path().join("artifact.zip");
        let bytes = b"abc";
        fs::write(&path, bytes).expect("artifact");
        assert_eq!(
            verify_open_artifact(&path, 2, &digest(bytes), 1024),
            Err(ArtifactVerifyError::Size {
                expected: 2,
                actual: 3
            })
        );
    }

    #[test]
    fn oversized_expected_size_is_refused_before_open() {
        let temp = TempDir::new("oversized");
        let path = temp.path().join("missing.zip");
        let digest = digest(b"bytes");
        assert_eq!(
            verify_open_artifact(&path, 11, &digest, 10),
            Err(ArtifactVerifyError::Oversized {
                size: 11,
                maximum: 10
            })
        );
    }

    #[test]
    fn same_size_digest_mismatch_is_reported() {
        let temp = TempDir::new("digest-mismatch");
        let path = temp.path().join("artifact.zip");
        fs::write(&path, b"abcd").expect("artifact");
        assert_eq!(
            verify_open_artifact(&path, 4, &digest(b"abce"), 1024),
            Err(ArtifactVerifyError::Digest)
        );
    }

    #[test]
    fn arbitrary_non_zip_bytes_with_matching_size_and_digest_are_ok() {
        let temp = TempDir::new("non-zip-bytes");
        let path = temp.path().join("artifact.zip");
        let bytes = b"this is not a zip archive";
        fs::write(&path, bytes).expect("artifact");
        assert_eq!(
            verify_open_artifact(&path, bytes.len() as u64, &digest(bytes), 1024),
            Ok(())
        );
    }

    #[test]
    fn bounded_hash_reads_at_most_limit_bytes() {
        struct CountingReader {
            remaining: usize,
            read: usize,
        }

        impl Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let count = buf.len().min(self.remaining).min(7);
                buf[..count].fill(b'x');
                self.remaining -= count;
                self.read += count;
                Ok(count)
            }
        }

        let mut reader = CountingReader {
            remaining: 100,
            read: 0,
        };
        let result = hash_bounded(&mut reader, 11).expect("hash");
        assert_eq!(reader.read, 11);
        assert_eq!(result, *digest(&[b'x'; 11]).as_bytes());
    }

    #[test]
    fn preflight_rejects_regular_file_root() {
        let temp = TempDir::new("root-regular-file");
        let root = temp.path().join("artifacts");
        fs::write(&root, b"not a directory").expect("root file");
        assert!(matches!(
            preflight_artifact_root(&root),
            Err(ArtifactRootError::Unusable(_))
        ));
    }

    #[test]
    fn open_error_maps_missing() {
        let temp = TempDir::new("open-missing");
        let path = temp.path().join("missing.zip");
        assert_eq!(
            verify_open_artifact(&path, 1, &digest(b"x"), 1024),
            Err(ArtifactVerifyError::Missing)
        );
    }

    #[test]
    fn missing_final_component_with_existing_parent_is_missing() {
        let temp = TempDir::new("missing-final");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let digest = digest(b"bytes");
        let relpath = canonical_artifact_relpath("mod", "1.0.0", &digest);
        fs::create_dir_all(root.join("mod").join("1.0.0")).expect("artifact parent");
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, "mod", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::Missing)
        );
    }

    #[test]
    fn dot_component_identity_is_non_canonical() {
        let temp = TempDir::new("dot-identity");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let bytes = b"bytes";
        let digest = digest(bytes);
        // The stored string equals the derived address, but the archive policy
        // rejects dot segments. Write the file at the normalized location so a
        // skipped policy check would resolve successfully instead of missing.
        let relpath = canonical_artifact_relpath(".", "1.0.0", &digest);
        let normalized = root.join("1.0.0").join(format!("{}.zip", digest.to_hex()));
        fs::create_dir_all(normalized.parent().expect("parent")).expect("artifact dir");
        fs::write(&normalized, bytes).expect("artifact");
        let canonical_root = preflight_artifact_root(&root).expect("preflight");
        assert_eq!(
            resolve_registered_artifact(&canonical_root, ".", "1.0.0", &digest, &relpath),
            Err(ArtifactPathError::NonCanonical)
        );
    }

    #[test]
    fn size_at_policy_bound_is_accepted() {
        let temp = TempDir::new("size-at-bound");
        let path = temp.path().join("artifact.zip");
        let bytes = b"12345";
        fs::write(&path, bytes).expect("artifact");
        assert_eq!(verify_open_artifact(&path, 5, &digest(bytes), 5), Ok(()));
    }

    #[test]
    fn expected_size_one_over_policy_bound_is_oversized() {
        let temp = TempDir::new("size-over-bound");
        let path = temp.path().join("missing.zip");
        assert_eq!(
            verify_open_artifact(&path, 6, &digest(b"12345"), 5),
            Err(ArtifactVerifyError::Oversized {
                size: 6,
                maximum: 5
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_open_artifact_rejects_final_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("open-final-symlink");
        let real = temp.path().join("real.zip");
        let bytes = b"abc";
        fs::write(&real, bytes).expect("real artifact");
        let link = temp.path().join("artifact.zip");
        symlink(&real, &link).expect("symlink artifact");
        assert_eq!(
            verify_open_artifact(&link, bytes.len() as u64, &digest(bytes), 1024),
            Err(ArtifactVerifyError::Symlink)
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_following_symlinks_reads_regular_file_bytes() {
        let temp = TempDir::new("follow-open");
        let path = temp.path().join("artifact.zip");
        let bytes = b"followed bytes";
        fs::write(&path, bytes).expect("artifact");
        let mut file = open_following_symlinks(&path).expect("open");
        let mut read = Vec::new();
        file.read_to_end(&mut read).expect("read");
        assert_eq!(read, bytes);
    }

    #[cfg(unix)]
    #[test]
    fn verify_open_artifact_rejects_fifo_without_blocking() {
        let temp = TempDir::new("open-fifo");
        let path = temp.path().join("artifact.zip");
        test_make_fifo(&path);
        // O_NONBLOCK makes the open return immediately; a blocking open would
        // hang this test with no writer.
        assert_eq!(
            verify_open_artifact(&path, 0, &digest(b""), 1024),
            Err(ArtifactVerifyError::NotRegular)
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_open_artifact_rejects_directory() {
        let temp = TempDir::new("open-directory");
        let path = temp.path().join("artifact.zip");
        fs::create_dir_all(&path).expect("directory at artifact path");
        assert_eq!(
            verify_open_artifact(&path, 0, &digest(b""), 1024),
            Err(ArtifactVerifyError::NotRegular)
        );
    }

    #[test]
    fn preflight_accepts_ordinary_temp_root() {
        let temp = TempDir::new("root-ok");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        let canonical = preflight_artifact_root(&root).expect("preflight");
        assert!(canonical.is_absolute());
        assert!(canonical.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_symlink_root() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("root-symlink");
        let target = temp.path().join("real-root");
        fs::create_dir_all(&target).expect("target");
        let link = temp.path().join("artifacts");
        symlink(&target, &link).expect("symlink root");
        assert!(matches!(
            preflight_artifact_root(&link),
            Err(ArtifactRootError::Unusable(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_symlink_root_with_trailing_separator() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("root-symlink-slash");
        let target = temp.path().join("real-root");
        fs::create_dir_all(&target).expect("target");
        let link = temp.path().join("artifacts");
        symlink(&target, &link).expect("symlink root");
        let with_separator = PathBuf::from(format!("{}/", link.display()));
        assert!(has_trailing_separator(&with_separator));
        assert!(matches!(
            preflight_artifact_root(&with_separator),
            Err(ArtifactRootError::Unusable(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_symlink_root_with_dot_suffix() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("root-symlink-dot");
        let target = temp.path().join("real-root");
        fs::create_dir_all(&target).expect("target");
        let link = temp.path().join("artifacts");
        symlink(&target, &link).expect("symlink root");
        let with_dot = PathBuf::from(format!("{}/.", link.display()));
        assert!(matches!(
            preflight_artifact_root(&with_dot),
            Err(ArtifactRootError::Unusable(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_symlink_root_with_parent_component() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("root-symlink-parent");
        let target = temp.path().join("real-root");
        fs::create_dir_all(&target).expect("target");
        let link = temp.path().join("artifacts");
        symlink(&target, &link).expect("symlink root");
        let with_parent = PathBuf::from(format!("{}/..", link.display()));
        assert!(matches!(
            preflight_artifact_root(&with_parent),
            Err(ArtifactRootError::Unusable(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn dot_component_matrix_distinguishes_raw_dot_suffix() {
        for path in [".", "..", "link/.", "link/.."] {
            assert!(
                has_dot_or_parent_component(Path::new(path)),
                "{path} must be rejected"
            );
        }
        for path in ["artifacts", "link/name"] {
            assert!(
                !has_dot_or_parent_component(Path::new(path)),
                "{path} must be accepted"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_group_or_world_writable_root() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new("root-writable");
        let root = temp.path().join("artifacts");
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("chmod");
        let _restore = RestoreMode {
            path: root.clone(),
            mode: 0o700,
        };
        assert!(matches!(
            preflight_artifact_root(&root),
            Err(ArtifactRootError::Unusable(_))
        ));
    }
}

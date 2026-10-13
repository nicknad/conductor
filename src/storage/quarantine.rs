//! Persists untrusted uploaded packages. Never exposes packages to
//! the execution runtime.
//!
//! The quarantine directory holds attacker-controlled bytes awaiting
//! validation. Files are created with [`OpenOptions::create_new`] so a
//! guessed name can never overwrite another upload, named
//! `upload-<pid>-<nanos>-<counter>.zip`, and removed by the caller on
//! validation failure to bound disk use. Validated bytes stay quarantined
//! until the artifact store promotes them; nothing here is ever executed.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

static QUARANTINE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates the quarantine directory (including parents) if missing.
pub fn ensure_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Builds a unique quarantine path without creating the file. The caller
/// opens it with `create_new(true)`; on collision it retries with a fresh
/// counter value.
#[must_use]
pub fn unique_path(dir: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("upload-{}-{nanos}-{count}.zip", std::process::id()))
}

/// Opens a uniquely named quarantine file with `create_new`, retrying on a
/// name collision. Returns the path and the open handle.
pub fn create_file(dir: &Path) -> io::Result<(PathBuf, std::fs::File)> {
    ensure_dir(dir)?;
    for _ in 0..100 {
        let path = unique_path(dir);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "quarantine name collisions exhausted",
    ))
}

/// Best-effort removal of a quarantine file. Failures are ignored: a
/// leftover is reaped on restart, while a delete error must never mask the
/// validation verdict.
pub fn discard(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_unique_files_and_discards() {
        let dir = std::env::temp_dir().join(format!(
            "conductor-quarantine-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let (a_path, _) = create_file(&dir).expect("first quarantine file");
        let (b_path, _) = create_file(&dir).expect("second quarantine file");
        assert_ne!(a_path, b_path);
        assert!(a_path.starts_with(&dir));
        discard(&a_path);
        discard(&b_path);
        assert!(!a_path.exists());
        std::fs::remove_dir_all(&dir).expect("quarantine dir must clean up");
    }

    #[test]
    fn create_new_never_overwrites() {
        let dir = std::env::temp_dir().join(format!(
            "conductor-quarantine-nooverwrite-{}",
            std::process::id()
        ));
        ensure_dir(&dir).expect("dir must be created");
        let victim = dir.join("upload-1-1-1.zip");
        std::fs::write(&victim, b"original").expect("victim must be written");
        let attempt = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&victim);
        assert_eq!(attempt.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&victim).expect("victim must read"),
            b"original"
        );
        std::fs::remove_dir_all(&dir).expect("quarantine dir must clean up");
    }
}

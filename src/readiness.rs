//! Cached host readiness.
//!
//! `/readyz` must stay cheap and must not touch SQLite per request: an
//! unauthenticated probe flood would otherwise spawn one blocking database
//! check per caller. Readiness is therefore owned by the host, refreshed by a
//! bounded background watcher, and read as two atomics on the request path.
//!
//! Both flags must be true. The database flag reflects the shared database
//! being at the current schema version and answering a trivial query. The
//! scheduler flag defaults to ready because no scheduler exists yet; the
//! future scheduler can set it without changing the HTTP route.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Per-host cached readiness state.
#[derive(Debug)]
pub struct Readiness {
    db_ready: AtomicBool,
    scheduler_ready: AtomicBool,
}

impl Readiness {
    /// Builds readiness with the current database result. The scheduler flag
    /// starts ready because this host has no scheduler component.
    #[must_use]
    pub fn new(db_ready: bool) -> Self {
        Self {
            db_ready: AtomicBool::new(db_ready),
            scheduler_ready: AtomicBool::new(true),
        }
    }

    /// Updates the database readiness flag.
    pub fn set_db_ready(&self, ready: bool) {
        self.db_ready.store(ready, Ordering::Relaxed);
    }

    /// Updates the scheduler readiness flag. Reserved for the future
    /// scheduler; today it defaults to true.
    pub fn set_scheduler_ready(&self, ready: bool) {
        self.scheduler_ready.store(ready, Ordering::Relaxed);
    }

    /// True only when both the database and scheduler are ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.db_ready.load(Ordering::Relaxed) && self.scheduler_ready.load(Ordering::Relaxed)
    }
}

impl fmt::Display for Readiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "db_ready={} scheduler_ready={}",
            self.db_ready.load(Ordering::Relaxed),
            self.scheduler_ready.load(Ordering::Relaxed)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_both_database_and_scheduler() {
        let readiness = Readiness::new(false);
        assert!(!readiness.is_ready(), "an unready database is not ready");

        readiness.set_db_ready(true);
        assert!(
            readiness.is_ready(),
            "the scheduler defaults to ready, so a ready database is ready"
        );

        readiness.set_scheduler_ready(false);
        assert!(
            !readiness.is_ready(),
            "a not-ready scheduler must make the host not ready"
        );

        readiness.set_scheduler_ready(true);
        readiness.set_db_ready(false);
        assert!(!readiness.is_ready());
    }

    #[test]
    fn flags_are_independent_and_idempotent() {
        let readiness = Readiness::new(true);
        for _ in 0..3 {
            readiness.set_db_ready(true);
            readiness.set_scheduler_ready(true);
        }
        assert!(readiness.is_ready());

        readiness.set_scheduler_ready(false);
        readiness.set_scheduler_ready(false);
        assert!(!readiness.is_ready());
        assert!(format!("{readiness}").contains("scheduler_ready=false"));
    }
}

/// Placeholder root for the Rust rewrite. No scheduler behavior is ported yet.
#[must_use]
pub fn placeholder() -> &'static str {
    "scheduler-unstable"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_reports_unstable() {
        assert_eq!(placeholder(), "scheduler-unstable");
    }
}

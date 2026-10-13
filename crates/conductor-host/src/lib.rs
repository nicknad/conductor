/// Long-running host: HTTP API, workflow, storage, scheduler. No implementation ported yet.
#[must_use]
pub fn placeholder() -> &'static str {
    "conductor-host-unstable"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_reports_unstable() {
        assert_eq!(placeholder(), "conductor-host-unstable");
    }
}

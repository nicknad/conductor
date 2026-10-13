/// Stable API surface for job modules. No implementation ported yet.
#[must_use]
pub fn placeholder() -> &'static str {
    "conductor-contracts-unstable"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_reports_unstable() {
        assert_eq!(placeholder(), "conductor-contracts-unstable");
    }
}

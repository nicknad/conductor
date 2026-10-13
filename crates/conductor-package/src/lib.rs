/// Package manifest, signature, and archive validation. No implementation ported yet.
#[must_use]
pub fn placeholder() -> &'static str {
    "conductor-package-unstable"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_reports_unstable() {
        assert_eq!(placeholder(), "conductor-package-unstable");
    }
}

//! Shared path-safe identity validation for module, version, and function
//! names. Upload, activation, execution, and scheduling all reject the same
//! shapes before an identity can become a path component or log field.

use thiserror::Error;

/// Maximum accepted byte length of an identity field.
pub const MAX_IDENTITY_BYTES: usize = 256;

/// Why an identity value was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("must not be empty")]
    Empty,
    #[error("must be at most {MAX_IDENTITY_BYTES} bytes")]
    TooLong,
    #[error("must be a path-safe identity component")]
    Unsafe,
}

/// True for the portable identity shape used by registered modules:
/// `[A-Za-z0-9._+-]`, non-empty, within the byte bound, and with no leading
/// or trailing dot.
#[must_use]
pub fn is_safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_BYTES
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

/// Validates an identity value, returning the specific refusal reason.
pub fn validate_identity(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty);
    }
    if value.len() > MAX_IDENTITY_BYTES {
        return Err(IdentityError::TooLong);
    }
    if !is_safe_identity(value) {
        return Err(IdentityError::Unsafe);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_identities_are_accepted() {
        for value in ["reporting-service", "1.2.3+build.7", "run", "a_b.c"] {
            assert_eq!(validate_identity(value), Ok(()), "{value:?}");
        }
    }

    #[test]
    fn separators_controls_and_edge_dots_are_refused() {
        for value in [
            "",
            "reporting/1.2.0",
            "reporting\\1.2.0",
            "reporting\n1.2.0",
            "reporting\t1.2.0",
            "reporting\u{1b}[31m",
            "..",
            ".hidden",
            "trailing.",
            "with space",
            &"a".repeat(MAX_IDENTITY_BYTES + 1),
        ] {
            assert!(validate_identity(value).is_err(), "{value:?}");
            assert!(!is_safe_identity(value), "{value:?}");
        }
    }
}

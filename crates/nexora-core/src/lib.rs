//! Shared core library for Nexora.
//!
//! Bootstrap scope only: this crate exposes the workspace version,
//! an identifier string, and the shared error/result contracts
//! (TASK-003). It implements no security functionality.
//!
//! The contract surface is re-exported at the crate root:
//! [`Error`], [`ErrorKind`], and [`Result`], plus [`VERSION`] and
//! [`identifier()`].

pub mod error;

pub use error::{Error, ErrorKind, Result};

/// The version of the Nexora workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns an identifier string containing the crate name and version,
/// for example `"nexora-core 0.1.0"`.
pub fn identifier() -> String {
    format!("nexora-core {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_starts_with_name_and_version() {
        assert!(identifier().starts_with("nexora-core 0.1.0"));
    }

    #[test]
    fn version_has_three_dot_separated_parts() {
        assert_eq!(VERSION.split('.').count(), 3);
    }
}

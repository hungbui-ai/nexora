//! Shared core library for Nexora.
//!
//! Bootstrap scope only: this crate exposes the workspace version
//! and an identifier string. It implements no security functionality.

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

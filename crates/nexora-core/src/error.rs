//! Shared error and result contracts for Nexora (TASK-003).
//!
//! One minimal, std-only error type shared by `nexora-core`,
//! `nexorad`, and `nexora-cli`. The core exposes numeric exit codes;
//! each binary translates them to its process exit code at its
//! single exit point.
//!
//! Message-content rule: a message is a short, lowercase,
//! user-facing sentence with no trailing period, and must contain
//! no secret, credential, token, filesystem path, stack detail, or
//! internal identifier. The call site owns message content — the
//! constructors below store the message verbatim and perform no
//! content validation, because no constructor can reliably detect
//! a secret or a path in an arbitrary string. Messages are static
//! literals wherever possible and never echo untrusted input.

use std::fmt;

/// Why a [`Error`] occurred. The kind decides the numeric exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The caller asked for something invalid (today: an invalid
    /// CLI invocation). Numeric exit code 2.
    Usage,
    /// An unexpected internal failure. Numeric exit code 1. No
    /// production path constructs it today; it exists so the first
    /// fallible operation has a kind to use.
    Internal,
}

impl ErrorKind {
    /// Returns the numeric exit code for this kind
    /// (`Usage` → 2, `Internal` → 1).
    pub fn exit_code(self) -> u8 {
        match self {
            ErrorKind::Usage => 2,
            ErrorKind::Internal => 1,
        }
    }
}

/// A Nexora error: a kind plus a user-facing message.
///
/// User-facing output uses [`std::fmt::Display`], which renders the
/// message only. `Debug` is never printed to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    /// Creates an error of the given kind with the given message.
    /// The message is stored verbatim; see the module docs for the
    /// message-content rule the call site must follow.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Creates a [`ErrorKind::Usage`] error.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    /// Creates a [`ErrorKind::Internal`] error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }

    /// Returns the kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the user-facing message of this error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the numeric exit code for this error's kind
    /// (`Usage` → 2, `Internal` → 1).
    pub fn exit_code(&self) -> u8 {
        self.kind.exit_code()
    }
}

impl fmt::Display for Error {
    /// Renders the message only, with no `error: ` prefix and no
    /// added detail. The reporter owns the prefix (see D5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

/// Shared result type for fallible functions that can fail with a
/// Nexora [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_renders_message_only() {
        let err = Error::usage("expected exactly one of --version or --help");
        assert_eq!(
            format!("{err}"),
            "expected exactly one of --version or --help"
        );
        // No prefix, no kind, no added detail.
        assert!(!format!("{err}").contains("error:"));
        assert!(!format!("{err}").contains("Usage"));
    }

    #[test]
    fn constructors_agree_on_kind_and_message() {
        let via_new = Error::new(ErrorKind::Usage, "some usage problem");
        let via_usage = Error::usage("some usage problem");
        assert_eq!(via_new, via_usage);
        assert_eq!(via_new.kind(), ErrorKind::Usage);
        assert_eq!(via_new.message(), "some usage problem");

        let via_internal = Error::internal("some internal failure");
        assert_eq!(via_internal.kind(), ErrorKind::Internal);
        assert_eq!(via_internal.message(), "some internal failure");
        assert_eq!(
            Error::new(ErrorKind::Internal, "some internal failure"),
            via_internal
        );
    }

    #[test]
    fn exit_code_mapping_on_kind_and_error() {
        assert_eq!(ErrorKind::Usage.exit_code(), 2);
        assert_eq!(ErrorKind::Internal.exit_code(), 1);
        assert_eq!(Error::usage("u").exit_code(), 2);
        assert_eq!(Error::internal("i").exit_code(), 1);
    }

    #[test]
    fn result_alias_is_usable_as_return_type() {
        fn fallible(ok: bool) -> Result<u32> {
            if ok {
                Ok(1)
            } else {
                Err(Error::usage("not ok"))
            }
        }
        assert_eq!(fallible(true), Ok(1));
        assert_eq!(fallible(false).unwrap_err().kind(), ErrorKind::Usage);
    }

    #[test]
    fn cloned_error_equals_original() {
        let err = Error::usage("expected exactly one of --version or --help");
        assert_eq!(err.clone(), err);
    }
}

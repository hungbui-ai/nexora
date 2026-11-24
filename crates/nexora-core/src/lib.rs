//! Shared core library for Nexora.
//!
//! This crate exposes the workspace version, an identifier string,
//! the shared error/result contracts (TASK-003), the SSH
//! brute-force detection parser (TASK-005), and the host exposure
//! inventory parser and aggregator (TASK-007).
//!
//! The contract surface is re-exported at the crate root:
//! [`Error`], [`ErrorKind`], and [`Result`], plus [`VERSION`] and
//! [`identifier()`]. The detection surface is likewise re-exported
//! from [`detection`]: [`SSH_BRUTE_FORCE_THRESHOLD`],
//! [`SshBruteForceFinding`], [`BruteForceCounter`], and
//! [`count_failed_passwords`]. The exposure surface is likewise
//! re-exported from [`exposure`]: the resource-limit constants,
//! [`SocketProtocol`], [`SocketEntry`], [`OwnerPair`],
//! [`ReportOwner`], [`ReportLine`], [`AggregatedReport`],
//! [`parse_proc_net_line`], [`sanitise_comm`], [`aggregate`], and
//! [`render_report`].

pub mod detection;
pub mod error;
pub mod exposure;

pub use detection::{
    count_failed_passwords, BruteForceCounter, SshBruteForceFinding, SSH_BRUTE_FORCE_THRESHOLD,
};
pub use error::{Error, ErrorKind, Result};
pub use exposure::{
    aggregate, parse_proc_net_line, render_report, sanitise_comm, AggregatedReport, OwnerPair,
    ReportLine, ReportOwner, SocketEntry, SocketProtocol, MAX_FDS_EXAMINED, MAX_PROCESSES_SCANNED,
    MAX_PROC_NET_LINE_BYTES, MAX_REPORT_BYTES, MAX_REPORT_LINES, MAX_SOCKET_ENTRIES,
    MAX_SOCKET_TABLE_LINES,
};

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

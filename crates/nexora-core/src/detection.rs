//! SSH brute-force detection report (TASK-005).
//!
//! Pure, std-only parsing and aggregation over OpenSSH
//! `Failed password` log lines. No I/O: the caller supplies lines
//! and counts total lines itself.
//!
//! The event rule (normative, see the TASK-005 task file): a line
//! is a failed-password event if and only if (a) it contains the
//! substring `Failed password for `; (b) the last occurrence of
//! ` from ` after that substring is followed by a token that parses
//! as an IPv4 address; and (c) the remainder of the line after that
//! token is exactly ` port ` followed by one or more ASCII digits
//! that parse as a `u16`, followed by ` ssh2`, and the line ends
//! there. The last-occurrence rule and the suffix anchor exist
//! because the username is attacker-influenced: a username
//! containing ` from 198.51.100.99` must not misattribute the
//! event to that address. A line that contains the marker but fails
//! (b) or (c) (IPv6 source, truncated line, `ssh1` line, missing
//! suffix) is counted as unparsed; all other lines are ignored.
//! Each line contributes at most one event. There is no time
//! window: counts are aggregated over the whole input.
//!
//! A line longer than [`MAX_LINE_BYTES`] is never an event. It is
//! counted as unparsed if its first [`MAX_LINE_BYTES`] bytes
//! contain the marker, and ignored otherwise.
//!
//! Two entry points share one classifier: [`count_failed_passwords`]
//! (the spec's function, over an in-memory iterator of lines) and
//! [`BruteForceCounter`] (a streaming accumulator). The counter
//! exists because the CLI must stream the file line by line without
//! loading it whole, and an `Iterator<Item = &str>` cannot borrow
//! lines from a buffer the CLI refills — so the CLI feeds the
//! counter one line at a time instead of collecting lines to pass
//! to [`count_failed_passwords`]. Both paths classify identically.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A source address is a finding if and only if its
/// failed-password count is this value or more.
pub const SSH_BRUTE_FORCE_THRESHOLD: u64 = 5;

/// Maximum length of one log line, in bytes. A longer line is never
/// an event (see the module docs).
pub const MAX_LINE_BYTES: usize = 1_048_576;

/// The substring that marks a failed-password log line.
const MARKER: &str = "Failed password for ";

/// One finding: a source address and its failed-password count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshBruteForceFinding {
    /// The canonical source IPv4 address.
    pub source: Ipv4Addr,
    /// The number of failed-password events from this source.
    pub attempts: u64,
}

/// What one input line classifies as.
enum LineClass {
    /// A failed-password event from this source address.
    Event(Ipv4Addr),
    /// Contains the marker but fails the event rule.
    Unparsed,
    /// Contains no marker; counted nowhere.
    Ignored,
}

/// Returns true if the head of an over-long line (its first
/// [`MAX_LINE_BYTES`] bytes) contains the failed-password marker,
/// meaning the line counts as unparsed rather than ignored.
pub fn overlong_head_is_unparsed(head: &[u8]) -> bool {
    head.windows(MARKER.len())
        .any(|window| window == MARKER.as_bytes())
}

/// Streaming accumulator for the detection report. The CLI feeds it
/// one line at a time as it streams the log file, so the whole file
/// is never held in memory. [`count_failed_passwords`] is built on
/// this type.
pub struct BruteForceCounter {
    counts: HashMap<Ipv4Addr, u64>,
    unparsed: u64,
}

impl BruteForceCounter {
    /// Creates an empty counter.
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            unparsed: 0,
        }
    }

    /// Classifies one line and aggregates the result. The line must
    /// already be split on `\n` with a single trailing `\r`, if
    /// any, stripped; decoding is the caller's job.
    pub fn add_line(&mut self, line: &str) {
        match classify(line) {
            LineClass::Event(source) => {
                *self.counts.entry(source).or_insert(0) += 1;
            }
            LineClass::Unparsed => self.unparsed += 1,
            LineClass::Ignored => {}
        }
    }

    /// Counts one over-long line (longer than [`MAX_LINE_BYTES`])
    /// as unparsed. The CLI calls this for a line it truncated
    /// while streaming; such a line is never an event.
    pub fn add_unparsed(&mut self) {
        self.unparsed += 1;
    }

    /// Returns the findings sorted by count descending, then by
    /// IPv4 address ascending in numeric octet order, and the
    /// unparsed failed-password line count.
    pub fn finish(self) -> (Vec<SshBruteForceFinding>, u64) {
        let mut findings: Vec<SshBruteForceFinding> = self
            .counts
            .into_iter()
            .filter(|(_, attempts)| *attempts >= SSH_BRUTE_FORCE_THRESHOLD)
            .map(|(source, attempts)| SshBruteForceFinding { source, attempts })
            .collect();
        findings.sort_by(|a, b| {
            b.attempts
                .cmp(&a.attempts)
                .then_with(|| a.source.octets().cmp(&b.source.octets()))
        });
        (findings, self.unparsed)
    }
}

impl Default for BruteForceCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts failed-password events per canonical source IPv4 address
/// over the given lines, returning the findings (sorted by count
/// descending, then address ascending) and the unparsed
/// failed-password line count.
pub fn count_failed_passwords<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> (Vec<SshBruteForceFinding>, u64) {
    let mut counter = BruteForceCounter::new();
    for line in lines {
        counter.add_line(line);
    }
    counter.finish()
}

/// Classifies one line. See the module docs for the rule.
fn classify(line: &str) -> LineClass {
    let bytes = line.as_bytes();
    if bytes.len() > MAX_LINE_BYTES {
        return if overlong_head_is_unparsed(&bytes[..MAX_LINE_BYTES]) {
            LineClass::Unparsed
        } else {
            LineClass::Ignored
        };
    }
    let Some(marker_at) = line.find(MARKER) else {
        return LineClass::Ignored;
    };
    let after_marker = &line[marker_at + MARKER.len()..];
    let Some(relative) = after_marker.rfind(" from ") else {
        return LineClass::Unparsed;
    };
    let after_from = &after_marker[relative + " from ".len()..];
    let token_end = after_from
        .find(|c: char| c.is_whitespace())
        .unwrap_or(after_from.len());
    let token = &after_from[..token_end];
    let remainder = &after_from[token_end..];
    let Some(source) = parse_ipv4(token) else {
        return LineClass::Unparsed;
    };
    let Some(rest) = remainder.strip_prefix(" port ") else {
        return LineClass::Unparsed;
    };
    let digit_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digit_len == 0 {
        return LineClass::Unparsed;
    }
    if rest[..digit_len].parse::<u16>().is_err() {
        return LineClass::Unparsed;
    }
    if &rest[digit_len..] != " ssh2" {
        return LineClass::Unparsed;
    }
    LineClass::Event(source)
}

/// Parses a token as an IPv4 address: exactly four parts, each one
/// to three ASCII digits, each a `u8`. Returns the canonical
/// address (leading zeros removed).
fn parse_ipv4(token: &str) -> Option<Ipv4Addr> {
    let mut parts = token.split('.');
    let a = parse_octet(parts.next()?)?;
    let b = parse_octet(parts.next()?)?;
    let c = parse_octet(parts.next()?)?;
    let d = parse_octet(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::new(a, b, c, d))
}

/// Parses one IPv4 octet: one to three ASCII digits, value 0–255.
fn parse_octet(part: &str) -> Option<u8> {
    if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<u8>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the detector over the given lines and returns
    /// (findings as (address, attempts) pairs, unparsed count).
    fn run(lines: &[&str]) -> (Vec<(Ipv4Addr, u64)>, u64) {
        let (findings, unparsed) = count_failed_passwords(lines.iter().copied());
        (
            findings.iter().map(|f| (f.source, f.attempts)).collect(),
            unparsed,
        )
    }

    fn addr(s: &str) -> Ipv4Addr {
        s.parse().expect("test address must parse")
    }

    #[test]
    fn valid_root_shape_is_event() {
        let (findings, unparsed) = run(&[
            "Failed password for root from 203.0.113.7 port 22 ssh2",
            "Failed password for root from 203.0.113.7 port 22 ssh2",
            "Failed password for root from 203.0.113.7 port 22 ssh2",
            "Failed password for root from 203.0.113.7 port 22 ssh2",
            "Failed password for root from 203.0.113.7 port 22 ssh2",
        ]);
        assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn valid_invalid_user_shape_is_event() {
        let (findings, unparsed) = run(&[
            "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
            "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
            "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
            "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
            "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2",
        ]);
        assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn syslog_prefixed_line_is_event() {
        let (findings, unparsed) = run(&[
            "Nov 22 10:00:00 myhost sshd[1234]: Failed password for root from 203.0.113.7 port 22 ssh2",
            "Nov 22 10:00:00 myhost sshd[1234]: Failed password for root from 203.0.113.7 port 22 ssh2",
            "Nov 22 10:00:00 myhost sshd[1234]: Failed password for root from 203.0.113.7 port 22 ssh2",
            "Nov 22 10:00:00 myhost sshd[1234]: Failed password for root from 203.0.113.7 port 22 ssh2",
            "Nov 22 10:00:00 myhost sshd[1234]: Failed password for root from 203.0.113.7 port 22 ssh2",
        ]);
        assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn threshold_boundary_four_five_six() {
        let mut lines = Vec::new();
        lines.extend(std::iter::repeat_n(
            "Failed password for root from 10.0.0.1 port 22 ssh2",
            4,
        ));
        lines.extend(std::iter::repeat_n(
            "Failed password for root from 10.0.0.2 port 22 ssh2",
            5,
        ));
        lines.extend(std::iter::repeat_n(
            "Failed password for root from 10.0.0.3 port 22 ssh2",
            6,
        ));
        let (findings, unparsed) = run(&lines);
        assert_eq!(findings, vec![(addr("10.0.0.3"), 6), (addr("10.0.0.2"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn ordering_count_desc_then_address_asc_with_tie() {
        let mut lines = Vec::new();
        lines.extend(std::iter::repeat_n(
            "Failed password for root from 10.0.0.4 port 22 ssh2",
            12,
        ));
        lines.extend(std::iter::repeat_n(
            "Failed password for root from 10.0.0.5 port 22 ssh2",
            6,
        ));
        lines.extend(std::iter::repeat_n(
            "Failed password for root from 10.0.0.3 port 22 ssh2",
            6,
        ));
        lines.extend(std::iter::repeat_n(
            "Failed password for root from 10.0.0.2 port 22 ssh2",
            5,
        ));
        let (findings, _) = run(&lines);
        assert_eq!(
            findings,
            vec![
                (addr("10.0.0.4"), 12),
                (addr("10.0.0.3"), 6),
                (addr("10.0.0.5"), 6),
                (addr("10.0.0.2"), 5),
            ]
        );
    }

    #[test]
    fn leading_zero_octets_canonicalise_and_merge() {
        let (findings, unparsed) = run(&[
            "Failed password for root from 203.0.113.007 port 22 ssh2",
            "Failed password for root from 203.0.113.7 port 22 ssh2",
            "Failed password for root from 203.0.113.007 port 22 ssh2",
            "Failed password for root from 203.0.113.7 port 22 ssh2",
            "Failed password for root from 203.0.113.007 port 22 ssh2",
        ]);
        assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn username_decoy_does_not_misattribute() {
        let (findings, unparsed) = run(&[
            "Failed password for evil from 198.51.100.99 from 203.0.113.7 port 22 ssh2",
            "Failed password for evil from 198.51.100.99 from 203.0.113.7 port 22 ssh2",
            "Failed password for evil from 198.51.100.99 from 203.0.113.7 port 22 ssh2",
            "Failed password for evil from 198.51.100.99 from 203.0.113.7 port 22 ssh2",
            "Failed password for evil from 198.51.100.99 from 203.0.113.7 port 22 ssh2",
        ]);
        assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn username_full_decoy_suffix_still_uses_real_source() {
        let (findings, unparsed) = run(&[
            "Failed password for x from 9.9.9.9 port 22 ssh2 from 203.0.113.7 port 22 ssh2",
            "Failed password for x from 9.9.9.9 port 22 ssh2 from 203.0.113.7 port 22 ssh2",
            "Failed password for x from 9.9.9.9 port 22 ssh2 from 203.0.113.7 port 22 ssh2",
            "Failed password for x from 9.9.9.9 port 22 ssh2 from 203.0.113.7 port 22 ssh2",
            "Failed password for x from 9.9.9.9 port 22 ssh2 from 203.0.113.7 port 22 ssh2",
        ]);
        assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn truncated_real_source_after_decoy_is_unparsed_not_decoy() {
        let (findings, unparsed) =
            run(&["Failed password for x from 9.9.9.9 port 22 ssh2 from 203.0.113.7 port 22"]);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 1);
    }

    #[test]
    fn port_boundaries_zero_one_max_and_over() {
        for port in ["0", "1", "65535"] {
            let line = format!("Failed password for root from 203.0.113.7 port {port} ssh2");
            let lines = vec![line.as_str(); 5];
            let (findings, unparsed) = run(&lines);
            assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
            assert_eq!(unparsed, 0);
        }
        for port in ["65536", "99999", "abc", "22a", ""] {
            let line = format!("Failed password for root from 203.0.113.7 port {port} ssh2");
            let (findings, unparsed) = run(&[line.as_str()]);
            assert_eq!(findings, vec![]);
            assert_eq!(unparsed, 1, "port {port} must be unparsed");
        }
    }

    #[test]
    fn malformed_ipv4_and_ipv6_are_unparsed() {
        let lines = [
            "Failed password for root from 2001:db8::1 port 22 ssh2",
            "Failed password for root from 1.2.3 port 22 ssh2",
            "Failed password for root from 1.2.3.4.5 port 22 ssh2",
            "Failed password for root from 256.1.1.1 port 22 ssh2",
            "Failed password for root from 1.2.3.0007 port 22 ssh2",
            "Failed password for root from 1..2.3 port 22 ssh2",
            "Failed password for root from 1.2.3.x port 22 ssh2",
        ];
        let (findings, unparsed) = run(&lines);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 7);
    }

    #[test]
    fn missing_suffix_parts_are_unparsed() {
        let lines = [
            "Failed password for root from 203.0.113.7 ssh2",
            "Failed password for root from 203.0.113.7 port 22",
            "Failed password for root from 203.0.113.7 port 22 ssh1",
            "Failed password for root from 203.0.113.7 port 22 ssh2 ",
            "Failed password for root from 203.0.113.7 port 22 ssh2 extra",
        ];
        let (findings, unparsed) = run(&lines);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 5);
    }

    #[test]
    fn non_matching_lines_are_ignored() {
        let lines = [
            "Accepted password for root from 203.0.113.7 port 22 ssh2",
            "Connection closed by 203.0.113.7 port 22 [preauth]",
            "Failed keyboard-interactive/pam for root from 203.0.113.7 port 22 ssh2",
            "",
            "   ",
            "Nov 22 10:00:00 myhost sshd[1234]: Server listening on 0.0.0.0 port 22.",
            "failed password for root from 203.0.113.7 port 22 ssh2",
            "Failed password  for root from 203.0.113.7 port 22 ssh2",
        ];
        let (findings, unparsed) = run(&lines);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn marker_without_source_is_unparsed() {
        let lines = ["Failed password for ", "Failed password for root"];
        let (findings, unparsed) = run(&lines);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 2);
    }

    #[test]
    fn one_line_contributes_at_most_one_event() {
        let (findings, unparsed) = run(&[
            "Failed password for root from 1.1.1.1 port 22 ssh2 Failed password for root from 2.2.2.2 port 22 ssh2",
            "Failed password for root from 1.1.1.1 port 22 ssh2 Failed password for root from 2.2.2.2 port 22 ssh2",
            "Failed password for root from 1.1.1.1 port 22 ssh2 Failed password for root from 2.2.2.2 port 22 ssh2",
            "Failed password for root from 1.1.1.1 port 22 ssh2 Failed password for root from 2.2.2.2 port 22 ssh2",
            "Failed password for root from 1.1.1.1 port 22 ssh2 Failed password for root from 2.2.2.2 port 22 ssh2",
        ]);
        assert_eq!(findings, vec![(addr("2.2.2.2"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn empty_input_has_no_findings_and_zero_unparsed() {
        let (findings, unparsed) = run(&[]);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn overlong_lines_follow_the_cap_rule() {
        // A valid event at the start of an over-long line is never
        // an event; the marker in the head makes it unparsed.
        let long_event = format!(
            "Failed password for root from 203.0.113.7 port 22 ssh2{}",
            "x".repeat(MAX_LINE_BYTES)
        );
        let (findings, unparsed) = run(&[long_event.as_str()]);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 1);
        // No marker in the head: ignored, not unparsed.
        let long_plain = "x".repeat(MAX_LINE_BYTES + 100);
        let (findings, unparsed) = run(&[long_plain.as_str()]);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 0);
        // Marker beyond the cap: ignored.
        let long_tail = format!(
            "{}{}",
            "x".repeat(MAX_LINE_BYTES + 100),
            "Failed password for root from 203.0.113.7 port 22 ssh2"
        );
        let (findings, unparsed) = run(&[long_tail.as_str()]);
        assert_eq!(findings, vec![]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn long_username_under_cap_is_still_an_event() {
        let line = format!(
            "Failed password for {} from 203.0.113.7 port 22 ssh2",
            "x".repeat(100_000)
        );
        let lines = vec![line.as_str(); 5];
        let (findings, unparsed) = run(&lines);
        assert_eq!(findings, vec![(addr("203.0.113.7"), 5)]);
        assert_eq!(unparsed, 0);
    }

    #[test]
    fn counter_and_function_agree() {
        let mut counter = BruteForceCounter::new();
        for _ in 0..5 {
            counter.add_line("Failed password for root from 203.0.113.7 port 22 ssh2");
        }
        counter.add_line("Failed password for root from 2001:db8::1 port 22 ssh2");
        counter.add_unparsed();
        let (findings, unparsed) = counter.finish();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, addr("203.0.113.7"));
        assert_eq!(findings[0].attempts, 5);
        assert_eq!(unparsed, 2);
    }
}

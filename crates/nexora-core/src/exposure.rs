//! Host exposure inventory report (TASK-007).
//!
//! Pure, std-only parsing and aggregation over `/proc/net`
//! socket-table lines. No I/O: the caller supplies lines and the
//! owner mapping; the CLI streams the files and scans `/proc`
//! (see the TASK-007 task file, §Component boundaries).
//!
//! The parser rule (normative, spec §Input and parsing, as amended
//! 2026-11-24 — D-007-01 field-layout amendment): a data line is a
//! socket entry if and only if (a) it splits on whitespace into at
//! least 10 fields; (b) field 2 (`local_address`) is
//! `<hex-ip>:<hex-port>` where the hex IP decodes as an IPv4
//! address (8 hex digits, four little-endian quads) for `tcp` /
//! `udp`, or as an IPv6 address (32 hex digits, four little-endian
//! 32-bit words) for `tcp6` / `udp6`, and the hex port decodes as a
//! `u16`; (c) field 4 (`st`) is exactly `0A` (LISTEN) for the TCP
//! files — for the UDP files the state field is parsed but not
//! filtered on, because UDP has no LISTEN state and every bound
//! UDP socket is reported; (d) field 10 (`inode`) parses as a
//! `u64`. The socket inode is field 10 — not field 8, which is the
//! owning UID, and not field 12, which is the kernel socket
//! pointer (`%pK`, printed as `0000000000000000` to readers
//! without `CAP_SYSLOG`) and is never an inode. Field 3 (remote
//! address), field 8 (UID), field 9, and every field after the
//! inode are ignored entirely: never parsed as an inode, stored,
//! or reported. Fields 5 (`tx_queue:rx_queue`) and 6
//! (`tr:tm->when`) are each a single whitespace-separated token.
//! A line longer than [`MAX_PROC_NET_LINE_BYTES`] is never an
//! entry.
//!
//! The aggregator ([`aggregate`]) sorts the deduplicated pairs
//! plus the unknown-owner inodes into report lines (protocol
//! order `tcp`, `tcp6`, `udp`, `udp6`; then local address
//! ascending in numeric byte order; then port ascending; then PID
//! ascending, with `unknown`-owner lines after known-owner
//! lines), counts `N` / `S` / `U`, and enforces
//! [`MAX_SOCKET_ENTRIES`] and [`MAX_REPORT_LINES`]. The render
//! function ([`render_report`]) produces the exact report string
//! and enforces [`MAX_REPORT_BYTES`] on the rendered bytes.
//! Exceeding any cap fails closed with the limits error
//! (`error: socket inventory exceeds limits`, exit 1): no
//! partial report is ever produced.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// Socket entries kept (LISTEN TCP plus bound UDP, across all
/// four files).
pub const MAX_SOCKET_ENTRIES: usize = 10_000;
/// Total report lines printed: known-owner pair lines plus
/// unknown-owner lines.
pub const MAX_REPORT_LINES: usize = 10_000;
/// Total data lines read across the four files (headers excluded).
pub const MAX_SOCKET_TABLE_LINES: u64 = 1_000_000;
/// PIDs visited in the owner scan.
pub const MAX_PROCESSES_SCANNED: usize = 10_000;
/// Fd entries read across all processes in the owner scan.
pub const MAX_FDS_EXAMINED: u64 = 100_000;
/// The per-line cap in §Input and parsing: a longer line is never
/// an entry.
pub const MAX_PROC_NET_LINE_BYTES: usize = 65_536;
/// The bound on the stdout report size, enforced on the rendered
/// output before anything is written.
pub const MAX_REPORT_BYTES: usize = 1_048_576;

/// The limits error: a resource cap was exceeded. The message is
/// the exact spec string (the CLI adds the `error: ` prefix).
fn limits_error() -> Error {
    Error::internal("socket inventory exceeds limits")
}

/// The socket-table protocol: which `/proc/net` file an entry
/// came from. The display and sort order is `tcp`, `tcp6`, `udp`,
/// `udp6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl SocketProtocol {
    /// The protocol name as printed in the report.
    pub fn as_str(self) -> &'static str {
        match self {
            SocketProtocol::Tcp => "tcp",
            SocketProtocol::Tcp6 => "tcp6",
            SocketProtocol::Udp => "udp",
            SocketProtocol::Udp6 => "udp6",
        }
    }

    /// Sort key for the protocol order `tcp`, `tcp6`, `udp`,
    /// `udp6`.
    fn order(self) -> u8 {
        match self {
            SocketProtocol::Tcp => 0,
            SocketProtocol::Tcp6 => 1,
            SocketProtocol::Udp => 2,
            SocketProtocol::Udp6 => 3,
        }
    }
}

impl std::fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One kept socket entry: a parsed `/proc/net` data line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEntry {
    /// Which socket-table file the entry came from.
    pub protocol: SocketProtocol,
    /// The local address, decoded from the hex field.
    pub local: IpAddr,
    /// The local port, decoded from the hex field.
    pub port: u16,
    /// The socket inode, from field 10 of the data line.
    pub inode: u64,
}

/// Parses one `/proc/net` data line (header already skipped) into
/// a socket entry, or `None` if the line is not an entry (an
/// unparsed socket line). The caller counts `None` results as
/// unparsed lines; lines with fewer than 10 fields, a bad address,
/// a bad port, a non-LISTEN TCP state, or a bad inode in field 10
/// are all `None`. Field 8 (UID) and field 9 are never read: a
/// non-numeric UID still parses, and a field-9 value is never
/// mistaken for the inode.
pub fn parse_proc_net_line(protocol: SocketProtocol, line: &str) -> Option<SocketEntry> {
    // A line longer than the per-line cap is never an entry.
    if line.len() > MAX_PROC_NET_LINE_BYTES {
        return None;
    }
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let (local, port) = parse_local_address(protocol, fields[1])?;
    // Field 4 (`st`): exactly `0A` for the TCP files. For the UDP
    // files the state is parsed but not filtered on — UDP has no
    // LISTEN state, so any value is accepted.
    if matches!(protocol, SocketProtocol::Tcp | SocketProtocol::Tcp6) && fields[3] != "0A" {
        return None;
    }
    // Field 10 (`inode`): decimal `u64`. Field 8 (UID) is never
    // parsed as an inode.
    let inode = parse_u64_decimal(fields[9])?;
    Some(SocketEntry {
        protocol,
        local,
        port,
        inode,
    })
}

/// Parses field 2 (`local_address`) as `<hex-ip>:<hex-port>`.
/// The hex IP is 8 digits (IPv4, four little-endian quads) for
/// `tcp` / `udp`, or 32 digits (IPv6, four little-endian 32-bit
/// words) for `tcp6` / `udp6`. The hex port decodes as a `u16`.
fn parse_local_address(protocol: SocketProtocol, field: &str) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    // Exactly one `:`: a second one means the field is malformed.
    if port_hex.contains(':') {
        return None;
    }
    let port = parse_hex_u16(port_hex)?;
    let local = match protocol {
        SocketProtocol::Tcp | SocketProtocol::Udp => IpAddr::V4(parse_ipv4_hex(ip_hex)?),
        SocketProtocol::Tcp6 | SocketProtocol::Udp6 => IpAddr::V6(parse_ipv6_hex(ip_hex)?),
    };
    Some((local, port))
}

/// Parses a 1–4 digit hex port as a `u16`. The all-hex check runs
/// first because `from_str_radix` would accept a leading `+`.
fn parse_hex_u16(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(text, 16).ok()
}

/// Parses exactly 8 hex digits as an IPv4 address: the digits are
/// one little-endian `u32`, so `0100007F` decodes to `127.0.0.1`.
fn parse_ipv4_hex(text: &str) -> Option<Ipv4Addr> {
    if text.len() != 8 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = u32::from_str_radix(text, 16).ok()?;
    Some(Ipv4Addr::from(value.to_le_bytes()))
}

/// Parses exactly 32 hex digits as an IPv6 address: four
/// little-endian `u32` words, so
/// `00000000000000000000000001000000` decodes to `::1`.
fn parse_ipv6_hex(text: &str) -> Option<Ipv6Addr> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, group) in text.as_bytes().chunks(8).enumerate() {
        let word_text = std::str::from_utf8(group).ok()?;
        let word = u32::from_str_radix(word_text, 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

/// Parses a decimal `u64` (the field-10 inode). The all-digit
/// check runs first because `from_str_radix` would accept a
/// leading `+`.
fn parse_u64_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok()
}

/// Sanitises a process name (`/proc/<pid>/comm`) for printing:
/// the single trailing newline is stripped first, then every byte
/// below `0x20`, equal to `0x7F`, or at or above `0x80` is
/// replaced with `?`. The replacement is byte-wise, so one
/// multi-byte non-ASCII character becomes one `?` per byte.
/// A name is at most 15 characters, so sanitising is bounded.
pub fn sanitise_comm(raw: &str) -> String {
    let stripped = raw.strip_suffix('\n').unwrap_or(raw);
    stripped
        .bytes()
        .map(|b| {
            if b < 0x20 || b == 0x7F || b >= 0x80 {
                '?'
            } else {
                b as char
            }
        })
        .collect()
}

/// A distinct socket-owner pair: a kept socket inode owned by one
/// process. The pair set passed to [`aggregate`] is already
/// deduplicated by `(inode, PID)` during the owner scan (spec
/// §Owner resolution); the aggregator deduplicates again
/// defensively, so a duplicate pair can never trip
/// [`MAX_REPORT_LINES`].
///
/// The `comm` must already be sanitised with [`sanitise_comm`]
/// by the caller. This type is a reshape of the plan's proposed
/// `OwnerPair = (u64, u32)` tuple (the plan permits reshaping the
/// proposed shapes): the tuple cannot carry the process name the
/// report line needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerPair {
    /// The socket inode (field 10).
    pub inode: u64,
    /// The owning process ID.
    pub pid: u32,
    /// The process name, already sanitised with [`sanitise_comm`].
    pub comm: String,
}

/// The owner of a reported socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOwner {
    /// A known owner: PID and sanitised process name.
    Known { pid: u32, comm: String },
    /// No known owner.
    Unknown,
}

/// One sorted report line (without the header and count lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLine {
    /// The socket-table protocol.
    pub protocol: SocketProtocol,
    /// The local address.
    pub local: IpAddr,
    /// The local port.
    pub port: u16,
    /// The owning process, or [`ReportOwner::Unknown`].
    pub owner: ReportOwner,
}

/// The aggregated inventory: sorted report lines plus the
/// counters the exact report prints. Produced by [`aggregate`];
/// [`render_report`] turns it into the exact report string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedReport {
    /// Sorted report lines (protocol, address, port, PID;
    /// unknown-owner lines after known-owner lines).
    pub lines: Vec<ReportLine>,
    /// `N`: total report lines (pair lines + unknown-owner lines).
    pub total_lines: usize,
    /// `S`: distinct socket inodes listed.
    pub sockets_listed: usize,
    /// `U`: distinct socket inodes with no known owner (also the
    /// number of unknown-owner lines).
    pub unknown_owners: usize,
    /// `T`: total data lines read across the four files (headers
    /// excluded).
    pub lines_read: u64,
    /// `K`: unparsed socket lines.
    pub unparsed_lines: u64,
}

/// Aggregates the kept socket entries, the deduplicated owner
/// pairs, and the unknown-owner inodes into the sorted report.
///
/// - The (cap + 1)th entry (`entries.len() >
///   MAX_SOCKET_ENTRIES`) returns the limits error, never a
///   truncation.
/// - Pairs are deduplicated by `(inode, PID)` again here, so a
///   duplicate pair counts once; distinct PIDs holding the same
///   inode count separately. A pair whose inode is outside the
///   kept set cannot be rendered and is skipped (the CLI never
///   produces one: pairs reference kept inodes only).
/// - Each unknown-owner inode in the kept set contributes exactly
///   one `unknown unknown` line; a repeated unknown inode
///   contributes one line, and an unknown inode outside the kept
///   set is skipped.
/// - The (cap + 1)th total report line (`lines.len() >
///   MAX_REPORT_LINES`, whether a known pair line or an
///   unknown-owner line) returns the limits error, never a
///   truncation.
///
/// The returned lines are sorted by protocol, local address in
/// numeric byte order, port, then PID ascending, with
/// unknown-owner lines after known-owner lines. The sort is
/// stable, so lines that compare equal keep their input order;
/// the CLI supplies entries and pairs in deterministic order
/// (file order, ascending PID), so the output is deterministic.
pub fn aggregate(
    entries: &[SocketEntry],
    pairs: &[OwnerPair],
    unknown_inodes: &[u64],
    lines_read: u64,
    unparsed_lines: u64,
) -> Result<AggregatedReport> {
    if entries.len() > MAX_SOCKET_ENTRIES {
        return Err(limits_error());
    }
    // First entry wins if an inode repeats (the CLI never produces
    // a repeated inode: one socket appears once per table).
    let mut by_inode: BTreeMap<u64, &SocketEntry> = BTreeMap::new();
    for entry in entries {
        by_inode.entry(entry.inode).or_insert(entry);
    }
    let mut lines: Vec<ReportLine> = Vec::new();
    let mut listed_inodes: BTreeSet<u64> = BTreeSet::new();
    let mut seen_pairs: BTreeSet<(u64, u32)> = BTreeSet::new();
    for pair in pairs {
        if !seen_pairs.insert((pair.inode, pair.pid)) {
            continue;
        }
        let Some(entry) = by_inode.get(&pair.inode) else {
            continue;
        };
        listed_inodes.insert(pair.inode);
        lines.push(ReportLine {
            protocol: entry.protocol,
            local: entry.local,
            port: entry.port,
            owner: ReportOwner::Known {
                pid: pair.pid,
                comm: pair.comm.clone(),
            },
        });
    }
    let mut seen_unknown: BTreeSet<u64> = BTreeSet::new();
    let mut unknown_owners = 0usize;
    for inode in unknown_inodes {
        if !seen_unknown.insert(*inode) {
            continue;
        }
        let Some(entry) = by_inode.get(inode) else {
            continue;
        };
        listed_inodes.insert(*inode);
        unknown_owners += 1;
        lines.push(ReportLine {
            protocol: entry.protocol,
            local: entry.local,
            port: entry.port,
            owner: ReportOwner::Unknown,
        });
    }
    if lines.len() > MAX_REPORT_LINES {
        return Err(limits_error());
    }
    lines.sort_by(report_line_cmp);
    Ok(AggregatedReport {
        total_lines: lines.len(),
        sockets_listed: listed_inodes.len(),
        unknown_owners,
        lines_read,
        unparsed_lines,
        lines,
    })
}

/// Sorts report lines by protocol, address bytes, port, then PID
/// ascending, with unknown-owner lines after known-owner lines.
fn report_line_cmp(a: &ReportLine, b: &ReportLine) -> std::cmp::Ordering {
    a.protocol
        .order()
        .cmp(&b.protocol.order())
        .then_with(|| match (a.local, b.local) {
            (IpAddr::V4(x), IpAddr::V4(y)) => x.octets().cmp(&y.octets()),
            (IpAddr::V6(x), IpAddr::V6(y)) => x.octets().cmp(&y.octets()),
            (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
            (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
        })
        .then_with(|| a.port.cmp(&b.port))
        .then_with(|| match (&a.owner, &b.owner) {
            (ReportOwner::Known { pid: first, .. }, ReportOwner::Known { pid: second, .. }) => {
                first.cmp(second)
            }
            (ReportOwner::Known { .. }, ReportOwner::Unknown) => std::cmp::Ordering::Less,
            (ReportOwner::Unknown, ReportOwner::Known { .. }) => std::cmp::Ordering::Greater,
            (ReportOwner::Unknown, ReportOwner::Unknown) => std::cmp::Ordering::Equal,
        })
}

/// Renders the exact report string for an aggregated inventory:
///
/// ```text
/// host exposure entries: N
/// <protocol> <local-address> <port> <pid|unknown> <comm|unknown>
/// ...
/// sockets listed: S
/// sockets with unknown owner: U
/// lines read: T
/// unparsed socket lines: K
/// ```
///
/// IPv4 addresses render as dotted decimal; IPv6 addresses in the
/// compressed lowercase form of `std::net::Ipv6Addr`'s `Display`
/// (IPv4-mapped IPv6 renders as IPv6, with no special-casing).
/// Every line ends with `\n`, including the last count line.
/// If the rendered bytes exceed [`MAX_REPORT_BYTES`], the limits
/// error is returned and no report is produced: the byte cap is
/// enforced on the actual output, not merely derived (a report
/// that passes [`aggregate`] can never exceed it — 10,000 lines
/// are at most ~751 KiB — so this check is defence in depth for
/// any future caller that renders a larger report).
pub fn render_report(report: &AggregatedReport) -> Result<String> {
    let mut out = String::new();
    out.push_str(&format!("host exposure entries: {}\n", report.total_lines));
    for line in &report.lines {
        let (pid, comm) = match &line.owner {
            ReportOwner::Known { pid, comm } => (pid.to_string(), comm.clone()),
            ReportOwner::Unknown => ("unknown".to_string(), "unknown".to_string()),
        };
        out.push_str(&format!(
            "{} {} {} {} {}\n",
            line.protocol, line.local, line.port, pid, comm
        ));
    }
    out.push_str(&format!("sockets listed: {}\n", report.sockets_listed));
    out.push_str(&format!(
        "sockets with unknown owner: {}\n",
        report.unknown_owners
    ));
    out.push_str(&format!("lines read: {}\n", report.lines_read));
    out.push_str(&format!(
        "unparsed socket lines: {}\n",
        report.unparsed_lines
    ));
    if out.len() > MAX_REPORT_BYTES {
        return Err(limits_error());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    /// A realistic TCP data line (17 fields), with the given
    /// local address, state, UID (field 8), field 9, and inode
    /// (field 10).
    fn tcp_line(local: &str, state: &str, uid: &str, field9: &str, inode: &str) -> String {
        format!(
            "   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 {uid} {field9} {inode} 1 0000000000000000 100 0 0 10 0"
        )
    }

    /// A realistic UDP data line (13 fields), with the given
    /// local address, state, UID (field 8), field 9, and inode
    /// (field 10).
    fn udp_line(local: &str, state: &str, uid: &str, field9: &str, inode: &str) -> String {
        format!(
            "   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 {uid} {field9} {inode} 1 0000000000000000 100"
        )
    }

    /// Parses `line` for `protocol` and returns the entry, failing
    /// the test if the line does not parse.
    fn must_parse(protocol: SocketProtocol, line: &str) -> SocketEntry {
        parse_proc_net_line(protocol, line).expect("test line must parse")
    }

    fn tcp_entry(local: &str, port: u16, inode: u64) -> SocketEntry {
        SocketEntry {
            protocol: SocketProtocol::Tcp,
            local: local.parse().expect("test address must parse"),
            port,
            inode,
        }
    }

    fn pair(inode: u64, pid: u32, comm: &str) -> OwnerPair {
        OwnerPair {
            inode,
            pid,
            comm: comm.to_string(),
        }
    }

    #[test]
    fn tcp_listen_entry_is_parsed() {
        let entry = must_parse(
            SocketProtocol::Tcp,
            &tcp_line("0100007F:0035", "0A", "0", "0", "123456"),
        );
        assert_eq!(entry.protocol, SocketProtocol::Tcp);
        assert_eq!(entry.local, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(entry.port, 53);
        assert_eq!(entry.inode, 123456);
    }

    #[test]
    fn tcp_non_listen_states_are_ignored() {
        for state in [
            "01", "02", "03", "04", "05", "06", "07", "08", "09", "0B", "0a",
        ] {
            let line = tcp_line("0100007F:0035", state, "0", "0", "123456");
            assert_eq!(
                parse_proc_net_line(SocketProtocol::Tcp, &line),
                None,
                "TCP state {state} must be unparsed"
            );
        }
    }

    #[test]
    fn udp_bound_entries_are_listed_whatever_the_state() {
        // UDP has no LISTEN state: any state value is accepted,
        // including 07 (the usual bound state) and 0A.
        for state in ["07", "0A", "01", "FF"] {
            let line = udp_line("00000000:0035", state, "0", "0", "654321");
            let entry =
                parse_proc_net_line(SocketProtocol::Udp, &line).expect("UDP line must parse");
            assert_eq!(entry.local, "0.0.0.0".parse::<IpAddr>().unwrap());
            assert_eq!(entry.port, 53);
            assert_eq!(entry.inode, 654321);
        }
    }

    #[test]
    fn ipv4_decodes_little_endian_and_renders_dotted_decimal() {
        // 127.0.0.1 is stored as 0100007F; 203.0.113.7 as
        // 070071CB; 0.0.0.0 as 00000000.
        let cases = [
            ("0100007F:0035", "127.0.0.1", 53),
            ("077100CB:1F90", "203.0.113.7", 8080),
            ("00000000:0000", "0.0.0.0", 0),
            ("FFFFFFFF:FFFF", "255.255.255.255", 65535),
        ];
        for (field, address, port) in cases {
            let line = tcp_line(field, "0A", "0", "0", "1");
            let entry = must_parse(SocketProtocol::Tcp, &line);
            assert_eq!(entry.local.to_string(), address);
            assert_eq!(entry.port, port);
        }
    }

    #[test]
    fn ipv6_decodes_four_little_endian_words() {
        // ::1 is stored as 00000000000000000000000001000000;
        // :: as all zeros.
        let line = tcp_line(
            "00000000000000000000000001000000:0035",
            "0A",
            "0",
            "0",
            "42",
        );
        let entry = must_parse(SocketProtocol::Tcp6, &line);
        assert_eq!(entry.local.to_string(), "::1");
        assert_eq!(entry.port, 53);
        let line = tcp_line(
            "00000000000000000000000000000000:1F90",
            "0A",
            "0",
            "0",
            "43",
        );
        let entry = must_parse(SocketProtocol::Tcp6, &line);
        assert_eq!(entry.local.to_string(), "::");
        assert_eq!(entry.port, 8080);
    }

    #[test]
    fn ipv4_mapped_ipv6_renders_as_ipv6() {
        // ::ffff:192.0.2.1: words 00000000 00000000 0000FFFF
        // 010200C0. Rendered as IPv6, with no special-casing.
        let line = tcp_line(
            "0000000000000000FFFF0000010200C0:0016",
            "0A",
            "0",
            "0",
            "77",
        );
        let entry = must_parse(SocketProtocol::Tcp6, &line);
        assert_eq!(entry.local.to_string(), "::ffff:192.0.2.1");
        assert_eq!(entry.port, 22);
    }

    #[test]
    fn leading_zero_hex_parses() {
        // Leading zeros in the IP and the port are fine: 1.0.0.0
        // is stored as 00000001, port 53 as 0035.
        let line = tcp_line("00000001:0035", "0A", "0", "0", "9");
        let entry = must_parse(SocketProtocol::Tcp, &line);
        assert_eq!(entry.local.to_string(), "1.0.0.0");
        assert_eq!(entry.port, 53);
    }

    #[test]
    fn bad_hex_address_is_unparsed() {
        let bad = [
            "0100007G:0035",    // non-hex digit in the IP
            "0100007:0035",     // 7 hex digits, not 8
            "0100007FF:0035",   // 9 hex digits, not 8
            "0100007F0035",     // no colon
            "0100007F:0035:00", // second colon
            ":0035",            // empty IP
            "0100007F:",        // empty port
            "0100007F:10000",   // port too large for u16
            "0100007F:ZZZZ",    // non-hex port
            "0100007F:+35",     // '+' is not a hex digit
        ];
        for field in bad {
            let line = tcp_line(field, "0A", "0", "0", "1");
            assert_eq!(
                parse_proc_net_line(SocketProtocol::Tcp, &line),
                None,
                "field {field} must be unparsed"
            );
        }
        // IPv6: 31 digits (not 32) and a non-hex digit.
        let line = tcp_line("0000000000000000000000001000000:0035", "0A", "0", "0", "1");
        assert_eq!(parse_proc_net_line(SocketProtocol::Tcp6, &line), None);
        let line = tcp_line("0000000000000000000000000100000G:0035", "0A", "0", "0", "1");
        assert_eq!(parse_proc_net_line(SocketProtocol::Tcp6, &line), None);
    }

    #[test]
    fn bad_inode_in_field_10_is_unparsed() {
        for inode in ["abc", "12a", "+123", "18446744073709551616"] {
            let line = tcp_line("0100007F:0035", "0A", "0", "0", inode);
            assert_eq!(
                parse_proc_net_line(SocketProtocol::Tcp, &line),
                None,
                "inode {inode:?} must be unparsed"
            );
        }
    }

    #[test]
    fn non_numeric_uid_in_field_8_still_parses() {
        // Field 8 (UID) is ignored entirely: a non-numeric UID
        // does not stop the line parsing.
        let line = tcp_line("0100007F:0035", "0A", "abc", "0", "123456");
        let entry = must_parse(SocketProtocol::Tcp, &line);
        assert_eq!(entry.inode, 123456);
    }

    #[test]
    fn field_9_is_never_used_as_the_inode() {
        // Field 9 holds a plausible inode value; the entry must
        // carry field 10, not field 9.
        let line = tcp_line("0100007F:0035", "0A", "0", "999999", "123456");
        let entry = must_parse(SocketProtocol::Tcp, &line);
        assert_eq!(entry.inode, 123456);
        // Field 10 bad while field 9 is a valid number: unparsed.
        let line = tcp_line("0100007F:0035", "0A", "0", "999999", "xyz");
        assert_eq!(parse_proc_net_line(SocketProtocol::Tcp, &line), None);
    }

    #[test]
    fn field_10_rule_is_pinned_uid_field9_inode_distinct() {
        // The dedicated field-10 case: UID (field 8), field 9, and
        // inode (field 10) hold distinct values, and the entry
        // carries the field-10 value — never the UID, never
        // field 9, never the field-12 kernel pointer.
        let line = "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 12345 99999 777777 1 0000000000000000 100 0 0 10 0";
        let entry = must_parse(SocketProtocol::Tcp, line);
        assert_eq!(entry.inode, 777777);
        assert_ne!(entry.inode, 12345);
        assert_ne!(entry.inode, 99999);
        assert_ne!(entry.inode, 0);
    }

    #[test]
    fn nine_field_line_is_unparsed() {
        // 9 fields: everything up to field 9, no inode.
        let line = "0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0";
        assert_eq!(parse_proc_net_line(SocketProtocol::Tcp, line), None);
    }

    #[test]
    fn too_few_fields_are_unparsed() {
        for line in [
            "",
            "   ",
            "0:",
            "0: 0100007F:0035",
            "0: 0100007F:0035 00000000:0000 0A",
        ] {
            assert_eq!(
                parse_proc_net_line(SocketProtocol::Tcp, line),
                None,
                "line {line:?} must be unparsed"
            );
        }
    }

    #[test]
    fn overlong_lines_follow_the_cap_rule() {
        let base = tcp_line("0100007F:0035", "0A", "0", "0", "123456");
        // Exactly MAX_PROC_NET_LINE_BYTES: a valid entry (the
        // padding is one trailing field, ignored).
        let mut at_cap = base.clone();
        at_cap.push(' ');
        at_cap.push_str(&"0".repeat(MAX_PROC_NET_LINE_BYTES - at_cap.len()));
        assert_eq!(at_cap.len(), MAX_PROC_NET_LINE_BYTES);
        assert_eq!(
            parse_proc_net_line(SocketProtocol::Tcp, &at_cap),
            Some(SocketEntry {
                protocol: SocketProtocol::Tcp,
                local: "127.0.0.1".parse().unwrap(),
                port: 53,
                inode: 123456,
            })
        );
        // One byte over the cap: never an entry.
        let mut over_cap = base.clone();
        over_cap.push(' ');
        over_cap.push_str(&"0".repeat(MAX_PROC_NET_LINE_BYTES + 1 - over_cap.len()));
        assert_eq!(over_cap.len(), MAX_PROC_NET_LINE_BYTES + 1);
        assert_eq!(parse_proc_net_line(SocketProtocol::Tcp, &over_cap), None);
    }

    #[test]
    fn empty_input_parses_to_nothing() {
        assert_eq!(parse_proc_net_line(SocketProtocol::Tcp, ""), None);
        assert_eq!(parse_proc_net_line(SocketProtocol::Udp, ""), None);
    }

    #[test]
    fn sanitiser_replaces_control_del_and_non_ascii() {
        assert_eq!(sanitise_comm("sshd"), "sshd");
        assert_eq!(sanitise_comm("a\x01b\x7fc"), "a?b?c");
        // ANSI escape: the ESC byte becomes '?'.
        assert_eq!(sanitise_comm("\x1b[31mfoo"), "?[31mfoo");
        // Non-ASCII is byte-wise: one '?' per byte.
        assert_eq!(sanitise_comm("café"), "caf??");
        // NUL and other control bytes.
        assert_eq!(sanitise_comm("a\x00b"), "a?b");
    }

    #[test]
    fn sanitiser_strips_one_trailing_newline_only() {
        assert_eq!(sanitise_comm("sshd\n"), "sshd");
        assert_eq!(sanitise_comm("sshd"), "sshd");
        // Two trailing newlines: one is stripped, the other is a
        // control byte and becomes '?'.
        assert_eq!(sanitise_comm("sshd\n\n"), "sshd?");
        assert_eq!(sanitise_comm("\n"), "");
        assert_eq!(sanitise_comm(""), "");
    }

    #[test]
    fn aggregate_orders_protocol_address_port_pid() {
        // Entries out of order on purpose: udp6, tcp, tcp6, udp.
        let entries = vec![
            SocketEntry {
                protocol: SocketProtocol::Udp6,
                local: "::1".parse().unwrap(),
                port: 53,
                inode: 4,
            },
            tcp_entry("127.0.0.1", 8080, 1),
            SocketEntry {
                protocol: SocketProtocol::Tcp6,
                local: "::1".parse().unwrap(),
                port: 80,
                inode: 3,
            },
            SocketEntry {
                protocol: SocketProtocol::Udp,
                local: "0.0.0.0".parse().unwrap(),
                port: 53,
                inode: 2,
            },
        ];
        let pairs = vec![
            pair(4, 40, "udp6d"),
            pair(1, 10, "httpd"),
            pair(3, 30, "tcp6d"),
            pair(2, 20, "udpd"),
        ];
        let report = aggregate(&entries, &pairs, &[], 4, 0).expect("must aggregate");
        assert_eq!(report.total_lines, 4);
        assert_eq!(report.sockets_listed, 4);
        assert_eq!(report.unknown_owners, 0);
        let rendered = render_report(&report).expect("must render");
        assert_eq!(
            rendered,
            "host exposure entries: 4\n\
             tcp 127.0.0.1 8080 10 httpd\n\
             tcp6 ::1 80 30 tcp6d\n\
             udp 0.0.0.0 53 20 udpd\n\
             udp6 ::1 53 40 udp6d\n\
             sockets listed: 4\n\
             sockets with unknown owner: 0\n\
             lines read: 4\n\
             unparsed socket lines: 0\n"
        );
    }

    #[test]
    fn aggregate_orders_address_port_and_pid_ties() {
        // Same protocol and address: the lower port sorts first.
        // Same address and port: the lower PID sorts first.
        let entries = vec![
            tcp_entry("10.0.0.2", 80, 2),
            tcp_entry("10.0.0.1", 443, 1),
            tcp_entry("10.0.0.1", 80, 3),
        ];
        let pairs = vec![
            pair(2, 22, "b"),
            pair(1, 11, "a"),
            pair(3, 33, "c"),
            pair(3, 31, "c"),
        ];
        let report = aggregate(&entries, &pairs, &[], 3, 0).expect("must aggregate");
        let rendered = render_report(&report).expect("must render");
        assert_eq!(
            rendered,
            "host exposure entries: 4\n\
             tcp 10.0.0.1 80 31 c\n\
             tcp 10.0.0.1 80 33 c\n\
             tcp 10.0.0.1 443 11 a\n\
             tcp 10.0.0.2 80 22 b\n\
             sockets listed: 3\n\
             sockets with unknown owner: 0\n\
             lines read: 3\n\
             unparsed socket lines: 0\n"
        );
    }

    #[test]
    fn unknown_owner_lines_sort_after_known_lines() {
        // Same protocol, address, and port: the known-owner line
        // sorts before the unknown-owner line.
        let entries = vec![tcp_entry("127.0.0.1", 80, 1), tcp_entry("127.0.0.1", 80, 2)];
        let pairs = vec![pair(1, 10, "httpd")];
        let report = aggregate(&entries, &pairs, &[2], 2, 0).expect("must aggregate");
        assert_eq!(report.total_lines, 2);
        assert_eq!(report.sockets_listed, 2);
        assert_eq!(report.unknown_owners, 1);
        let rendered = render_report(&report).expect("must render");
        assert_eq!(
            rendered,
            "host exposure entries: 2\n\
             tcp 127.0.0.1 80 10 httpd\n\
             tcp 127.0.0.1 80 unknown unknown\n\
             sockets listed: 2\n\
             sockets with unknown owner: 1\n\
             lines read: 2\n\
             unparsed socket lines: 0\n"
        );
    }

    #[test]
    fn duplicate_pair_counts_once_and_distinct_pids_count_separately() {
        let entries = vec![tcp_entry("127.0.0.1", 80, 1)];
        let pairs = vec![
            pair(1, 10, "httpd"),
            pair(1, 10, "httpd"),
            pair(1, 11, "httpd"),
        ];
        let report = aggregate(&entries, &pairs, &[], 1, 0).expect("must aggregate");
        assert_eq!(report.total_lines, 2);
        assert_eq!(report.sockets_listed, 1);
    }

    #[test]
    fn one_unknown_inode_contributes_exactly_one_line() {
        let entries = vec![tcp_entry("127.0.0.1", 80, 1), tcp_entry("127.0.0.1", 81, 2)];
        let report = aggregate(&entries, &[], &[1, 1, 2], 2, 0).expect("must aggregate");
        assert_eq!(report.total_lines, 2);
        assert_eq!(report.sockets_listed, 2);
        assert_eq!(report.unknown_owners, 2);
    }

    #[test]
    fn pairs_for_inodes_outside_the_kept_set_are_skipped() {
        let entries = vec![tcp_entry("127.0.0.1", 80, 1)];
        let pairs = vec![pair(99, 10, "ghost")];
        let report = aggregate(&entries, &pairs, &[99], 1, 0).expect("must aggregate");
        assert_eq!(report.total_lines, 0);
        assert_eq!(report.sockets_listed, 0);
        assert_eq!(report.unknown_owners, 0);
    }

    #[test]
    fn zero_entries_renders_header_plus_count_lines() {
        let report = aggregate(&[], &[], &[], 42, 3).expect("must aggregate");
        assert_eq!(report.total_lines, 0);
        let rendered = render_report(&report).expect("must render");
        assert_eq!(
            rendered,
            "host exposure entries: 0\n\
             sockets listed: 0\n\
             sockets with unknown owner: 0\n\
             lines read: 42\n\
             unparsed socket lines: 3\n"
        );
    }

    #[test]
    fn cap_plus_one_entry_returns_the_limits_error() {
        let entries: Vec<SocketEntry> = (0..MAX_SOCKET_ENTRIES + 1)
            .map(|i| tcp_entry("127.0.0.1", 80, i as u64 + 1))
            .collect();
        let err = aggregate(&entries, &[], &[], 0, 0).expect_err("must fail");
        assert_eq!(err.kind(), ErrorKind::Internal);
        assert_eq!(err.message(), "socket inventory exceeds limits");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn cap_plus_one_total_line_via_pairs_returns_the_limits_error() {
        // One entry held by 10,001 distinct processes: entries
        // stay under the cap, total lines trip it.
        let entries = vec![tcp_entry("127.0.0.1", 80, 1)];
        let pairs: Vec<OwnerPair> = (0..MAX_REPORT_LINES + 1)
            .map(|i| pair(1, i as u32 + 1, "httpd"))
            .collect();
        let err = aggregate(&entries, &pairs, &[], 1, 0).expect_err("must fail");
        assert_eq!(err.kind(), ErrorKind::Internal);
        assert_eq!(err.message(), "socket inventory exceeds limits");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn cap_plus_one_total_line_via_unknown_mix_returns_the_limits_error() {
        // The AC15 shape: 1 inode owned by 5,001 processes (5,001
        // pair lines) plus 5,000 unknown-owner inodes (5,000
        // unknown lines) — 5,001 entries, 10,001 total lines, so
        // only the total-lines cap trips.
        let mut entries = vec![tcp_entry("127.0.0.1", 80, 1)];
        entries.extend((0..5_000).map(|i| tcp_entry("127.0.0.1", 81, i as u64 + 2)));
        let pairs: Vec<OwnerPair> = (0..5_001).map(|i| pair(1, i as u32 + 1, "httpd")).collect();
        let unknown: Vec<u64> = (2..5_002).collect();
        let err = aggregate(&entries, &pairs, &unknown, 5_001, 0).expect_err("must fail");
        assert_eq!(err.message(), "socket inventory exceeds limits");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn mixed_boundary_of_exactly_10000_lines_is_accepted() {
        // 5,000 pair lines plus 5,000 unknown-owner lines:
        // exactly 10,000 total lines, exit path is Ok, and the
        // rendered report stays under 1 MiB.
        let mut entries = vec![tcp_entry("127.0.0.1", 80, 1)];
        entries.extend((0..5_000).map(|i| tcp_entry("127.0.0.1", 81, i as u64 + 2)));
        let pairs: Vec<OwnerPair> = (0..5_000).map(|i| pair(1, i as u32 + 1, "httpd")).collect();
        let unknown: Vec<u64> = (2..5_002).collect();
        let report = aggregate(&entries, &pairs, &unknown, 5_001, 0).expect("must aggregate");
        assert_eq!(report.total_lines, 10_000);
        assert_eq!(report.sockets_listed, 5_001);
        assert_eq!(report.unknown_owners, 5_000);
        let rendered = render_report(&report).expect("must render");
        assert!(rendered.len() < MAX_REPORT_BYTES);
    }

    #[test]
    fn render_over_1mib_returns_the_limits_error() {
        // The byte cap is enforced on the rendered output, not
        // merely derived: a report constructed with 15,000
        // maximum-length lines (~75 bytes each) exceeds 1 MiB.
        // Such a report cannot pass `aggregate` (10,000 lines
        // max), so it is constructed directly.
        let line = ReportLine {
            protocol: SocketProtocol::Tcp6,
            local: "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
            port: 65535,
            owner: ReportOwner::Known {
                pid: 9_999_999,
                comm: "a".repeat(15),
            },
        };
        let report = AggregatedReport {
            lines: vec![line; 15_000],
            total_lines: 15_000,
            sockets_listed: 15_000,
            unknown_owners: 0,
            lines_read: 15_000,
            unparsed_lines: 0,
        };
        let err = render_report(&report).expect_err("must fail");
        assert_eq!(err.kind(), ErrorKind::Internal);
        assert_eq!(err.message(), "socket inventory exceeds limits");
        assert_eq!(err.exit_code(), 1);
    }
}

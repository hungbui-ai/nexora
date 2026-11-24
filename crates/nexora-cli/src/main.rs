//! `nexora-cli` — Nexora command-line interface.
//!
//! Supports `--version` / `-V`, `--help` / `-h`, the TASK-005
//! subcommand `detect-ssh-brute-force --log <path>`, which prints a
//! read-only SSH brute-force detection report for an
//! operator-supplied log file, and the TASK-007 subcommand
//! `report-host-exposure`, which prints a read-only inventory of
//! listening TCP and bound UDP sockets with their owning processes.
//! Any other invocation prints an error and usage to stderr and
//! exits 2. Arguments are matched, never interpolated into a shell
//! string; no shell is invoked.
//!
//! Failure reporting follows the TASK-003 contract: `main` collects
//! the arguments and calls `run`, which parses them with the pure
//! function `parse` (no I/O) and then acts. Errors are reported
//! with `error: {err}` on stderr plus the usage line for usage
//! errors, and the numeric exit code from the error is translated
//! to `ExitCode` at the single exit point in `main`.
//!
//! The detection subcommand owns I/O and presentation only: it
//! opens and streams the file line by line (never loading the whole
//! file into memory), feeds each line to the `nexora-core`
//! [`BruteForceCounter`], and prints the exact report. All parsing
//! and aggregation live in `nexora-core`.
//!
//! The report subcommand owns I/O and presentation only: it streams
//! the four socket tables under a source root (production: `/proc`;
//! tests: a fixture root via the `NEXORA_TEST_PROC_ROOT`
//! environment variable — no CLI flag exposes the seam), scans the
//! process tree for socket owners, and prints the exact report the
//! core builds. All parsing, aggregation, and rendering live in
//! `nexora-core` (`exposure`).

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nexora_core::detection::{overlong_head_is_unparsed, MAX_LINE_BYTES};
use nexora_core::exposure::{
    build_report, parse_proc_net_line, sanitise_comm, OwnerPair, SocketEntry, SocketProtocol,
    MAX_FDS_EXAMINED, MAX_PROCESSES_SCANNED, MAX_PROC_NET_LINE_BYTES, MAX_SOCKET_ENTRIES,
    MAX_SOCKET_TABLE_LINES,
};
use nexora_core::{BruteForceCounter, Error, ErrorKind, Result};

const USAGE: &str =
    "Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>|report-host-exposure]";

/// The commands this CLI understands. Binary-private: parsing is
/// an internal detail, not a public contract.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Version,
    Help,
    DetectSshBruteForce { log_path: String },
    ReportHostExposure,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunFailure::Report(err)) => {
            report(&err);
            ExitCode::from(err.exit_code())
        }
        // Stdout could not be written (for example a broken pipe):
        // `Internal`, exit 1, with no message text (spec §Errors
        // names no text for this case, so none is invented —
        // implementation plan §4.3, §10 Q5, to be confirmed at
        // review).
        Err(RunFailure::StdoutWrite) => ExitCode::from(1),
    }
}

/// How `run` can fail: either with a reportable [`Error`] (usage
/// or internal, printed as `error: {err}`), or because the single
/// stdout write failed, which carries no message text.
enum RunFailure {
    Report(Error),
    StdoutWrite,
}

impl From<Error> for RunFailure {
    fn from(err: Error) -> Self {
        RunFailure::Report(err)
    }
}

fn run(args: &[String]) -> std::result::Result<(), RunFailure> {
    match parse(args)? {
        Command::Version => {
            println!("nexora-cli {}", nexora_core::VERSION);
        }
        Command::Help => {
            println!("{USAGE}");
        }
        Command::DetectSshBruteForce { log_path } => detect(&log_path)?,
        Command::ReportHostExposure => report_host_exposure()?,
    }
    Ok(())
}

/// Pure argument parsing: no I/O, so every argument case is
/// unit-testable without a subprocess.
fn parse(args: &[String]) -> Result<Command> {
    match args {
        [arg] if arg == "--version" || arg == "-V" => Ok(Command::Version),
        [arg] if arg == "--help" || arg == "-h" => Ok(Command::Help),
        [a, b, c] if a == "detect-ssh-brute-force" && b == "--log" => {
            Ok(Command::DetectSshBruteForce {
                log_path: c.clone(),
            })
        }
        [arg] if arg == "report-host-exposure" => Ok(Command::ReportHostExposure),
        _ => Err(Error::usage("invalid arguments")),
    }
}

/// Prints `error: {err}` to stderr; for a usage error, also prints
/// the usage line. Uses `Display` only, never `Debug`.
fn report(err: &Error) {
    eprintln!("error: {err}");
    if err.kind() == ErrorKind::Usage {
        eprintln!("{USAGE}");
    }
}

/// Runs the TASK-005 detection report for the log file at
/// `log_path`: streams the file, counts failed-password events per
/// source IPv4 address, and prints the exact report to stdout.
/// Nothing is printed unless the whole file was read successfully.
fn detect(log_path: &str) -> Result<()> {
    let file = File::open(log_path).map_err(|_| Error::internal("cannot read log file"))?;
    let mut reader = BufReader::new(file);
    let mut counter = BruteForceCounter::new();
    let mut lines_read: u64 = 0;
    loop {
        match read_line_capped(&mut reader, MAX_LINE_BYTES)
            .map_err(|_| Error::internal("cannot read log file"))?
        {
            ReadLine::Eof => break,
            ReadLine::Line(line) => {
                lines_read += 1;
                counter.add_line(&line);
            }
            ReadLine::Overlong { head } => {
                lines_read += 1;
                if overlong_head_is_unparsed(&head) {
                    counter.add_unparsed();
                }
            }
        }
    }
    let (findings, unparsed) = counter.finish();
    let mut out = String::new();
    out.push_str(&format!("ssh brute-force findings: {}\n", findings.len()));
    for finding in &findings {
        out.push_str(&format!(
            "{} {} failed password attempts\n",
            finding.source, finding.attempts
        ));
    }
    out.push_str(&format!("lines read: {lines_read}\n"));
    out.push_str(&format!("unparsed failed-password lines: {unparsed}\n"));
    print!("{out}");
    Ok(())
}

/// One line read from a file by [`read_line_capped`].
enum ReadLine {
    /// End of file: no more lines.
    Eof,
    /// A complete line: `\n` split, one trailing `\r` stripped,
    /// UTF-8 lossy decoded.
    Line(String),
    /// A line longer than the cap: the remainder was consumed and
    /// discarded. `head` is the first `max_bytes` bytes of the
    /// line; the caller decides what an over-long line means
    /// (TASK-005 checks the head for the failed-password marker;
    /// TASK-007 counts every over-long socket-table line as
    /// unparsed).
    Overlong { head: Vec<u8> },
}

/// Reads one line with a bounded buffer: at most `max_bytes` + 1
/// bytes are ever held for a line, so a single huge line cannot
/// exhaust memory. Returns [`ReadLine::Eof`] at end of file; a
/// trailing `\n` does not produce an extra empty line, and a final
/// line without `\n` still counts. The cap is a parameter because
/// the two callers cap different decisions: TASK-005's
/// [`MAX_LINE_BYTES`] (1 MiB) and TASK-007's
/// [`MAX_PROC_NET_LINE_BYTES`] (65,536 bytes) — silently reusing
/// one cap for the other is not allowed (plan §10 Q1).
fn read_line_capped<R: BufRead>(reader: &mut R, max_bytes: usize) -> std::io::Result<ReadLine> {
    let mut buf: Vec<u8> = Vec::new();
    let n = reader
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(ReadLine::Eof);
    }
    if buf.ends_with(b"\n") {
        buf.pop();
        return Ok(ReadLine::Line(decode(buf)));
    }
    if n < max_bytes + 1 {
        // End of file without a trailing newline: a complete line.
        return Ok(ReadLine::Line(decode(buf)));
    }
    // More than `max_bytes` bytes without a newline: over-long.
    // Keep the head for the caller; discard the rest.
    let head = buf[..max_bytes].to_vec();
    discard_until_newline(reader)?;
    Ok(ReadLine::Overlong { head })
}

/// Consumes input until (and including) the next `\n`, or end of
/// file, discarding it. Reads through the reader's internal buffer
/// only, so memory stays bounded.
fn discard_until_newline<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                reader.consume(pos + 1);
                return Ok(());
            }
            None => {
                let len = available.len();
                reader.consume(len);
            }
        }
    }
}

/// Decodes line bytes as UTF-8 lossy and strips a single trailing
/// `\r`, if present.
fn decode(mut bytes: Vec<u8>) -> String {
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The exact limits error (spec §Errors): exit 1, stderr
/// `error: socket inventory exceeds limits`, stdout empty, no
/// partial report.
fn limits_error() -> Error {
    Error::internal("socket inventory exceeds limits")
}

/// The source root the host-exposure report reads socket data
/// from. Production: `/proc`. The test seam (spec-mandated, plan
/// §4.6): when the `NEXORA_TEST_PROC_ROOT` environment variable is
/// set to a non-empty value, that directory is used instead, so
/// integration tests can point the binary at fixture trees. No CLI
/// flag exposes the seam, it is not documented in the usage text
/// or the README, and it is not an operator feature: it exists
/// only so tests can exercise the binary against fixture trees.
/// An empty or non-UTF-8 value is treated as unset.
fn source_root() -> PathBuf {
    match env::var("NEXORA_TEST_PROC_ROOT") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/proc"),
    }
}

/// Runs the TASK-007 host-exposure report: builds the exact
/// report from the source root and writes it to stdout exactly
/// once, only after the report was built successfully. Any error
/// before the write leaves stdout empty. A stdout write failure
/// (for example a broken pipe) is `Internal`, exit 1, with no
/// message text (plan §4.3, §10 Q5).
fn report_host_exposure() -> std::result::Result<(), RunFailure> {
    let report = build_host_exposure_report(&source_root())?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(report.as_bytes())
        .map_err(|_| RunFailure::StdoutWrite)?;
    handle.flush().map_err(|_| RunFailure::StdoutWrite)?;
    Ok(())
}

/// Builds the exact host-exposure report from the socket tables
/// and the process tree under `source_root` (production: `/proc`;
/// tests: a fixture root). Streams the four tables in the fixed
/// order `tcp`, `tcp6`, `udp`, `udp6`, skipping each file's header
/// line; scans owners; aggregates and renders through core. Caps
/// are enforced in pipeline order (plan §6.3): socket-table
/// lines, then entries; owner scan (processes, then fds);
/// aggregation (total report lines); rendering (bytes). Any cap
/// failure returns the limits error and nothing is printed.
fn build_host_exposure_report(source_root: &Path) -> Result<String> {
    let mut entries: Vec<SocketEntry> = Vec::new();
    let mut lines_read: u64 = 0;
    let mut unparsed_lines: u64 = 0;
    for (file, protocol) in [
        ("net/tcp", SocketProtocol::Tcp),
        ("net/tcp6", SocketProtocol::Tcp6),
        ("net/udp", SocketProtocol::Udp),
        ("net/udp6", SocketProtocol::Udp6),
    ] {
        let path = source_root.join(file);
        let file =
            File::open(&path).map_err(|_| Error::internal("cannot read socket inventory"))?;
        let mut reader = BufReader::new(file);
        // The first line of each file is a header line: always
        // skipped, never parsed, never counted — not a data line
        // and not an unparsed socket line, even if it is over-long
        // (the reader already consumed its remainder).
        match read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES)
            .map_err(|_| Error::internal("cannot read socket inventory"))?
        {
            ReadLine::Eof => continue,
            ReadLine::Line(_) | ReadLine::Overlong { .. } => {}
        }
        loop {
            match read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES)
                .map_err(|_| Error::internal("cannot read socket inventory"))?
            {
                ReadLine::Eof => break,
                ReadLine::Line(line) => {
                    lines_read += 1;
                    if lines_read > MAX_SOCKET_TABLE_LINES {
                        return Err(limits_error());
                    }
                    match parse_proc_net_line(protocol, &line) {
                        Some(entry) => {
                            entries.push(entry);
                            if entries.len() > MAX_SOCKET_ENTRIES {
                                return Err(limits_error());
                            }
                        }
                        None => unparsed_lines += 1,
                    }
                }
                ReadLine::Overlong { .. } => {
                    // A line longer than MAX_PROC_NET_LINE_BYTES is
                    // never an entry: it is counted as a data line
                    // and as an unparsed socket line.
                    lines_read += 1;
                    if lines_read > MAX_SOCKET_TABLE_LINES {
                        return Err(limits_error());
                    }
                    unparsed_lines += 1;
                }
            }
        }
    }
    let resolution = scan_owners(source_root, &entries)?;
    build_report(
        &entries,
        &resolution.pairs,
        &resolution.unknown,
        lines_read,
        unparsed_lines,
    )
}

/// The resolved owners of the kept socket entries.
struct OwnerResolution {
    /// Deduplicated owner pairs, in ascending `(inode, PID)` order.
    pairs: Vec<OwnerPair>,
    /// Kept inodes with no known owner.
    unknown: Vec<u64>,
}

/// Scans the process tree under `source_root` for the owners of
/// the kept socket entries (plan WP3). Visits processes in
/// ascending numeric PID order and each process's fds in ascending
/// numeric fd order, reading each fd symlink with `read_link`
/// only (never following it) and each owning PID's `comm` lazily
/// (cached per PID, including a failed read, so it is never
/// retried). Only PID and `comm` are ever read — never `cmdline`,
/// `environ`, `exe`, `cwd`, or `status`, and never a UID or
/// username. A process or fd that disappears, or that cannot be
/// read, makes its sockets `unknown`, never an error. Exceeding
/// `MAX_PROCESSES_SCANNED` or `MAX_FDS_EXAMINED` stops the scan
/// and returns the limits error.
fn scan_owners(source_root: &Path, entries: &[SocketEntry]) -> Result<OwnerResolution> {
    let kept: BTreeSet<u64> = entries.iter().map(|entry| entry.inode).collect();
    let mut pairs: BTreeSet<(u64, u32)> = BTreeSet::new();
    // PID -> sanitised comm, or `None` when the `comm` read
    // failed (cached so the failure is not retried per fd).
    let mut names: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let mut processes_scanned: usize = 0;
    let mut fds_examined: u64 = 0;

    let proc_dir =
        fs::read_dir(source_root).map_err(|_| Error::internal("cannot read socket inventory"))?;
    let mut pids: Vec<u32> = Vec::new();
    for dir_entry in proc_dir {
        let Ok(dir_entry) = dir_entry else {
            continue;
        };
        let name = dir_entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        pids.push(pid);
    }
    pids.sort_unstable();
    for pid in pids {
        processes_scanned += 1;
        if processes_scanned > MAX_PROCESSES_SCANNED {
            return Err(limits_error());
        }
        let pid_dir = source_root.join(pid.to_string());
        let fd_dir = match fs::read_dir(pid_dir.join("fd")) {
            Ok(dir) => dir,
            // Vanished or unreadable: its sockets are unknown.
            Err(_) => continue,
        };
        let mut fds: Vec<u32> = Vec::new();
        for dir_entry in fd_dir {
            let Ok(dir_entry) = dir_entry else {
                continue;
            };
            let name = dir_entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(fd) = name.parse::<u32>() else {
                continue;
            };
            fds.push(fd);
        }
        fds.sort_unstable();
        for fd in fds {
            fds_examined += 1;
            if fds_examined > MAX_FDS_EXAMINED {
                return Err(limits_error());
            }
            let target = match fs::read_link(pid_dir.join("fd").join(fd.to_string())) {
                Ok(target) => target,
                // The fd closed between listing and reading.
                Err(_) => continue,
            };
            let Some(inode) = socket_inode(&target) else {
                continue; // Not a socket.
            };
            if !kept.contains(&inode) {
                // Skip non-kept inodes early: the owner map is
                // bounded by the entry set.
                continue;
            }
            // Lazily read and cache this PID's sanitised comm.
            let comm = match names.get(&pid) {
                Some(cached) => cached.clone(),
                None => {
                    let comm = read_comm(source_root, pid).map(|raw| sanitise_comm(&raw));
                    names.insert(pid, comm.clone());
                    comm
                }
            };
            let Some(_comm) = comm else {
                // Unreadable comm: this socket's owner is unknown.
                continue;
            };
            pairs.insert((inode, pid));
        }
    }
    let mut owned: BTreeSet<u64> = BTreeSet::new();
    for (inode, _) in &pairs {
        owned.insert(*inode);
    }
    let unknown: Vec<u64> = kept.difference(&owned).copied().collect();
    let pairs: Vec<OwnerPair> = pairs
        .iter()
        .filter_map(|(inode, pid)| {
            names
                .get(pid)
                .and_then(|comm| comm.as_ref())
                .map(|comm| OwnerPair {
                    inode: *inode,
                    pid: *pid,
                    comm: comm.clone(),
                })
        })
        .collect();
    Ok(OwnerResolution { pairs, unknown })
}

/// Parses a `socket:[<inode>]` fd-symlink target into the inode.
/// Returns `None` for any other target (pipes, files, devices),
/// a malformed socket target, or a non-UTF-8 target. The match is
/// strict: the whole target must be `socket:[` + decimal digits
/// + `]`.
fn socket_inode(target: &Path) -> Option<u64> {
    let target = target.to_str()?;
    let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    inner.parse::<u64>().ok()
}

/// Reads `/proc/<pid>/comm` under `source_root` as bytes and
/// decodes it lossily. Returns `None` if the file cannot be read
/// (the process vanished, or permission was denied). Reads with
/// `fs::read`, never `read_to_string` on a `/proc` file (AC9).
/// The bytes are bounded by the kernel (`comm` is at most 15
/// characters plus a newline), so no cap is needed.
fn read_comm(source_root: &Path, pid: u32) -> Option<String> {
    let bytes = fs::read(source_root.join(pid.to_string()).join("comm")).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_flags() {
        assert!(matches!(
            parse(&["--version".to_string()]),
            Ok(Command::Version)
        ));
        assert!(matches!(parse(&["-V".to_string()]), Ok(Command::Version)));
    }

    #[test]
    fn parse_help_flags() {
        assert!(matches!(parse(&["--help".to_string()]), Ok(Command::Help)));
        assert!(matches!(parse(&["-h".to_string()]), Ok(Command::Help)));
    }

    #[test]
    fn parse_detect_accepted_form() {
        assert_eq!(
            parse(&[
                "detect-ssh-brute-force".to_string(),
                "--log".to_string(),
                "/var/log/auth.log".to_string(),
            ]),
            Ok(Command::DetectSshBruteForce {
                log_path: "/var/log/auth.log".to_string(),
            })
        );
    }

    #[test]
    fn parse_detect_path_is_verbatim() {
        // No flag parsing happens in path position: a flag-like
        // path is taken as the path.
        assert_eq!(
            parse(&[
                "detect-ssh-brute-force".to_string(),
                "--log".to_string(),
                "--help".to_string(),
            ]),
            Ok(Command::DetectSshBruteForce {
                log_path: "--help".to_string(),
            })
        );
    }

    #[test]
    fn parse_detect_missing_log_value_is_usage_error() {
        let err = parse(&["detect-ssh-brute-force".to_string(), "--log".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn parse_detect_extra_argument_is_usage_error() {
        let err = parse(&[
            "detect-ssh-brute-force".to_string(),
            "--log".to_string(),
            "a.log".to_string(),
            "extra".to_string(),
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
    }

    #[test]
    fn parse_detect_wrong_flag_is_usage_error() {
        let err = parse(&[
            "detect-ssh-brute-force".to_string(),
            "--file".to_string(),
            "a.log".to_string(),
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
    }

    #[test]
    fn parse_report_accepted_form() {
        assert_eq!(
            parse(&["report-host-exposure".to_string()]),
            Ok(Command::ReportHostExposure)
        );
    }

    #[test]
    fn parse_report_extra_argument_is_usage_error() {
        let err = parse(&["report-host-exposure".to_string(), "extra".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn parse_unknown_subcommand_is_usage_error() {
        let err = parse(&["watch".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
    }

    #[test]
    fn parse_no_arguments_is_usage_error() {
        let err = parse(&[]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn parse_one_invalid_argument_is_usage_error() {
        let err = parse(&["--bogus".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
    }

    #[test]
    fn parse_two_arguments_is_usage_error() {
        let err = parse(&["--version".to_string(), "--help".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "invalid arguments");
    }

    #[test]
    fn read_line_capped_splits_lines_and_counts_last_line() {
        let data = b"one\ntwo\nthree";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "one"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "two"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "three"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Eof)
        ));
    }

    #[test]
    fn read_line_capped_trailing_newline_creates_no_extra_line() {
        let data = b"one\n";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "one"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Eof)
        ));
    }

    #[test]
    fn read_line_capped_strips_one_trailing_cr() {
        let data = b"one\r\ntwo\r";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "one"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "two"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Eof)
        ));
    }

    #[test]
    fn read_line_capped_at_proc_net_cap_splits_and_strips_cr() {
        // Same splitting behaviour as the 1 MiB cap, at the
        // 65,536-byte cap: lines split, one trailing `\r` stripped,
        // the last line without a newline still counts, and a
        // trailing newline creates no extra line.
        let data = b"one\r\ntwo\nthree";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "one"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "two"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "three"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Eof)
        ));
    }

    #[test]
    fn read_line_capped_at_proc_net_cap_overlong_line_is_never_a_line() {
        let mut data = vec![b'x'; MAX_PROC_NET_LINE_BYTES + 1];
        data.extend(b"\nnext\n");
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Overlong { ref head }) if head.len() == MAX_PROC_NET_LINE_BYTES
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "next"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Eof)
        ));
    }

    #[test]
    fn read_line_capped_at_proc_net_cap_exact_cap_line_parses() {
        // A line of exactly 65,536 bytes plus a newline is a
        // complete line, not over-long.
        let mut data = vec![b'x'; MAX_PROC_NET_LINE_BYTES];
        data.extend(b"\nnext\n");
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s.len() == MAX_PROC_NET_LINE_BYTES
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_PROC_NET_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "next"
        ));
    }

    #[test]
    fn read_line_capped_empty_input_is_eof() {
        let data = b"";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Eof)
        ));
    }

    #[test]
    fn read_line_capped_overlong_line_is_never_a_line() {
        let mut data = b"Failed password for root from 203.0.113.7 port 22 ssh2".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES));
        data.extend(b"\nnext\n");
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Overlong { ref head }) if overlong_head_is_unparsed(head)
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "next"
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Eof)
        ));
    }

    #[test]
    fn read_line_capped_overlong_without_marker_is_not_unparsed() {
        let mut data = vec![b'x'; MAX_LINE_BYTES + 100];
        data.extend(b"\nnext\n");
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Overlong { ref head }) if !overlong_head_is_unparsed(head)
        ));
        assert!(matches!(
            read_line_capped(&mut reader, MAX_LINE_BYTES),
            Ok(ReadLine::Line(ref s)) if s == "next"
        ));
    }
}

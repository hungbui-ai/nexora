//! `nexora-cli` — Nexora command-line interface.
//!
//! Supports `--version` / `-V`, `--help` / `-h`, and the TASK-005
//! subcommand `detect-ssh-brute-force --log <path>`, which prints a
//! read-only SSH brute-force detection report for an
//! operator-supplied log file. Any other invocation prints an error
//! and usage to stderr and exits 2. Arguments are matched, never
//! interpolated into a shell string; no shell is invoked.
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

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::process::ExitCode;

use nexora_core::detection::{overlong_head_is_unparsed, MAX_LINE_BYTES};
use nexora_core::{BruteForceCounter, Error, ErrorKind, Result};

const USAGE: &str = "Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>]";

/// The commands this CLI understands. Binary-private: parsing is
/// an internal detail, not a public contract.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Version,
    Help,
    DetectSshBruteForce { log_path: String },
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report(&err);
            ExitCode::from(err.exit_code())
        }
    }
}

fn run(args: &[String]) -> Result<()> {
    match parse(args)? {
        Command::Version => {
            println!("nexora-cli {}", nexora_core::VERSION);
            Ok(())
        }
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::DetectSshBruteForce { log_path } => detect(&log_path),
    }
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
        match read_line_capped(&mut reader).map_err(|_| Error::internal("cannot read log file"))? {
            ReadLine::Eof => break,
            ReadLine::Line(line) => {
                lines_read += 1;
                counter.add_line(&line);
            }
            ReadLine::Overlong { unparsed } => {
                lines_read += 1;
                if unparsed {
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

/// One line read from the log file by [`read_line_capped`].
enum ReadLine {
    /// End of file: no more lines.
    Eof,
    /// A complete line: `\n` split, one trailing `\r` stripped,
    /// UTF-8 lossy decoded.
    Line(String),
    /// A line longer than [`MAX_LINE_BYTES`]: the remainder was
    /// consumed and discarded. `unparsed` is true when the head of
    /// the line contains the failed-password marker.
    Overlong { unparsed: bool },
}

/// Reads one line with a bounded buffer: at most
/// [`MAX_LINE_BYTES`] + 1 bytes are ever held for a line, so a
/// single huge line cannot exhaust memory. Returns [`ReadLine::Eof`]
/// at end of file; a trailing `\n` does not produce an extra empty
/// line, and a final line without `\n` still counts.
fn read_line_capped<R: BufRead>(reader: &mut R) -> std::io::Result<ReadLine> {
    let mut buf: Vec<u8> = Vec::new();
    let n = reader
        .by_ref()
        .take((MAX_LINE_BYTES + 1) as u64)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(ReadLine::Eof);
    }
    if buf.ends_with(b"\n") {
        buf.pop();
        return Ok(ReadLine::Line(decode(buf)));
    }
    if n < MAX_LINE_BYTES + 1 {
        // End of file without a trailing newline: a complete line.
        return Ok(ReadLine::Line(decode(buf)));
    }
    // More than MAX_LINE_BYTES bytes without a newline: over-long.
    // The head decides unparsedness; discard the rest.
    let unparsed = overlong_head_is_unparsed(&buf[..MAX_LINE_BYTES]);
    discard_until_newline(reader)?;
    Ok(ReadLine::Overlong { unparsed })
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
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "one"
        ));
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "two"
        ));
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "three"
        ));
        assert!(matches!(read_line_capped(&mut reader), Ok(ReadLine::Eof)));
    }

    #[test]
    fn read_line_capped_trailing_newline_creates_no_extra_line() {
        let data = b"one\n";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "one"
        ));
        assert!(matches!(read_line_capped(&mut reader), Ok(ReadLine::Eof)));
    }

    #[test]
    fn read_line_capped_strips_one_trailing_cr() {
        let data = b"one\r\ntwo\r";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "one"
        ));
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "two"
        ));
        assert!(matches!(read_line_capped(&mut reader), Ok(ReadLine::Eof)));
    }

    #[test]
    fn read_line_capped_empty_input_is_eof() {
        let data = b"";
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(read_line_capped(&mut reader), Ok(ReadLine::Eof)));
    }

    #[test]
    fn read_line_capped_overlong_line_is_never_a_line() {
        let mut data = b"Failed password for root from 203.0.113.7 port 22 ssh2".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES));
        data.extend(b"\nnext\n");
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Overlong { unparsed: true })
        ));
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "next"
        ));
        assert!(matches!(read_line_capped(&mut reader), Ok(ReadLine::Eof)));
    }

    #[test]
    fn read_line_capped_overlong_without_marker_is_not_unparsed() {
        let mut data = vec![b'x'; MAX_LINE_BYTES + 100];
        data.extend(b"\nnext\n");
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Overlong { unparsed: false })
        ));
        assert!(matches!(
            read_line_capped(&mut reader),
            Ok(ReadLine::Line(ref s)) if s == "next"
        ));
    }
}

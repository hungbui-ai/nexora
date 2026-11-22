//! `nexora-cli` — Nexora command-line interface.
//!
//! Bootstrap scope only: supports `--version` / `-V` and `--help` /
//! `-h`. Any other invocation prints an error and usage to stderr
//! and exits 2. No other command is implemented. Arguments are
//! matched, never interpolated into a shell string; no shell is
//! invoked.
//!
//! Failure reporting follows the TASK-003 contract: `main` collects
//! the arguments and calls `run`, which parses them with the pure
//! function `parse` (no I/O) and then prints. Errors are reported
//! with `error: {err}` on stderr plus the usage line, and the
//! numeric exit code from the error is translated to `ExitCode` at
//! the single exit point in `main`.

use std::env;
use std::process::ExitCode;

use nexora_core::{Error, ErrorKind, Result};

const USAGE: &str = "Usage: nexora-cli [--version|--help]";

/// The one command this bootstrap CLI understands. Binary-private:
/// parsing is an internal detail, not a public contract.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Version,
    Help,
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
    }
}

/// Pure argument parsing: no I/O, so every argument case is
/// unit-testable without a subprocess.
fn parse(args: &[String]) -> Result<Command> {
    match args {
        [arg] if arg == "--version" || arg == "-V" => Ok(Command::Version),
        [arg] if arg == "--help" || arg == "-h" => Ok(Command::Help),
        _ => Err(Error::usage("expected exactly one of --version or --help")),
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
    fn parse_no_arguments_is_usage_error() {
        let err = parse(&[]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "expected exactly one of --version or --help");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn parse_one_invalid_argument_is_usage_error() {
        let err = parse(&["--bogus".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "expected exactly one of --version or --help");
    }

    #[test]
    fn parse_two_arguments_is_usage_error() {
        let err = parse(&["--version".to_string(), "--help".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "expected exactly one of --version or --help");
    }
}

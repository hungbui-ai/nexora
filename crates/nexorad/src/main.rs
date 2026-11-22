//! `nexorad` — Nexora daemon binary.
//!
//! Bootstrap scope only: prints the core identifier and states that
//! the daemon is not started in this build, then exits. It starts no
//! daemon, binds no socket, opens no file, and performs no security
//! function.
//!
//! Failure reporting follows the TASK-003 contract: `main` collects
//! the arguments and calls `run`, which parses them with the pure
//! function `parse` (no I/O) and then prints. Any argument is a
//! usage error (exit 2) — a deliberate change versus TASK-001,
//! which silently ignored arguments. Errors are reported with
//! `error: {err}` on stderr, and the numeric exit code from the
//! error is translated to `ExitCode` at the single exit point in
//! `main`. The daemon defines no usage text, so no usage line is
//! printed on error.

use std::env;
use std::process::ExitCode;

use nexora_core::{Error, Result};

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
    parse(args)?;
    println!("{}", nexora_core::identifier());
    println!("nexorad does not start a daemon in this build.");
    Ok(())
}

/// Pure argument parsing: no I/O, so every argument case is
/// unit-testable without a subprocess. Any argument is a usage
/// error; only the empty argument list is accepted.
fn parse(args: &[String]) -> Result<()> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(Error::usage("expected no arguments"))
    }
}

/// Prints `error: {err}` to stderr. Uses `Display` only, never
/// `Debug`. The daemon defines no usage text.
fn report(err: &Error) {
    eprintln!("error: {err}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexora_core::ErrorKind;

    #[test]
    fn parse_no_arguments_ok() {
        assert_eq!(parse(&[]), Ok(()));
    }

    #[test]
    fn parse_any_argument_is_usage_error() {
        let err = parse(&["--bogus".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "expected no arguments");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn parse_two_arguments_is_usage_error() {
        let err = parse(&["a".to_string(), "b".to_string()]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "expected no arguments");
    }
}

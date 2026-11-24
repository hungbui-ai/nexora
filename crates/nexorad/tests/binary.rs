//! Integration tests for the `nexorad` binary (TASK-003).
//!
//! These tests run the actual compiled binary as a subprocess and
//! assert its exact stdout, stderr, and exit code — the behaviour
//! the approved TASK-003 specification describes, including the
//! deliberate change (OD7) that any argument is a usage error
//! instead of being silently ignored. They complement the unit
//! tests for the pure `parse()` function in `src/main.rs`, which
//! perform no I/O.

use std::process::{Command, Output};

const EXPECTED_OUTPUT: &str = "nexora-core 0.1.0\n\
                                nexorad does not start a daemon in this build.\n";

fn run(args: &[&str]) -> Output {
    // The second of the two permitted lint suppressions in the
    // workspace (implementation plan §8.6, clippy.toml branch A,
    // D-007-09 amendment): this statement spawns the binary under
    // test. Statement scope only; it covers the `Command::new`
    // and `.output()` calls in this statement — the two
    // pre-existing TASK-003 calls — and nothing else. The helper
    // is in let-form so the allow has a statement to attach to;
    // the tests, the binary under test, and every assertion are
    // unchanged.
    #[allow(clippy::disallowed_methods)]
    let output = Command::new(env!("CARGO_BIN_EXE_nexorad"))
        .args(args)
        .output()
        .expect("failed to run nexorad binary");
    output
}

fn assert_output(output: &Output, stdout: &str, stderr: &str, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
    assert_eq!(String::from_utf8_lossy(&output.stderr), stderr);
}

#[test]
fn no_arguments_prints_identifier_and_exits_zero() {
    assert_output(&run(&[]), EXPECTED_OUTPUT, "", 0);
}

#[test]
fn one_argument_is_usage_error() {
    assert_output(&run(&["--bogus"]), "", "error: expected no arguments\n", 2);
}

#[test]
fn two_arguments_is_usage_error() {
    assert_output(&run(&["a", "b"]), "", "error: expected no arguments\n", 2);
}

//! Integration tests for the `nexora-cli` binary (TASK-003).
//!
//! These tests run the actual compiled binary as a subprocess and
//! assert its exact stdout, stderr, and exit code — the behaviour
//! the approved TASK-003 specification describes. They complement
//! the unit tests for the pure `parse()` function in `src/main.rs`,
//! which perform no I/O.

use std::process::{Command, Output};

const EXPECTED_ERROR: &str = "error: expected exactly one of --version or --help\n\
                               Usage: nexora-cli [--version|--help]\n";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nexora-cli"))
        .args(args)
        .output()
        .expect("failed to run nexora-cli binary")
}

fn assert_output(output: &Output, stdout: &str, stderr: &str, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
    assert_eq!(String::from_utf8_lossy(&output.stderr), stderr);
}

#[test]
fn version_long_flag() {
    assert_output(&run(&["--version"]), "nexora-cli 0.1.0\n", "", 0);
}

#[test]
fn version_short_flag() {
    assert_output(&run(&["-V"]), "nexora-cli 0.1.0\n", "", 0);
}

#[test]
fn help_long_flag() {
    assert_output(
        &run(&["--help"]),
        "Usage: nexora-cli [--version|--help]\n",
        "",
        0,
    );
}

#[test]
fn help_short_flag() {
    assert_output(
        &run(&["-h"]),
        "Usage: nexora-cli [--version|--help]\n",
        "",
        0,
    );
}

#[test]
fn no_arguments_is_usage_error() {
    assert_output(&run(&[]), "", EXPECTED_ERROR, 2);
}

#[test]
fn invalid_argument_is_usage_error() {
    assert_output(&run(&["--bogus"]), "", EXPECTED_ERROR, 2);
}

#[test]
fn multiple_arguments_is_usage_error() {
    assert_output(&run(&["--version", "--help"]), "", EXPECTED_ERROR, 2);
}

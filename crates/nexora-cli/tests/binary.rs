//! Integration tests for the `nexora-cli` binary (TASK-003, TASK-005).
//!
//! These tests run the actual compiled binary as a subprocess and
//! assert its exact stdout, stderr, and exit code — the behaviour
//! the approved TASK-003 and TASK-005 specifications describe. They
//! complement the unit tests for the pure `parse()` function in
//! `src/main.rs`, which perform no I/O, and the parser unit tests
//! in `nexora-core`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

const EXPECTED_ERROR: &str = "error: invalid arguments\n\
                               Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>]\n";

const EXPECTED_READ_ERROR: &str = "error: cannot read log file\n";

const MAX_LINE_BYTES: usize = 1_048_576;

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

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn detect(fixture_name: &str) -> Output {
    let path = fixture(fixture_name);
    run(&["detect-ssh-brute-force", "--log", &path])
}

/// A fresh temporary directory unique to this test process.
/// Removed by the caller when the test is done.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nexora-task-005-{}-{}", tag, std::process::id()));
    fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
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
        "Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>]\n",
        "",
        0,
    );
}

#[test]
fn help_short_flag() {
    assert_output(
        &run(&["-h"]),
        "Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>]\n",
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

#[test]
fn detect_missing_log_value_is_usage_error() {
    assert_output(
        &run(&["detect-ssh-brute-force", "--log"]),
        "",
        EXPECTED_ERROR,
        2,
    );
}

#[test]
fn detect_extra_argument_is_usage_error() {
    let path = fixture("ssh-mixed.log");
    assert_output(
        &run(&["detect-ssh-brute-force", "--log", &path, "extra"]),
        "",
        EXPECTED_ERROR,
        2,
    );
}

#[test]
fn detect_unknown_subcommand_is_usage_error() {
    assert_output(&run(&["watch", "--log", "a.log"]), "", EXPECTED_ERROR, 2);
}

#[test]
fn detect_mixed_fixture_exact_report() {
    assert_output(
        &detect("ssh-mixed.log"),
        "ssh brute-force findings: 0\n\
         lines read: 7\n\
         unparsed failed-password lines: 1\n",
        "",
        0,
    );
}

#[test]
fn detect_threshold_order_fixture_exact_report() {
    assert_output(
        &detect("ssh-threshold-order.log"),
        "ssh brute-force findings: 4\n\
         10.0.0.4 12 failed password attempts\n\
         10.0.0.3 6 failed password attempts\n\
         10.0.0.5 6 failed password attempts\n\
         10.0.0.2 5 failed password attempts\n\
         lines read: 33\n\
         unparsed failed-password lines: 0\n",
        "",
        0,
    );
}

#[test]
fn detect_no_findings_fixture_exact_report() {
    assert_output(
        &detect("ssh-no-findings.log"),
        "ssh brute-force findings: 0\n\
         lines read: 4\n\
         unparsed failed-password lines: 0\n",
        "",
        0,
    );
}

#[test]
fn detect_empty_file_exact_report() {
    assert_output(
        &detect("ssh-empty.log"),
        "ssh brute-force findings: 0\n\
         lines read: 0\n\
         unparsed failed-password lines: 0\n",
        "",
        0,
    );
}

#[test]
fn detect_unparsed_fixture_exact_report() {
    assert_output(
        &detect("ssh-unparsed.log"),
        "ssh brute-force findings: 0\n\
         lines read: 4\n\
         unparsed failed-password lines: 4\n",
        "",
        0,
    );
}

#[test]
fn detect_adversarial_fixture_exact_report() {
    assert_output(
        &detect("ssh-adversarial.log"),
        "ssh brute-force findings: 0\n\
         lines read: 7\n\
         unparsed failed-password lines: 4\n",
        "",
        0,
    );
}

#[test]
fn detect_missing_file_is_internal_error() {
    assert_output(
        &run(&[
            "detect-ssh-brute-force",
            "--log",
            "/nonexistent/nexora-task-005-missing.log",
        ]),
        "",
        EXPECTED_READ_ERROR,
        1,
    );
}

#[test]
fn detect_directory_is_internal_error() {
    let dir = temp_dir("directory");
    assert_output(
        &run(&[
            "detect-ssh-brute-force",
            "--log",
            dir.to_str().expect("temp dir must be UTF-8"),
        ]),
        "",
        EXPECTED_READ_ERROR,
        1,
    );
    fs::remove_dir_all(&dir).expect("failed to remove temp dir");
}

#[test]
fn detect_unreadable_file_is_internal_error() {
    // Skipped where the test user can still open a mode-000 file
    // (for example when running as root).
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("unreadable");
    let path = dir.join("no-read.log");
    fs::write(
        &path,
        "Failed password for root from 203.0.113.7 port 22 ssh2\n",
    )
    .expect("failed to write temp file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
        .expect("failed to chmod temp file");
    if fs::File::open(&path).is_ok() {
        // The file is still readable: running as root (or with an
        // equivalent override). Restore permissions, clean up, skip.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("failed to restore temp file permissions");
        fs::remove_dir_all(&dir).expect("failed to remove temp dir");
        return;
    }
    assert_output(
        &run(&[
            "detect-ssh-brute-force",
            "--log",
            path.to_str().expect("temp path must be UTF-8"),
        ]),
        "",
        EXPECTED_READ_ERROR,
        1,
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("failed to restore temp file permissions");
    fs::remove_dir_all(&dir).expect("failed to remove temp dir");
}

#[test]
fn detect_file_without_trailing_newline_counts_last_line() {
    let dir = temp_dir("no-trailing-newline");
    let path = dir.join("five.log");
    let mut content = String::new();
    for _ in 0..5 {
        content.push_str("Failed password for root from 203.0.113.7 port 22 ssh2\n");
    }
    content.pop(); // remove the final newline: last line has none
    fs::write(&path, content).expect("failed to write temp file");
    assert_output(
        &run(&[
            "detect-ssh-brute-force",
            "--log",
            path.to_str().expect("temp path must be UTF-8"),
        ]),
        "ssh brute-force findings: 1\n\
         203.0.113.7 5 failed password attempts\n\
         lines read: 5\n\
         unparsed failed-password lines: 0\n",
        "",
        0,
    );
    fs::remove_dir_all(&dir).expect("failed to remove temp dir");
}

#[test]
fn detect_overlong_lines_generated_at_runtime() {
    let dir = temp_dir("overlong");
    let path = dir.join("overlong.log");
    let mut content: Vec<u8> = Vec::new();
    // Line 1: a valid event at the start of an over-long line:
    // never an event; the marker in the head makes it unparsed.
    content.extend(b"Failed password for root from 203.0.113.7 port 22 ssh2");
    content.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES));
    content.push(b'\n');
    // Line 2: the marker lies beyond the 1 MiB cap: ignored.
    content.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES + 100));
    content.extend(b"Failed password for root from 203.0.113.7 port 22 ssh2\n");
    fs::write(&path, content).expect("failed to write temp file");
    assert_output(
        &run(&[
            "detect-ssh-brute-force",
            "--log",
            path.to_str().expect("temp path must be UTF-8"),
        ]),
        "ssh brute-force findings: 0\n\
         lines read: 2\n\
         unparsed failed-password lines: 1\n",
        "",
        0,
    );
    fs::remove_dir_all(&dir).expect("failed to remove temp dir");
}

#[test]
fn detect_hundred_thousand_line_file_streams() {
    let dir = temp_dir("streaming");
    let path = dir.join("large.log");
    let event = b"Failed password for root from 203.0.113.7 port 22 ssh2\n";
    let unrelated = b"Nov 22 10:00:00 myhost sshd[1234]: Server listening on 0.0.0.0 port 22.\n";
    let file = fs::File::create(&path).expect("failed to create temp file");
    let mut writer = std::io::BufWriter::new(file);
    for _ in 0..60_000 {
        writer.write_all(event).expect("failed to write temp file");
    }
    for _ in 0..40_000 {
        writer
            .write_all(unrelated)
            .expect("failed to write temp file");
    }
    writer.flush().expect("failed to flush temp file");
    drop(writer);
    assert_output(
        &run(&[
            "detect-ssh-brute-force",
            "--log",
            path.to_str().expect("temp path must be UTF-8"),
        ]),
        "ssh brute-force findings: 1\n\
         203.0.113.7 60000 failed password attempts\n\
         lines read: 100000\n\
         unparsed failed-password lines: 0\n",
        "",
        0,
    );
    fs::remove_dir_all(&dir).expect("failed to remove temp dir");
}

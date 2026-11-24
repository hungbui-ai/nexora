//! Integration tests for the `nexora-cli` binary (TASK-003, TASK-005,
//! TASK-007).
//!
//! These tests run the actual compiled binary as a subprocess and
//! assert its exact stdout, stderr, and exit code — the behaviour
//! the approved TASK-003 and TASK-005 specifications describe. They
//! complement the unit tests for the pure `parse()` function in
//! `src/main.rs`, which perform no I/O, and the parser unit tests
//! in `nexora-core`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EXPECTED_ERROR: &str = "error: invalid arguments\n\
                               Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>|report-host-exposure]\n";

const EXPECTED_LIMITS_ERROR: &str = "error: socket inventory exceeds limits\n";

const EXPECTED_INVENTORY_READ_ERROR: &str = "error: cannot read socket inventory\n";

const EXPECTED_READ_ERROR: &str = "error: cannot read log file\n";

const MAX_LINE_BYTES: usize = 1_048_576;

/// Runs the binary under test with the given arguments (the single
/// spawn site in this file).
fn run(args: &[&str]) -> Output {
    run_with(args, None, None)
}

/// Runs the binary under test, pointing its source-root seam at
/// `proc_root` when given (tests for `report-host-exposure` pass a
/// fixture root; all other tests pass `None`, which the binary
/// treats as `/proc`) and running it in `cwd` when given (the AC9
/// empty-temp-dir run passes its empty directory; all other tests
/// pass `None`, which leaves the working directory unchanged).
/// An empty `proc_root` is treated as unset by the binary.
fn run_with(args: &[&str], proc_root: Option<&Path>, cwd: Option<&Path>) -> Output {
    // The first of the two permitted lint suppressions in the
    // workspace (implementation plan §8.6, clippy.toml branch A):
    // this statement spawns the binary under test. Statement scope
    // only; it covers the `Command::new` and `.output()` calls in
    // this statement and nothing else. The second permitted
    // suppression is the pre-existing TASK-003 spawn site in
    // `crates/nexorad/tests/binary.rs` (D-007-09 amendment).
    #[allow(clippy::disallowed_methods)]
    let output = Command::new(env!("CARGO_BIN_EXE_nexora-cli"))
        .args(args)
        .env("NEXORA_TEST_PROC_ROOT", proc_root.unwrap_or(Path::new("")))
        .current_dir(cwd.unwrap_or(Path::new(".")))
        .output()
        .expect("failed to run nexora-cli binary");
    output
}

/// Runs `report-host-exposure` against the fixture root at
/// `root`.
fn report(root: &Path) -> Output {
    run_with(&["report-host-exposure"], Some(root), None)
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

/// A fresh temporary directory for a TASK-007 fixture root, unique
/// per call (a counter, so parallel tests never share one). Removed
/// when the guard drops, even if the test fails — a test that leaves
/// a 100,001-fd tree behind is a defect (plan §8.6).
struct TempDir007(PathBuf);

static TEMP_007_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl TempDir007 {
    fn new(tag: &str) -> Self {
        let n = TEMP_007_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "nexora-task-007-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        TempDir007(dir)
    }
}

impl Drop for TempDir007 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Copies the committed `net/` directory of a fixture into a fresh
/// temp root and returns the guarded root.
fn fixture_root(name: &str) -> TempDir007 {
    let guard = TempDir007::new(name);
    let src = PathBuf::from(format!(
        "{}/tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ));
    let dst = guard.0.join("net");
    fs::create_dir_all(&dst).expect("failed to create fixture net dir");
    for file in ["tcp", "tcp6", "udp", "udp6"] {
        fs::copy(src.join("net").join(file), dst.join(file)).expect("failed to copy fixture file");
    }
    guard
}

/// Adds a process to a fixture root: `<root>/<pid>/fd/<fd>`
/// symlinks to `socket:[<inode>]` and a `<root>/<pid>/comm` file
/// with the given bytes (the comm file's trailing newline is part
/// of the fixture, as the kernel writes it).
fn add_process(root: &Path, pid: u32, comm: &[u8], fds: &[(u32, u64)]) {
    let pid_dir = root.join(pid.to_string());
    let fd_dir = pid_dir.join("fd");
    fs::create_dir_all(&fd_dir).expect("failed to create fixture fd dir");
    fs::write(pid_dir.join("comm"), comm).expect("failed to write fixture comm");
    for (fd, inode) in fds {
        symlink(format!("socket:[{inode}]"), fd_dir.join(fd.to_string()))
            .expect("failed to create fixture fd symlink");
    }
}

/// Writes one socket-table file (`net/<name>`) under a fixture
/// root. The first line is a header (the CLI skips it); the data
/// lines follow.
fn write_table(root: &Path, name: &str, data_lines: &[String]) {
    let net_dir = root.join("net");
    fs::create_dir_all(&net_dir).expect("failed to create fixture net dir");
    let mut content = String::from(TABLE_HEADER);
    for line in data_lines {
        content.push_str(line);
        content.push('\n');
    }
    fs::write(net_dir.join(name), content).expect("failed to write fixture table");
}

/// One TCP LISTEN data line for a runtime table: local address
/// (dotted decimal), port, UID (field 8), field 9, inode (field 10).
/// The hex encoding is computed from the address, never hand-typed.
fn tcp_listen_line(local: &str, port: u16, uid: u32, field9: u32, inode: u64) -> String {
    let octets: Vec<u8> = local
        .split('.')
        .map(|o| o.parse().expect("test address must parse"))
        .collect();
    let hex: String = octets.iter().rev().map(|b| format!("{b:02X}")).collect();
    format!(
        "   0: {hex}:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid} {field9} {inode} 1 0000000000000000 100 0 0 10 0"
    )
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
        "Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>|report-host-exposure]\n",
        "",
        0,
    );
}

#[test]
fn help_short_flag() {
    assert_output(
        &run(&["-h"]),
        "Usage: nexora-cli [--version|--help|detect-ssh-brute-force --log <path>|report-host-exposure]\n",
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

// ---------------------------------------------------------------------------
// TASK-007: host-exposure inventory report (`report-host-exposure`).
// Every test asserts the full exact stdout, not a substring.
// ---------------------------------------------------------------------------

/// The header line written at the top of every runtime socket-table
/// file (the CLI skips it).
const TABLE_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

/// Writes header-only tables for tcp6, udp, and udp6 (the files a
/// runtime-table test does not populate).
fn empty_tables(root: &Path) {
    for name in ["tcp6", "udp", "udp6"] {
        write_table(root, name, &[]);
    }
}

#[test]
fn report_accepted_form_empty_fixture_exact_report() {
    let root = fixture_root("proc-net-empty");
    assert_output(
        &report(&root.0),
        "host exposure entries: 0\n\
         sockets listed: 0\n\
         sockets with unknown owner: 0\n\
         lines read: 0\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_mixed_fixture_exact_report() {
    let root = fixture_root("proc-net-mixed");
    add_process(
        &root.0,
        100,
        b"nginx\n",
        &[(3, 100001), (4, 100002), (5, 100005)],
    );
    add_process(&root.0, 200, b"sshd\n", &[(3, 100002)]);
    add_process(&root.0, 300, b"myapp\n", &[(3, 100004)]);
    add_process(&root.0, 400, b"named\n", &[(3, 100007), (4, 100009)]);
    // PID 500 owns the non-LISTEN socket (inode 100003): it must
    // not appear in the report.
    add_process(&root.0, 500, b"ignored\n", &[(3, 100003)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 9\n\
         tcp 0.0.0.0 22 100 nginx\n\
         tcp 0.0.0.0 22 200 sshd\n\
         tcp 127.0.0.1 8080 100 nginx\n\
         tcp 203.0.113.7 8443 300 myapp\n\
         tcp6 :: 80 100 nginx\n\
         tcp6 ::1 8080 unknown unknown\n\
         udp 0.0.0.0 53 400 named\n\
         udp 127.0.0.1 123 unknown unknown\n\
         udp6 :: 53 400 named\n\
         sockets listed: 8\n\
         sockets with unknown owner: 2\n\
         lines read: 9\n\
         unparsed socket lines: 1\n",
        "",
        0,
    );
}

#[test]
fn report_order_fixture_exact_report() {
    let root = fixture_root("proc-net-order");
    add_process(&root.0, 100, b"a100\n", &[(3, 200001)]);
    add_process(&root.0, 300, b"a300\n", &[(3, 200001)]);
    add_process(&root.0, 150, b"b150\n", &[(3, 200002)]);
    add_process(&root.0, 120, b"c120\n", &[(3, 200003)]);
    add_process(&root.0, 110, b"d110\n", &[(3, 200004)]);
    add_process(&root.0, 130, b"e130\n", &[(3, 200005)]);
    add_process(&root.0, 140, b"f140\n", &[(3, 200006)]);
    add_process(&root.0, 160, b"g160\n", &[(3, 200007)]);
    add_process(&root.0, 170, b"h170\n", &[(3, 200008)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 9\n\
         tcp 10.0.0.1 80 100 a100\n\
         tcp 10.0.0.1 80 300 a300\n\
         tcp 10.0.0.1 443 150 b150\n\
         tcp 10.0.0.2 80 120 c120\n\
         tcp6 ::1 80 110 d110\n\
         tcp6 2001:db8::1 80 130 e130\n\
         udp 0.0.0.0 53 140 f140\n\
         udp 0.0.0.0 123 160 g160\n\
         udp6 :: 53 170 h170\n\
         sockets listed: 8\n\
         sockets with unknown owner: 0\n\
         lines read: 8\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_inode_field_fixture_exact_report() {
    // Each line resolves to its own owner through the field-10
    // inode — not through the UID (field 8) or field 9, which
    // equal another line's inode in this fixture.
    let root = fixture_root("proc-net-inode-field");
    add_process(&root.0, 100, b"p100\n", &[(3, 600001)]);
    add_process(&root.0, 200, b"p200\n", &[(3, 600002)]);
    add_process(&root.0, 300, b"p300\n", &[(3, 600003)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 3\n\
         tcp 127.0.0.1 9001 100 p100\n\
         tcp 127.0.0.1 9002 200 p200\n\
         tcp 127.0.0.1 9003 300 p300\n\
         sockets listed: 3\n\
         sockets with unknown owner: 0\n\
         lines read: 3\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_unparsed_fixture_exact_report() {
    let root = fixture_root("proc-net-unparsed");
    // A line longer than 65,536 bytes is never an entry: it counts
    // as a data line and as an unparsed socket line.
    let tcp_path = root.0.join("net").join("tcp");
    let mut tcp = fs::OpenOptions::new()
        .append(true)
        .open(&tcp_path)
        .expect("failed to open fixture tcp");
    tcp.write_all(&vec![b'x'; 65_537])
        .expect("failed to write over-long line");
    tcp.write_all(b"\n").expect("failed to write newline");
    drop(tcp);
    add_process(&root.0, 100, b"ok1\n", &[(3, 300001)]);
    add_process(&root.0, 200, b"ok2\n", &[(3, 300004)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 2\n\
         tcp 127.0.0.1 9001 100 ok1\n\
         tcp 127.0.0.1 9003 200 ok2\n\
         sockets listed: 2\n\
         sockets with unknown owner: 0\n\
         lines read: 8\n\
         unparsed socket lines: 6\n",
        "",
        0,
    );
}

#[test]
fn report_adversarial_fixture_exact_report() {
    let root = fixture_root("proc-net-adversarial");
    // A 100,000-character line: over the per-line cap, so it is
    // counted as a data line and as an unparsed socket line, and
    // the command still exits 0 with an empty stderr.
    let tcp_path = root.0.join("net").join("tcp");
    let mut tcp = fs::OpenOptions::new()
        .append(true)
        .open(&tcp_path)
        .expect("failed to open fixture tcp");
    tcp.write_all(&vec![b'y'; 100_000])
        .expect("failed to write long line");
    tcp.write_all(b"\n").expect("failed to write newline");
    drop(tcp);
    // The process name carries ANSI escapes and a newline: both
    // render as `?`.
    add_process(&root.0, 100, b"\x1b[31mred\n", &[(3, 700001)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 2\n\
         tcp 127.0.0.1 7001 100 ?[31mred\n\
         tcp 127.0.0.1 7002 unknown unknown\n\
         sockets listed: 2\n\
         sockets with unknown owner: 1\n\
         lines read: 6\n\
         unparsed socket lines: 4\n",
        "",
        0,
    );
}

#[test]
fn report_extra_argument_is_usage_error() {
    assert_output(
        &run(&["report-host-exposure", "extra"]),
        "",
        EXPECTED_ERROR,
        2,
    );
}

#[test]
fn report_missing_table_is_internal_error() {
    let root = TempDir007::new("missing-table");
    assert_output(&report(&root.0), "", EXPECTED_INVENTORY_READ_ERROR, 1);
}

#[test]
fn report_missing_one_table_is_internal_error() {
    let root = TempDir007::new("missing-one-table");
    write_table(&root.0, "tcp", &[]);
    assert_output(&report(&root.0), "", EXPECTED_INVENTORY_READ_ERROR, 1);
}

#[test]
fn report_unreadable_table_is_internal_error() {
    // Skipped where the test user can still open a mode-000 file
    // (for example when running as root).
    use std::os::unix::fs::PermissionsExt;
    let root = fixture_root("proc-net-empty");
    let path = root.0.join("net").join("tcp");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
        .expect("failed to chmod temp file");
    if fs::File::open(&path).is_ok() {
        // The file is still readable: running as root (or with an
        // equivalent override). Restore permissions and skip.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("failed to restore temp file permissions");
        return;
    }
    assert_output(&report(&root.0), "", EXPECTED_INVENTORY_READ_ERROR, 1);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("failed to restore temp file permissions");
}

#[test]
fn report_one_pid_two_fds_same_inode_is_one_line() {
    // One PID holding one inode through two fds: exactly one line,
    // and N counts it once.
    let root = TempDir007::new("dedup");
    write_table(
        &root.0,
        "tcp",
        &[tcp_listen_line("127.0.0.1", 8080, 1000, 1, 800001)],
    );
    empty_tables(&root.0);
    add_process(&root.0, 100, b"owner\n", &[(3, 800001), (7, 800001)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 1\n\
         tcp 127.0.0.1 8080 100 owner\n\
         sockets listed: 1\n\
         sockets with unknown owner: 0\n\
         lines read: 1\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_shared_inode_two_pids_is_two_lines() {
    let root = TempDir007::new("shared-inode");
    write_table(
        &root.0,
        "tcp",
        &[tcp_listen_line("127.0.0.1", 8080, 1000, 1, 800002)],
    );
    empty_tables(&root.0);
    add_process(&root.0, 100, b"first\n", &[(3, 800002)]);
    add_process(&root.0, 200, b"second\n", &[(5, 800002)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 2\n\
         tcp 127.0.0.1 8080 100 first\n\
         tcp 127.0.0.1 8080 200 second\n\
         sockets listed: 1\n\
         sockets with unknown owner: 0\n\
         lines read: 1\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_unknown_owner_is_one_unknown_line() {
    let root = TempDir007::new("unknown-owner");
    write_table(
        &root.0,
        "tcp",
        &[tcp_listen_line("127.0.0.1", 8080, 1000, 1, 800003)],
    );
    empty_tables(&root.0);
    // No process tree at all: the socket has no known owner.
    assert_output(
        &report(&root.0),
        "host exposure entries: 1\n\
         tcp 127.0.0.1 8080 unknown unknown\n\
         sockets listed: 1\n\
         sockets with unknown owner: 1\n\
         lines read: 1\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_mixed_known_and_unknown_counts() {
    let root = TempDir007::new("mixed-counts");
    write_table(
        &root.0,
        "tcp",
        &[
            tcp_listen_line("127.0.0.1", 8080, 1000, 1, 800004),
            tcp_listen_line("127.0.0.1", 8081, 1000, 1, 800005),
            tcp_listen_line("127.0.0.1", 8082, 1000, 1, 800006),
        ],
    );
    empty_tables(&root.0);
    add_process(&root.0, 100, b"a\n", &[(3, 800004)]);
    add_process(&root.0, 200, b"b\n", &[(3, 800005)]);
    // 800006 has no owner.
    assert_output(
        &report(&root.0),
        "host exposure entries: 3\n\
         tcp 127.0.0.1 8080 100 a\n\
         tcp 127.0.0.1 8081 200 b\n\
         tcp 127.0.0.1 8082 unknown unknown\n\
         sockets listed: 3\n\
         sockets with unknown owner: 1\n\
         lines read: 3\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_process_without_fd_dir_is_unknown() {
    // Deterministic disappearance (plan §7.2): the process
    // directory exists but has no `fd/` subdirectory, so its
    // sockets are unknown — never an error.
    let root = TempDir007::new("no-fd-dir");
    write_table(
        &root.0,
        "tcp",
        &[tcp_listen_line("127.0.0.1", 8080, 1000, 1, 800007)],
    );
    empty_tables(&root.0);
    let pid_dir = root.0.join("100");
    fs::create_dir_all(&pid_dir).expect("failed to create fixture pid dir");
    fs::write(pid_dir.join("comm"), b"gone\n").expect("failed to write fixture comm");
    assert_output(
        &report(&root.0),
        "host exposure entries: 1\n\
         tcp 127.0.0.1 8080 unknown unknown\n\
         sockets listed: 1\n\
         sockets with unknown owner: 1\n\
         lines read: 1\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
}

#[test]
fn report_hundred_thousand_line_table_streams() {
    let root = TempDir007::new("streaming");
    let mut lines = vec![tcp_listen_line("127.0.0.1", 8080, 1000, 1, 970_001)];
    lines.extend(std::iter::repeat_n("garbage".to_string(), 99_999));
    write_table(&root.0, "tcp", &lines);
    empty_tables(&root.0);
    add_process(&root.0, 100, b"owner\n", &[(3, 970_001)]);
    assert_output(
        &report(&root.0),
        "host exposure entries: 1\n\
         tcp 127.0.0.1 8080 100 owner\n\
         sockets listed: 1\n\
         sockets with unknown owner: 0\n\
         lines read: 100000\n\
         unparsed socket lines: 99999\n",
        "",
        0,
    );
}

#[test]
fn report_ten_thousand_entries_boundary_is_ok() {
    let root = TempDir007::new("entries-boundary");
    let lines: Vec<String> = (0..10_000)
        .map(|i| tcp_listen_line("127.0.0.1", (i + 1) as u16, 1000, 1, 900_001 + i as u64))
        .collect();
    write_table(&root.0, "tcp", &lines);
    empty_tables(&root.0);
    let fds: Vec<(u32, u64)> = (0..10_000)
        .map(|i| (3 + i as u32, 900_001 + i as u64))
        .collect();
    add_process(&root.0, 100, b"owner\n", &fds);
    let output = report(&root.0);
    let mut expected = String::from("host exposure entries: 10000\n");
    for port in 1..=10_000u16 {
        expected.push_str(&format!("tcp 127.0.0.1 {port} 100 owner\n"));
    }
    expected.push_str(
        "sockets listed: 10000\n\
         sockets with unknown owner: 0\n\
         lines read: 10000\n\
         unparsed socket lines: 0\n",
    );
    assert_output(&output, &expected, "", 0);
    assert!(output.stdout.len() < 1_048_576);
}

#[test]
fn report_ten_thousand_first_entry_is_limits_error() {
    let root = TempDir007::new("entries-over");
    let lines: Vec<String> = (0..10_001)
        .map(|i| {
            tcp_listen_line(
                "127.0.0.1",
                ((i % 10_000) + 1) as u16,
                1000,
                1,
                910_001 + i as u64,
            )
        })
        .collect();
    write_table(&root.0, "tcp", &lines);
    empty_tables(&root.0);
    assert_output(&report(&root.0), "", EXPECTED_LIMITS_ERROR, 1);
}

#[test]
fn report_one_million_first_line_is_limits_error() {
    let root = TempDir007::new("lines-over");
    let path = root.0.join("net").join("tcp");
    fs::create_dir_all(root.0.join("net")).expect("failed to create fixture net dir");
    let file = fs::File::create(&path).expect("failed to create fixture tcp");
    let mut writer = std::io::BufWriter::new(file);
    writer
        .write_all(TABLE_HEADER.as_bytes())
        .expect("failed to write header");
    for _ in 0..1_000_001 {
        writer.write_all(b"x\n").expect("failed to write line");
    }
    writer.flush().expect("failed to flush");
    drop(writer);
    empty_tables(&root.0);
    assert_output(&report(&root.0), "", EXPECTED_LIMITS_ERROR, 1);
}

#[test]
fn report_ten_thousand_first_process_is_limits_error() {
    let root = TempDir007::new("processes-over");
    write_table(
        &root.0,
        "tcp",
        &[tcp_listen_line("127.0.0.1", 8080, 1000, 1, 920_001)],
    );
    empty_tables(&root.0);
    for pid in 1..=10_001u32 {
        let pid_dir = root.0.join(pid.to_string());
        fs::create_dir_all(pid_dir.join("fd")).expect("failed to create fixture fd dir");
        if pid == 100 {
            fs::write(pid_dir.join("comm"), b"owner\n").expect("failed to write fixture comm");
            symlink("socket:[920001]", pid_dir.join("fd").join("3"))
                .expect("failed to create fixture fd symlink");
        }
    }
    assert_output(&report(&root.0), "", EXPECTED_LIMITS_ERROR, 1);
}

#[test]
fn report_hundred_thousand_first_fd_is_limits_error() {
    let root = TempDir007::new("fds-over");
    write_table(
        &root.0,
        "tcp",
        &[tcp_listen_line("127.0.0.1", 8080, 1000, 1, 930_001)],
    );
    empty_tables(&root.0);
    let pid_dir = root.0.join("100");
    let fd_dir = pid_dir.join("fd");
    fs::create_dir_all(&fd_dir).expect("failed to create fixture fd dir");
    fs::write(pid_dir.join("comm"), b"owner\n").expect("failed to write fixture comm");
    for fd in 0..100_001u32 {
        let inode = if fd == 0 { 930_001 } else { 999_999 };
        symlink(format!("socket:[{inode}]"), fd_dir.join(fd.to_string()))
            .expect("failed to create fixture fd symlink");
    }
    assert_output(&report(&root.0), "", EXPECTED_LIMITS_ERROR, 1);
}

#[test]
fn report_five_thousand_one_processes_two_inodes_is_limits_error() {
    // 5,001 processes x same 2 inodes = 10,002 distinct pairs, so
    // only the total-lines cap trips: processes (5,001 < 10,000)
    // and fds (10,002 < 100,000) are under their caps, with only 2
    // entries.
    let root = TempDir007::new("pairs-over");
    write_table(
        &root.0,
        "tcp",
        &[
            tcp_listen_line("127.0.0.1", 80, 1000, 1, 940_001),
            tcp_listen_line("127.0.0.1", 81, 1000, 1, 940_002),
        ],
    );
    empty_tables(&root.0);
    for pid in 1..=5_001u32 {
        add_process(&root.0, pid, b"w\n", &[(3, 940_001), (4, 940_002)]);
    }
    assert_output(&report(&root.0), "", EXPECTED_LIMITS_ERROR, 1);
}

#[test]
fn report_one_inode_five_thousand_one_processes_plus_five_thousand_unknown_is_limits_error() {
    // 1 inode x 5,001 processes (5,001 pair lines) + 5,000
    // unknown-owner inodes (5,000 unknown lines) = 10,001 total
    // lines, so only the total-lines cap trips: entries (5,001),
    // processes (5,001), and fds (5,001) are all under their caps.
    let root = TempDir007::new("pairs-unknown-over");
    let mut lines = vec![tcp_listen_line("127.0.0.1", 80, 1000, 1, 950_001)];
    lines.extend(
        (0..5_000)
            .map(|i| tcp_listen_line("127.0.0.1", (i + 1) as u16, 1000, 1, 950_002 + i as u64)),
    );
    write_table(&root.0, "tcp", &lines);
    empty_tables(&root.0);
    for pid in 1..=5_001u32 {
        add_process(&root.0, pid, b"w\n", &[(3, 950_001)]);
    }
    assert_output(&report(&root.0), "", EXPECTED_LIMITS_ERROR, 1);
}

#[test]
fn report_mixed_boundary_five_thousand_plus_five_thousand_is_ok() {
    // 5,000 pair lines + 5,000 unknown-owner lines = exactly
    // 10,000 total lines: exit 0 with the exact report.
    let root = TempDir007::new("mixed-boundary");
    let mut lines = vec![tcp_listen_line("127.0.0.1", 80, 1000, 1, 960_001)];
    lines.extend(
        (0..5_000)
            .map(|i| tcp_listen_line("127.0.0.1", (i + 1) as u16, 1000, 1, 960_002 + i as u64)),
    );
    write_table(&root.0, "tcp", &lines);
    empty_tables(&root.0);
    for pid in 1..=5_000u32 {
        add_process(&root.0, pid, b"w\n", &[(3, 960_001)]);
    }
    let output = report(&root.0);
    let mut expected = String::from("host exposure entries: 10000\n");
    for port in 1..=5_000u16 {
        if port == 80 {
            // At port 80 the 5,000 pair lines (PID ascending) come
            // first; the unknown line for port 80 follows them.
            for pid in 1..=5_000u32 {
                expected.push_str(&format!("tcp 127.0.0.1 80 {pid} w\n"));
            }
        }
        expected.push_str(&format!("tcp 127.0.0.1 {port} unknown unknown\n"));
    }
    expected.push_str(
        "sockets listed: 5001\n\
         sockets with unknown owner: 5000\n\
         lines read: 5001\n\
         unparsed socket lines: 0\n",
    );
    assert_output(&output, &expected, "", 0);
    assert!(output.stdout.len() < 1_048_576);
}

#[test]
fn report_empty_temp_dir_run_leaves_it_empty() {
    let work = TempDir007::new("empty-run");
    let root = fixture_root("proc-net-empty");
    assert_output(
        &run_with(&["report-host-exposure"], Some(&root.0), Some(&work.0)),
        "host exposure entries: 0\n\
         sockets listed: 0\n\
         sockets with unknown owner: 0\n\
         lines read: 0\n\
         unparsed socket lines: 0\n",
        "",
        0,
    );
    assert!(
        fs::read_dir(&work.0)
            .expect("failed to read temp dir")
            .next()
            .is_none(),
        "the binary must not write anything"
    );
}

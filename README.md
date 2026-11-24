# nexora

Open-source Linux-first security agent and local security engine for Nexora.

> **Bootstrap workspace skeleton plus the first two detection features.**
> This repository currently contains a minimal, building Rust
> workspace: a shared core library, a daemon binary, and a CLI
> binary. The CLI already implements two read-only detection reports:
> SSH brute-force detection from an operator-supplied log file
> (TASK-005) and a host-exposure inventory report of the local
> listening TCP and bound UDP sockets (TASK-007). It performs no
> protection, firewall, vulnerability, remediation, scoring, or AI
> behaviour. Those capabilities belong to later phases of the Nexora
> roadmap.

## Workspace layout

- `crates/nexora-core` — shared core library: version and identifier,
  shared error contracts (TASK-003), the SSH brute-force detection
  parser (TASK-005), and the host-exposure inventory parser and
  report builder (TASK-007).
- `crates/nexorad` — daemon binary. Prints its version, states that it
  does not start a daemon in this build, and exits. It starts no daemon,
  binds no socket, and performs no security function.
- `crates/nexora-cli` — CLI binary. Supports `--version` (`-V`),
  `--help` (`-h`), `detect-ssh-brute-force --log <path>`
  (TASK-005), and `report-host-exposure` (TASK-007); any other
  invocation prints usage to stderr and exits 2.

## Detection report (TASK-005)

```sh
cargo run -p nexora-cli -- detect-ssh-brute-force --log /path/to/auth.log
```

Reads the operator-supplied log file line by line (streaming,
1 MiB per-line cap) and prints an exact, deterministic report to
stdout: the SSH sources with 5 or more failed-password events
(IPv4 only, no time window), ordered by count descending then
address ascending, plus the total lines read and the unparsed
failed-password line count. Usernames and log content are never
printed. Zero findings is a successful run (exit 0). A missing or
unreadable file exits 1 with `error: cannot read log file`; bad
arguments exit 2. The command is read-only, unprivileged, and
stateless: it writes nothing, needs no privilege, and starts no
daemon.

## Host exposure inventory report (TASK-007)

```sh
cargo run -p nexora-cli -- report-host-exposure
```

Reads the local socket tables (`/proc/net/tcp`, `/proc/net/tcp6`,
`/proc/net/udp`, `/proc/net/udp6`) line by line (streaming,
65,536-byte per-line cap) and resolves each socket's owner from
`/proc/<pid>/fd` and `/proc/<pid>/comm`, then prints an exact,
deterministic report to stdout: one line per (socket, process)
pair — `protocol local-address port pid process-name` — plus the
counts `sockets listed`, `sockets with unknown owner`, `lines read`,
and `unparsed socket lines`. Lines are ordered by protocol, local
address (byte order), port, then PID; unknown owners sort after
known owners. Only listening TCP sockets are listed (non-LISTEN
TCP lines count as unparsed); every bound UDP socket is listed.
An empty inventory is a successful run (exit 0). A missing or
unreadable socket table exits 1 with
`error: cannot read socket inventory`; exceeding any resource
limit (10,000 sockets, 10,000 report lines, 1,000,000 table lines,
10,000 processes, 100,000 file descriptors, or a 1 MiB report)
exits 1 with `error: socket inventory exceeds limits` and an empty
stdout — there is no partial report and no silent truncation. Bad
arguments exit 2.

The command is read-only, unprivileged, and stateless: it writes
nothing, needs no privilege, starts no daemon, and keeps no state
between runs. It is a point-in-time snapshot of the local host
only: it cannot block, allow, or close a socket, and it says
nothing about traffic or about sockets on other hosts. The process
name is a hint, not an identity — a process can change its name
after the report is taken, and a socket whose owner cannot be
resolved is listed as `unknown unknown` rather than guessed. A UDP
entry is a bound socket, not a listener. The report never includes
a UID, username, command line, environment, executable path, or
remote socket address.

Rust edition 2021, Cargo resolver 2, version 0.1.0, licence
MIT OR Apache-2.0, zero external dependencies. `Cargo.lock` is checked in.

## Building

```sh
cargo build --workspace
```

## Testing

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

## Developing

```sh
cargo run -p nexora-cli -- --version
cargo run -p nexora-cli -- --help
cargo run -p nexorad
```

Continuous integration runs the same four checks (format, Clippy,
test, build) on `ubuntu-24.04` for every push and pull request
(see `.github/workflows/ci.yml`).

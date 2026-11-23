# nexora

Open-source Linux-first security agent and local security engine for Nexora.

> **Bootstrap workspace skeleton plus the first detection feature.**
> This repository currently contains a minimal, building Rust
> workspace: a shared core library, a daemon binary, and a CLI
> binary. The CLI already implements one read-only detection report
> (TASK-005, SSH brute-force detection from an operator-supplied
> log file). It performs no protection, firewall, vulnerability,
> remediation, scoring, or AI behaviour. Those capabilities belong to
> later phases of the Nexora roadmap.

## Workspace layout

- `crates/nexora-core` — shared core library: version and identifier,
  shared error contracts (TASK-003), and the SSH brute-force
  detection parser (TASK-005).
- `crates/nexorad` — daemon binary. Prints its version, states that it
  does not start a daemon in this build, and exits. It starts no daemon,
  binds no socket, and performs no security function.
- `crates/nexora-cli` — CLI binary. Supports `--version` (`-V`),
  `--help` (`-h`), and `detect-ssh-brute-force --log <path>`
  (TASK-005); any other invocation prints usage to stderr and
  exits 2.

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

# nexora

Open-source Linux-first security agent and local security engine for Nexora.

> **Bootstrap workspace skeleton — no security functionality yet.**
> This repository currently contains only a minimal, building Rust
> workspace: a shared core library, a daemon binary, and a CLI binary.
> It performs no detection, protection, firewall, vulnerability,
> remediation, scoring, or AI behaviour. Those capabilities belong to
> later phases of the Nexora roadmap.

## Workspace layout

- `crates/nexora-core` — shared core library (version and identifier only).
- `crates/nexorad` — daemon binary. Prints its version, states that it
  does not start a daemon in this build, and exits. It starts no daemon,
  binds no socket, and performs no security function.
- `crates/nexora-cli` — CLI binary. Supports only `--version` (`-V`) and
  `--help` (`-h`); any other invocation prints usage to stderr and
  exits 2.

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

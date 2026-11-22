# CI Gate Procedure

This document describes the contributor gate for Nexora's Rust workspace.
It is maintained in the Nexora repository as part of TASK-002.

## Before opening a pull request

Run these commands from the repository root, in order:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

All four commands must exit with code 0. Do not suppress warnings, skip tests,
or weaken a check to make the gate pass. If a command fails, fix the cause and
rerun the full set.

## What CI runs

GitHub Actions workflow `.github/workflows/ci.yml` runs on every push and pull
request using `ubuntu-24.04`. It has one job, `linux`, and runs the same four
commands listed above. The actions used by the workflow are pinned to full commit
SHAs. No duplicate workflow or additional CI job should be introduced for these
checks.

## Failure handling

- A failed check blocks the contributor from treating the change as ready.
- Read the failing step's output and reproduce it locally where possible.
- Correct the source or configuration; do not remove, bypass, or weaken the check.
- Push the correction and verify the new CI run is green.
- If the failure appears runner/environment-specific, record the error and
  investigate; do not claim success based on a local pass alone.

## Evidence for a pull request

The PR description or review record should include:

- The four local commands and their exit codes. Local verification must be
  performed before opening the PR; a PR without it is not ready for review.
- The CI run URL and final result for the `linux` job.
- Any relevant test count or failure details.
- Confirmation that no check was weakened and no duplicate workflow was added.

## Enforcement status

The workflow is configured to run on pushes and pull requests. The `linux` job
is the CI status to require on `main` once repository branch protection is
approved and configured. Until that setting is verified, CI is a contributor
procedure and is **not** an enforced merge requirement. TASK-002 AC4 remains
pending separate repository-admin approval.

## TASK-002 verification notes

A deliberately failing CI test must be performed on a disposable test branch or
PR, observed failing, and then removed/reverted. Record the run URL and failed
check; do not merge the broken test change. A clean PR run is the positive test.
The TASK-001 four-command verification set must be rerun after any code or
workflow changes in this task, with exact commands and exit codes recorded.

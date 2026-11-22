//! `nexorad` — Nexora daemon binary.
//!
//! Bootstrap scope only: prints the core identifier and states that
//! the daemon is not started in this build, then exits. It starts no
//! daemon, binds no socket, opens no file, and performs no security
//! function.

fn main() {
    println!("{}", nexora_core::identifier());
    println!("nexorad does not start a daemon in this build.");
}

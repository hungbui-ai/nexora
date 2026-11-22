//! `nexora-cli` — Nexora command-line interface.
//!
//! Bootstrap scope only: supports `--version` / `-V` and `--help` /
//! `-h`. Any other invocation prints usage to stderr and exits 2.
//! No other command is implemented. Arguments are matched, never
//! interpolated into a shell string; no shell is invoked.

use std::env;
use std::process::ExitCode;

const USAGE: &str = "Usage: nexora-cli [--version|--help]";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "--version" || arg == "-V" => {
            println!("nexora-cli {}", nexora_core::VERSION);
            ExitCode::SUCCESS
        }
        [arg] if arg == "--help" || arg == "-h" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("error: expected exactly one of --version or --help");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

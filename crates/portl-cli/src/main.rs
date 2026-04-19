//! portl — single multicall binary.
//!
//! Entry point. Argument parsing and dispatch live in `cli.rs`.
//! This file is intentionally thin so that tests can call into
//! the dispatch logic without going through the real process
//! entry.

use std::process::ExitCode;

fn main() -> ExitCode {
    portl_cli::run(std::env::args_os().collect())
}

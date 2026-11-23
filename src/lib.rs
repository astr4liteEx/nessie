//! nessie reads Nessus scans and emits what is in them as JSON Lines records.
//!
//! `run` is the whole program: `main` only wires up the process's streams,
//! so tests run nessie in-process.

pub mod cli;
pub mod diag;
mod ext;
mod identity;
mod inputs;
pub mod jsonl;
pub mod nessus;
mod records;
mod stream;
pub mod table;
mod verbs;

use std::io::{BufRead, Write};

/// The version in Cargo.toml; release builds are tagged `v<VERSION>`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit codes, per the chainable-tools convention.
pub mod exit {
    /// Success.
    pub const OK: i32 = 0;
    /// Problems in the input or the data; nessie still did what it could.
    pub const PROBLEMS: i32 = 1;
    /// Usage error: wrong flags or arguments.
    pub const USAGE: i32 = 2;
}

/// The streams one run of nessie uses. Verbs never touch the process's own.
pub struct Io<'a> {
    pub stdin: &'a mut dyn BufRead,
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub stdin_tty: bool,
    pub stdout_tty: bool,
    /// How tables are drawn when stdout is a terminal.
    pub style: table::Style,
}

/// Runs nessie with `args` (without the program name) and returns the exit code.
pub fn run(args: &[String], io: &mut Io) -> i32 {
    cli::run(args, io)
}

//! Library surface of the portl CLI.
//!
//! The binary's `main` is a thin shim over [`run`]. Keeping the
//! dispatch logic exposed as a library function lets integration
//! tests drive the CLI without spawning subprocesses. Command
//! parsing is further split into [`parse`] so tests can assert
//! on a structured [`Command`] value without caring about
//! stdout, exit codes, or process setup.

use std::{ffi::OsString, path::Path, process::ExitCode};

use clap::{Parser, Subcommand};

/// Structured representation of a parsed invocation.
///
/// M0 models only the subset required to exercise multicall
/// dispatch. Every milestone adds variants here as subcommands
/// land; the CLI surface in `080-cli.md` is the full roadmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `portl agent run` (or its `portl-agent run` symlink form).
    AgentRun,
}

/// Errors returned by [`parse`].
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// argv was empty, so not even argv[0] is available.
    #[error("argv is empty; argv[0] is required")]
    EmptyArgv,
    /// Clap rejected the arguments. The inner error carries the
    /// human-readable message clap would normally print.
    #[error(transparent)]
    Clap(#[from] clap::Error),
}

/// Parse an argv vector into a structured [`Command`].
///
/// Handles multicall dispatch: if argv[0]'s basename is
/// `portl-agent`, the argument vector is rewritten to
/// `["portl", "agent", ...rest]` before clap parses it. This
/// keeps the symlink + systemd-unit pathway working without a
/// second binary.
pub fn parse(argv: Vec<OsString>) -> Result<Command, ParseError> {
    let argv = rewrite_multicall(argv)?;
    let cli = Cli::try_parse_from(argv)?;
    Ok(cli.into_command())
}

/// Library entry point wrapping [`parse`] + dispatch.
///
/// M0 ships a minimal dispatcher: successful parses return
/// `ExitCode::SUCCESS`; parse errors are printed to stderr and
/// return `ExitCode::FAILURE`. Real subcommand execution lands in
/// M1+ as each subcommand gets an implementation.
pub fn run(argv: Vec<OsString>) -> ExitCode {
    match parse(argv) {
        Ok(_cmd) => ExitCode::SUCCESS,
        Err(ParseError::EmptyArgv) => {
            eprintln!("portl: argv is empty");
            ExitCode::FAILURE
        }
        Err(ParseError::Clap(err)) => {
            // clap's Display is the human-friendly error message.
            let _ = err.print();
            ExitCode::FAILURE
        }
    }
}

fn rewrite_multicall(mut argv: Vec<OsString>) -> Result<Vec<OsString>, ParseError> {
    let first = argv.first().ok_or(ParseError::EmptyArgv)?;
    let basename = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if basename == "portl-agent" {
        // Replace argv[0] with a canonical "portl" and insert "agent"
        // as the first positional. From clap's perspective the
        // invocation is indistinguishable from `portl agent ...`.
        argv[0] = OsString::from("portl");
        argv.insert(1, OsString::from("agent"));
    }
    Ok(argv)
}

#[derive(Parser, Debug)]
#[command(name = "portl", bin_name = "portl", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Subcommand, Debug)]
enum TopLevel {
    /// Target-side agent subcommands (run, enroll, identity, ...).
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
}

#[derive(Subcommand, Debug)]
enum AgentAction {
    /// Start the long-running agent service.
    Run,
}

impl Cli {
    fn into_command(self) -> Command {
        match self.command {
            TopLevel::Agent {
                action: AgentAction::Run,
            } => Command::AgentRun,
        }
    }
}

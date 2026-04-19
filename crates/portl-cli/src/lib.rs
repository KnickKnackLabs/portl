//! Library surface of the portl CLI.
//!
//! The binary's `main` is a thin shim over [`run`]. Keeping the
//! dispatch logic exposed as a library function lets integration
//! tests drive the CLI without spawning subprocesses. Command
//! parsing is further split into [`parse`] so tests can assert
//! on a structured [`Command`] value without caring about
//! stdout, exit codes, or process setup.

mod commands;

use std::{ffi::OsString, path::Path, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};

/// Structured representation of a parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `portl agent run` (or its `portl-agent run` symlink form).
    AgentRun,
    /// `portl id new [--force]`
    IdNew { force: bool },
    /// `portl id show`
    IdShow,
    /// `portl id export --out <path>`
    IdExport { out: PathBuf },
    /// `portl id import --from <path>`
    IdImport { from: PathBuf },
    /// `portl mint-root --endpoint ... --caps ... --ttl ...`
    MintRoot {
        endpoint: String,
        caps: String,
        ttl: String,
        to: Option<String>,
        depth: Option<u8>,
        print: MintRootPrint,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MintRootPrint {
    String,
    Qr,
    Url,
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
pub fn run(argv: Vec<OsString>) -> ExitCode {
    match parse(argv) {
        Ok(cmd) => match dispatch(cmd) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("{err:#}");
                ExitCode::FAILURE
            }
        },
        Err(ParseError::EmptyArgv) => {
            eprintln!("portl: argv is empty");
            ExitCode::FAILURE
        }
        Err(ParseError::Clap(err)) => {
            let _ = err.print();
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cmd: Command) -> anyhow::Result<ExitCode> {
    match cmd {
        Command::AgentRun => Ok(ExitCode::SUCCESS),
        Command::IdNew { force } => commands::id::new::run(force),
        Command::IdShow => commands::id::show::run(),
        Command::IdExport { out } => commands::id::export::run(&out),
        Command::IdImport { from } => commands::id::import::run(&from),
        Command::MintRoot {
            endpoint,
            caps,
            ttl,
            to,
            depth,
            print,
        } => commands::mint_root::run(&endpoint, &caps, &ttl, to.as_deref(), depth, print),
    }
}

fn rewrite_multicall(mut argv: Vec<OsString>) -> Result<Vec<OsString>, ParseError> {
    let first = argv.first().ok_or(ParseError::EmptyArgv)?;
    let basename = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if basename == "portl-agent" {
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
    /// Local operator identity management.
    Id {
        #[command(subcommand)]
        action: IdAction,
    },
    /// Mint a root ticket with the local operator identity.
    MintRoot {
        #[arg(long, alias = "node")]
        endpoint: String,
        #[arg(long)]
        caps: String,
        #[arg(long)]
        ttl: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        depth: Option<u8>,
        #[arg(short = 'o', long = "print", value_enum, default_value = "string")]
        print: MintRootPrint,
    },
}

#[derive(Subcommand, Debug)]
enum AgentAction {
    /// Start the long-running agent service.
    Run,
}

#[derive(Subcommand, Debug)]
enum IdAction {
    /// Generate a new local identity.
    New {
        #[arg(long)]
        force: bool,
    },
    /// Show the current identity.
    Show,
    /// Export the current identity.
    Export {
        #[arg(long)]
        out: PathBuf,
    },
    /// Import an encrypted identity export.
    Import {
        #[arg(long)]
        from: PathBuf,
    },
}

impl Cli {
    fn into_command(self) -> Command {
        match self.command {
            TopLevel::Agent {
                action: AgentAction::Run,
            } => Command::AgentRun,
            TopLevel::Id {
                action: IdAction::New { force },
            } => Command::IdNew { force },
            TopLevel::Id {
                action: IdAction::Show,
            } => Command::IdShow,
            TopLevel::Id {
                action: IdAction::Export { out },
            } => Command::IdExport { out },
            TopLevel::Id {
                action: IdAction::Import { from },
            } => Command::IdImport { from },
            TopLevel::MintRoot {
                endpoint,
                caps,
                ttl,
                to,
                depth,
                print,
            } => Command::MintRoot {
                endpoint,
                caps,
                ttl,
                to,
                depth,
                print,
            },
        }
    }
}

//! Library surface of the portl CLI.
//!
//! The binary's `main` is a thin shim over [`run`]. Keeping the
//! dispatch logic exposed as a library function lets integration
//! tests drive the CLI without spawning subprocesses. Command
//! parsing is further split into [`parse`] so tests can assert
//! on a structured [`Command`] value without caring about
//! stdout, exit codes, or process setup.

mod alias_store;
mod commands;

pub use commands::agent::run::load_config as load_agent_config;
pub use commands::status::run_with_identity_path as run_status_with_identity_path;
pub use commands::status::run_with_identity_path_and_endpoint as run_status_with_identity_path_and_endpoint;

use std::{ffi::OsString, path::Path, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};

/// Structured representation of a parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `portl agent run` (or its `portl-agent run` symlink form).
    AgentRun {
        config: Option<PathBuf>,
    },
    /// `portl id new [--force]`
    IdNew {
        force: bool,
    },
    /// `portl id show`
    IdShow,
    /// `portl id export --out <path> [--passphrase-cmd <cmd>]`
    IdExport {
        out: PathBuf,
        passphrase_cmd: Option<String>,
    },
    /// `portl id import --from <path> [--force] [--passphrase-cmd <cmd>]`
    IdImport {
        from: PathBuf,
        force: bool,
        passphrase_cmd: Option<String>,
    },
    /// `portl mint-root --endpoint ... --caps ... --ttl ...`
    MintRoot {
        endpoint: String,
        caps: String,
        ttl: String,
        to: Option<String>,
        depth: Option<u8>,
        print: MintRootPrint,
    },
    /// `portl status <peer>`
    Status {
        peer: String,
    },
    /// `portl shell <peer>`
    Shell {
        peer: String,
        cwd: Option<String>,
        user: Option<String>,
    },
    /// `portl exec <peer> -- <argv...>`
    Exec {
        peer: String,
        cwd: Option<String>,
        user: Option<String>,
        argv: Vec<String>,
    },
    /// `portl tcp <peer> -L ...`
    Tcp {
        peer: String,
        local: Vec<String>,
    },
    /// `portl docker container add ...`
    DockerAdd {
        name: String,
        image: Option<String>,
        network: Option<String>,
        agent_caps: String,
        ttl: String,
        to: Option<String>,
        labels: Vec<String>,
    },
    DockerList {
        json: bool,
    },
    DockerRm {
        name: String,
        force: bool,
        keep_tickets: bool,
    },
    DockerRebuild {
        name: String,
    },
    DockerLogs {
        name: String,
        follow: bool,
        tail: Option<String>,
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
        Command::AgentRun { config } => commands::agent::run::run(config.as_deref()),
        Command::IdNew { force } => commands::id::new::run(force),
        Command::IdShow => commands::id::show::run(),
        Command::IdExport {
            out,
            passphrase_cmd,
        } => commands::id::export::run(&out, passphrase_cmd.as_deref()),
        Command::IdImport {
            from,
            force,
            passphrase_cmd,
        } => commands::id::import::run(&from, force, passphrase_cmd.as_deref()),
        Command::MintRoot {
            endpoint,
            caps,
            ttl,
            to,
            depth,
            print,
        } => commands::mint_root::run(&endpoint, &caps, &ttl, to.as_deref(), depth, print),
        Command::Status { peer } => commands::status::run(&peer),
        Command::Shell { peer, cwd, user } => {
            commands::shell::run(&peer, cwd.as_deref(), user.as_deref())
        }
        Command::Exec {
            peer,
            cwd,
            user,
            argv,
        } => commands::exec::run(&peer, cwd.as_deref(), user.as_deref(), &argv),
        Command::Tcp { peer, local } => commands::tcp::run(&peer, &local),
        Command::DockerAdd {
            name,
            image,
            network,
            agent_caps,
            ttl,
            to,
            labels,
        } => commands::docker::add(
            &name,
            image.as_deref(),
            network.as_deref(),
            &agent_caps,
            &ttl,
            to.as_deref(),
            &labels,
        ),
        Command::DockerList { json } => commands::docker::list(json),
        Command::DockerRm {
            name,
            force,
            keep_tickets,
        } => commands::docker::rm(&name, force, keep_tickets),
        Command::DockerRebuild { name } => commands::docker::rebuild(&name),
        Command::DockerLogs { name, follow, tail } => {
            commands::docker::logs(&name, follow, tail.as_deref())
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
    /// Query peer reachability and metadata.
    Status { peer: String },
    /// Open an interactive remote PTY shell.
    Shell {
        peer: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
    /// Run a remote command without a PTY.
    Exec {
        peer: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Set up one or more local TCP forwards.
    Tcp {
        peer: String,
        #[arg(short = 'L', required = true)]
        local: Vec<String>,
    },
    /// Docker target management.
    Docker {
        #[command(subcommand)]
        action: DockerAction,
    },
}

#[derive(Subcommand, Debug)]
enum AgentAction {
    /// Start the long-running agent service.
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum DockerAction {
    Container {
        #[command(subcommand)]
        action: DockerContainerAction,
    },
}

#[derive(Subcommand, Debug)]
enum DockerContainerAction {
    Add {
        name: String,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        network: Option<String>,
        #[arg(long = "agent-caps", default_value = "shell")]
        agent_caps: String,
        #[arg(long, default_value = "30d")]
        ttl: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "label")]
        labels: Vec<String>,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    Rm {
        name: String,
        #[arg(long)]
        force: bool,
        #[arg(long = "keep-tickets")]
        keep_tickets: bool,
    },
    Rebuild {
        name: String,
    },
    Logs {
        name: String,
        #[arg(long)]
        follow: bool,
        #[arg(long)]
        tail: Option<String>,
    },
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
        #[arg(long = "passphrase-cmd")]
        passphrase_cmd: Option<String>,
    },
    /// Import an encrypted identity export.
    Import {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long = "passphrase-cmd")]
        passphrase_cmd: Option<String>,
    },
}

impl Cli {
    fn into_command(self) -> Command {
        match self.command {
            TopLevel::Agent {
                action: AgentAction::Run { config },
            } => Command::AgentRun { config },
            TopLevel::Id {
                action: IdAction::New { force },
            } => Command::IdNew { force },
            TopLevel::Id {
                action: IdAction::Show,
            } => Command::IdShow,
            TopLevel::Id {
                action:
                    IdAction::Export {
                        out,
                        passphrase_cmd,
                    },
            } => Command::IdExport {
                out,
                passphrase_cmd,
            },
            TopLevel::Id {
                action:
                    IdAction::Import {
                        from,
                        force,
                        passphrase_cmd,
                    },
            } => Command::IdImport {
                from,
                force,
                passphrase_cmd,
            },
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
            TopLevel::Status { peer } => Command::Status { peer },
            TopLevel::Shell { peer, cwd, user } => Command::Shell { peer, cwd, user },
            TopLevel::Exec {
                peer,
                cwd,
                user,
                argv,
            } => Command::Exec {
                peer,
                cwd,
                user,
                argv,
            },
            TopLevel::Tcp { peer, local } => Command::Tcp { peer, local },
            TopLevel::Docker {
                action:
                    DockerAction::Container {
                        action:
                            DockerContainerAction::Add {
                                name,
                                image,
                                network,
                                agent_caps,
                                ttl,
                                to,
                                labels,
                            },
                    },
            } => Command::DockerAdd {
                name,
                image,
                network,
                agent_caps,
                ttl,
                to,
                labels,
            },
            TopLevel::Docker {
                action:
                    DockerAction::Container {
                        action: DockerContainerAction::List { json },
                    },
            } => Command::DockerList { json },
            TopLevel::Docker {
                action:
                    DockerAction::Container {
                        action:
                            DockerContainerAction::Rm {
                                name,
                                force,
                                keep_tickets,
                            },
                    },
            } => Command::DockerRm {
                name,
                force,
                keep_tickets,
            },
            TopLevel::Docker {
                action:
                    DockerAction::Container {
                        action: DockerContainerAction::Rebuild { name },
                    },
            } => Command::DockerRebuild { name },
            TopLevel::Docker {
                action:
                    DockerAction::Container {
                        action: DockerContainerAction::Logs { name, follow, tail },
                    },
            } => Command::DockerLogs { name, follow, tail },
        }
    }
}

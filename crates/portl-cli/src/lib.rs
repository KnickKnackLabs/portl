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

pub use commands::init::InitRole;
pub use commands::install::InstallTarget;
pub use commands::status::run_with_identity_path as run_status_with_identity_path;
pub use commands::status::run_with_identity_path_and_endpoint as run_status_with_identity_path_and_endpoint;

use std::{ffi::OsString, path::Path, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};

pub fn load_agent_config() -> anyhow::Result<portl_agent::AgentConfig> {
    commands::agent::run::load_config(None, None)
}

/// Structured representation of a parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Hidden compatibility path for `portl-agent` until Task 3.5 lands.
    AgentRun {
        mode: Option<AgentModeArg>,
        upstream_url: Option<String>,
    },
    /// Hidden compatibility path for the pre-v0.2 `id` namespace.
    IdNew {
        force: bool,
    },
    IdShow,
    IdExport {
        out: PathBuf,
        passphrase_cmd: Option<String>,
    },
    IdImport {
        from: PathBuf,
        force: bool,
        passphrase_cmd: Option<String>,
    },
    Init {
        force: bool,
        role: Option<InitRole>,
    },
    Doctor,
    Status {
        peer: String,
        relay: bool,
    },
    Shell {
        peer: String,
        cwd: Option<String>,
        user: Option<String>,
    },
    Exec {
        peer: String,
        cwd: Option<String>,
        user: Option<String>,
        argv: Vec<String>,
    },
    Tcp {
        peer: String,
        local: Vec<String>,
    },
    Udp {
        peer: String,
        local: Vec<String>,
    },
    Mint {
        caps: String,
        ttl: String,
        to: Option<String>,
        from: Option<String>,
        print: MintRootPrint,
        endpoint: Option<String>,
    },
    Revoke {
        id: Option<String>,
        list: bool,
        publish: bool,
    },
    Install {
        target: Option<InstallTarget>,
        apply: bool,
        yes: bool,
        detect: bool,
        dry_run: bool,
    },
    DockerRun {
        image: String,
        name: Option<String>,
        from_binary: Option<PathBuf>,
        watch: bool,
    },
    DockerAttach {
        container: String,
        from_binary: Option<PathBuf>,
    },
    DockerDetach {
        container: String,
    },
    DockerList {
        json: bool,
    },
    DockerRm {
        name: String,
        force: bool,
        keep_tickets: bool,
    },
    DockerBake {
        base_image: String,
        output: Option<PathBuf>,
        tag: Option<String>,
        push: bool,
        init_shim: bool,
    },
    SlicerRun {
        image: String,
        base_url: Option<String>,
        cpus: Option<u8>,
        ram_gb: Option<u16>,
        tags: Vec<String>,
        ticket_out: Option<PathBuf>,
    },
    SlicerList {
        base_url: Option<String>,
        json: bool,
    },
    SlicerRm {
        name: String,
        base_url: Option<String>,
    },
    SlicerBake {
        base_image: String,
    },
    Gateway {
        upstream_url: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MintRootPrint {
    String,
    Qr,
    Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AgentModeArg {
    Listener,
    Gateway,
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
/// Handles multicall dispatch: `portl-agent` maps directly to the
/// daemon entrypoint, while `portl-gateway` rewrites to the top-level
/// `gateway` subcommand.
pub fn parse(argv: Vec<OsString>) -> Result<Command, ParseError> {
    if is_portl_agent_invocation(&argv)? {
        let _ = AgentCli::try_parse_from(argv)?;
        return Ok(Command::AgentRun {
            mode: None,
            upstream_url: None,
        });
    }
    let argv = rewrite_multicall(argv)?;
    let cli = Cli::try_parse_from(argv)?;
    Ok(cli.into_command())
}

/// Library entry point wrapping parsing + dispatch.
fn clap_exit_code(err: &clap::Error) -> ExitCode {
    match err.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
            ExitCode::SUCCESS
        }
        _ => ExitCode::FAILURE,
    }
}

pub fn run(argv: Vec<OsString>) -> ExitCode {
    match is_portl_agent_invocation(&argv) {
        Ok(true) => {
            return match AgentCli::try_parse_from(argv) {
                Ok(_) => match dispatch(Command::AgentRun {
                    mode: None,
                    upstream_url: None,
                }) {
                    Ok(code) => code,
                    Err(err) => {
                        eprintln!("{err:#}");
                        ExitCode::FAILURE
                    }
                },
                Err(err) => {
                    let code = clap_exit_code(&err);
                    let _ = err.print();
                    code
                }
            };
        }
        Ok(false) => {}
        Err(ParseError::EmptyArgv) => {
            eprintln!("portl: argv is empty");
            return ExitCode::FAILURE;
        }
        Err(ParseError::Clap(err)) => {
            let _ = err.print();
            return ExitCode::FAILURE;
        }
    }

    let argv = match rewrite_multicall(argv) {
        Ok(argv) => argv,
        Err(ParseError::EmptyArgv) => {
            eprintln!("portl: argv is empty");
            return ExitCode::FAILURE;
        }
        Err(ParseError::Clap(err)) => {
            let _ = err.print();
            return ExitCode::FAILURE;
        }
    };

    if let Some(code) = removed_invocation_exit(&argv) {
        return code;
    }

    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            let code = clap_exit_code(&err);
            let _ = err.print();
            return code;
        }
    };

    match dispatch(cli.into_command()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch(cmd: Command) -> anyhow::Result<ExitCode> {
    match cmd {
        Command::AgentRun { mode, upstream_url } => {
            commands::agent::run::run(mode, upstream_url.as_deref())
        }
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
        Command::Init { force, role } => commands::init::run(force, role),
        Command::Doctor => Ok(commands::doctor::run()),
        Command::Status { peer, relay } => commands::status::run(&peer, relay),
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
        Command::Udp { peer, local } => commands::udp::run(&peer, &local),
        Command::Mint {
            caps,
            ttl,
            to,
            from,
            print,
            endpoint,
        } => commands::mint_root::run(
            &caps,
            &ttl,
            to.as_deref(),
            from.as_deref(),
            print,
            endpoint.as_deref(),
        ),
        Command::Revoke { id, list, publish } => {
            commands::revoke::run(id.as_deref(), list, publish)
        }
        Command::Install {
            target,
            apply,
            yes,
            detect,
            dry_run,
        } => commands::install::run(target, apply, yes, detect, dry_run),
        Command::DockerRun {
            image,
            name,
            from_binary,
            watch,
        } => commands::docker::run(&image, name.as_deref(), from_binary.as_deref(), watch),
        Command::DockerAttach {
            container,
            from_binary,
        } => commands::docker::attach(&container, from_binary.as_deref()),
        Command::DockerDetach { container } => commands::docker::detach(&container),
        Command::DockerList { json } => commands::docker::list(json),
        Command::DockerRm {
            name,
            force,
            keep_tickets,
        } => commands::docker::rm(&name, force, keep_tickets),
        Command::DockerBake {
            base_image,
            output,
            tag,
            push,
            init_shim,
        } => commands::docker::bake(
            &base_image,
            output.as_deref(),
            tag.as_deref(),
            push,
            init_shim,
        ),
        Command::SlicerRun {
            image,
            base_url,
            cpus,
            ram_gb,
            tags,
            ticket_out,
        } => commands::slicer::run(
            &image,
            base_url.as_deref(),
            cpus,
            ram_gb,
            &tags,
            ticket_out.as_deref(),
        ),
        Command::SlicerList { base_url, json } => commands::slicer::list(base_url.as_deref(), json),
        Command::SlicerRm { name, base_url } => commands::slicer::rm(&name, base_url.as_deref()),
        Command::SlicerBake { base_image } => commands::slicer::bake(&base_image),
        Command::Gateway { upstream_url } => {
            commands::agent::run::run(Some(AgentModeArg::Gateway), Some(&upstream_url))
        }
    }
}

fn removed_invocation_exit(argv: &[OsString]) -> Option<ExitCode> {
    match argv.get(1).and_then(|arg| arg.to_str()) {
        Some("mint-root") => {
            eprintln!("portl: `portl mint-root` was removed in v0.2.0. Use `portl mint` instead.");
            Some(ExitCode::FAILURE)
        }
        Some("agent") => {
            eprintln!(
                "portl: `portl agent *` was removed in v0.2.0. Use `portl-agent` instead.\n      See https://github.com/KnickKnackLabs/portl/blob/v0.2.0/docs/specs/140-v0.2-operability.md#12-multicall-only-daemon"
            );
            Some(ExitCode::from(2))
        }
        _ => None,
    }
}

fn is_portl_agent_invocation(argv: &[OsString]) -> Result<bool, ParseError> {
    let first = argv.first().ok_or(ParseError::EmptyArgv)?;
    let basename = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    Ok(basename == "portl-agent")
}

fn rewrite_multicall(mut argv: Vec<OsString>) -> Result<Vec<OsString>, ParseError> {
    let first = argv.first().ok_or(ParseError::EmptyArgv)?;
    let basename = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if basename == "portl-gateway" {
        argv[0] = OsString::from("portl");
        argv.insert(1, OsString::from("gateway"));
    }
    Ok(argv)
}

#[derive(Parser, Debug)]
#[command(name = "portl", bin_name = "portl", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Parser, Debug)]
#[command(name = "portl-agent", bin_name = "portl-agent", version, about = "portl daemon", long_about = None)]
struct AgentCli {}

#[derive(Subcommand, Debug)]
enum TopLevel {
    /// Create identity, run doctor, and print next steps.
    Init {
        #[arg(long)]
        force: bool,
        #[arg(long, value_enum)]
        role: Option<InitRole>,
    },
    /// Print strictly local diagnostics (clock, identity, listener bind, discovery config, ticket expiry).
    Doctor,
    /// Query peer reachability and metadata.
    Status {
        peer: String,
        /// Also force the handshake over the peer's relay path.
        #[arg(long)]
        relay: bool,
    },
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
        #[arg(short = 'L', required = true)]
        local: Vec<String>,
        peer: String,
    },
    /// Set up one or more local UDP forwards.
    Udp {
        #[arg(short = 'L', required = true)]
        local: Vec<String>,
        peer: String,
    },
    /// Mint a ticket with the local identity.
    Mint {
        caps: String,
        #[arg(long, default_value = "30d")]
        ttl: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "from")]
        from: Option<String>,
        #[arg(short = 'o', long = "print", value_enum, default_value = "string")]
        print: MintRootPrint,
        #[arg(long, hide = true, alias = "node")]
        endpoint: Option<String>,
    },
    /// Append a local ticket revocation, optionally publish it, or list the current revocation log.
    Revoke {
        id: Option<String>,
        #[arg(long, conflicts_with = "id")]
        list: bool,
        #[arg(long, requires = "id")]
        publish: bool,
    },
    /// Install the daemon for a supported target.
    Install {
        target: Option<InstallTarget>,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        detect: bool,
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    /// Docker target management.
    Docker {
        #[command(subcommand)]
        action: DockerAction,
    },
    /// Slicer target management.
    Slicer {
        #[command(subcommand)]
        action: SlicerAction,
    },
    /// Run the slicer HTTP bridge against an upstream API.
    Gateway { upstream_url: String },
    #[command(hide = true)]
    Id {
        #[command(subcommand)]
        action: IdAction,
    },
}

#[derive(Subcommand, Debug)]
enum DockerAction {
    Run {
        image: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "from-binary")]
        from_binary: Option<PathBuf>,
        #[arg(long)]
        watch: bool,
    },
    Attach {
        container: String,
        #[arg(long = "from-binary")]
        from_binary: Option<PathBuf>,
    },
    Detach {
        container: String,
    },
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    Rm {
        name: String,
        #[arg(long, hide = true)]
        force: bool,
        #[arg(long = "keep-tickets", hide = true)]
        keep_tickets: bool,
    },
    Bake {
        base_image: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        push: bool,
        #[arg(long = "init-shim")]
        init_shim: bool,
    },
}

#[derive(Subcommand, Debug)]
enum SlicerAction {
    Run {
        image: String,
        #[arg(long)]
        base_url: Option<String>,
        #[arg(long)]
        cpus: Option<u8>,
        #[arg(long = "ram-gb")]
        ram_gb: Option<u16>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long = "ticket-out")]
        ticket_out: Option<PathBuf>,
    },
    List {
        #[arg(long, hide = true)]
        base_url: Option<String>,
        #[arg(long, hide = true)]
        json: bool,
    },
    Rm {
        name: String,
        #[arg(long, hide = true)]
        base_url: Option<String>,
    },
    Bake {
        base_image: String,
    },
}

#[derive(Subcommand, Debug)]
enum IdAction {
    New {
        #[arg(long)]
        force: bool,
    },
    Show,
    Export {
        #[arg(long)]
        out: PathBuf,
        #[arg(long = "passphrase-cmd")]
        passphrase_cmd: Option<String>,
    },
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
    #[allow(clippy::too_many_lines)]
    fn into_command(self) -> Command {
        match self.command {
            TopLevel::Init { force, role } => Command::Init { force, role },
            TopLevel::Doctor => Command::Doctor,
            TopLevel::Status { peer, relay } => Command::Status { peer, relay },
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
            TopLevel::Tcp { local, peer } => Command::Tcp { peer, local },
            TopLevel::Udp { local, peer } => Command::Udp { peer, local },
            TopLevel::Mint {
                caps,
                ttl,
                to,
                from,
                print,
                endpoint,
            } => Command::Mint {
                caps,
                ttl,
                to,
                from,
                print,
                endpoint,
            },
            TopLevel::Revoke { id, list, publish } => Command::Revoke { id, list, publish },
            TopLevel::Install {
                target,
                apply,
                yes,
                detect,
                dry_run,
            } => Command::Install {
                target,
                apply,
                yes,
                detect,
                dry_run,
            },
            TopLevel::Docker {
                action:
                    DockerAction::Run {
                        image,
                        name,
                        from_binary,
                        watch,
                    },
            } => Command::DockerRun {
                image,
                name,
                from_binary,
                watch,
            },
            TopLevel::Docker {
                action:
                    DockerAction::Attach {
                        container,
                        from_binary,
                    },
            } => Command::DockerAttach {
                container,
                from_binary,
            },
            TopLevel::Docker {
                action: DockerAction::Detach { container },
            } => Command::DockerDetach { container },
            TopLevel::Docker {
                action: DockerAction::List { json },
            } => Command::DockerList { json },
            TopLevel::Docker {
                action:
                    DockerAction::Rm {
                        name,
                        force,
                        keep_tickets,
                    },
            } => Command::DockerRm {
                name,
                force,
                keep_tickets,
            },
            TopLevel::Docker {
                action:
                    DockerAction::Bake {
                        base_image,
                        output,
                        tag,
                        push,
                        init_shim,
                    },
            } => Command::DockerBake {
                base_image,
                output,
                tag,
                push,
                init_shim,
            },
            TopLevel::Slicer {
                action:
                    SlicerAction::Run {
                        image,
                        base_url,
                        cpus,
                        ram_gb,
                        tags,
                        ticket_out,
                    },
            } => Command::SlicerRun {
                image,
                base_url,
                cpus,
                ram_gb,
                tags,
                ticket_out,
            },
            TopLevel::Slicer {
                action: SlicerAction::List { base_url, json },
            } => Command::SlicerList { base_url, json },
            TopLevel::Slicer {
                action: SlicerAction::Rm { name, base_url },
            } => Command::SlicerRm { name, base_url },
            TopLevel::Slicer {
                action: SlicerAction::Bake { base_image },
            } => Command::SlicerBake { base_image },
            TopLevel::Gateway { upstream_url } => Command::Gateway { upstream_url },
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
        }
    }
}

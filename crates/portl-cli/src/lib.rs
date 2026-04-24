//! Library surface of the portl CLI.
//!
//! The binary's `main` is a thin shim over [`run`]. Keeping the
//! dispatch logic exposed as a library function lets integration
//! tests drive the CLI without spawning subprocesses. Command
//! parsing is further split into [`parse`] so tests can assert
//! on a structured [`Command`] value without caring about
//! stdout, exit codes, or process setup.

mod agent_ipc;
mod alias_store;
mod client_endpoint;
mod commands;
mod eid;
mod logging;
mod release_binary;

pub use commands::config::ConfigAction;
pub use commands::init::InitRole;
pub use commands::install::InstallTarget;
pub use commands::status::run_with_identity_path as run_status_with_identity_path;
pub use commands::status::run_with_identity_path_and_endpoint as run_status_with_identity_path_and_endpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InitiatorMode {
    Mutual,
    Me,
    Them,
}

impl From<InitiatorMode> for portl_core::pair_code::InitiatorMode {
    fn from(value: InitiatorMode) -> Self {
        match value {
            InitiatorMode::Mutual => Self::Mutual,
            InitiatorMode::Me => Self::Me,
            InitiatorMode::Them => Self::Them,
        }
    }
}

use std::{ffi::OsString, path::Path, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};

pub fn load_agent_config() -> anyhow::Result<portl_agent::AgentConfig> {
    commands::agent::run::load_config(None, None)
}

/// Structured representation of a parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `portl-agent` daemon entrypoint. Also reached by `portl-gateway`
    /// after the multicall rewrite sets `mode = Gateway`.
    AgentRun {
        mode: Option<AgentModeArg>,
        upstream_url: Option<String>,
    },
    Init {
        force: bool,
        role: Option<InitRole>,
        quiet: bool,
    },
    Doctor {
        fix: bool,
        yes: bool,
        verbose: bool,
        json: bool,
        quiet: bool,
    },
    Status {
        target: Option<String>,
        relay: bool,
        json: bool,
        watch: Option<u64>,
        count: u32,
        timeout: std::time::Duration,
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
    // v0.3.0: peer / ticket / whoami replace top-level mint + revoke.
    PeerLs {
        json: bool,
        active: bool,
    },
    PeerRm {
        label: String,
    },
    PeerAddUnsafeRaw {
        endpoint: String,
        label: Option<String>,
        mutual: bool,
        inbound: bool,
        outbound: bool,
        yes: bool,
    },
    InviteIssue {
        initiator: InitiatorMode,
        ttl: Option<String>,
        for_label: Option<String>,
        json: bool,
        yes: bool,
    },
    InviteLs {
        json: bool,
    },
    InviteRm {
        prefix: String,
    },
    Accept {
        code: String,
        yes: bool,
    },
    TicketIssue {
        caps: Option<String>,
        ttl: String,
        to: Option<String>,
        from: Option<String>,
        print: MintRootPrint,
        endpoint: Option<String>,
    },
    TicketCaps {
        cap: Option<String>,
        json: bool,
    },
    TicketSave {
        label: String,
        ticket: Option<String>,
    },
    TicketLs {
        json: bool,
    },
    TicketRm {
        label: String,
    },
    TicketPrune,
    TicketRevoke {
        id: Option<String>,
        action: Option<RevokeAction>,
    },
    Whoami {
        eid: bool,
        json: bool,
    },
    Config {
        action: ConfigAction,
    },
    Install {
        target: Option<InstallTarget>,
        apply: bool,
        yes: bool,
        detect: bool,
        dry_run: bool,
        output: Option<PathBuf>,
    },
    DockerRun {
        image: String,
        name: Option<String>,
        from_binary: Option<PathBuf>,
        from_release: Option<String>,
        watch: bool,
        env: Vec<String>,
        volume: Vec<String>,
        network: Option<String>,
        user: Option<String>,
    },
    DockerAttach {
        container: String,
        from_binary: Option<PathBuf>,
        from_release: Option<String>,
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
        from_binary: Option<PathBuf>,
        from_release: Option<String>,
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
    Gateway {
        upstream_url: String,
    },
    Completions {
        shell: clap_complete::Shell,
    },
    Man {
        out_dir: Option<PathBuf>,
        section: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeAction {
    Ls { json: bool },
    Publish { id: Option<String>, yes: bool },
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
const EX_USAGE: u8 = 2;

fn clap_exit_code(err: &clap::Error) -> ExitCode {
    match err.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(EX_USAGE),
    }
}

fn validate_bool_env(name: &str) -> Result<(), String> {
    let Ok(value) = std::env::var(name) else {
        return Ok(());
    };
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "0" | "1" | "false" | "true" | "no" | "yes" | "off" | "on" => Ok(()),
        _ => Err(format!(
            "{name} must be a boolean value (0/1, true/false, yes/no, on/off), got {value:?}"
        )),
    }
}

pub fn run(argv: Vec<OsString>) -> ExitCode {
    portl_core::tls::install_default_crypto_provider();
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
            return ExitCode::from(EX_USAGE);
        }
        Err(ParseError::Clap(err)) => {
            let code = clap_exit_code(&err);
            let _ = err.print();
            return code;
        }
    }

    let argv = match rewrite_multicall(argv) {
        Ok(argv) => argv,
        Err(ParseError::EmptyArgv) => {
            eprintln!("portl: argv is empty");
            return ExitCode::from(EX_USAGE);
        }
        Err(ParseError::Clap(err)) => {
            let code = clap_exit_code(&err);
            let _ = err.print();
            return code;
        }
    };

    for name in ["PORTL_JSON", "PORTL_QUIET"] {
        if let Err(err) = validate_bool_env(name) {
            eprintln!("error: {err}");
            return ExitCode::from(EX_USAGE);
        }
    }

    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            let code = clap_exit_code(&err);
            let _ = err.print();
            return code;
        }
    };

    logging::init(cli.log_verbose, cli.log.as_deref());

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
        Command::Init { force, role, quiet } => commands::init::run(force, role, quiet),
        Command::Doctor {
            fix,
            yes,
            verbose,
            json,
            quiet,
        } => Ok(commands::doctor::run(commands::doctor::RunOpts {
            fix,
            yes,
            verbose,
            json,
            quiet,
        })),
        Command::Status {
            target,
            relay,
            json,
            watch,
            count,
            timeout,
        } => commands::status::run(target.as_deref(), relay, json, watch, count, timeout),
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
        Command::PeerLs { json, active } => commands::peer::ls::run(json, active),
        Command::PeerRm { label } => commands::peer::unlink::run(&label),
        Command::PeerAddUnsafeRaw {
            endpoint,
            label,
            mutual,
            inbound,
            outbound,
            yes,
        } => commands::peer::add_unsafe_raw::run(&endpoint, label, mutual, inbound, outbound, yes),
        Command::InviteIssue {
            initiator,
            ttl,
            for_label,
            json,
            yes,
        } => commands::peer::invite::issue(
            initiator.into(),
            ttl.as_deref(),
            for_label.as_deref(),
            json,
            yes,
        ),
        Command::InviteLs { json } => commands::peer::invite::list(json),
        Command::InviteRm { prefix } => commands::peer::invite::revoke(&prefix),
        Command::Accept { code, yes } => commands::peer::pair::run(&code, yes),
        Command::TicketIssue {
            caps,
            ttl,
            to,
            from,
            print,
            endpoint,
        } => commands::ticket::issue::run(
            caps.as_deref(),
            &ttl,
            to.as_deref(),
            from.as_deref(),
            print,
            endpoint.as_deref(),
            false,
        ),
        Command::TicketCaps { cap, json } => commands::ticket::caps::run(cap.as_deref(), json),
        Command::TicketSave { label, ticket } => {
            commands::ticket::save::run(&label, ticket.as_deref())
        }
        Command::TicketLs { json } => commands::ticket::ls::run(json),
        Command::TicketRm { label } => commands::ticket::rm::run(&label),
        Command::TicketPrune => commands::ticket::prune::run(),
        Command::TicketRevoke { id, action } => match action {
            None => commands::ticket::revoke::run(id.as_deref(), false, false),
            Some(RevokeAction::Ls { json: _ }) => commands::ticket::revoke::run(None, true, false),
            Some(RevokeAction::Publish { id, yes }) => {
                commands::revocations::publish(id.as_deref(), yes || id.is_none())
            }
        },
        Command::Whoami { eid, json } => commands::whoami::run(eid, json),
        Command::Config { action } => Ok(commands::config::run(action)),
        Command::Install {
            target,
            apply,
            yes,
            detect,
            dry_run,
            output,
        } => commands::install::run(target, apply, yes, detect, dry_run, output.as_deref()),
        Command::DockerRun {
            image,
            name,
            from_binary,
            from_release,
            watch,
            env,
            volume,
            network,
            user,
        } => commands::docker::run(
            &image,
            name.as_deref(),
            from_binary.as_deref(),
            from_release.as_deref(),
            watch,
            &env,
            &volume,
            network.as_deref(),
            user.as_deref(),
        ),
        Command::DockerAttach {
            container,
            from_binary,
            from_release,
        } => commands::docker::attach(&container, from_binary.as_deref(), from_release.as_deref()),
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
            from_binary,
            from_release,
        } => commands::docker::bake(
            &base_image,
            output.as_deref(),
            tag.as_deref(),
            push,
            init_shim,
            from_binary.as_deref(),
            from_release.as_deref(),
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
        Command::Gateway { upstream_url } => {
            commands::agent::run::run(Some(AgentModeArg::Gateway), Some(&upstream_url))
        }
        Command::Completions { shell } => Ok(commands::completions(shell)),
        Command::Man { out_dir, section } => commands::man(out_dir.as_deref(), &section),
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

const PORTL_ABOUT: &str = "portl — peer-to-peer remote access and port forwarding.";

pub const TARGET_HELP: &str = "Target identifier. Accepts any of:\n\n  * peer label    — short name from `portl peer ls`\n  * adapter alias — Docker/Slicer target from `portl docker ls` or `portl slicer ls`\n  * ticket label  — saved ticket from `portl ticket ls`\n  * ticket string — raw `portl...` ticket\n  * endpoint_id   — 64-char hex endpoint id\n\nResolution follows portl's connection cascade: inline ticket, peer label, saved ticket, adapter alias, then endpoint_id.";

const PORTL_AFTER_HELP: &str = "Pair two machines:\n  $ portl init\n  $ portl invite                       # on the other machine\n  $ portl accept PORTLINV-…            # on this machine\n  $ portl shell other-machine          # one-shot interactive shell\n  $ portl session attach other-machine # persistent shell, if available\n\nRun `portl <COMMAND> --help` for details on any subcommand.\n\nEnvironment variables:\n  PORTL_HOME       State directory override.\n  PORTL_CONFIG     Alt portl.toml path.\n  PORTL_JSON       Force --json where supported (0/1).\n  PORTL_QUIET      Force --quiet where supported (0/1).\n  NO_COLOR         Disable color output.\n\nSee `docs/ENV.md` for the full list including relay and internal variables.";

const RELATIONSHIP_HELP: &str = "Relationship between portl trust objects:\n\n                    peer              invite                ticket\nOwns on disk        peers.json        pending_invites.json   tickets.json + revocations.jsonl\nLifecycle           permanent         ephemeral (single-use) scoped by TTL\nWhen created        on accept         by `portl invite`      by `portl ticket issue`\nWhen consumed       on rm             on `portl accept`      every connection/operation\n\nWorkflow:\n    first contact     →  `portl invite` + `portl accept`       (writes peer row)\n    day-to-day auth   →  `portl shell <target>`                (one-shot terminal)\n    persistent auth   →  `portl session attach <target>`       (persistent terminal, if available)\n    advanced: bounded →  `portl ticket issue` + `ticket save`  (explicit permission)";

const INVITE_AFTER_HELP: &str = "Examples:\n  portl invite                              # mutual pair, 1h TTL\n  portl invite --initiator me --for cust    # remote-support invite\n  portl invite --ttl 10m --for laptop\n  portl invite ls\n  portl invite rm abc123\n\nRelationship between portl trust objects:\n\n                    peer              invite                ticket\nOwns on disk        peers.json        pending_invites.json   tickets.json + revocations.jsonl\nLifecycle           permanent         ephemeral (single-use) scoped by TTL\nWhen created        on accept         by `portl invite`      by `portl ticket issue`\nWhen consumed       on rm             on `portl accept`      every connection/operation\n\nWorkflow:\n    first contact     →  `portl invite` + `portl accept`       (writes peer row)\n    day-to-day auth   →  `portl shell <target>`                (one-shot terminal)\n    persistent auth   →  `portl session attach <target>`       (persistent terminal, if available)\n    advanced: bounded →  `portl ticket issue` + `ticket save`  (explicit permission)";

const ACCEPT_AFTER_HELP: &str =
    "Examples:\n  portl accept PORTLINV-ABCDEFGH…\n  portl accept --yes PORTLINV-ABCDEFGH…";

#[derive(Parser, Debug)]
#[command(name = "portl", bin_name = "portl", version, about = PORTL_ABOUT, after_long_help = PORTL_AFTER_HELP)]
struct Cli {
    /// Increase logging; in doctor, also show passing checks.
    #[arg(id = "log-verbose", short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    log_verbose: u8,
    /// RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`.
    #[arg(long = "log", global = true, value_name = "FILTER")]
    log: Option<String>,
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Parser, Debug)]
#[command(name = "portl-agent", bin_name = "portl-agent", version, about = "portl-agent daemon entrypoint", long_about = None)]
struct AgentCli {}

#[derive(Subcommand, Debug)]
enum TopLevel {
    /// Create identity, run doctor, and print next steps.
    #[command(next_help_heading = "Setup", display_order = 10)]
    Init {
        /// Overwrite any existing local identity.
        #[arg(long)]
        force: bool,
        /// Tune next-step copy for this machine's role.
        #[arg(long, value_enum)]
        role: Option<InitRole>,
        /// Suppress the doctor table and welcome banner.
        #[arg(long, short = 'q')]
        quiet: bool,
    },
    /// Print strictly local diagnostics (clock, identity, listener bind, discovery config, ticket expiry).
    #[command(display_order = 20)]
    Doctor {
        /// Attempt to auto-remediate warnings where possible. Currently handles
        /// duplicate launchd / systemd services (bootout + rm the wrong lane).
        #[arg(long)]
        fix: bool,
        /// Skip confirmation prompts. Required in non-TTY contexts when --fix is set.
        #[arg(long)]
        yes: bool,
        /// Emit structured JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Report health for this machine or probe a target.
    #[command(next_help_heading = "Connect", display_order = 100)]
    Status {
        #[arg(help = TARGET_HELP)]
        target: Option<String>,
        /// Force the handshake over the target's relay path.
        #[arg(long, requires = "target")]
        relay: bool,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
        /// Re-render every N seconds (min 1, max 3600). Self dashboard only.
        #[arg(long, value_name = "SECS", conflicts_with = "target")]
        watch: Option<u64>,
        /// Probe N times with one-second intervals. Target mode only.
        #[arg(long, requires = "target", default_value_t = 1)]
        count: u32,
        /// Fail a single probe after this duration (for example, 500ms or 3s).
        #[arg(long, requires = "target", default_value = "5s", value_parser = humantime::parse_duration)]
        timeout: std::time::Duration,
    },
    /// Open an interactive remote PTY shell.
    #[command(display_order = 110)]
    Shell {
        #[arg(help = TARGET_HELP)]
        peer: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
    /// Run a remote command without a PTY.
    #[command(display_order = 120)]
    Exec {
        #[arg(help = TARGET_HELP)]
        peer: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Set up one or more local TCP forwards.
    #[command(display_order = 130)]
    Tcp {
        /// Local forward spec: `[LOCAL_HOST:]LOCAL_PORT:REMOTE_HOST:REMOTE_PORT`.
        #[arg(short = 'L', required = true)]
        local: Vec<String>,
        #[arg(help = TARGET_HELP)]
        peer: String,
    },
    /// Set up one or more local UDP forwards.
    #[command(display_order = 140)]
    Udp {
        /// Local forward spec: `[LOCAL_HOST:]LOCAL_PORT:REMOTE_HOST:REMOTE_PORT`.
        #[arg(short = 'L', required = true)]
        local: Vec<String>,
        #[arg(help = TARGET_HELP)]
        peer: String,
    },
    /// Manage paired machines.
    #[command(next_help_heading = "Trust", display_order = 50, after_long_help = RELATIONSHIP_HELP)]
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },
    /// Issue codes to pair with new machines.
    #[command(next_help_heading = "Trust", display_order = 60, after_long_help = INVITE_AFTER_HELP, args_conflicts_with_subcommands = true)]
    Invite {
        #[command(subcommand)]
        action: Option<InviteAction>,
        /// Who can open connections after pairing. Default: mutual.
        #[arg(long, value_enum)]
        initiator: Option<InitiatorMode>,
        /// Time-to-live. Seconds or s/m/h/d shorthand. Default: 1h.
        #[arg(long)]
        ttl: Option<String>,
        /// Hint the acceptor should use as the local peer label.
        #[arg(long = "for")]
        for_label: Option<String>,
        /// Emit the issued code and metadata as JSON.
        #[arg(long)]
        json: bool,
        /// Skip the confirmation prompt. Implied in non-TTY.
        #[arg(long)]
        yes: bool,
    },
    /// Consume an invite code.
    #[command(next_help_heading = "Pairing", display_order = 70, after_long_help = ACCEPT_AFTER_HELP)]
    Accept {
        /// PORTLINV-… code received from the inviter.
        code: String,
        /// Skip the confirmation prompt. Implied in non-TTY.
        #[arg(long)]
        yes: bool,
    },
    /// Manage bounded permission tickets.
    #[command(next_help_heading = "Permissions", display_order = 200, after_long_help = RELATIONSHIP_HELP)]
    Ticket {
        #[command(subcommand)]
        action: TicketAction,
    },
    /// Print the local identity's `endpoint_id` and peer-store label.
    #[command(next_help_heading = "Setup", display_order = 50)]
    Whoami {
        /// Print only the 64-char `endpoint_id` hex (script-friendly).
        #[arg(long, conflicts_with = "json")]
        eid: bool,
        /// Emit structured JSON.
        #[arg(long, conflicts_with = "eid")]
        json: bool,
    },
    /// Read or scaffold `portl.toml`.
    #[command(display_order = 40)]
    Config {
        #[command(subcommand)]
        action: ConfigSub,
    },
    /// Install the daemon for a supported target.
    #[command(display_order = 30)]
    Install {
        /// Target service manager or artifact type.
        target: Option<InstallTarget>,
        /// Write the rendered service or artifact to the host.
        #[arg(long, conflicts_with_all = ["output", "detect", "dry_run"])]
        apply: bool,
        /// Skip confirmation prompts when applying changes.
        #[arg(long, requires = "apply")]
        yes: bool,
        /// Detect the host's preferred install target and print it.
        #[arg(long, conflicts_with_all = ["apply", "dry_run", "output"])]
        detect: bool,
        /// Render changes without writing or enabling anything.
        #[arg(long = "dry-run", conflicts_with = "apply")]
        dry_run: bool,
        /// Write rendered output to this path instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Docker target management.
    #[command(next_help_heading = "Integrations", display_order = 300)]
    Docker {
        #[command(subcommand)]
        action: DockerAction,
    },
    /// Slicer target management.
    #[command(display_order = 310)]
    Slicer {
        #[command(subcommand)]
        action: SlicerAction,
    },
    /// Run the slicer HTTP bridge against an upstream API.
    #[command(display_order = 320)]
    Gateway { upstream_url: String },
    /// Generate shell completions.
    #[command(next_help_heading = "Utility", display_order = 400)]
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Generate man pages from the CLI command tree.
    #[command(display_order = 410)]
    Man {
        /// Write one man page per command to this directory.
        #[arg(long = "out-dir")]
        out_dir: Option<PathBuf>,
        /// Man section for generated pages.
        #[arg(long, default_value = "1")]
        section: String,
    },
}

#[derive(Subcommand, Debug)]
enum InviteAction {
    /// Issue a code (explicit form).
    Issue {
        /// Who can open connections after pairing. Default: mutual.
        #[arg(long, value_enum, default_value = "mutual")]
        initiator: InitiatorMode,
        /// Time-to-live. Seconds or s/m/h/d shorthand. Default: 1h.
        #[arg(long)]
        ttl: Option<String>,
        /// Hint the acceptor should use as the local peer label.
        #[arg(long = "for")]
        for_label: Option<String>,
        /// Emit the issued code and metadata as JSON.
        #[arg(long)]
        json: bool,
        /// Skip the confirmation prompt. Implied in non-TTY.
        #[arg(long)]
        yes: bool,
    },
    /// List my pending invites.
    Ls {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Revoke a pending invite.
    Rm {
        /// Nonce prefix of the pending invite to revoke.
        prefix: String,
    },
    /// Consume a code (alias of `portl accept`).
    Accept {
        /// PORTLINV-… code received from the inviter.
        code: String,
        /// Skip the confirmation prompt. Implied in non-TTY.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PeerAction {
    /// List stored peers.
    Ls {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
        /// Overlay live-connection state by querying the agent IPC.
        #[arg(long)]
        active: bool,
    },
    /// Remove a peer by label.
    Rm { label: String },
    /// Add a peer by raw `endpoint_id` without a pairing handshake.
    /// Requires the user to retype the `endpoint_id` at a confirmation
    /// prompt to guard against blind paste-ins; pick exactly one of
    /// --mutual / --inbound / --outbound to set relationship.
    AddUnsafeRaw {
        /// 64-char hex `endpoint_id`.
        endpoint: String,
        #[arg(long)]
        label: Option<String>,
        /// Mutual trust (both sides accept each other's tickets).
        #[arg(long, conflicts_with_all = ["inbound", "outbound"])]
        mutual: bool,
        /// We accept their tickets; they do not accept ours.
        #[arg(long, conflicts_with = "outbound")]
        inbound: bool,
        /// They accept our tickets; we do not accept theirs.
        #[arg(long)]
        outbound: bool,
        /// Skip the retype-to-confirm prompt. Useful in scripts.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TicketAction {
    /// Mint a new ticket signed by the local identity.
    Issue {
        /// Capability spec — see `portl ticket caps` for the grammar.
        caps: String,
        /// Time-to-live for the ticket, e.g. `10m`, `1h`, `30d`, `3600` (seconds).
        #[arg(long, default_value = "30d")]
        ttl: String,
        /// Restrict this ticket to a specific caller `endpoint_id` (64-hex).
        /// Omit for a bearer ticket usable by anyone who has the string.
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "from")]
        from: Option<String>,
        #[arg(short = 'o', long = "print", value_enum, default_value = "string")]
        print: MintRootPrint,
        #[arg(long, hide = true, alias = "node")]
        endpoint: Option<String>,
    },
    /// Print the capability-grammar reference.
    Caps {
        /// Print only this capability entry.
        #[arg(long, value_name = "NAME")]
        cap: Option<String>,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Save a ticket string under a local label.
    Save {
        label: String,
        ticket: Option<String>,
    },
    /// List saved tickets.
    Ls {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove a saved ticket.
    Rm { label: String },
    /// Bulk-remove expired tickets.
    Prune,
    /// Append a local ticket revocation, publish, or list revocations.
    Revoke {
        /// Ticket id, ticket string, or saved-ticket label to revoke locally.
        id: Option<String>,
        #[command(subcommand)]
        action: Option<RevokeSubcommand>,
    },
}

#[derive(Subcommand, Debug)]
enum RevokeSubcommand {
    /// List local revocations.
    Ls {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Broadcast revocations to paired peers.
    Publish {
        /// Publish only this ticket id. Omit to publish all unpushed revocations.
        id: Option<String>,
        /// Skip the confirmation prompt. Implied in non-TTY.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigSub {
    /// Print the effective file-layer config.
    Show {
        /// Emit structured JSON instead of TOML.
        #[arg(long)]
        json: bool,
    },
    /// Print the absolute path to portl.toml.
    Path,
    /// Print a commented default template to stdout.
    Template,
    /// Parse + type-check a `portl.toml`. Defaults to `$PORTL_HOME/portl.toml`.
    Validate {
        /// Path to validate. Defaults to `$PORTL_HOME/portl.toml`.
        #[arg(long = "path", conflicts_with = "stdin")]
        path: Option<PathBuf>,
        /// Read TOML from standard input.
        #[arg(long)]
        stdin: bool,
        /// Emit structured errors as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DockerAction {
    Run {
        image: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "from-binary", conflicts_with = "from_release")]
        from_binary: Option<PathBuf>,
        #[arg(long = "from-release", conflicts_with = "from_binary")]
        from_release: Option<String>,
        #[arg(long)]
        watch: bool,
        #[arg(long = "env")]
        env: Vec<String>,
        #[arg(long = "volume")]
        volume: Vec<String>,
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
    Attach {
        container: String,
        #[arg(long = "from-binary", conflicts_with = "from_release")]
        from_binary: Option<PathBuf>,
        #[arg(long = "from-release", conflicts_with = "from_binary")]
        from_release: Option<String>,
    },
    Detach {
        container: String,
    },
    #[command(name = "ls", alias = "list")]
    Ls {
        /// Emit structured JSON.
        #[arg(long)]
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
        #[arg(long = "from-binary", conflicts_with = "from_release")]
        from_binary: Option<PathBuf>,
        #[arg(long = "from-release", conflicts_with = "from_binary")]
        from_release: Option<String>,
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
    #[command(name = "ls", alias = "list")]
    Ls {
        /// Override the slicer API base URL.
        #[arg(long)]
        base_url: Option<String>,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    Rm {
        name: String,
        #[arg(long, hide = true)]
        base_url: Option<String>,
    },
}

fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

impl Cli {
    #[allow(clippy::too_many_lines)]
    fn into_command(self) -> Command {
        let log_verbose = self.log_verbose;
        match self.command {
            TopLevel::Init { force, role, quiet } => Command::Init {
                force,
                role,
                quiet: quiet || env_flag("PORTL_QUIET"),
            },
            TopLevel::Doctor { fix, yes, json } => Command::Doctor {
                fix,
                yes,
                verbose: log_verbose > 0,
                json: json || env_flag("PORTL_JSON"),
                quiet: env_flag("PORTL_QUIET"),
            },
            TopLevel::Status {
                target,
                relay,
                json,
                watch,
                count,
                timeout,
            } => Command::Status {
                target,
                relay,
                json: json || env_flag("PORTL_JSON"),
                watch,
                count,
                timeout,
            },
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
            TopLevel::Peer {
                action: PeerAction::Ls { json, active },
            } => Command::PeerLs { json, active },
            TopLevel::Peer {
                action: PeerAction::Rm { label },
            } => Command::PeerRm { label },
            TopLevel::Peer {
                action:
                    PeerAction::AddUnsafeRaw {
                        endpoint,
                        label,
                        mutual,
                        inbound,
                        outbound,
                        yes,
                    },
            } => Command::PeerAddUnsafeRaw {
                endpoint,
                label,
                mutual,
                inbound,
                outbound,
                yes,
            },
            TopLevel::Invite {
                action: None,
                initiator,
                ttl,
                for_label,
                json,
                yes,
            } => Command::InviteIssue {
                initiator: initiator.unwrap_or(InitiatorMode::Mutual),
                ttl,
                for_label,
                json: json || env_flag("PORTL_JSON"),
                yes,
            },
            TopLevel::Invite {
                action:
                    Some(InviteAction::Issue {
                        initiator,
                        ttl,
                        for_label,
                        json,
                        yes,
                    }),
                ..
            } => Command::InviteIssue {
                initiator,
                ttl,
                for_label,
                json: json || env_flag("PORTL_JSON"),
                yes,
            },
            TopLevel::Invite {
                action: Some(InviteAction::Ls { json }),
                ..
            } => Command::InviteLs {
                json: json || env_flag("PORTL_JSON"),
            },
            TopLevel::Invite {
                action: Some(InviteAction::Rm { prefix }),
                ..
            } => Command::InviteRm { prefix },
            TopLevel::Invite {
                action: Some(InviteAction::Accept { code, yes }),
                ..
            }
            | TopLevel::Accept { code, yes } => Command::Accept { code, yes },
            TopLevel::Ticket {
                action:
                    TicketAction::Issue {
                        caps,
                        ttl,
                        to,
                        from,
                        print,
                        endpoint,
                    },
            } => Command::TicketIssue {
                caps: Some(caps),
                ttl,
                to,
                from,
                print,
                endpoint,
            },
            TopLevel::Ticket {
                action: TicketAction::Caps { cap, json },
            } => Command::TicketCaps {
                cap,
                json: json || env_flag("PORTL_JSON"),
            },
            TopLevel::Ticket {
                action: TicketAction::Save { label, ticket },
            } => Command::TicketSave { label, ticket },
            TopLevel::Ticket {
                action: TicketAction::Ls { json },
            } => Command::TicketLs { json },
            TopLevel::Ticket {
                action: TicketAction::Rm { label },
            } => Command::TicketRm { label },
            TopLevel::Ticket {
                action: TicketAction::Prune,
            } => Command::TicketPrune,
            TopLevel::Ticket {
                action: TicketAction::Revoke { id, action },
            } => Command::TicketRevoke {
                id,
                action: action.map(|action| match action {
                    RevokeSubcommand::Ls { json } => RevokeAction::Ls {
                        json: json || env_flag("PORTL_JSON"),
                    },
                    RevokeSubcommand::Publish { id, yes } => RevokeAction::Publish { id, yes },
                }),
            },
            TopLevel::Whoami { eid, json } => Command::Whoami { eid, json },
            TopLevel::Config { action } => Command::Config {
                action: match action {
                    ConfigSub::Show { json } => ConfigAction::Show {
                        json: json || env_flag("PORTL_JSON"),
                    },
                    ConfigSub::Path => ConfigAction::Path,
                    ConfigSub::Template => ConfigAction::Template,
                    ConfigSub::Validate { path, stdin, json } => ConfigAction::Validate {
                        path,
                        stdin,
                        json: json || env_flag("PORTL_JSON"),
                    },
                },
            },
            TopLevel::Install {
                target,
                apply,
                yes,
                detect,
                dry_run,
                output,
            } => Command::Install {
                target,
                apply,
                yes,
                detect,
                dry_run,
                output,
            },
            TopLevel::Docker {
                action:
                    DockerAction::Run {
                        image,
                        name,
                        from_binary,
                        from_release,
                        watch,
                        env,
                        volume,
                        network,
                        user,
                    },
            } => Command::DockerRun {
                image,
                name,
                from_binary,
                from_release,
                watch,
                env,
                volume,
                network,
                user,
            },
            TopLevel::Docker {
                action:
                    DockerAction::Attach {
                        container,
                        from_binary,
                        from_release,
                    },
            } => Command::DockerAttach {
                container,
                from_binary,
                from_release,
            },
            TopLevel::Docker {
                action: DockerAction::Detach { container },
            } => Command::DockerDetach { container },
            TopLevel::Docker {
                action: DockerAction::Ls { json },
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
                        from_binary,
                        from_release,
                    },
            } => Command::DockerBake {
                base_image,
                output,
                tag,
                push,
                init_shim,
                from_binary,
                from_release,
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
                action: SlicerAction::Ls { base_url, json },
            } => Command::SlicerList { base_url, json },
            TopLevel::Slicer {
                action: SlicerAction::Rm { name, base_url },
            } => Command::SlicerRm { name, base_url },
            TopLevel::Gateway { upstream_url } => Command::Gateway { upstream_url },
            TopLevel::Completions { shell } => Command::Completions { shell },
            TopLevel::Man { out_dir, section } => Command::Man { out_dir, section },
        }
    }
}

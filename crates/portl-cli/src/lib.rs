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
pub use commands::session::SessionHistoryFormat;
pub use commands::status::run_with_identity_path as run_status_with_identity_path;
pub use commands::status::run_with_identity_path_and_endpoint as run_status_with_identity_path_and_endpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InitiatorMode {
    Mutual,
    Me,
    Them,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SshConfigMode {
    /// Generate a no-sshd `ProxyCommand` config backed by `portl ssh --stdio`.
    NativeProxycommand,
    /// Generate a `ProxyCommand` config that tunnels to a real sshd on the Portl target.
    SshdProxy,
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

#[cfg(feature = "ghostty-vt")]
use anyhow::Context as _;
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
    AgentLifecycle {
        action: AgentAction,
        json: bool,
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
        bundle: bool,
        output: Option<PathBuf>,
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
        forward_l: Vec<String>,
        forward_r: Vec<String>,
    },
    SessionProviders {
        target: Option<String>,
        json: bool,
    },
    SessionAttach {
        session: Option<String>,
        target: Option<String>,
        provider: Option<String>,
        user: Option<String>,
        cwd: Option<String>,
        forward_l: Vec<String>,
        forward_r: Vec<String>,
        argv: Vec<String>,
    },
    SessionLs {
        target_ref: Option<String>,
        target: Option<String>,
        provider: Option<String>,
        json: bool,
    },
    SessionRun {
        session: Option<String>,
        target: Option<String>,
        provider: Option<String>,
        argv: Vec<String>,
    },
    SessionHistory {
        session: Option<String>,
        target: Option<String>,
        provider: Option<String>,
        format: SessionHistoryFormat,
    },
    SessionKill {
        session: Option<String>,
        target: Option<String>,
        provider: Option<String>,
    },
    SessionShare {
        session: String,
        target: Option<String>,
        provider: Option<String>,
        ttl: std::time::Duration,
        access_ttl: std::time::Duration,
        label: Option<String>,
        rendezvous_url: Option<String>,
        yes: bool,
        allow_bearer_fallback: bool,
    },
    Exec {
        peer: String,
        cwd: Option<String>,
        user: Option<String>,
        argv: Vec<String>,
    },
    Ssh {
        peer: String,
        user: Option<String>,
        tty: Option<bool>,
        forward_agent: bool,
        stdin_null: bool,
        stdio: bool,
        quiet: bool,
        verbose: u8,
        forward_l: Vec<String>,
        forward_r: Vec<String>,
        remote_command: Vec<String>,
    },
    SshProxy {
        peer: String,
        host: String,
        port: u16,
        forward_l: Vec<String>,
        forward_r: Vec<String>,
    },
    SshConfig {
        mode: SshConfigMode,
        target: String,
        host_alias: Option<String>,
        remote_host: String,
        remote_port: u16,
        portl_bin: String,
    },
    Tcp {
        peer: String,
        local: Vec<String>,
    },
    Udp {
        peer: String,
        local: Vec<String>,
    },
    Socket {
        peer: String,
        local: Option<String>,
        connect: Option<String>,
        listen: Option<String>,
        socket_l: Vec<String>,
        socket_r: Vec<String>,
        cleanup: bool,
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
        label: Option<String>,
        rendezvous_url: Option<String>,
        timeout: std::time::Duration,
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
        session_provider: Option<String>,
    },
    DockerAttach {
        container: String,
        from_binary: Option<PathBuf>,
        from_release: Option<String>,
        session_provider: Option<String>,
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
        session_provider: Option<String>,
    },
    SlicerRun {
        image: String,
        base_url: Option<String>,
        cpus: Option<u8>,
        ram_gb: Option<u16>,
        tags: Vec<String>,
        ticket_out: Option<PathBuf>,
        session_provider: Option<String>,
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
    GhosttySessionHelper {
        name: String,
        socket_path: PathBuf,
        state_root: PathBuf,
        cwd: Option<String>,
        rows: u16,
        cols: u16,
        argv: Vec<String>,
    },
    GhosttySmoke,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum AgentAction {
    /// Show installed service, running process, and IPC status.
    Status {
        /// Exit based on service-manager configuration instead of IPC health.
        #[arg(long)]
        service: bool,
    },
    /// Install/enable/start the agent service.
    Up,
    /// Stop/disable/unload the agent service, keeping binaries and state.
    Down,
    /// Restart the installed agent service.
    Restart,
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
    if is_hidden_ghostty_command_invocation(&argv)? {
        let cli = Cli::try_parse_from(argv)?;
        return Ok(cli.into_command());
    }
    if is_portl_agent_invocation(&argv)? {
        let cli = AgentCli::try_parse_from(argv)?;
        return Ok(agent_cli_to_command(&cli));
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

fn dispatch_command(command: Command) -> ExitCode {
    match dispatch(command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone)]
struct CommandLogContext {
    command_id: String,
    argv: Vec<String>,
    cwd: String,
}

fn command_log_context(argv: &[OsString]) -> CommandLogContext {
    let argv_strings = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let started_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    CommandLogContext {
        command_id: format!("{}-{started_nanos}", std::process::id()),
        argv: portl_core::diagnostics::redact_argv(&argv_strings),
        cwd: std::env::current_dir().map_or_else(
            |_| "<unknown>".to_owned(),
            |path| path.display().to_string(),
        ),
    }
}

fn dispatch_command_logged(command: Command, context: &CommandLogContext) -> ExitCode {
    let command_name = command_log_name(&command);
    let started = std::time::Instant::now();
    tracing::info!(
        event = "cli.command.start",
        command_id = %context.command_id,
        command = command_name,
        argv = ?context.argv,
        cwd = %context.cwd,
    );
    match dispatch(command) {
        Ok(code) => {
            tracing::info!(
                event = "cli.command.finish",
                command_id = %context.command_id,
                command = command_name,
                exit_code = exit_code_u8(code),
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
            code
        }
        Err(err) => {
            let log_error = portl_core::diagnostics::redact_text(&format!("{err:#}"));
            tracing::error!(
                event = "cli.command.error",
                command_id = %context.command_id,
                command = command_name,
                error = %log_error,
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn exit_code_u8(code: ExitCode) -> u8 {
    u8::from(code != ExitCode::SUCCESS)
}

fn command_log_name(command: &Command) -> &'static str {
    match command {
        Command::AgentRun { .. } => "agent.run",
        Command::AgentLifecycle { .. } => "agent",
        Command::Init { .. } => "init",
        Command::Doctor { .. } => "doctor",
        Command::Status { .. } => "status",
        Command::Shell { .. } => "shell",
        Command::SessionProviders { .. } => "session.providers",
        Command::SessionAttach { .. } => "session.attach",
        Command::SessionLs { .. } => "session.ls",
        Command::SessionRun { .. } => "session.run",
        Command::SessionHistory { .. } => "session.history",
        Command::SessionKill { .. } => "session.kill",
        Command::SessionShare { .. } => "session.share",
        Command::Exec { .. } => "exec",
        Command::Ssh { .. } => "ssh",
        Command::SshProxy { .. } => "ssh.proxy",
        Command::SshConfig { .. } => "ssh.config",
        Command::Tcp { .. } => "tcp",
        Command::Udp { .. } => "udp",
        Command::Socket { .. } => "socket",
        Command::PeerLs { .. } => "peer.ls",
        Command::PeerRm { .. } => "peer.rm",
        Command::PeerAddUnsafeRaw { .. } => "peer.add-unsafe-raw",
        Command::InviteIssue { .. } => "invite.issue",
        Command::InviteLs { .. } => "invite.ls",
        Command::InviteRm { .. } => "invite.rm",
        Command::Accept { .. } => "accept",
        Command::TicketIssue { .. } => "ticket.issue",
        Command::TicketCaps { .. } => "ticket.caps",
        Command::TicketSave { .. } => "ticket.save",
        Command::TicketLs { .. } => "ticket.ls",
        Command::TicketRm { .. } => "ticket.rm",
        Command::TicketPrune => "ticket.prune",
        Command::TicketRevoke { .. } => "ticket.revoke",
        Command::Whoami { .. } => "whoami",
        Command::Config { .. } => "config",
        Command::Install { .. } => "install",
        Command::DockerRun { .. } => "docker.run",
        Command::DockerAttach { .. } => "docker.attach",
        Command::DockerDetach { .. } => "docker.detach",
        Command::DockerList { .. } => "docker.list",
        Command::DockerRm { .. } => "docker.rm",
        Command::DockerBake { .. } => "docker.bake",
        Command::SlicerRun { .. } => "slicer.run",
        Command::SlicerList { .. } => "slicer.list",
        Command::SlicerRm { .. } => "slicer.rm",
        Command::Gateway { .. } => "gateway",
        Command::Completions { .. } => "completions",
        Command::Man { .. } => "man",
        Command::GhosttySessionHelper { .. } => "ghostty.session-helper",
        Command::GhosttySmoke => "ghostty.smoke",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayoutMigrationAction {
    Run,
    Skip,
    StopInstallServiceThenRun(Option<InstallTarget>),
    Refuse(&'static str),
}

fn layout_migration_action(command: &Command) -> LayoutMigrationAction {
    match command {
        Command::Install {
            target: Some(InstallTarget::Dockerfile),
            ..
        } => LayoutMigrationAction::Skip,
        Command::Install {
            apply: true,
            yes: false,
            detect: false,
            dry_run: false,
            ..
        } => LayoutMigrationAction::Refuse("`portl install --apply` requires `--yes`"),
        Command::Install {
            apply: true,
            yes: true,
            detect: false,
            dry_run: false,
            target,
            ..
        } => LayoutMigrationAction::StopInstallServiceThenRun(*target),
        Command::Install { .. } | Command::Doctor { .. } => LayoutMigrationAction::Skip,
        _ => LayoutMigrationAction::Run,
    }
}

#[cfg(test)]
mod service_safe_upgrade_tests {
    use super::{
        Command, InstallTarget, LayoutMigrationAction, command_log_name, layout_migration_action,
    };

    #[test]
    fn install_apply_yes_stops_requested_target_before_migration() {
        assert_eq!(
            layout_migration_action(&Command::Install {
                target: Some(InstallTarget::Openrc),
                apply: true,
                yes: true,
                detect: false,
                dry_run: false,
                output: None,
            }),
            LayoutMigrationAction::StopInstallServiceThenRun(Some(InstallTarget::Openrc))
        );
    }

    #[test]
    fn install_inspection_paths_do_not_migrate() {
        assert_eq!(
            layout_migration_action(&Command::Install {
                target: None,
                apply: false,
                yes: false,
                detect: false,
                dry_run: false,
                output: None,
            }),
            LayoutMigrationAction::Skip
        );
        assert_eq!(
            layout_migration_action(&Command::Install {
                target: None,
                apply: false,
                yes: false,
                detect: true,
                dry_run: false,
                output: None,
            }),
            LayoutMigrationAction::Skip
        );
        assert_eq!(
            layout_migration_action(&Command::Install {
                target: None,
                apply: true,
                yes: false,
                detect: false,
                dry_run: true,
                output: None,
            }),
            LayoutMigrationAction::Skip
        );
    }

    #[test]
    fn dockerfile_install_does_not_migrate() {
        assert_eq!(
            layout_migration_action(&Command::Install {
                target: Some(InstallTarget::Dockerfile),
                apply: true,
                yes: true,
                detect: false,
                dry_run: false,
                output: None,
            }),
            LayoutMigrationAction::Skip
        );
    }

    #[test]
    fn install_apply_without_yes_fails_before_migration() {
        assert_eq!(
            layout_migration_action(&Command::Install {
                target: None,
                apply: true,
                yes: false,
                detect: false,
                dry_run: false,
                output: None,
            }),
            LayoutMigrationAction::Refuse("`portl install --apply` requires `--yes`")
        );
    }

    #[test]
    fn doctor_does_not_migrate_state() {
        assert_eq!(
            layout_migration_action(&Command::Doctor {
                fix: false,
                yes: false,
                verbose: false,
                json: false,
                quiet: false,
                bundle: false,
                output: None,
            }),
            LayoutMigrationAction::Skip
        );
    }

    #[test]
    fn command_log_name_is_stable_for_status_and_doctor() {
        assert_eq!(
            command_log_name(&Command::Status {
                target: Some("vn3".to_owned()),
                relay: true,
                json: false,
                watch: None,
                count: 1,
                timeout: std::time::Duration::from_secs(5),
            }),
            "status"
        );

        assert_eq!(
            command_log_name(&Command::Doctor {
                fix: false,
                yes: false,
                verbose: false,
                json: false,
                quiet: false,
                bundle: false,
                output: None,
            }),
            "doctor"
        );
    }
}

fn prepare_layout_for_command(command: &Command) -> Result<bool, ExitCode> {
    match layout_migration_action(command) {
        LayoutMigrationAction::Skip => Ok(false),
        LayoutMigrationAction::Refuse(message) => {
            eprintln!("{message}");
            Err(ExitCode::FAILURE)
        }
        LayoutMigrationAction::StopInstallServiceThenRun(target) => {
            if let Err(err) = commands::install::stop_existing_agent_for_upgrade(target) {
                eprintln!("portl: stop existing agent before install: {err:#}");
                return Err(ExitCode::FAILURE);
            }
            Ok(true)
        }
        LayoutMigrationAction::Run => {
            if !portl_core::paths::home_is_explicit()
                && let Err(code) = reject_default_home_migration_with_loaded_agent()
            {
                return Err(code);
            }
            Ok(true)
        }
    }
}

fn reject_default_home_migration_with_loaded_agent() -> Result<(), ExitCode> {
    match portl_core::paths::layout_migration_needed() {
        Ok(true) if commands::install::managed_agent_is_loaded() => {
            eprintln!(
                "portl: local state needs migration, but a managed portl-agent service is still loaded. Run the current installer so it can stop the old agent, install the new binary, migrate state, and restart safely."
            );
            Err(ExitCode::FAILURE)
        }
        Ok(_) => Ok(()),
        Err(err) => {
            eprintln!("portl: inspect local state migration: {err:#}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn ensure_layout_migrated_or_exit() -> Result<(), ExitCode> {
    match portl_core::paths::ensure_layout_migrated() {
        Ok(report) => {
            if !report.is_empty() && !env_flag("PORTL_QUIET") {
                eprintln!(
                    "portl: migrated local state to {} ({} files)",
                    report.root.display(),
                    report.moved_count()
                );
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("portl: migrate local state: {err:#}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn dispatch_parse_result(parsed: Result<Command, clap::Error>) -> ExitCode {
    match parsed {
        Ok(command) => dispatch_command(command),
        Err(err) => {
            let code = clap_exit_code(&err);
            let _ = err.print();
            code
        }
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
    commands::session::install_panic_hook();
    portl_core::tls::install_default_crypto_provider();
    match is_hidden_ghostty_command_invocation(&argv) {
        Ok(true) => {
            return dispatch_parse_result(Cli::try_parse_from(argv).map(Cli::into_command));
        }
        Ok(false) => match is_portl_agent_invocation(&argv) {
            Ok(true) => {
                return dispatch_parse_result(
                    AgentCli::try_parse_from(argv).map(|cli| agent_cli_to_command(&cli)),
                );
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
        },
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

    if is_top_level_help_request(&argv) {
        print_top_level_help();
        return ExitCode::SUCCESS;
    }

    let log_context = command_log_context(&argv);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            let code = clap_exit_code(&err);
            let _ = err.print();
            return code;
        }
    };

    logging::init(cli.log_verbose, cli.log.as_deref());
    let command = cli.into_command();
    let should_migrate = match prepare_layout_for_command(&command) {
        Ok(should_migrate) => should_migrate,
        Err(code) => return code,
    };
    if should_migrate && let Err(code) = ensure_layout_migrated_or_exit() {
        return code;
    }

    dispatch_command_logged(command, &log_context)
}

#[allow(clippy::too_many_lines)]
fn dispatch(cmd: Command) -> anyhow::Result<ExitCode> {
    match cmd {
        Command::AgentRun { mode, upstream_url } => {
            commands::agent::run::run(mode, upstream_url.as_deref())
        }
        Command::AgentLifecycle { action, json } => commands::agent::service::run(action, json),
        Command::Init { force, role, quiet } => commands::init::run(force, role, quiet),
        Command::Doctor {
            fix,
            yes,
            verbose,
            json,
            quiet,
            bundle,
            output,
        } => Ok(commands::doctor::run(&commands::doctor::RunOpts {
            fix,
            yes,
            verbose,
            json,
            quiet,
            bundle,
            output,
        })),
        Command::Status {
            target,
            relay,
            json,
            watch,
            count,
            timeout,
        } => commands::status::run(target.as_deref(), relay, json, watch, count, timeout),
        Command::Shell {
            peer,
            cwd,
            user,
            forward_l,
            forward_r,
        } => commands::shell::run(
            &peer,
            cwd.as_deref(),
            user.as_deref(),
            commands::forwarding::ForwardingArgs {
                local: forward_l,
                remote: forward_r,
            },
        ),
        Command::GhosttySessionHelper {
            name,
            socket_path,
            state_root,
            cwd,
            rows,
            cols,
            argv,
        } => run_ghostty_session_helper(name, socket_path, state_root, cwd, rows, cols, argv),
        Command::GhosttySmoke => commands::ghostty_smoke::run(),
        Command::SessionProviders { target, json } => {
            commands::session::providers(target.as_deref(), json)
        }
        Command::SessionAttach {
            target,
            session,
            provider,
            user,
            cwd,
            forward_l,
            forward_r,
            argv,
        } => commands::session::attach(
            session.as_deref(),
            target.as_deref(),
            provider.as_deref(),
            user.as_deref(),
            cwd.as_deref(),
            &argv,
            commands::forwarding::ForwardingArgs {
                local: forward_l,
                remote: forward_r,
            },
        ),
        Command::SessionLs {
            target_ref,
            target,
            provider,
            json,
        } => commands::session::ls(
            target_ref.as_deref(),
            target.as_deref(),
            provider.as_deref(),
            json,
        ),
        Command::SessionRun {
            target,
            session,
            provider,
            argv,
        } => commands::session::run(
            session.as_deref(),
            target.as_deref(),
            provider.as_deref(),
            &argv,
        ),
        Command::SessionHistory {
            target,
            session,
            provider,
            format,
        } => commands::session::history(
            session.as_deref(),
            target.as_deref(),
            provider.as_deref(),
            format,
        ),
        Command::SessionKill {
            target,
            session,
            provider,
        } => commands::session::kill(session.as_deref(), target.as_deref(), provider.as_deref()),
        Command::SessionShare {
            session,
            target,
            provider,
            ttl,
            access_ttl,
            label,
            rendezvous_url,
            yes,
            allow_bearer_fallback,
        } => commands::session::share(
            target.as_deref(),
            &session,
            provider.as_deref(),
            ttl,
            access_ttl,
            label.as_deref(),
            rendezvous_url.as_deref(),
            yes,
            allow_bearer_fallback,
        ),
        Command::Exec {
            peer,
            cwd,
            user,
            argv,
        } => commands::exec::run(&peer, cwd.as_deref(), user.as_deref(), &argv),
        Command::Ssh {
            peer,
            user,
            tty,
            forward_agent,
            stdin_null,
            stdio,
            quiet,
            verbose,
            forward_l,
            forward_r,
            remote_command,
        } => commands::ssh::run(
            &peer,
            user.as_deref(),
            tty,
            forward_agent,
            stdin_null,
            stdio,
            quiet,
            verbose,
            &remote_command,
            commands::forwarding::ForwardingArgs {
                local: forward_l,
                remote: forward_r,
            },
        ),
        Command::SshProxy {
            peer,
            host,
            port,
            forward_l,
            forward_r,
        } => commands::ssh_proxy::run(
            &peer,
            &host,
            port,
            commands::forwarding::ForwardingArgs {
                local: forward_l,
                remote: forward_r,
            },
        ),
        Command::SshConfig {
            mode,
            target,
            host_alias,
            remote_host,
            remote_port,
            portl_bin,
        } => commands::ssh_config::print_config(
            mode,
            &target,
            host_alias.as_deref(),
            &remote_host,
            remote_port,
            &portl_bin,
        ),
        Command::Tcp { peer, local } => commands::tcp::run(&peer, &local),
        Command::Udp { peer, local } => commands::udp::run(&peer, &local),
        Command::Socket {
            peer,
            local,
            connect,
            listen,
            socket_l,
            socket_r,
            cleanup,
        } => commands::socket::run(
            &peer,
            local.as_deref(),
            connect.as_deref(),
            listen.as_deref(),
            &socket_l,
            &socket_r,
            cleanup,
        ),
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
        Command::Accept {
            code,
            yes,
            label,
            rendezvous_url,
            timeout,
        } => commands::accept::run(
            &code,
            yes,
            label.as_deref(),
            rendezvous_url.as_deref(),
            timeout,
        ),
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
            session_provider,
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
            session_provider.as_deref(),
        ),
        Command::DockerAttach {
            container,
            from_binary,
            from_release,
            session_provider,
        } => commands::docker::attach(
            &container,
            from_binary.as_deref(),
            from_release.as_deref(),
            session_provider.as_deref(),
        ),
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
            session_provider,
        } => commands::docker::bake(
            &base_image,
            output.as_deref(),
            tag.as_deref(),
            push,
            init_shim,
            from_binary.as_deref(),
            from_release.as_deref(),
            session_provider.as_deref(),
        ),
        Command::SlicerRun {
            image,
            base_url,
            cpus,
            ram_gb,
            tags,
            ticket_out,
            session_provider,
        } => commands::slicer::run(
            &image,
            base_url.as_deref(),
            cpus,
            ram_gb,
            &tags,
            ticket_out.as_deref(),
            session_provider.as_deref(),
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

#[cfg(feature = "ghostty-vt")]
fn run_ghostty_session_helper(
    name: String,
    socket_path: PathBuf,
    state_root: PathBuf,
    cwd: Option<String>,
    rows: u16,
    cols: u16,
    argv: Vec<String>,
) -> anyhow::Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("spawn ghostty helper runtime")?;
    runtime.block_on(portl_agent::run_ghostty_session_helper(
        name,
        socket_path,
        state_root,
        cwd,
        rows,
        cols,
        argv,
    ))?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "ghostty-vt"))]
fn run_ghostty_session_helper(
    _name: String,
    _socket_path: PathBuf,
    _state_root: PathBuf,
    _cwd: Option<String>,
    _rows: u16,
    _cols: u16,
    _argv: Vec<String>,
) -> anyhow::Result<ExitCode> {
    anyhow::bail!("ghostty-vt support is not built into this portl binary")
}

fn is_hidden_ghostty_command_invocation(argv: &[OsString]) -> Result<bool, ParseError> {
    let _ = argv.first().ok_or(ParseError::EmptyArgv)?;
    Ok(argv
        .get(1)
        .and_then(|arg| arg.to_str())
        .is_some_and(|arg| matches!(arg, "__ghostty-session" | "__ghostty-smoke")))
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
    } else if basename == "portl-ssh" {
        argv[0] = OsString::from("portl");
        argv.insert(1, OsString::from("ssh"));
    }
    Ok(argv)
}

fn is_top_level_help_request(argv: &[OsString]) -> bool {
    matches!(
        argv.get(1).and_then(|arg| arg.to_str()),
        Some("--help" | "-h" | "help")
    ) && argv.len() == 2
}

fn print_top_level_help() {
    println!("{TOP_LEVEL_HELP}");
}

const PORTL_ABOUT: &str = "portl — peer-to-peer remote access and port forwarding.";

pub const TARGET_HELP: &str = "Target identifier. Accepts any of:\n\n  * peer label    — short name from `portl peer ls`\n  * adapter alias — Docker/Slicer target from `portl docker ls` or `portl slicer ls`\n  * ticket label  — saved ticket from `portl ticket ls`\n  * ticket string — raw `portl...` ticket\n  * endpoint_id   — 64-char hex endpoint id\n\nResolution follows portl's connection cascade: inline ticket, peer label, saved ticket, adapter alias, then endpoint_id.";

/// Narrower target help for `portl session share`. The share flow
/// only supports forms where the CLI can mint a fresh root ticket
/// from local identity to a resolved endpoint address; saved tickets
/// and raw ticket strings are intentionally excluded.
pub const SESSION_SHARE_TARGET_HELP: &str = "Target identifier. Supported forms:\n\n  * peer label    — outbound-capable peer from `portl peer ls`\n  * adapter alias — alias backed by an `endpoint_id`\n  * endpoint_id   — 64-char hex endpoint id (or PPPP…SSSS elided form)\n\nSaved tickets and raw `portl…` ticket strings are NOT accepted here:\nthe share flow refuses to delegate a ticket credential to an unknown\nrecipient.";

const SESSION_ENV_HELP: &str = "Session environment overrides:\n  PORTL_SESSION_PROVIDER       Preferred persistent-session provider (default, ghostty, herdr, zmx, tmux).\n                              `default` resolves to ghostty.\n  PORTL_SESSION_PROVIDER_PATH  Absolute path to a zmx, tmux, or herdr provider binary.\n  PORTL_HERDR_PATH             Absolute path to the local or target-side herdr binary.\n";

const PORTL_AFTER_HELP: &str = "Everyday sessions:\n  $ portl attach dotfiles\n  $ portl run dotfiles -- git status\n  $ PORTL_TARGET=other-machine portl attach dotfiles\n  $ portl session share dotfiles\n\nPair two machines:\n  $ portl init\n  $ portl invite                       # on the other machine\n  $ portl accept PORTLINV-…            # on this machine\n\nRun `portl <COMMAND> --help` for details on any subcommand.\n\nEnvironment variables:\n  PORTL_HOME       Portl home root override (default: ~/.portl).\n  PORTL_CONFIG     Alt portl.toml path.\n  PORTL_TARGET     Default target for session commands.\n  PORTL_JSON       Force --json where supported (0/1).\n  PORTL_QUIET      Force --quiet where supported (0/1).\n  NO_COLOR         Disable color output.\n\nSession environment overrides:\n  PORTL_SESSION_PROVIDER       Preferred persistent-session provider (default, ghostty, zmx, tmux).\n                              `default` resolves to ghostty.\n  PORTL_SESSION_PROVIDER_PATH  Absolute path to a zmx or tmux provider binary.\n\nSee `docs/ENV.md` for the full list including relay and internal variables.";

const TOP_LEVEL_HELP: &str = "portl — peer-to-peer remote access and port forwarding.

Usage: portl [OPTIONS] <COMMAND>

Setup:
  init         Create identity, run doctor, and print next steps
  doctor       Print strictly local diagnostics (clock, identity, listener bind, discovery config,
               ticket expiry)
  install      Install the daemon for a supported target
  config       Read or scaffold `portl.toml`
  whoami       Print the local identity's `endpoint_id` and peer-store label

Trust:
  peer         Manage paired machines
  invite       Issue codes to pair with new machines

Pairing:
  accept       Consume an invite (PORTLINV-…) or short share (PORTL-S-…)

Sessions:
  attach       Attach to a persistent session
  run          Run a command in a persistent session
  ls           List persistent sessions
  history      Print persistent session history
  kill         Kill a persistent session
  session      Manage persistent terminal sessions

Connect:
  status       Report health for this machine or probe a target
  shell        Open a one-shot remote PTY shell
  exec         Run a one-shot remote command without a persistent session
  ssh          SSH-like native Portl shell/exec command
  ssh-proxy    Proxy stdio to a real sshd reachable from the Portl target
  ssh-config   Emit OpenSSH config snippets for Portl SSH workflows
  tcp          Set up one or more local TCP forwards
  udp          Set up one or more local UDP forwards
  socket       Set up Unix-domain socket forwards

Permissions:
  ticket       Manage bounded permission tickets

Integrations:
  docker       Docker target management
  slicer       Slicer target management
  gateway      Run the slicer HTTP bridge against an upstream API

Utility:
  completions  Generate shell completions
  man          Generate man pages from the CLI command tree
  help         Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
  -V, --version       Print version

Everyday sessions:
  $ portl attach dotfiles
  $ portl run dotfiles -- git status
  $ PORTL_TARGET=other-machine portl attach dotfiles
  $ portl session share dotfiles

Pair two machines:
  $ portl init
  $ portl invite                       # on the other machine
  $ portl accept PORTLINV-…            # on this machine

Run `portl <COMMAND> --help` for details on any subcommand.

Environment variables:
  PORTL_HOME       Portl home root override (default: ~/.portl).
  PORTL_CONFIG     Alt portl.toml path.
  PORTL_TARGET     Default target for session commands.
  PORTL_JSON       Force --json where supported (0/1).
  PORTL_QUIET      Force --quiet where supported (0/1).
  NO_COLOR         Disable color output.

Session environment overrides:
  PORTL_SESSION_PROVIDER       Preferred persistent-session provider (default, ghostty, herdr, zmx, tmux).
                              `default` resolves to ghostty.
  PORTL_SESSION_PROVIDER_PATH  Absolute path to a zmx, tmux, or herdr provider binary.
  PORTL_HERDR_PATH             Absolute path to the local or target-side herdr binary.

See `docs/ENV.md` for the full list including relay and internal variables.";

const TCP_AFTER_HELP: &str = "TCP forwarding examples:\n  portl tcp -L 9090 remote-dev\n      Forwards port 9090 on the current machine to port 9090 on remote-dev.\n\n  portl tcp -L 8080:3000 remote-dev\n      Forwards port 8080 on the current machine to port 3000 on remote-dev.\n\n  portl tcp -L 15432:db.internal:5432 remote-dev\n      Forwards local port 15432 to db.internal:5432 as seen from remote-dev.\n";

const UDP_AFTER_HELP: &str = "UDP forwarding examples:\n  portl udp -L 5353/udp remote-dev\n      Forwards UDP port 5353 on the current machine to UDP port 5353 on remote-dev.\n\n  portl udp -L 1053:dns.internal:53/udp remote-dev\n      Forwards local UDP port 1053 to dns.internal:53 as seen from remote-dev.\n";

const SOCKET_AFTER_HELP: &str = "Socket forwarding quick guide:\n  -L opens a socket on the current machine; traffic exits on the target.\n  -R opens a socket on the target; traffic comes back to this machine.\n\nAssuming this machine is local-dev and the target is remote-dev:\n  -L /run/myapp/api.sock remote-dev\n      creates /tmp/portl-to-remote-dev/api.sock on local-dev\n      and forwards it to remote-dev:/run/myapp/api.sock\n\n  -R /tmp/local-agent.sock remote-dev\n      creates /tmp/portl-from-local-dev/local-agent.sock on remote-dev\n      and forwards it back to local-dev:/tmp/local-agent.sock\n\nExample with both directions:\n  $ portl socket -L /run/herdr/server.sock -R /tmp/herdr-client.sock remote-dev\n\n  local-dev:/tmp/portl-to-remote-dev/server.sock              -> remote-dev:/run/herdr/server.sock\n  remote-dev:/tmp/portl-from-local-dev/herdr-client.sock      -> local-dev:/tmp/herdr-client.sock\n\nIf a generated socket path is already active, Portl refuses to replace it.\nStop the existing forward, or choose an explicit path with LOCAL:REMOTE.";

const RELATIONSHIP_HELP: &str = "Relationship between portl trust objects:\n\n                    peer              invite                ticket\nOwns on disk        peers.json        pending_invites.json   tickets.json + revocations.jsonl\nLifecycle           permanent         ephemeral (single-use) scoped by TTL\nWhen created        on accept         by `portl invite`      by `portl ticket issue`\nWhen consumed       on rm             on `portl accept`      every connection/operation\n\nWorkflow:\n    first contact     →  `portl invite` + `portl accept`       (writes peer row)\n    day-to-day auth   →  `portl shell <target>`                (one-shot terminal)\n    persistent auth   →  `portl attach <session> --target <target>` (persistent terminal, if available)\n    advanced: bounded →  `portl ticket issue` + `ticket save`  (explicit permission)";

const INVITE_AFTER_HELP: &str = "Examples:\n  portl invite                              # mutual pair, 1h TTL\n  portl invite --initiator me --for cust    # remote-support invite\n  portl invite --ttl 10m --for laptop\n  portl invite ls\n  portl invite rm abc123\n\nRelationship between portl trust objects:\n\n                    peer              invite                ticket\nOwns on disk        peers.json        pending_invites.json   tickets.json + revocations.jsonl\nLifecycle           permanent         ephemeral (single-use) scoped by TTL\nWhen created        on accept         by `portl invite`      by `portl ticket issue`\nWhen consumed       on rm             on `portl accept`      every connection/operation\n\nWorkflow:\n    first contact     →  `portl invite` + `portl accept`       (writes peer row)\n    day-to-day auth   →  `portl shell <target>`                (one-shot terminal)\n    persistent auth   →  `portl attach <session> --target <target>` (persistent terminal, if available)\n    advanced: bounded →  `portl ticket issue` + `ticket save`  (explicit permission)";

const ACCEPT_AFTER_HELP: &str = "Generic receiver for codes Portl knows how to consume:\n\n  PORTLINV-…     pairing invite from `portl invite` (peer trust handshake)\n  PORTL-S-…      short online session share (online exchange)\n  PORTL-SHARE1-… offline share token (not yet implemented)\n  portl…         ticket string — use `portl ticket save <label> <ticket>`\n\nExamples:\n  portl accept PORTLINV-ABCDEFGH…\n  portl accept PORTL-S-2-nebula-involve\n  portl accept PORTL-S-2-nebula-involve --label dev-laptop\n  portl accept --yes PORTLINV-ABCDEFGH…";

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
struct AgentCli {
    /// Emit structured JSON where supported.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    action: Option<AgentAction>,
}

fn agent_cli_to_command(cli: &AgentCli) -> Command {
    match cli.action {
        Some(action) => Command::AgentLifecycle {
            action,
            json: cli.json,
        },
        None => Command::AgentRun {
            mode: None,
            upstream_url: None,
        },
    }
}

#[derive(Subcommand, Debug)]
enum TopLevel {
    #[command(flatten, next_help_heading = "Setup", next_display_order = 10)]
    Setup(SetupTopLevel),
    #[command(flatten, next_help_heading = "Trust", next_display_order = 60)]
    Trust(TrustTopLevel),
    #[command(flatten, next_help_heading = "Pairing", next_display_order = 80)]
    Pairing(PairingTopLevel),
    #[command(flatten, next_help_heading = "Sessions", next_display_order = 100)]
    Sessions(SessionTopLevel),
    #[command(flatten, next_help_heading = "Connect", next_display_order = 150)]
    Connect(ConnectTopLevel),
    #[command(flatten, next_help_heading = "Permissions", next_display_order = 200)]
    Permissions(PermissionsTopLevel),
    #[command(flatten, next_help_heading = "Integrations", next_display_order = 300)]
    Integrations(IntegrationsTopLevel),
    #[command(flatten, next_help_heading = "Utility", next_display_order = 400)]
    Utility(UtilityTopLevel),
    #[command(name = "__ghostty-session", hide = true)]
    GhosttySessionHelper {
        #[arg(long)]
        name: String,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long = "state-dir")]
        state_dir: PathBuf,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long, default_value_t = 24)]
        rows: u16,
        #[arg(long, default_value_t = 80)]
        cols: u16,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    #[command(name = "__ghostty-smoke", hide = true)]
    GhosttySmoke,
}

#[derive(Subcommand, Debug)]
enum SetupTopLevel {
    /// Create identity, run doctor, and print next steps.
    #[command(display_order = 10)]
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
        /// Write a support bundle with doctor/status/metrics/log snapshots.
        #[arg(long)]
        bundle: bool,
        /// Bundle output file or directory. Defaults to a timestamped zip in the current directory.
        #[arg(long, value_name = "PATH", requires = "bundle")]
        output: Option<PathBuf>,
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
    /// Read or scaffold `portl.toml`.
    #[command(display_order = 40)]
    Config {
        #[command(subcommand)]
        action: ConfigSub,
    },
    /// Print the local identity's `endpoint_id` and peer-store label.
    #[command(display_order = 50)]
    Whoami {
        /// Print only the 64-char `endpoint_id` hex (script-friendly).
        #[arg(long, conflicts_with = "json")]
        eid: bool,
        /// Emit structured JSON.
        #[arg(long, conflicts_with = "eid")]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TrustTopLevel {
    /// Manage paired machines.
    #[command(display_order = 60, after_long_help = RELATIONSHIP_HELP)]
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },
    /// Issue codes to pair with new machines.
    #[command(display_order = 70, after_long_help = INVITE_AFTER_HELP, args_conflicts_with_subcommands = true)]
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
}

#[derive(Subcommand, Debug)]
enum PairingTopLevel {
    /// Consume an invite code, short online share, or other Portl code.
    #[command(display_order = 80, after_long_help = ACCEPT_AFTER_HELP)]
    Accept {
        /// Code or token to accept: PORTLINV-…, PORTL-S-…, PORTL-SHARE1-…, or a `portl…` ticket.
        #[arg(value_name = "THING")]
        code: String,
        /// Label to use when saving an accepted PORTL-S session share.
        #[arg(long)]
        label: Option<String>,
        /// Rendezvous mailbox URL for PORTL-S shares. Defaults to `PORTL_RENDEZVOUS_URL` or the public-compatible relay.
        #[arg(long)]
        rendezvous_url: Option<String>,
        /// Timeout for online PORTL-S rendezvous.
        #[arg(long, default_value = "10m", value_parser = humantime::parse_duration)]
        timeout: std::time::Duration,
        /// Skip the confirmation prompt. Implied in non-TTY.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum SessionTopLevel {
    /// Attach to a persistent session.
    #[command(display_order = 100)]
    Attach {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        /// Forward from the current machine to the target. Accepts TCP, UDP (/udp), or Unix socket specs.
        #[arg(short = 'L', value_name = "SPEC")]
        forward_l: Vec<String>,
        /// Forward from the target back to this machine. Unix sockets only for now.
        #[arg(short = 'R', value_name = "SPEC")]
        forward_r: Vec<String>,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Run a command in a persistent session.
    #[command(display_order = 101)]
    Run {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// List persistent sessions.
    #[command(display_order = 102)]
    Ls {
        /// Optional target/provider shorthand, e.g. `remote-dev` or `remote-dev/tmux`.
        #[arg(value_name = "TARGET_REF")]
        target_ref: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print persistent session history.
    #[command(display_order = 103)]
    History {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long, value_enum, default_value = "plain")]
        format: SessionHistoryFormat,
    },
    /// Kill a persistent session.
    #[command(display_order = 104)]
    Kill {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
    },
    /// Manage persistent terminal sessions.
    #[command(display_order = 120, after_long_help = SESSION_ENV_HELP)]
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
}

#[derive(Subcommand, Debug)]
enum ConnectTopLevel {
    /// Report health for this machine or probe a target.
    #[command(display_order = 100)]
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
    /// Open a one-shot remote PTY shell.
    #[command(display_order = 160)]
    Shell {
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        peer: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        user: Option<String>,
        /// Forward from the current machine to the target. Accepts TCP, UDP (/udp), or Unix socket specs.
        #[arg(short = 'L', value_name = "SPEC")]
        forward_l: Vec<String>,
        /// Forward from the target back to this machine. Unix sockets only for now.
        #[arg(short = 'R', value_name = "SPEC")]
        forward_r: Vec<String>,
    },
    /// Run a one-shot remote command without a persistent session.
    #[command(display_order = 170)]
    Exec {
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        peer: String,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// SSH-like native Portl shell/exec command.
    #[command(display_order = 175)]
    Ssh {
        /// Login name. Also accepts USER@TARGET in the target position.
        #[arg(short = 'l', value_name = "USER")]
        login_name: Option<String>,
        /// Request SSH-agent forwarding to the remote Portl session.
        #[arg(short = 'A', long = "forward-agent")]
        forward_agent: bool,
        /// Disable SSH-agent forwarding.
        #[arg(short = 'a')]
        disable_agent: bool,
        /// Disable pseudo-terminal allocation.
        #[arg(short = 'T', conflicts_with = "tty")]
        no_tty: bool,
        /// Force pseudo-terminal allocation. Repeat as -tt for OpenSSH compatibility.
        #[arg(short = 't', action = clap::ArgAction::Count, conflicts_with = "no_tty")]
        tty: u8,
        /// Redirect stdin from /dev/null. Parsed for SSH argv compatibility.
        #[arg(short = 'n')]
        stdin_null: bool,
        /// Serve one SSH protocol connection on stdin/stdout for OpenSSH `ProxyCommand`.
        #[arg(long)]
        stdio: bool,
        /// Quiet mode. Parsed for SSH argv compatibility.
        #[arg(short = 'q')]
        quiet: bool,
        /// SSH config option. Parsed for compatibility and ignored by native Portl mode.
        #[arg(short = 'o', value_name = "OPTION", action = clap::ArgAction::Append)]
        option: Vec<String>,
        /// SSH config file. Parsed for compatibility and ignored by native Portl mode.
        #[arg(short = 'F', value_name = "CONFIG")]
        config: Option<String>,
        /// SSH port. Parsed for compatibility and ignored by native Portl mode.
        #[arg(short = 'p', value_name = "PORT")]
        port: Option<String>,
        /// Forward from the current machine to the target. Accepts TCP, UDP (/udp), or Unix socket specs.
        #[arg(short = 'L', value_name = "SPEC")]
        forward_l: Vec<String>,
        /// Forward from the target back to this machine. Unix sockets only for now.
        #[arg(short = 'R', value_name = "SPEC")]
        forward_r: Vec<String>,
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        target: String,
        #[arg(
            value_name = "COMMAND",
            help = "Remote command to execute",
            num_args = 0..,
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        remote_command: Vec<String>,
    },
    /// Proxy stdio to a real sshd reachable from the Portl target.
    #[command(display_order = 176)]
    SshProxy {
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        target: String,
        /// Hostname or address to connect to from the target.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to connect to from the target.
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Forward from the current machine to the target. Accepts TCP, UDP (/udp), or Unix socket specs.
        #[arg(short = 'L', value_name = "SPEC")]
        forward_l: Vec<String>,
        /// Forward from the target back to this machine. Unix sockets only for now.
        #[arg(short = 'R', value_name = "SPEC")]
        forward_r: Vec<String>,
    },
    /// Emit OpenSSH config snippets for Portl SSH workflows.
    #[command(display_order = 177)]
    SshConfig {
        /// Config generation mode.
        #[arg(long, value_enum, default_value_t = SshConfigMode::NativeProxycommand)]
        mode: SshConfigMode,
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        target: String,
        /// OpenSSH Host alias to emit. Defaults to TARGET.
        #[arg(long = "host", value_name = "HOST_ALIAS")]
        host_alias: Option<String>,
        /// Hostname or address of the real sshd from the target.
        #[arg(long = "remote-host", default_value = "127.0.0.1")]
        remote_host: String,
        /// Port of the real sshd from the target.
        #[arg(long = "remote-port", default_value_t = 22)]
        remote_port: u16,
        /// Portl executable name/path to use in `ProxyCommand`.
        #[arg(long = "portl", default_value = "portl")]
        portl_bin: String,
    },
    /// Set up one or more local TCP forwards.
    #[command(display_order = 180, after_long_help = TCP_AFTER_HELP)]
    Tcp {
        /// Local forward spec: `LOCAL_PORT`, `LOCAL_PORT:REMOTE_PORT`, or `[LOCAL_HOST:]LOCAL_PORT:REMOTE_HOST:REMOTE_PORT[/tcp]`.
        #[arg(short = 'L', required = true)]
        local: Vec<String>,
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        peer: String,
    },
    /// Set up one or more local UDP forwards.
    #[command(display_order = 190, after_long_help = UDP_AFTER_HELP)]
    Udp {
        /// Local forward spec: `LOCAL_PORT`, `LOCAL_PORT:REMOTE_PORT`, or `[LOCAL_HOST:]LOCAL_PORT:REMOTE_HOST:REMOTE_PORT[/udp]`.
        #[arg(short = 'L', required = true)]
        local: Vec<String>,
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        peer: String,
    },
    /// Set up Unix-domain socket forwards.
    #[command(display_order = 195, after_long_help = SOCKET_AFTER_HELP)]
    Socket {
        /// Local Unix socket path. In --connect mode this is the local listener; in --listen mode this is the local target socket.
        #[arg(long, value_name = "PATH")]
        local: Option<String>,
        /// Remote Unix socket path to connect to for each local connection.
        #[arg(long, value_name = "REMOTE_PATH", conflicts_with = "listen")]
        connect: Option<String>,
        /// Remote Unix socket path the agent should listen on and reverse-forward back to --local.
        #[arg(long, value_name = "REMOTE_PATH", conflicts_with = "connect")]
        listen: Option<String>,
        /// Unix local forward: `[LOCAL_SOCKET:]REMOTE_SOCKET`. A single path generates the local socket.
        #[arg(short = 'L', value_name = "SPEC")]
        socket_l: Vec<String>,
        /// Unix remote forward: `[REMOTE_SOCKET:]LOCAL_SOCKET`. A single path generates the remote socket.
        #[arg(short = 'R', value_name = "SPEC")]
        socket_r: Vec<String>,
        /// Remove an existing socket path before binding and remove it on exit.
        #[arg(long)]
        cleanup: bool,
        #[arg(help = TARGET_HELP, value_name = "TARGET")]
        peer: String,
    },
}

#[derive(Subcommand, Debug)]
enum PermissionsTopLevel {
    /// Manage bounded permission tickets.
    #[command(display_order = 200, after_long_help = RELATIONSHIP_HELP)]
    Ticket {
        #[command(subcommand)]
        action: TicketAction,
    },
}

#[derive(Subcommand, Debug)]
enum IntegrationsTopLevel {
    /// Docker target management.
    #[command(display_order = 300)]
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
}

#[derive(Subcommand, Debug)]
enum UtilityTopLevel {
    /// Generate shell completions.
    #[command(display_order = 400)]
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
enum SessionAction {
    /// Show available persistent-session providers.
    Providers {
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Attach to a persistent terminal session, creating it when supported.
    Attach {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        /// Forward from the current machine to the target. Accepts TCP, UDP (/udp), or Unix socket specs.
        #[arg(short = 'L', value_name = "SPEC")]
        forward_l: Vec<String>,
        /// Forward from the target back to this machine. Unix sockets only for now.
        #[arg(short = 'R', value_name = "SPEC")]
        forward_r: Vec<String>,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// List persistent sessions.
    Ls {
        /// Optional target/provider shorthand, e.g. `remote-dev` or `remote-dev/tmux`.
        #[arg(value_name = "TARGET_REF")]
        target_ref: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a command in a persistent session.
    Run {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Print persistent session history.
    History {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long, value_enum, default_value = "plain")]
        format: SessionHistoryFormat,
    },
    /// Kill a persistent session.
    Kill {
        /// Session name or HOST/SESSION ref. Defaults to `default`.
        #[arg(value_name = "SESSION")]
        session: Option<String>,
        /// Explicit remote target. Defaults to `PORTL_TARGET`, then local.
        #[arg(long, help = TARGET_HELP)]
        target: Option<String>,
        #[arg(long)]
        provider: Option<String>,
    },
    /// Share a local session with another machine via a `PORTL-S-*` short online code.
    ///
    /// Allocates a short rendezvous code, prints it, and waits for a recipient
    /// to accept. Keep this command running until they accept; the sender
    /// process must stay online for the duration of the exchange. The
    /// recipient runs `portl accept PORTL-S-...` to import the offered
    /// session.
    #[command(
        long_about = "Share local session SESSION via a `PORTL-S-*` short online code.\n\nAllocates a short code, prints it, and waits for a recipient to accept.\nYou must keep this command running until the recipient accepts.\nThe recipient runs `portl accept PORTL-S-...` to import the offered session.\n\nBy default, SESSION is shared from this machine. Use --target only to share a session on another peer explicitly."
    )]
    Share {
        /// Local session name to share.
        session: String,
        /// Explicit target peer/alias/endpoint to share instead of this machine.
        #[arg(long, help = SESSION_SHARE_TARGET_HELP)]
        target: Option<String>,
        /// Persistent-session provider hint (e.g. `zmx`).
        #[arg(long)]
        provider: Option<String>,
        /// Rendezvous TTL (how long the short code stays valid). Default: 10m.
        #[arg(long, default_value = "10m", value_parser = humantime::parse_duration)]
        ttl: std::time::Duration,
        /// TTL for the resulting Portl ticket the recipient gets. Default: 2h.
        #[arg(long = "access-ttl", default_value = "2h", value_parser = humantime::parse_duration)]
        access_ttl: std::time::Duration,
        /// Optional sender label hint shown to the recipient.
        #[arg(long)]
        label: Option<String>,
        /// Override the rendezvous server URL.
        #[arg(long = "rendezvous-url")]
        rendezvous_url: Option<String>,
        /// Skip confirmation prompts.
        #[arg(long)]
        yes: bool,
        /// Allow falling back to a short-lived bearer ticket when the
        /// recipient's identity is not available. Capped to min(access-ttl, 10m).
        #[arg(long = "allow-bearer-fallback")]
        allow_bearer_fallback: bool,
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
    /// Parse + type-check a `portl.toml`. Defaults to `$PORTL_HOME/config/portl.toml`.
    Validate {
        /// Path to validate. Defaults to `$PORTL_HOME/config/portl.toml`.
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
        /// Configure a persistent-session provider inside the target.
        #[arg(long = "session-provider", value_parser = ["zmx"])]
        session_provider: Option<String>,
    },
    Attach {
        container: String,
        #[arg(long = "from-binary", conflicts_with = "from_release")]
        from_binary: Option<PathBuf>,
        #[arg(long = "from-release", conflicts_with = "from_binary")]
        from_release: Option<String>,
        /// Configure a persistent-session provider inside the target.
        #[arg(long = "session-provider", value_parser = ["zmx"])]
        session_provider: Option<String>,
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
        /// Require/configure a persistent-session provider in the baked image.
        #[arg(long = "session-provider", value_parser = ["zmx"])]
        session_provider: Option<String>,
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
        /// Configure a persistent-session provider in VM userdata.
        #[arg(long = "session-provider", value_parser = ["zmx"])]
        session_provider: Option<String>,
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
            TopLevel::Setup(action) => setup_into_command(action, log_verbose),
            TopLevel::Trust(action) => trust_into_command(action),
            TopLevel::Pairing(PairingTopLevel::Accept {
                code,
                yes,
                label,
                rendezvous_url,
                timeout,
            }) => Command::Accept {
                code,
                yes,
                label,
                rendezvous_url,
                timeout,
            },
            TopLevel::Sessions(action) => session_top_level_into_command(action),
            TopLevel::Connect(action) => connect_into_command(action, log_verbose),
            TopLevel::Permissions(action) => permissions_into_command(action),
            TopLevel::Integrations(action) => integrations_into_command(action),
            TopLevel::Utility(UtilityTopLevel::Completions { shell }) => {
                Command::Completions { shell }
            }
            TopLevel::Utility(UtilityTopLevel::Man { out_dir, section }) => {
                Command::Man { out_dir, section }
            }
            TopLevel::GhosttySessionHelper {
                name,
                socket,
                state_dir,
                cwd,
                rows,
                cols,
                argv,
            } => Command::GhosttySessionHelper {
                name,
                socket_path: socket,
                state_root: state_dir,
                cwd,
                rows,
                cols,
                argv,
            },
            TopLevel::GhosttySmoke => Command::GhosttySmoke,
        }
    }
}

fn setup_into_command(action: SetupTopLevel, log_verbose: u8) -> Command {
    match action {
        SetupTopLevel::Init { force, role, quiet } => Command::Init {
            force,
            role,
            quiet: quiet || env_flag("PORTL_QUIET"),
        },
        SetupTopLevel::Doctor {
            fix,
            yes,
            json,
            bundle,
            output,
        } => Command::Doctor {
            fix,
            yes,
            verbose: log_verbose > 0,
            json: json || env_flag("PORTL_JSON"),
            quiet: env_flag("PORTL_QUIET"),
            bundle,
            output,
        },
        SetupTopLevel::Install {
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
        SetupTopLevel::Config { action } => Command::Config {
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
        SetupTopLevel::Whoami { eid, json } => Command::Whoami { eid, json },
    }
}

fn trust_into_command(action: TrustTopLevel) -> Command {
    match action {
        TrustTopLevel::Peer {
            action: PeerAction::Ls { json, active },
        } => Command::PeerLs { json, active },
        TrustTopLevel::Peer {
            action: PeerAction::Rm { label },
        } => Command::PeerRm { label },
        TrustTopLevel::Peer {
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
        TrustTopLevel::Invite {
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
        TrustTopLevel::Invite {
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
        TrustTopLevel::Invite {
            action: Some(InviteAction::Ls { json }),
            ..
        } => Command::InviteLs {
            json: json || env_flag("PORTL_JSON"),
        },
        TrustTopLevel::Invite {
            action: Some(InviteAction::Rm { prefix }),
            ..
        } => Command::InviteRm { prefix },
        TrustTopLevel::Invite {
            action: Some(InviteAction::Accept { code, yes }),
            ..
        } => Command::Accept {
            code,
            yes,
            label: None,
            rendezvous_url: None,
            timeout: std::time::Duration::from_mins(10),
        },
    }
}

#[allow(clippy::too_many_lines)]
fn session_top_level_into_command(action: SessionTopLevel) -> Command {
    match action {
        SessionTopLevel::Attach {
            session,
            target,
            provider,
            user,
            cwd,
            forward_l,
            forward_r,
            argv,
        } => Command::SessionAttach {
            session,
            target,
            provider,
            user,
            cwd,
            forward_l,
            forward_r,
            argv,
        },
        SessionTopLevel::Run {
            session,
            target,
            provider,
            argv,
        } => Command::SessionRun {
            session,
            target,
            provider,
            argv,
        },
        SessionTopLevel::Ls {
            target_ref,
            target,
            provider,
            json,
        } => Command::SessionLs {
            target_ref,
            target,
            provider,
            json: json || env_flag("PORTL_JSON"),
        },
        SessionTopLevel::History {
            session,
            target,
            provider,
            format,
        } => Command::SessionHistory {
            session,
            target,
            provider,
            format,
        },
        SessionTopLevel::Kill {
            session,
            target,
            provider,
        } => Command::SessionKill {
            session,
            target,
            provider,
        },
        SessionTopLevel::Session { action } => session_action_into_command(action),
    }
}

#[allow(clippy::too_many_lines)]
fn session_action_into_command(action: SessionAction) -> Command {
    match action {
        SessionAction::Providers { target, json } => Command::SessionProviders {
            target,
            json: json || env_flag("PORTL_JSON"),
        },
        SessionAction::Attach {
            session,
            target,
            provider,
            user,
            cwd,
            forward_l,
            forward_r,
            argv,
        } => Command::SessionAttach {
            session,
            target,
            provider,
            user,
            cwd,
            forward_l,
            forward_r,
            argv,
        },
        SessionAction::Ls {
            target_ref,
            target,
            provider,
            json,
        } => Command::SessionLs {
            target_ref,
            target,
            provider,
            json: json || env_flag("PORTL_JSON"),
        },
        SessionAction::Run {
            session,
            target,
            provider,
            argv,
        } => Command::SessionRun {
            session,
            target,
            provider,
            argv,
        },
        SessionAction::History {
            session,
            target,
            provider,
            format,
        } => Command::SessionHistory {
            session,
            target,
            provider,
            format,
        },
        SessionAction::Kill {
            session,
            target,
            provider,
        } => Command::SessionKill {
            session,
            target,
            provider,
        },
        SessionAction::Share {
            session,
            target,
            provider,
            ttl,
            access_ttl,
            label,
            rendezvous_url,
            yes,
            allow_bearer_fallback,
        } => Command::SessionShare {
            session,
            target,
            provider,
            ttl,
            access_ttl,
            label,
            rendezvous_url,
            yes,
            allow_bearer_fallback,
        },
    }
}

#[allow(clippy::too_many_lines)]
fn connect_into_command(action: ConnectTopLevel, log_verbose: u8) -> Command {
    match action {
        ConnectTopLevel::Status {
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
        ConnectTopLevel::Shell {
            peer,
            cwd,
            user,
            forward_l,
            forward_r,
        } => Command::Shell {
            peer,
            cwd,
            user,
            forward_l,
            forward_r,
        },
        ConnectTopLevel::Exec {
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
        ConnectTopLevel::Ssh {
            login_name,
            forward_agent,
            disable_agent,
            no_tty,
            tty,
            stdin_null,
            stdio,
            quiet,
            option: _,
            config: _,
            port: _,
            forward_l,
            forward_r,
            target,
            remote_command,
        } => {
            let (target_user, peer) = split_ssh_target(&target);
            let user = login_name.or(target_user);
            let tty = if no_tty {
                Some(false)
            } else if tty > 0 {
                Some(true)
            } else {
                None
            };
            Command::Ssh {
                peer,
                user,
                tty,
                forward_agent: forward_agent && !disable_agent,
                stdin_null,
                stdio,
                quiet,
                verbose: log_verbose,
                forward_l,
                forward_r,
                remote_command,
            }
        }
        ConnectTopLevel::SshProxy {
            target,
            host,
            port,
            forward_l,
            forward_r,
        } => Command::SshProxy {
            peer: target,
            host,
            port,
            forward_l,
            forward_r,
        },
        ConnectTopLevel::SshConfig {
            mode,
            target,
            host_alias,
            remote_host,
            remote_port,
            portl_bin,
        } => Command::SshConfig {
            mode,
            target,
            host_alias,
            remote_host,
            remote_port,
            portl_bin,
        },
        ConnectTopLevel::Tcp { local, peer } => Command::Tcp { peer, local },
        ConnectTopLevel::Udp { local, peer } => Command::Udp { peer, local },
        ConnectTopLevel::Socket {
            peer,
            local,
            connect,
            listen,
            socket_l,
            socket_r,
            cleanup,
        } => Command::Socket {
            peer,
            local,
            connect,
            listen,
            socket_l,
            socket_r,
            cleanup,
        },
    }
}

fn split_ssh_target(target: &str) -> (Option<String>, String) {
    let Some((user, peer)) = target.rsplit_once('@') else {
        return (None, target.to_owned());
    };
    if user.is_empty() || peer.is_empty() {
        return (None, target.to_owned());
    }
    (Some(user.to_owned()), peer.to_owned())
}

#[cfg(test)]
mod ssh_parse_tests {
    use super::split_ssh_target;

    #[test]
    fn ssh_target_splits_optional_user_prefix() {
        assert_eq!(
            split_ssh_target("remote-dev"),
            (None, "remote-dev".to_owned())
        );
        assert_eq!(
            split_ssh_target("devuser@remote-dev"),
            (Some("devuser".to_owned()), "remote-dev".to_owned())
        );
        assert_eq!(
            split_ssh_target("@remote-dev"),
            (None, "@remote-dev".to_owned())
        );
        assert_eq!(split_ssh_target("devuser@"), (None, "devuser@".to_owned()));
    }
}

fn permissions_into_command(action: PermissionsTopLevel) -> Command {
    match action {
        PermissionsTopLevel::Ticket {
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
        PermissionsTopLevel::Ticket {
            action: TicketAction::Caps { cap, json },
        } => Command::TicketCaps {
            cap,
            json: json || env_flag("PORTL_JSON"),
        },
        PermissionsTopLevel::Ticket {
            action: TicketAction::Save { label, ticket },
        } => Command::TicketSave { label, ticket },
        PermissionsTopLevel::Ticket {
            action: TicketAction::Ls { json },
        } => Command::TicketLs { json },
        PermissionsTopLevel::Ticket {
            action: TicketAction::Rm { label },
        } => Command::TicketRm { label },
        PermissionsTopLevel::Ticket {
            action: TicketAction::Prune,
        } => Command::TicketPrune,
        PermissionsTopLevel::Ticket {
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
    }
}

#[allow(clippy::too_many_lines)]
fn integrations_into_command(action: IntegrationsTopLevel) -> Command {
    match action {
        IntegrationsTopLevel::Docker {
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
                    session_provider,
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
            session_provider,
        },
        IntegrationsTopLevel::Docker {
            action:
                DockerAction::Attach {
                    container,
                    from_binary,
                    from_release,
                    session_provider,
                },
        } => Command::DockerAttach {
            container,
            from_binary,
            from_release,
            session_provider,
        },
        IntegrationsTopLevel::Docker {
            action: DockerAction::Detach { container },
        } => Command::DockerDetach { container },
        IntegrationsTopLevel::Docker {
            action: DockerAction::Ls { json },
        } => Command::DockerList { json },
        IntegrationsTopLevel::Docker {
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
        IntegrationsTopLevel::Docker {
            action:
                DockerAction::Bake {
                    base_image,
                    output,
                    tag,
                    push,
                    init_shim,
                    from_binary,
                    from_release,
                    session_provider,
                },
        } => Command::DockerBake {
            base_image,
            output,
            tag,
            push,
            init_shim,
            from_binary,
            from_release,
            session_provider,
        },
        IntegrationsTopLevel::Slicer {
            action:
                SlicerAction::Run {
                    image,
                    base_url,
                    cpus,
                    ram_gb,
                    tags,
                    ticket_out,
                    session_provider,
                },
        } => Command::SlicerRun {
            image,
            base_url,
            cpus,
            ram_gb,
            tags,
            ticket_out,
            session_provider,
        },
        IntegrationsTopLevel::Slicer {
            action: SlicerAction::Ls { base_url, json },
        } => Command::SlicerList { base_url, json },
        IntegrationsTopLevel::Slicer {
            action: SlicerAction::Rm { name, base_url },
        } => Command::SlicerRm { name, base_url },
        IntegrationsTopLevel::Gateway { upstream_url } => Command::Gateway { upstream_url },
    }
}

#[cfg(test)]
mod skipped_test_manifest {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    #[test]
    fn skipped_test_manifest_matches_nextest_inventory() {
        if Command::new("zig").arg("version").output().is_err() {
            eprintln!(
                "skipped-test manifest gate skipped: zig is required to enumerate \
                 ghostty-vt features but is not on PATH"
            );
            return;
        }

        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("portl-cli lives under crates/portl-cli")
            .to_path_buf();
        let script = workspace_root.join("scripts/check-skipped-tests.py");
        let output = Command::new("python3")
            .arg(&script)
            .current_dir(&workspace_root)
            .env(
                "CARGO_TARGET_DIR",
                workspace_root.join("target/skipped-test-manifest"),
            )
            .output()
            .expect("failed to run skipped-test manifest checker");

        assert!(
            output.status.success(),
            "skipped-test manifest checker failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

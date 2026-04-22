//! Audit logging helpers.
//!
//! Security note: never log passphrases or full argv vectors. Exec audit
//! records intentionally include only `argv[0]` because later arguments may
//! carry secrets.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use tracing::Level;
use tracing_subscriber::{EnvFilter, prelude::*};

use crate::session::Session;

static AUDIT_INIT: OnceLock<()> = OnceLock::new();
static SHELL_EXIT_AUDIT_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

pub(crate) fn init() {
    let () = *AUDIT_INIT.get_or_init(|| {
        let _ = SHELL_EXIT_AUDIT_FILE.get_or_init(init_shell_exit_audit_file);
        // Default to INFO for the agent's own crates and WARN for
        // noisy deps (iroh / quinn / rustls / h2 / hickory / pkarr).
        // Operators override via `RUST_LOG` env var as usual.
        // Without this, tracing_subscriber defaults to TRACE which
        // is unusable in production.
        let default_filter = "info,\
            iroh=warn,iroh_net=warn,iroh_quinn=warn,iroh_relay=warn,\
            iroh_base=warn,iroh_dns=warn,\
            quinn=warn,quinn_proto=warn,quinn_udp=warn,\
            rustls=warn,h2=warn,hickory_proto=warn,hickory_resolver=warn,\
            pkarr=warn,mainline=warn,portmapper=warn,netwatch=warn";
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

        #[cfg(target_os = "linux")]
        {
            if let Ok(layer) = tracing_journald::layer() {
                let _ = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(layer)
                    .try_init();
                return;
            }
        }

        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init();
    });
}

pub(crate) fn ticket_accepted(session: &Session) {
    tracing::event!(
        Level::INFO,
        event = "audit.ticket_accepted",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id = %hex::encode(session.ticket_id),
    );
}

pub(crate) fn shell_start(
    session: &Session,
    session_id: &str,
    mode: &'static str,
    pid: u32,
    user: Option<&str>,
    argv: Option<&Vec<String>>,
) {
    tracing::event!(
        Level::INFO,
        event = "audit.shell_start",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id = %hex::encode(session.ticket_id),
        session_id = session_id,
        pid,
        mode,
        shell_user = user.unwrap_or(""),
        shell_argv0 = argv.and_then(|argv| argv.first()).map_or("", String::as_str),
    );
}

/// Emit an `audit.shell_reject` record when a shell/exec request is
/// refused before spawn. `reason` is one of the enumerated strings
/// defined in spec 150 §3.2 (`path_probe_failed`, `uid_lookup_failed`,
/// `user_switch_refused`, `pty_allocation_failed`, `caps_denied`,
/// `argv_empty`).
pub(crate) fn shell_reject(session: &Session, reason: &'static str) {
    tracing::event!(
        Level::INFO,
        event = "audit.shell_reject",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id = %hex::encode(session.ticket_id),
        reason = reason,
    );
}

pub(crate) fn shell_exit_raw(
    ticket_id: [u8; 16],
    caller_endpoint_id: [u8; 32],
    session_id: &str,
    pid: u32,
    exit_code: i32,
    duration_ms: u64,
) {
    tracing::event!(
        Level::INFO,
        event = "audit.shell_exit",
        caller_endpoint_id = %hex::encode(caller_endpoint_id),
        ticket_id = %hex::encode(ticket_id),
        session_id = session_id,
        pid,
        exit_code,
        duration_ms,
    );

    if let Some(file) = SHELL_EXIT_AUDIT_FILE
        .get_or_init(init_shell_exit_audit_file)
        .as_ref()
    {
        let mut file = file.lock().expect("shell exit audit file mutex");
        let _ = writeln!(
            file,
            "{{\"event\":\"audit.shell_exit\",\"caller_endpoint_id\":\"{}\",\"ticket_id\":\"{}\",\"session_id\":\"{}\",\"pid\":{},\"exit_code\":{},\"duration_ms\":{}}}",
            hex::encode(caller_endpoint_id),
            hex::encode(ticket_id),
            session_id,
            pid,
            exit_code,
            duration_ms,
        );
        let _ = file.flush();
    }
}

pub(crate) fn sync_shell_exit_records() {
    if let Some(file) = SHELL_EXIT_AUDIT_FILE
        .get_or_init(init_shell_exit_audit_file)
        .as_ref()
    {
        let file = file.lock().expect("shell exit audit file mutex");
        let _ = file.sync_all();
    }
}

fn init_shell_exit_audit_file() -> Option<Mutex<File>> {
    let path = std::env::var_os("PORTL_AUDIT_SHELL_EXIT_PATH").map(PathBuf::from)?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()?;
    Some(Mutex::new(file))
}

pub(crate) fn tcp_connect(session: &Session, host: &str, port: u16) {
    tracing::event!(
        Level::INFO,
        event = "audit.tcp_connect",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id = %hex::encode(session.ticket_id),
        tcp_host = host,
        tcp_port = port,
    );
}

pub(crate) fn tcp_disconnect(session: &Session, host: &str, port: u16) {
    tracing::event!(
        Level::INFO,
        event = "audit.tcp_disconnect",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id = %hex::encode(session.ticket_id),
        tcp_host = host,
        tcp_port = port,
    );
}

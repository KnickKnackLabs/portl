//! Audit logging helpers.
//!
//! Security note: never log passphrases or full argv vectors. Exec audit
//! records intentionally include only `argv[0]` because later arguments may
//! carry secrets.

use std::sync::OnceLock;

use tracing::Level;
use tracing_subscriber::prelude::*;

use crate::session::Session;

static AUDIT_INIT: OnceLock<()> = OnceLock::new();

pub(crate) fn init() {
    let () = *AUDIT_INIT.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            if let Ok(layer) = tracing_journald::layer() {
                let _ = tracing_subscriber::registry().with(layer).try_init();
                return;
            }
        }

        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .try_init();
    });
}

pub(crate) fn ticket_accepted(session: &Session) {
    tracing::event!(
        Level::INFO,
        event = "audit.ticket_accepted",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id_hex = %hex::encode(session.ticket_id),
    );
}

pub(crate) fn shell_spawn(session: &Session, user: Option<&str>, argv: Option<&Vec<String>>) {
    tracing::event!(
        Level::INFO,
        event = "audit.shell_spawn",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id_hex = %hex::encode(session.ticket_id),
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
        ticket_id_hex = %hex::encode(session.ticket_id),
        reason = reason,
    );
}

pub(crate) fn shell_exit_raw(
    ticket_id: [u8; 16],
    caller_endpoint_id: [u8; 32],
    pid: u32,
    code: i32,
) {
    tracing::event!(
        Level::INFO,
        event = "audit.shell_exit",
        caller_endpoint_id = %hex::encode(caller_endpoint_id),
        ticket_id_hex = %hex::encode(ticket_id),
        pid,
        code,
    );
}

pub(crate) fn tcp_connect(session: &Session, host: &str, port: u16) {
    tracing::event!(
        Level::INFO,
        event = "audit.tcp_connect",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id_hex = %hex::encode(session.ticket_id),
        tcp_host = host,
        tcp_port = port,
    );
}

pub(crate) fn tcp_disconnect(session: &Session, host: &str, port: u16) {
    tracing::event!(
        Level::INFO,
        event = "audit.tcp_disconnect",
        caller_endpoint_id = %hex::encode(session.caller_endpoint_id),
        ticket_id_hex = %hex::encode(session.ticket_id),
        tcp_host = host,
        tcp_port = port,
    );
}

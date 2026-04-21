//! `portl doctor` — local diagnostics.
//!
//! Runs a set of independent health checks and prints each with a
//! leading `ok`/`warn`/`fail` tag. Exit code 0 when every check is
//! `ok` or `warn`, 1 when any check is `fail`.

use std::net::UdpSocket;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use iroh_tickets::Ticket;
use portl_core::id::store;
use portl_core::ticket::schema::PortlTicket;

use crate::alias_store::AliasStore;

#[derive(Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug)]
struct CheckResult {
    name: &'static str,
    status: Status,
    detail: String,
}

pub fn run() -> ExitCode {
    let results: Vec<CheckResult> = vec![
        check_clock_skew(),
        check_identity(),
        check_listener_bind(),
        check_discovery_config(),
        check_stored_ticket_expiry(),
    ];

    let mut any_fail = false;
    for result in &results {
        let tag = match result.status {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "fail",
        };
        if result.status == Status::Fail {
            any_fail = true;
        }
        println!("[{tag}] {}: {}", result.name, result.detail);
    }

    if any_fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Sanity-check the wall clock against `UNIX_EPOCH`. `doctor` is
/// strictly local and does not hit the network, so NTP drift is out
/// of scope; this surfaces the commonly-broken case where the host
/// clock is decades off.
fn check_clock_skew() -> CheckResult {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs();
            // Sanity: we expect >= 2024-01-01 UTC.
            if secs < 1_704_067_200 {
                CheckResult {
                    name: "clock",
                    status: Status::Fail,
                    detail: format!("wall clock appears to be before 2024-01-01 ({secs})"),
                }
            } else {
                CheckResult {
                    name: "clock",
                    status: Status::Ok,
                    detail: format!("{secs} seconds since unix epoch"),
                }
            }
        }
        Err(err) => CheckResult {
            name: "clock",
            status: Status::Fail,
            detail: format!("system time before unix epoch: {err}"),
        },
    }
}

/// Identity check: loadable, decodable, and the file permissions on
/// unix look reasonable.
fn check_identity() -> CheckResult {
    let path = store::default_path();
    match store::load(&path) {
        Ok(id) => {
            let endpoint = hex::encode(id.verifying_key());
            let mode_note = identity_mode_warning(&path);
            let detail = format!("endpoint_id={endpoint} at {}{mode_note}", path.display());
            CheckResult {
                name: "identity",
                status: if mode_note.is_empty() {
                    Status::Ok
                } else {
                    Status::Warn
                },
                detail,
            }
        }
        Err(err) => CheckResult {
            name: "identity",
            status: Status::Fail,
            detail: format!(
                "cannot load identity at {}: {err}; run `portl init`",
                path.display()
            ),
        },
    }
}

#[cfg(unix)]
fn identity_mode_warning(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(md) => {
            let mode = md.mode() & 0o777;
            if mode & 0o077 != 0 {
                format!(" (warning: mode {mode:o}, expected 0600)")
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    }
}

#[cfg(not(unix))]
fn identity_mode_warning(_: &Path) -> String {
    String::new()
}

/// Listener bind: try UDP bind on an ephemeral port to surface the
/// "no networking" / "sandboxed" case. We do not try to bind on a
/// configured listen address because that would require parsing the
/// agent config, which the doctor runs outside of.
fn check_listener_bind() -> CheckResult {
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => match socket.local_addr() {
            Ok(addr) => CheckResult {
                name: "listener",
                status: Status::Ok,
                detail: format!("UDP ephemeral bind succeeded on {addr}"),
            },
            Err(err) => CheckResult {
                name: "listener",
                status: Status::Warn,
                detail: format!("bind ok but local_addr failed: {err}"),
            },
        },
        Err(err) => CheckResult {
            name: "listener",
            status: Status::Fail,
            detail: format!("UDP ephemeral bind failed: {err}"),
        },
    }
}

/// Report the agent's effective discovery config as derived from the
/// fixed env-var schema. Doesn't actually probe DNS here; that's the
/// relay check's job.
fn check_discovery_config() -> CheckResult {
    match portl_agent::AgentConfig::from_env() {
        Ok(cfg) => {
            let discovery = &cfg.discovery;
            let relay = cfg
                .discovery
                .relay
                .as_ref()
                .map_or_else(|| "none".to_owned(), ToString::to_string);
            let detail = format!(
                "dns={} pkarr={} local={} relay={}",
                discovery.dns, discovery.pkarr, discovery.local, relay
            );
            let status = if discovery.dns || discovery.pkarr || discovery.local {
                Status::Ok
            } else {
                Status::Warn
            };
            CheckResult {
                name: "discovery",
                status,
                detail,
            }
        }
        Err(err) => CheckResult {
            name: "discovery",
            status: Status::Fail,
            detail: format!("cannot load agent env config: {err}"),
        },
    }
}

/// Walk stored tickets in the alias store. Warn on any ticket within
/// 24h of expiry, fail on expired.
fn check_stored_ticket_expiry() -> CheckResult {
    let store = AliasStore::default();
    let aliases = match store.list() {
        Ok(v) => v,
        Err(err) => {
            return CheckResult {
                name: "tickets",
                status: Status::Warn,
                detail: format!("cannot list aliases: {err}"),
            };
        }
    };
    if aliases.is_empty() {
        return CheckResult {
            name: "tickets",
            status: Status::Ok,
            detail: "no aliases in store".to_owned(),
        };
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let warn_threshold = now + 24 * 3600;

    let mut expired = Vec::new();
    let mut expiring_soon = Vec::new();

    for alias in aliases {
        let name = alias.name.clone();
        let Ok(Some(spec)) = store.get_spec(&name) else {
            continue;
        };
        let Some(ticket_path) = spec.ticket_file_path else {
            continue;
        };
        let Ok(raw) = std::fs::read_to_string(&ticket_path) else {
            continue;
        };
        let Ok(ticket) = <PortlTicket as Ticket>::deserialize(raw.trim()) else {
            continue;
        };
        if ticket.body.not_after <= now {
            expired.push(name);
        } else if ticket.body.not_after <= warn_threshold {
            expiring_soon.push(name);
        }
    }

    if !expired.is_empty() {
        CheckResult {
            name: "tickets",
            status: Status::Fail,
            detail: format!(
                "{} alias(es) expired: {}",
                expired.len(),
                expired.join(", ")
            ),
        }
    } else if !expiring_soon.is_empty() {
        CheckResult {
            name: "tickets",
            status: Status::Warn,
            detail: format!(
                "{} alias(es) expire within 24h: {}",
                expiring_soon.len(),
                expiring_soon.join(", ")
            ),
        }
    } else {
        CheckResult {
            name: "tickets",
            status: Status::Ok,
            detail: "all stored tickets are valid".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_check_returns_ok_on_sane_system() {
        let r = check_clock_skew();
        assert_eq!(r.status, Status::Ok);
    }

    #[test]
    fn listener_check_returns_ok_on_unrestricted_env() {
        let r = check_listener_bind();
        assert_eq!(r.status, Status::Ok, "unexpected: {}", r.detail);
    }
}

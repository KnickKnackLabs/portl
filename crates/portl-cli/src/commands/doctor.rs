//! `portl doctor` — local diagnostics.
//!
//! Runs a set of independent health checks and prints each with a
//! leading `ok`/`warn`/`fail` tag. Exit code 0 when every check is
//! `ok` or `warn`, 1 when any check is `fail`.

use std::net::UdpSocket;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use iroh_tickets::Ticket;
use portl_core::id::store;
use portl_core::peer_store::PeerStore;
use portl_core::ticket::schema::PortlTicket;
use portl_core::ticket_store::TicketStore;

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
        check_peer_store(),
        check_ticket_store(),
        check_stored_ticket_expiry(),
        check_package_manager(),
        check_binary_drift(),
        check_service_drift(),
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

/// Summarize the peer store: total count and breakdown by
/// relationship. Doesn't hit the network. Warns when the store is
/// empty on a host that looks like it should be the listener side
/// (has an identity file), because an empty peer store rejects
/// every handshake.
fn check_peer_store() -> CheckResult {
    let peers = match PeerStore::load(&PeerStore::default_path()) {
        Ok(p) => p,
        Err(err) => {
            return CheckResult {
                name: "peers",
                status: Status::Fail,
                detail: format!("read peer store: {err}"),
            };
        }
    };
    if peers.is_empty() {
        return CheckResult {
            name: "peers",
            status: Status::Warn,
            detail: "empty; agent will reject every ticket. Run `portl install --apply` \
                 (seeds self-row) or `portl peer add-unsafe-raw …`."
                .to_owned(),
        };
    }
    let mut mutual = 0usize;
    let mut inbound = 0usize;
    let mut outbound = 0usize;
    let mut held = 0usize;
    let mut selves = 0usize;
    for entry in peers.iter() {
        if entry.last_hold_at.is_some() {
            held += 1;
            continue;
        }
        if entry.is_self {
            selves += 1;
            continue;
        }
        match (entry.accepts_from_them, entry.they_accept_from_me) {
            (true, true) => mutual += 1,
            (true, false) => inbound += 1,
            (false, true) => outbound += 1,
            _ => {}
        }
    }
    CheckResult {
        name: "peers",
        status: Status::Ok,
        detail: format!(
            "{} total ({selves} self, {mutual} mutual, {inbound} inbound, {outbound} outbound, {held} held)",
            peers.len()
        ),
    }
}

/// Summarize the ticket store: total + soonest expiry.
fn check_ticket_store() -> CheckResult {
    let tickets = match TicketStore::load(&TicketStore::default_path()) {
        Ok(t) => t,
        Err(err) => {
            return CheckResult {
                name: "tickets-saved",
                status: Status::Fail,
                detail: format!("read ticket store: {err}"),
            };
        }
    };
    if tickets.is_empty() {
        return CheckResult {
            name: "tickets-saved",
            status: Status::Ok,
            detail: "no saved tickets".to_owned(),
        };
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expired: Vec<_> = tickets
        .iter()
        .filter(|(_, e)| e.expires_at <= now)
        .map(|(k, _)| k.clone())
        .collect();
    if !expired.is_empty() {
        return CheckResult {
            name: "tickets-saved",
            status: Status::Warn,
            detail: format!(
                "{expired_count} of {total} expired: {names} (run `portl ticket prune`)",
                expired_count = expired.len(),
                total = tickets.len(),
                names = expired.join(", ")
            ),
        };
    }
    let soonest = tickets
        .soonest_expiry(now)
        .map_or_else(|| "none active".to_owned(), format_ttl);
    CheckResult {
        name: "tickets-saved",
        status: Status::Ok,
        detail: format!(
            "{total} saved (soonest expires {soonest})",
            total = tickets.len()
        ),
    }
}

fn format_ttl(secs: u64) -> String {
    if secs >= 24 * 3600 {
        format!("in {}d", secs / (24 * 3600))
    } else if secs >= 3600 {
        format!("in {}h", secs / 3600)
    } else if secs >= 60 {
        format!("in {}m", secs / 60)
    } else {
        format!("in {secs}s")
    }
}

/// v0.3.1: package-manager awareness. Detects whether the portl
/// binary was installed via mise (path contains `/mise/installs/`)
/// and emits an `[info]`-style warn with upgrade guidance. Adds
/// zero overhead for non-mise users.
fn check_package_manager() -> CheckResult {
    let current = std::env::current_exe().ok();
    let Some(path) = current else {
        return CheckResult {
            name: "package",
            status: Status::Warn,
            detail: "could not resolve current executable".to_owned(),
        };
    };
    let path_str = path.display().to_string();
    if path_str.contains("/mise/installs/") || path_str.contains("/mise/shims/") {
        return CheckResult {
            name: "package",
            status: Status::Warn,
            detail: format!(
                "mise-managed ({path_str}). On version bump re-run \
                 `portl install --apply --yes` so the LaunchAgent/unit \
                 picks up the new binary."
            ),
        };
    }
    if path_str.contains("/homebrew/") || path_str.starts_with("/opt/homebrew/") {
        return CheckResult {
            name: "package",
            status: Status::Ok,
            detail: format!("homebrew-managed ({path_str})"),
        };
    }
    if path_str.contains("/nix/store/") {
        return CheckResult {
            name: "package",
            status: Status::Ok,
            detail: format!("nix-managed ({path_str})"),
        };
    }
    CheckResult {
        name: "package",
        status: Status::Ok,
        detail: format!("running {path_str}"),
    }
}

/// v0.3.1: detect multiple portl / portl-agent binaries on $PATH
/// and warn if their versions disagree. Catches the common "I
/// upgraded portl but the running agent still reports old version"
/// failure mode surfaced during v0.3.0.1 testing.
fn check_binary_drift() -> CheckResult {
    let Some(path_env) = std::env::var_os("PATH") else {
        return CheckResult {
            name: "binaries",
            status: Status::Warn,
            detail: "$PATH is unset".to_owned(),
        };
    };
    let mut found: Vec<(PathBuf, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dir in std::env::split_paths(&path_env) {
        for name in ["portl", "portl-agent"] {
            let candidate = dir.join(name);
            let Ok(resolved) = candidate.canonicalize() else {
                continue;
            };
            if !seen.insert(resolved.clone()) {
                continue;
            }
            let version = ProcessCommand::new(&candidate)
                .arg("--version")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .and_then(|s| s.split_whitespace().nth(1).map(str::to_owned))
                .unwrap_or_else(|| "?".to_owned());
            found.push((candidate, version));
        }
    }
    if found.is_empty() {
        return CheckResult {
            name: "binaries",
            status: Status::Warn,
            detail: "no portl binaries on $PATH".to_owned(),
        };
    }
    let versions: std::collections::HashSet<&str> = found.iter().map(|(_, v)| v.as_str()).collect();
    if versions.len() > 1 {
        let list = found
            .iter()
            .map(|(p, v)| format!("{} ({v})", p.display()))
            .collect::<Vec<_>>()
            .join(", ");
        return CheckResult {
            name: "binaries",
            status: Status::Warn,
            detail: format!(
                "version drift across $PATH: {list}. \
                 Upgrade the stragglers or remove stale copies."
            ),
        };
    }
    CheckResult {
        name: "binaries",
        status: Status::Ok,
        detail: format!(
            "{count} on $PATH (all v{ver})",
            count = found.len(),
            ver = versions.iter().next().unwrap_or(&"?")
        ),
    }
}

/// v0.3.1: surface multi-service-loaded state (the user-level
/// `LaunchAgent` + system `LaunchDaemon` footgun from the v0.3.0
/// install thread). Non-fatal — this is common during migrations
/// but should get cleaned up before relying on the service.
fn check_service_drift() -> CheckResult {
    #[cfg(target_os = "macos")]
    {
        let uid_str = format!("{}", nix::unistd::getuid());
        let user_loaded = launchctl_is_loaded(&format!("gui/{uid_str}/com.portl.agent"));
        let system_loaded = launchctl_is_loaded("system/com.portl.agent");
        match (user_loaded, system_loaded) {
            (true, true) => CheckResult {
                name: "service",
                status: Status::Warn,
                detail: "both user LaunchAgent (gui/{uid}) and system LaunchDaemon are loaded; \
                 they'll fight over UDP binds. Pick one lane: \
                 `launchctl bootout system/com.portl.agent` + \
                 `sudo rm /Library/LaunchDaemons/com.portl.agent.plist`"
                    .replace("{uid}", &uid_str),
            },
            (true, false) => CheckResult {
                name: "service",
                status: Status::Ok,
                detail: format!("user LaunchAgent loaded (gui/{uid_str})"),
            },
            (false, true) => CheckResult {
                name: "service",
                status: Status::Ok,
                detail: "system LaunchDaemon loaded".to_owned(),
            },
            (false, false) => CheckResult {
                name: "service",
                status: Status::Warn,
                detail: "no portl-agent service loaded. Run \
                 `portl install --apply --yes` to install one, or \
                 `portl-agent &` to run ad-hoc."
                    .to_owned(),
            },
        }
    }
    #[cfg(target_os = "linux")]
    {
        let user = systemctl_is_active(&["--user"]);
        let system = systemctl_is_active(&[]);
        match (user, system) {
            (true, true) => CheckResult {
                name: "service",
                status: Status::Warn,
                detail: "both user and system portl-agent.service are active; \
                 they'll fight over UDP binds. Pick one lane."
                    .to_owned(),
            },
            (true, false) => CheckResult {
                name: "service",
                status: Status::Ok,
                detail: "user systemd unit active".to_owned(),
            },
            (false, true) => CheckResult {
                name: "service",
                status: Status::Ok,
                detail: "system systemd unit active".to_owned(),
            },
            (false, false) => CheckResult {
                name: "service",
                status: Status::Warn,
                detail: "no portl-agent service active. Run \
                 `portl install --apply --yes` to install one, or \
                 `portl-agent &` to run ad-hoc."
                    .to_owned(),
            },
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        CheckResult {
            name: "service",
            status: Status::Ok,
            detail: "service drift check skipped on this OS".to_owned(),
        }
    }
}

#[cfg(target_os = "macos")]
fn launchctl_is_loaded(target: &str) -> bool {
    ProcessCommand::new("launchctl")
        .args(["print", target])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn systemctl_is_active(extra: &[&str]) -> bool {
    let mut args: Vec<&str> = Vec::new();
    args.extend_from_slice(extra);
    args.extend_from_slice(&["is-active", "portl-agent.service"]);
    ProcessCommand::new("systemctl")
        .args(&args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

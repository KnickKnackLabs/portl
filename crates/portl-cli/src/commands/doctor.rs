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
use portl_agent::config_file::PortlConfig;
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

#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct RunOpts {
    pub fix: bool,
    pub yes: bool,
    /// Show all checks including passing ones. Default hides `ok`
    /// rows so operators see only actionable output.
    pub verbose: bool,
    /// Emit structured JSON instead of the human-readable table.
    pub json: bool,
    /// Suppress non-error human output.
    pub quiet: bool,
}

pub fn run(opts: RunOpts) -> ExitCode {
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
        check_home_layout(),
        check_session_providers(),
        check_service_drift(),
        check_agent_runtime_socket(),
        check_agent_network_endpoint(),
    ];

    let any_fail = results.iter().any(|r| r.status == Status::Fail);
    if opts.json {
        render_json(&results);
    } else if !opts.quiet {
        render_human(&results, opts.verbose);
    }

    if opts.fix {
        match fix_service_drift(opts.yes) {
            Ok(summary) => {
                if !summary.is_empty() && !opts.quiet {
                    println!("{summary}");
                }
            }
            Err(e) => {
                eprintln!("fix failed: {e:#}");
                return ExitCode::FAILURE;
            }
        }
    }

    if any_fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn render_human(results: &[CheckResult], verbose: bool) {
    let mut hidden = 0usize;
    for result in results {
        if !verbose && result.status == Status::Ok {
            hidden += 1;
            continue;
        }
        let tag = match result.status {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "fail",
        };
        println!("[{tag}] {}: {}", result.name, result.detail);
    }
    if !verbose && hidden > 0 {
        println!("({hidden} passing checks hidden — use --verbose to show)");
    }
}

fn render_json(results: &[CheckResult]) {
    use serde_json::json;
    let checks: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "status": match r.status {
                    Status::Ok => "ok",
                    Status::Warn => "warn",
                    Status::Fail => "fail",
                },
                "detail": r.detail,
            })
        })
        .collect();
    let envelope = json!({
        "schema": 1,
        "kind": "doctor",
        "any_fail": results.iter().any(|r| r.status == Status::Fail),
        "checks": checks,
    });
    match serde_json::to_string_pretty(&envelope) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("failed to serialize doctor JSON: {e}"),
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
        Err(err) => {
            let legacy_path = portl_core::paths::current().root().join("identity.bin");
            if legacy_path != path
                && let Ok(id) = store::load(&legacy_path)
            {
                let endpoint = hex::encode(id.verifying_key());
                return CheckResult {
                    name: "identity",
                    status: Status::Warn,
                    detail: format!(
                        "endpoint_id={endpoint} at legacy path {}; run `portl config path` after stopping any old agent to migrate it",
                        legacy_path.display()
                    ),
                };
            }
            CheckResult {
                name: "identity",
                status: if portl_core::paths::home_is_explicit() {
                    Status::Warn
                } else {
                    Status::Fail
                },
                detail: format!(
                    "cannot load identity at {}: {err}; run `portl init`",
                    path.display()
                ),
            }
        }
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
    match portl_agent::AgentConfig::from_env_without_layout_migration() {
        Ok(cfg) => {
            let discovery = &cfg.discovery;
            let relay = if cfg.discovery.relays.is_empty() {
                "none".to_owned()
            } else {
                cfg.discovery
                    .relays
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
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
        .map_or(0, |d| d.as_secs());
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
        .map_or(0, |d| d.as_secs());
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

fn check_home_layout() -> CheckResult {
    let current = portl_core::paths::current();
    let current_identity = current.identity_path();
    let stale = stale_legacy_durable_files_by_home();
    if current_identity.exists() && stale.is_empty() {
        return CheckResult {
            name: "home layout",
            status: Status::Ok,
            detail: format!(
                "using {}; no unmigrated durable legacy files found",
                current.root().display()
            ),
        };
    }
    if current_identity.exists() {
        return CheckResult {
            name: "home layout",
            status: Status::Warn,
            detail: format!(
                "using {}, but previous durable files remain: {}. Back up, then move or remove these stale files before release validation.",
                current.root().display(),
                format_stale_legacy_files(&stale)
            ),
        };
    }
    if !stale.is_empty() {
        let explicit = portl_core::paths::home_is_explicit();
        return CheckResult {
            name: "home layout",
            status: if explicit { Status::Warn } else { Status::Fail },
            detail: format!(
                "new home {} has no identity but previous durable state exists: {}. Run the current installer so it can stop any old agent, install the new binary, migrate state, and restart safely; or stop the agent first and run `portl config path` manually.",
                current.root().display(),
                format_stale_legacy_files(&stale)
            ),
        };
    }
    CheckResult {
        name: "home layout",
        status: Status::Ok,
        detail: format!("using {}", current.root().display()),
    }
}

fn stale_legacy_durable_files_by_home() -> Vec<(PathBuf, Vec<PathBuf>)> {
    portl_core::paths::legacy_home_candidates()
        .into_iter()
        .filter_map(|home| {
            let stale = stale_legacy_durable_files(&home);
            (!stale.is_empty()).then_some((home, stale))
        })
        .collect()
}

fn format_stale_legacy_files(stale: &[(PathBuf, Vec<PathBuf>)]) -> String {
    stale
        .iter()
        .map(|(home, files)| {
            let files = files
                .iter()
                .map(|path| {
                    path.strip_prefix(home)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}: {files}", home.display())
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn stale_legacy_durable_files(previous: &Path) -> Vec<PathBuf> {
    let mut stale = [
        "portl.toml",
        "identity.bin",
        "peers.json",
        "tickets.json",
        "aliases.json",
        "revocations.jsonl",
        "pending_invites.json",
    ]
    .into_iter()
    .map(|relative| previous.join(relative))
    .filter(|path| path.exists())
    .collect::<Vec<_>>();
    let sessions_dir = previous.join("ghostty/sessions");
    if directory_has_entries(&sessions_dir) {
        stale.push(sessions_dir);
    }
    stale
}

fn directory_has_entries(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
}

fn check_agent_runtime_socket() -> CheckResult {
    let socket = portl_core::paths::metrics_socket_path();
    match fetch_agent_status_sync(&socket) {
        Ok(status) => CheckResult {
            name: "agent runtime",
            status: Status::Ok,
            detail: format!(
                "agent IPC ok at {} (pid {}, v{})",
                socket.display(),
                status.agent.pid,
                status.agent.version
            ),
        },
        Err(err) if service_is_loaded() && !portl_core::paths::home_is_explicit() => CheckResult {
            name: "agent runtime",
            status: Status::Fail,
            detail: format!(
                "managed portl-agent is loaded but current agent IPC is unavailable at {}: {err}. This usually means an old agent binary was restarted after state migrated; run the current installer or `portl-agent restart` after installing the new binary.",
                socket.display()
            ),
        },
        Err(err) => CheckResult {
            name: "agent runtime",
            status: Status::Warn,
            detail: format!(
                "agent service is not loaded or not reachable at {}: {err}",
                socket.display()
            ),
        },
    }
}

fn check_agent_network_endpoint() -> CheckResult {
    let socket = portl_core::paths::metrics_socket_path();
    match fetch_agent_status_sync(&socket) {
        Ok(status) => check_agent_network_endpoint_status(&status),
        Err(err) => CheckResult {
            name: "network endpoint",
            status: Status::Warn,
            detail: format!(
                "agent status unavailable at {}; cannot inspect endpoint watchdog health: {err}",
                socket.display()
            ),
        },
    }
}

fn check_agent_network_endpoint_status(
    status: &portl_agent::status_schema::StatusResponse,
) -> CheckResult {
    let health = &status.network_health;
    let status = match health.state {
        portl_agent::network_watchdog::WatchdogState::Ok => Status::Ok,
        portl_agent::network_watchdog::WatchdogState::Degraded
        | portl_agent::network_watchdog::WatchdogState::Refreshing => Status::Warn,
        portl_agent::network_watchdog::WatchdogState::Failed => Status::Fail,
        portl_agent::network_watchdog::WatchdogState::Disabled => Status::Warn,
    };
    let mut detail = format!(
        "state={:?}, endpoint generation {}, failures={}, refresh_count={}",
        health.state,
        health.endpoint_generation,
        health.consecutive_self_probe_failures,
        health.endpoint_refresh_count
    )
    .to_lowercase();
    if let Some(error) = &health.last_endpoint_refresh_error {
        detail.push_str(&format!(", last_refresh_error={error}"));
    }
    CheckResult {
        name: "network endpoint",
        status,
        detail,
    }
}

fn fetch_agent_status_sync(
    socket: &Path,
) -> anyhow::Result<portl_agent::status_schema::StatusResponse> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(crate::agent_ipc::fetch_status(socket))
}

fn service_is_loaded() -> bool {
    crate::commands::install::managed_agent_is_loaded()
}

fn check_session_providers() -> CheckResult {
    check_session_providers_with_config(effective_session_provider_path().as_deref())
}

fn effective_session_provider_path() -> Option<PathBuf> {
    std::env::var_os("PORTL_SESSION_PROVIDER_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            let path = portl_core::paths::config_path();
            PortlConfig::load(&path)
                .ok()
                .and_then(|config| config.agent.session_provider_path)
        })
}

fn check_session_providers_with_config(configured: Option<&Path>) -> CheckResult {
    let info = portl_agent::session_provider_discovery_info(configured);
    if let Some(broken_config) = info
        .search_paths
        .iter()
        .find(|probe| probe.source == "config" && !probe.exists)
    {
        return CheckResult {
            name: "session providers",
            status: Status::Fail,
            detail: format!(
                "configured session_provider_path does not exist: {}. \
                 Remove session_provider_path from portl.toml to let Portl discover zmx/tmux, \
                 or update it to an existing provider binary if you intentionally need an override.",
                broken_config.path
            ),
        };
    }

    let detected = info
        .providers
        .iter()
        .filter(|provider| provider.name != "raw" && provider.detected)
        .map(|provider| {
            format!(
                "{} at {} ({})",
                provider.name,
                provider.path.as_deref().unwrap_or("-"),
                provider.source.as_deref().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>();
    if detected.is_empty() {
        CheckResult {
            name: "session providers",
            status: Status::Warn,
            detail: "no zmx or tmux provider found; shell/exec still work, persistent sessions need zmx or tmux".to_owned(),
        }
    } else {
        CheckResult {
            name: "session providers",
            status: Status::Ok,
            detail: detected.join(", "),
        }
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
        let mut active = Vec::new();
        if systemctl_is_active(&["--user"]) {
            active.push("user systemd unit");
        }
        if systemctl_is_active(&[]) {
            active.push("system systemd unit");
        }
        if openrc_is_active() {
            active.push("OpenRC service");
        }
        match active.as_slice() {
            [] => CheckResult {
                name: "service",
                status: Status::Warn,
                detail: "no portl-agent service active. Run \
                 `portl install --apply --yes` to install one, or \
                 `portl-agent &` to run ad-hoc."
                    .to_owned(),
            },
            [one] => CheckResult {
                name: "service",
                status: Status::Ok,
                detail: format!("{one} active"),
            },
            many => CheckResult {
                name: "service",
                status: Status::Warn,
                detail: format!(
                    "multiple portl-agent services are active ({}); they'll fight over UDP binds. Pick one lane.",
                    many.join(", ")
                ),
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
        .is_ok_and(|o| o.status.success())
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

#[cfg(target_os = "linux")]
fn openrc_is_active() -> bool {
    if !Path::new("/etc/init.d/portl-agent").exists() {
        return false;
    }
    ProcessCommand::new("rc-service")
        .args(["portl-agent", "status"])
        .output()
        .is_ok_and(|output| output.status.success())
        || ProcessCommand::new("service")
            .args(["portl-agent", "status"])
            .output()
            .is_ok_and(|output| output.status.success())
}

/// Auto-remediate the duplicate-service drift detected by
/// [`check_service_drift`].
///
/// Strategy: keep the *user* lane (`LaunchAgent` / `--user` systemd
/// unit), tear down the *system* lane. User-scope is what `portl
/// install --apply` writes by default for non-root invocations and
/// is the lane new docs steer toward. The wrong-lane removal is
/// reversible by re-running `portl install --apply` as root.
///
/// Returns a short human-readable summary of what was done. Returns
/// `Ok("")` when there's nothing to fix.
fn fix_service_drift(yes: bool) -> anyhow::Result<String> {
    use anyhow::bail;

    #[cfg(target_os = "macos")]
    {
        let uid_str = format!("{}", nix::unistd::getuid());
        let user_loaded = launchctl_is_loaded(&format!("gui/{uid_str}/com.portl.agent"));
        let system_loaded = launchctl_is_loaded("system/com.portl.agent");

        if !(user_loaded && system_loaded) {
            return Ok(String::new());
        }

        let cmds = [
            (
                "sudo",
                &["launchctl", "bootout", "system/com.portl.agent"][..],
            ),
            (
                "sudo",
                &["rm", "-f", "/Library/LaunchDaemons/com.portl.agent.plist"][..],
            ),
        ];

        if !yes && !confirm_fix(&cmds)? {
            bail!("aborted by user");
        }

        for (bin, args) in cmds {
            run_remediation(bin, args)?;
        }
        Ok("removed system LaunchDaemon; user LaunchAgent retained".to_owned())
    }
    #[cfg(target_os = "linux")]
    {
        let user = systemctl_is_active(&["--user"]);
        let system = systemctl_is_active(&[]);

        if !(user && system) {
            return Ok(String::new());
        }

        let cmds = [
            (
                "sudo",
                &["systemctl", "disable", "--now", "portl-agent.service"][..],
            ),
            (
                "sudo",
                &["rm", "-f", "/etc/systemd/system/portl-agent.service"][..],
            ),
        ];

        if !yes && !confirm_fix(&cmds)? {
            bail!("aborted by user");
        }

        for (bin, args) in cmds {
            run_remediation(bin, args)?;
        }
        Ok("removed system portl-agent.service; user --user unit retained".to_owned())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = yes;
        Ok(String::new())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn confirm_fix(cmds: &[(&str, &[&str])]) -> anyhow::Result<bool> {
    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal() {
        anyhow::bail!("--fix requires --yes when stdin is not a TTY");
    }

    println!("the following commands will run:");
    for (bin, args) in cmds {
        println!("    {bin} {}", args.join(" "));
    }
    print!("proceed? [y/N] ");
    std::io::stdout().flush().ok();

    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(matches!(buf.trim(), "y" | "Y" | "yes"))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_remediation(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    use anyhow::Context;
    println!("    -> {bin} {}", args.join(" "));
    let status = ProcessCommand::new(bin)
        .args(args)
        .status()
        .with_context(|| format!("spawn {bin}"))?;
    if !status.success() {
        anyhow::bail!("{bin} {} exited {status}", args.join(" "));
    }
    Ok(())
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

    #[test]
    fn stale_legacy_durable_files_reports_only_migrated_inputs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old = temp.path().join("old");
        std::fs::create_dir_all(old.join("ghostty/runtime/sockets")).expect("runtime dirs");
        std::fs::create_dir_all(old.join("ghostty/sessions")).expect("session dirs");
        std::fs::write(old.join("ghostty/sessions/foo.json"), b"{}").expect("ghostty session");
        std::fs::write(old.join("identity.bin"), b"id").expect("identity");
        std::fs::write(old.join("metrics.sock"), b"runtime").expect("runtime leftover");

        let stale = stale_legacy_durable_files(&old);

        assert!(stale.contains(&old.join("identity.bin")));
        assert!(stale.contains(&old.join("ghostty/sessions")));
        assert!(!stale.contains(&old.join("metrics.sock")));
        assert!(!stale.contains(&old.join("ghostty/runtime/sockets")));
    }

    #[test]
    fn format_stale_legacy_files_groups_by_home() {
        let first = PathBuf::from("/tmp/old-a");
        let second = PathBuf::from("/tmp/old-b");
        let formatted = format_stale_legacy_files(&[
            (first.clone(), vec![first.join("identity.bin")]),
            (second.clone(), vec![second.join("ghostty/sessions")]),
        ]);

        assert!(formatted.contains("/tmp/old-a: identity.bin"));
        assert!(formatted.contains("/tmp/old-b: ghostty/sessions"));
    }

    #[test]
    fn stale_legacy_durable_files_ignores_empty_session_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let old = temp.path().join("old");
        std::fs::create_dir_all(old.join("ghostty/sessions")).expect("session dirs");

        let stale = stale_legacy_durable_files(&old);

        assert!(stale.is_empty(), "stale files were {stale:?}");
    }

    #[test]
    fn network_endpoint_check_warns_when_degraded() {
        let mut status = portl_agent::status_schema::StatusResponse::new(
            portl_agent::status_schema::AgentInfo {
                pid: 42,
                version: "0.8.2".to_owned(),
                started_at_unix: 100,
                home: "/tmp/portl".to_owned(),
                metrics_socket: "/tmp/portl/run/metrics.sock".to_owned(),
            },
            Vec::new(),
            portl_agent::status_schema::NetworkInfo {
                relays: Vec::new(),
                discovery: portl_agent::status_schema::DiscoveryInfo {
                    dns: false,
                    pkarr: false,
                    local: true,
                },
            },
            portl_agent::status_schema::NetworkHealthInfo::disabled(),
            portl_agent::status_schema::SessionProvidersInfo::default(),
            portl_agent::relay::RelayStatus::disabled(),
        );
        status.network_health.state = portl_agent::network_watchdog::WatchdogState::Degraded;
        status.network_health.endpoint_generation = 7;
        status.network_health.consecutive_self_probe_failures = 2;
        status.network_health.endpoint_refresh_count = 1;

        let result = check_agent_network_endpoint_status(&status);

        assert_eq!(result.name, "network endpoint");
        assert_eq!(result.status, Status::Warn);
        assert!(result.detail.contains("state=degraded"));
        assert!(result.detail.contains("endpoint generation 7"));
    }

    #[test]
    fn session_provider_check_fails_for_missing_file_configured_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing-zmx");
        let result = check_session_providers_with_config(Some(missing.as_path()));

        assert_eq!(result.status, Status::Fail);
        assert!(
            result
                .detail
                .contains("configured session_provider_path does not exist"),
            "detail was {}",
            result.detail
        );
        assert!(
            result.detail.contains("Remove session_provider_path"),
            "detail was {}",
            result.detail
        );
    }
}

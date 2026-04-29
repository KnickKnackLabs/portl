use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use iroh::endpoint::SendStream;
use portl_core::io::BufferedRecv;
use portl_core::net::{
    SessionClient, open_session_attach, open_session_history, open_session_kill,
    open_session_list_detailed, open_session_providers, open_session_run,
};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use tokio::io::{AsyncWriteExt, copy};
use tokio::process::Command;
use tracing::debug;

use crate::commands::peer_resolve::{close_connected, connect_peer};
use crate::commands::session_share::{
    BuiltEnvelope, EnvelopeInputs, ResolveTargetError, ShareTargetForm,
    build_session_share_envelope, classify_share_target, fresh_workspace_handles, load_identity,
    resolve_rendezvous_url, run_offer_against_transport, unix_now,
};
use portl_core::peer_store::PeerStore;
use portl_core::rendezvous::ws::WsRendezvousBackend;
use portl_core::ticket_store::TicketStore;
use portl_proto::session_v1::{
    ProviderCapabilities, ProviderReport, ProviderStatus, SessionInfo, SessionProviderSessions,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SessionHistoryFormat {
    Plain,
    Vt,
    Html,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SessionListing {
    target: String,
    provider_filter: Option<String>,
    total: usize,
    providers: BTreeMap<String, SessionProviderListing>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SessionProviderListing {
    available: bool,
    #[serde(rename = "default")]
    is_default: bool,
    count: usize,
    sessions: Vec<SessionListingEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SessionListingEntry {
    name: String,
    provider: String,
    metadata: serde_json::Value,
}

impl SessionListing {
    fn from_groups(
        target: &str,
        provider_filter: Option<&str>,
        groups: Vec<SessionProviderSessions>,
    ) -> Self {
        let total = groups.iter().map(|group| group.sessions.len()).sum();
        let providers = groups
            .into_iter()
            .map(|group| {
                let provider = group.provider.clone();
                let sessions = group
                    .sessions
                    .into_iter()
                    .map(SessionListingEntry::from)
                    .collect::<Vec<_>>();
                (
                    provider,
                    SessionProviderListing {
                        available: group.available,
                        is_default: group.default,
                        count: sessions.len(),
                        sessions,
                    },
                )
            })
            .collect();
        Self {
            target: target.to_owned(),
            provider_filter: provider_filter.map(ToOwned::to_owned),
            total,
            providers,
        }
    }
}

impl From<SessionInfo> for SessionListingEntry {
    fn from(session: SessionInfo) -> Self {
        Self {
            name: session.name,
            provider: session.provider,
            metadata: metadata_map_to_json(session.metadata),
        }
    }
}

fn metadata_map_to_json(metadata: BTreeMap<String, String>) -> serde_json::Value {
    serde_json::Value::Object(
        metadata
            .into_iter()
            .map(|(key, value)| (key, metadata_value_to_json(&value)))
            .collect(),
    )
}

fn metadata_value_to_json(value: &str) -> serde_json::Value {
    if value.eq_ignore_ascii_case("true") {
        serde_json::Value::Bool(true)
    } else if value.eq_ignore_ascii_case("false") {
        serde_json::Value::Bool(false)
    } else if let Ok(number) = value.parse::<u64>() {
        serde_json::Value::Number(number.into())
    } else if value.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(value.to_owned())
    }
}

fn render_session_listing_human(listing: &SessionListing) -> String {
    if listing.total == 0 {
        return match listing.provider_filter.as_deref() {
            Some(provider) => format!("0 existing {provider} sessions found.\n"),
            None => "0 existing sessions found.\n".to_owned(),
        };
    }

    let mut out = String::new();
    if listing.provider_filter.is_some() && listing.providers.len() == 1 {
        for provider in listing.providers.values() {
            for session in &provider.sessions {
                out.push_str(&session.name);
                out.push('\n');
            }
        }
    } else {
        out.push_str("PROVIDER  NAME\n");
        for (provider_name, provider) in &listing.providers {
            for session in &provider.sessions {
                out.push_str(&format!("{provider_name:<8}  {}\n", session.name));
            }
        }
    }
    out
}

impl SessionHistoryFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Vt => "vt",
            Self::Html => "html",
        }
    }
}

fn effective_provider(provider: Option<&str>) -> Option<String> {
    let env_provider = std::env::var("PORTL_SESSION_PROVIDER").ok();
    effective_provider_from_env(provider, env_provider.as_deref())
}

fn effective_provider_from_env(
    provider: Option<&str>,
    env_provider: Option<&str>,
) -> Option<String> {
    provider
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            env_provider
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(ToOwned::to_owned)
}

pub fn providers(target: Option<&str>, json: bool) -> Result<ExitCode> {
    let target = resolve_target_only(target)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let report = if resolved_target_is_local(&target)? {
            local_session_providers()
        } else {
            let connected = connect_peer(&target, session_caps()).await?;
            let report = open_session_providers(&connected.connection, &connected.session).await?;
            close_connected(connected, b"session complete").await;
            report
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("PROVIDER  AVAILABLE  DEFAULT  TIER      FEATURES  NOTES");
            for provider in &report.providers {
                let available = if provider.available { "yes" } else { "no" };
                let default = if report.default_provider.as_deref() == Some(provider.name.as_str())
                {
                    "yes"
                } else {
                    "no"
                };
                let tier = provider.tier.as_deref().unwrap_or("-");
                let features = if provider.features.is_empty() {
                    "-".to_owned()
                } else {
                    provider.features.join(",")
                };
                println!(
                    "{:<8}  {:<9}  {:<7}  {:<8}  {:<8}  {}",
                    provider.name,
                    available,
                    default,
                    tier,
                    features,
                    provider.notes.as_deref().unwrap_or("")
                );
            }
        }
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

pub fn ls(target: Option<&str>, provider: Option<&str>, json: bool) -> Result<ExitCode> {
    let target = resolve_target_only(target)?;
    let provider = effective_provider(provider);
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let groups = if resolved_target_is_local(&target)? {
            local_session_list_detailed(provider.as_deref()).await?
        } else {
            let connected = connect_peer(&target, session_caps()).await?;
            let groups = open_session_list_detailed(
                &connected.connection,
                &connected.session,
                provider.clone(),
            )
            .await?;
            close_connected(connected, b"session complete").await;
            groups
        };
        let listing = SessionListing::from_groups(&target, provider.as_deref(), groups);
        if json {
            println!("{}", serde_json::to_string_pretty(&listing)?);
        } else {
            print!("{}", render_session_listing_human(&listing));
        }
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

pub fn run(
    session: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let provider = effective_provider(provider);
    let resolved = resolve_session_ref(session, target)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let run = if resolved_target_is_local(&resolved.target)? {
            local_session_run(provider.as_deref(), &resolved.session, argv).await?
        } else {
            let connected = connect_peer(&resolved.target, session_caps()).await?;
            let run = open_session_run(
                &connected.connection,
                &connected.session,
                provider.clone(),
                resolved.session,
                argv.to_vec(),
            )
            .await?;
            close_connected(connected, b"session complete").await;
            run
        };
        print!("{}", run.stdout);
        eprint!("{}", run.stderr);
        Ok(exit_code_from_i32(run.code))
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

pub fn history(
    session: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
    format: SessionHistoryFormat,
) -> Result<ExitCode> {
    if format != SessionHistoryFormat::Plain {
        anyhow::bail!(
            "persistent session history format '{}' is not supported by the zmx provider yet",
            format.as_str()
        );
    }
    let provider = effective_provider(provider);
    let resolved = resolve_session_ref(session, target)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let output = if resolved_target_is_local(&resolved.target)? {
            local_session_history(provider.as_deref(), &resolved.session).await?
        } else {
            let connected = connect_peer(&resolved.target, session_caps()).await?;
            let output = open_session_history(
                &connected.connection,
                &connected.session,
                provider.clone(),
                resolved.session,
            )
            .await?;
            close_connected(connected, b"session complete").await;
            output
        };
        print!("{output}");
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

pub fn kill(
    session: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
) -> Result<ExitCode> {
    let provider = effective_provider(provider);
    let resolved = resolve_session_ref(session, target)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        if resolved_target_is_local(&resolved.target)? {
            local_session_kill(provider.as_deref(), &resolved.session).await?;
        } else {
            let connected = connect_peer(&resolved.target, session_caps()).await?;
            open_session_kill(
                &connected.connection,
                &connected.session,
                provider.clone(),
                resolved.session,
            )
            .await?;
            close_connected(connected, b"session complete").await;
        }
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn share(
    target: Option<&str>,
    session: &str,
    provider: Option<&str>,
    ttl: Duration,
    access_ttl: Duration,
    label: Option<&str>,
    rendezvous_url: Option<&str>,
    _yes: bool,
    allow_bearer_fallback: bool,
) -> Result<ExitCode> {
    let provider = effective_provider(provider);
    let raw_session = session.trim();
    if raw_session.is_empty() {
        anyhow::bail!("session name cannot be empty");
    }
    let (target_from_ref, session_name) = split_session_ref(Some(raw_session))?;
    let session_name = session_name.expect("split_session_ref returns a session for Some input");

    let target_form = {
        // Classify explicit targets up-front so unsupported forms fail fast without
        // needing local identity and without echoing raw input that may be a ticket credential.
        let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
        let tickets =
            TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
        let aliases = crate::alias_store::AliasStore::default();
        let classify = |hint: &str| match classify_share_target(hint, &peers, &tickets, &aliases) {
            Ok(form) => Ok(form),
            Err(ResolveTargetError::TicketCredential) => {
                anyhow::bail!(
                    "session share cannot delegate a ticket credential passed as --target. \
                     Use a peer-store label, alias, or `endpoint_id` instead."
                );
            }
            Err(err) => Err(err.into()),
        };
        let from_ref = target_from_ref.map(classify).transpose()?;
        let from_flag = target.map(classify).transpose()?;
        if let (Some(left), Some(right)) = (&from_ref, &from_flag)
            && left.endpoint_id() != right.endpoint_id()
        {
            anyhow::bail!(
                "conflicting session share targets: ref selects '{}' but --target selects '{}'",
                left.target_label_hint(),
                right.target_label_hint()
            );
        }
        from_flag.or(from_ref)
    };

    let identity = load_identity(None)?;
    let local_label = crate::commands::local_machine_label(&hex::encode(identity.verifying_key()));
    let (target_label_hint, share_display) = if let Some(form) = &target_form {
        let target_label_hint = form.target_label_hint();
        let display = format!("session \"{session_name}\" on {}", form.safe_display());
        (target_label_hint, display)
    } else {
        let display = format!("local session \"{session_name}\" from {local_label}");
        (local_label.clone(), display)
    };

    let url = resolve_rendezvous_url(rendezvous_url);
    let origin_label_hint = Some(label.map_or_else(|| local_label.clone(), ToOwned::to_owned));
    let target_label_hint = Some(target_label_hint);
    let (workspace_id, conflict_handle) = fresh_workspace_handles();
    let client_cfg = crate::client_endpoint::load_client_config()?;

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let target_addr = if let Some(form) = target_form {
            let client_endpoint =
                crate::client_endpoint::bind_client_endpoint_with_config(&identity, &client_cfg)
                    .await?;
            let endpoint_id = form.endpoint_id();
            let configured_relay_hints = client_cfg
                .discovery
                .relays
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            let resolved_addr = match &form {
                ShareTargetForm::PeerStore { relay_hint, .. } => {
                    crate::commands::peer_resolve::resolve_endpoint_addr_with_relay_hints(
                        &client_endpoint,
                        endpoint_id,
                        relay_hint.as_deref(),
                        &configured_relay_hints,
                        false,
                    )
                    .await
                }
                ShareTargetForm::AliasEid { .. } | ShareTargetForm::RawEid { .. } => {
                    crate::commands::peer_resolve::resolve_endpoint_addr_with_relay_hints(
                        &client_endpoint,
                        endpoint_id,
                        None,
                        &configured_relay_hints,
                        false,
                    )
                    .await
                }
            };
            crate::commands::peer_resolve::close_client_endpoint(client_endpoint, "share resolve")
                .await;
            let (target_addr, _provenance) = resolved_addr?;
            target_addr
        } else {
            local_session_target_addr(&identity, &client_cfg)?
        };

        let share_result = tokio::time::timeout(ttl, async {
            // Open the rendezvous transport.
            let backend = WsRendezvousBackend::new(&url)
                .map_err(|e| anyhow!("rendezvous backend: {e}"))?
                .with_timeout(ttl);
            let mut transport = backend
                .connect_transport()
                .await
                .map_err(|e| anyhow!("connect to rendezvous server: {e}"))?;

            eprintln!("portl: sharing {share_display}");

            let now = unix_now()?;
            let envelope_result = run_offer_against_transport(
                &mut transport,
                None,
                |code| {
                    let display = code.display_code();
                    println!("{display}");
                    println!(
                        "Share this code with a recipient running a Portl build that supports \
                     `portl accept PORTL-S-*`; they should run `portl accept {display}`."
                    );
                    println!(
                        "Keep this command running until they accept (rendezvous TTL {}s).",
                        ttl.as_secs()
                    );
                },
                |hello| {
                    let inputs = EnvelopeInputs {
                        identity: &identity,
                        target_addr: target_addr.clone(),
                        hello,
                        session_name: &session_name,
                        provider: provider.as_deref(),
                        origin_label_hint: origin_label_hint.clone(),
                        target_label_hint: target_label_hint.clone(),
                        workspace_id: workspace_id.clone(),
                        conflict_handle: conflict_handle.clone(),
                        now_unix: now,
                        access_ttl,
                        allow_bearer_fallback,
                    };
                    let BuiltEnvelope {
                        envelope,
                        bound_to_recipient,
                        effective_access_ttl,
                    } = build_session_share_envelope(inputs)?;
                    if bound_to_recipient {
                        eprintln!(
                            "portl: minted recipient-bound ticket (ttl {}s)",
                            effective_access_ttl.as_secs()
                        );
                    } else {
                        eprintln!(
                            "portl: WARNING: recipient hello had no endpoint id; \
                         minting bearer ticket capped at {}s (--allow-bearer-fallback)",
                            effective_access_ttl.as_secs()
                        );
                    }
                    Ok(envelope)
                },
            )
            .await;

            match envelope_result {
                Ok(()) => {
                    eprintln!("portl: recipient accepted; share complete");
                    Ok(ExitCode::SUCCESS)
                }
                Err(err) => Err(err),
            }
        })
        .await;

        match share_result {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "session share timed out after {}s; the short code is no longer being hosted",
                ttl.as_secs()
            )),
        }
    });
    runtime.shutdown_background();
    result
}

fn local_session_target_addr(
    identity: &portl_core::id::Identity,
    cfg: &portl_agent::AgentConfig,
) -> Result<iroh_base::EndpointAddr> {
    let mut addr = iroh_base::EndpointAddr::new(identity.endpoint_id());
    if let Some(relay_hint) = crate::client_endpoint::preferred_relay_hint(cfg) {
        let relay_url = relay_hint
            .parse()
            .with_context(|| format!("parse configured relay URL {relay_hint:?}"))?;
        addr = addr.with_relay_url(relay_url);
    }
    Ok(addr)
}

fn resolved_target_is_local(target: &str) -> Result<bool> {
    let identity = load_identity(None)?;
    let local_endpoint_hex = hex::encode(identity.verifying_key());
    let local_label = crate::commands::local_machine_label(&local_endpoint_hex);
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    let aliases = crate::alias_store::AliasStore::default();
    Ok(resolved_target_is_local_with_stores(
        target,
        &local_label,
        &local_endpoint_hex,
        &peers,
        &tickets,
        &aliases,
    ))
}

fn resolved_target_is_local_with_stores(
    target: &str,
    local_label: &str,
    local_endpoint_hex: &str,
    peers: &PeerStore,
    tickets: &TicketStore,
    aliases: &crate::alias_store::AliasStore,
) -> bool {
    let target = target.trim();
    if target.eq_ignore_ascii_case(local_endpoint_hex) || target == local_label {
        return true;
    }

    for hint in target_hints_for_locality(target) {
        if hint.eq_ignore_ascii_case(local_endpoint_hex) || hint == local_label {
            return true;
        }
        if let Some(entry) = peers.get_by_label(hint)
            && (entry.is_self
                || entry
                    .endpoint_id_hex
                    .eq_ignore_ascii_case(local_endpoint_hex))
        {
            return true;
        }
        if let Some(entry) = tickets.get(hint)
            && entry
                .endpoint_id_hex
                .eq_ignore_ascii_case(local_endpoint_hex)
        {
            return true;
        }
        if let Ok(resolved) = resolve_target_hint_with_stores(hint, peers, tickets, aliases)
            && resolved
                .endpoint_id_hex
                .as_deref()
                .is_some_and(|endpoint| endpoint.eq_ignore_ascii_case(local_endpoint_hex))
        {
            return true;
        }
    }

    false
}

fn target_hints_for_locality(target: &str) -> Vec<&str> {
    let mut hints = vec![target];
    if let Some((host, _session)) = target.split_once('/') {
        hints.push(host);
    }
    hints
}

fn local_session_providers() -> ProviderReport {
    let configured = crate::client_endpoint::load_client_config()
        .ok()
        .and_then(|cfg| cfg.session_provider_path);
    let discovery = portl_agent::session_provider_discovery_info(configured.as_deref());
    ProviderReport {
        default_provider: discovery.default_provider,
        providers: discovery
            .providers
            .into_iter()
            .map(|provider| ProviderStatus {
                capabilities: provider_capabilities(&provider.name),
                available: provider.detected,
                path: provider.path.clone(),
                notes: provider.notes.or(provider.path),
                tier: Some(
                    if provider.name == "raw" {
                        "raw"
                    } else {
                        "local"
                    }
                    .to_owned(),
                ),
                features: Vec::new(),
                name: provider.name,
            })
            .collect(),
    }
}

fn provider_capabilities(provider: &str) -> ProviderCapabilities {
    match provider {
        "zmx" => ProviderCapabilities::zmx(),
        "tmux" => ProviderCapabilities::tmux(),
        _ => ProviderCapabilities::raw(),
    }
}

async fn local_session_list_detailed(
    provider: Option<&str>,
) -> Result<Vec<SessionProviderSessions>> {
    match provider {
        Some("zmx") => Ok(vec![local_zmx_session_group(true).await?]),
        Some("tmux") => Ok(vec![
            local_tmux_session_group(local_zmx_path_opt().is_none()).await?,
        ]),
        Some(other) => {
            anyhow::bail!("unsupported local session provider '{other}' (supported: zmx, tmux)")
        }
        None => {
            let default_provider = local_default_provider().ok();
            let mut groups = Vec::new();
            if local_zmx_path_opt().is_some() {
                groups.push(
                    local_zmx_session_group(default_provider.as_deref() == Some("zmx")).await?,
                );
            }
            if local_tmux_path_opt().is_some() {
                groups.push(
                    local_tmux_session_group(default_provider.as_deref() == Some("tmux")).await?,
                );
            }
            Ok(groups)
        }
    }
}

async fn local_zmx_session_group(is_default: bool) -> Result<SessionProviderSessions> {
    Ok(SessionProviderSessions {
        provider: "zmx".to_owned(),
        available: true,
        default: is_default,
        sessions: local_zmx_sessions_detailed().await?,
    })
}

async fn local_tmux_session_group(is_default: bool) -> Result<SessionProviderSessions> {
    Ok(SessionProviderSessions {
        provider: "tmux".to_owned(),
        available: true,
        default: is_default,
        sessions: local_tmux_sessions_detailed().await?,
    })
}

async fn local_zmx_sessions_detailed() -> Result<Vec<SessionInfo>> {
    let output = run_local_zmx_capture(&["list", "--json"]).await?;
    if output.code == 0 {
        if let Some(sessions) = parse_local_zmx_json_sessions(&output.stdout) {
            return Ok(sessions);
        }
    }
    Ok(local_zmx_list()
        .await?
        .into_iter()
        .map(|name| SessionInfo {
            name,
            provider: "zmx".to_owned(),
            metadata: BTreeMap::new(),
        })
        .collect())
}

async fn local_tmux_sessions_detailed() -> Result<Vec<SessionInfo>> {
    let output = run_local_tmux_capture(&[
        "list-sessions",
        "-F",
        "#{session_name}\t#{session_id}\t#{session_attached}\t#{session_created}\t#{session_windows}\t#{window_width}\t#{window_height}",
    ])
    .await?;
    if output.code != 0 {
        let stderr = output.stderr.to_lowercase();
        if tmux_list_empty_error(&stderr) {
            return Ok(Vec::new());
        }
        ensure_local_provider_success("tmux list-sessions", &output)?;
    }
    Ok(output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(parse_local_tmux_session_line)
        .collect())
}

async fn local_zmx_list() -> Result<Vec<String>> {
    let output = run_local_zmx_capture(&["list"]).await?;
    ensure_local_provider_success("zmx list", &output)?;
    Ok(session_names_from_stdout(&output.stdout))
}

async fn local_tmux_list() -> Result<Vec<String>> {
    let output = run_local_tmux_capture(&["list-sessions", "-F", "#{session_name}"]).await?;
    if output.code != 0 {
        let stderr = output.stderr.to_lowercase();
        if tmux_list_empty_error(&stderr) {
            return Ok(Vec::new());
        }
        ensure_local_provider_success("tmux list-sessions", &output)?;
    }
    Ok(session_names_from_stdout(&output.stdout))
}

fn parse_local_zmx_json_sessions(stdout: &str) -> Option<Vec<SessionInfo>> {
    let value: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let items = value.as_array()?;
    Some(
        items
            .iter()
            .filter_map(|item| match item {
                serde_json::Value::String(name) => Some(SessionInfo {
                    name: name.clone(),
                    provider: "zmx".to_owned(),
                    metadata: BTreeMap::new(),
                }),
                serde_json::Value::Object(object) => object
                    .get("name")
                    .or_else(|| object.get("session"))
                    .and_then(serde_json::Value::as_str)
                    .map(|name| SessionInfo {
                        name: name.to_owned(),
                        provider: "zmx".to_owned(),
                        metadata: stringify_local_json_object(object, &["name", "session"]),
                    }),
                _ => None,
            })
            .collect(),
    )
}

fn parse_local_tmux_session_line(line: &str) -> SessionInfo {
    let mut parts = line.split('\t');
    let name = parts.next().unwrap_or_default().to_owned();
    let id = parts.next().unwrap_or_default();
    let attached = parts.next().unwrap_or_default();
    let created = parts.next().unwrap_or_default();
    let windows = parts.next().unwrap_or_default();
    let width = parts.next().unwrap_or_default();
    let height = parts.next().unwrap_or_default();
    SessionInfo {
        name,
        provider: "tmux".to_owned(),
        metadata: BTreeMap::from([
            ("id".to_owned(), id.to_owned()),
            ("attached".to_owned(), (attached == "1").to_string()),
            ("created_unix".to_owned(), created.to_owned()),
            ("windows".to_owned(), windows.to_owned()),
            ("width".to_owned(), width.to_owned()),
            ("height".to_owned(), height.to_owned()),
        ]),
    }
}

fn session_names_from_stdout(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn tmux_list_empty_error(stderr: &str) -> bool {
    stderr.contains("no server running")
        || stderr.contains("no sessions")
        || (stderr.contains("error connecting") && stderr.contains("no such file or directory"))
}

fn stringify_local_json_object(
    object: &serde_json::Map<String, serde_json::Value>,
    skip_keys: &[&str],
) -> BTreeMap<String, String> {
    object
        .iter()
        .filter(|(key, _)| !skip_keys.contains(&key.as_str()))
        .map(|(key, value)| {
            let value = value
                .as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| value.to_string());
            (key.clone(), value)
        })
        .collect()
}

async fn local_session_run(
    provider: Option<&str>,
    session: &str,
    argv: &[String],
) -> Result<portl_proto::session_v1::SessionRunResult> {
    match provider {
        None | Some("zmx") => {
            let mut zmx_args = vec!["run", session];
            zmx_args.extend(argv.iter().map(String::as_str));
            run_local_zmx_capture(&zmx_args).await
        }
        Some("tmux") => anyhow::bail!("persistent session provider 'tmux' does not support run"),
        Some(other) => {
            anyhow::bail!("unsupported local session provider '{other}' (supported: zmx, tmux)")
        }
    }
}

async fn local_session_history(provider: Option<&str>, session: &str) -> Result<String> {
    match resolve_local_provider_for_session(provider, session, false)
        .await?
        .as_str()
    {
        "zmx" => {
            let output = run_local_zmx_capture(&["history", session]).await?;
            ensure_local_provider_success("zmx history", &output)?;
            Ok(output.stdout)
        }
        "tmux" => {
            let output = run_local_tmux_capture(&[
                "capture-pane",
                "-p",
                "-e",
                "-S",
                "-",
                "-E",
                "-",
                "-t",
                session,
            ])
            .await?;
            ensure_local_provider_success("tmux capture-pane", &output)?;
            Ok(output.stdout)
        }
        other => unreachable!("unsupported provider {other}"),
    }
}

async fn local_session_kill(provider: Option<&str>, session: &str) -> Result<()> {
    match resolve_local_provider_for_session(provider, session, false)
        .await?
        .as_str()
    {
        "zmx" => {
            let output = run_local_zmx_capture(&["kill", session]).await?;
            ensure_local_provider_success("zmx kill", &output)
        }
        "tmux" => {
            let output = run_local_tmux_capture(&["kill-session", "-t", session]).await?;
            ensure_local_provider_success("tmux kill-session", &output)
        }
        other => unreachable!("unsupported provider {other}"),
    }
}

async fn local_session_attach(
    provider: Option<&str>,
    session: &str,
    user: Option<&str>,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    if let Some(user) = user {
        anyhow::bail!(
            "--user is only supported for remote session targets, not local attach ({user})"
        );
    }
    match resolve_local_provider_for_session(provider, session, true)
        .await?
        .as_str()
    {
        "zmx" => local_zmx_attach(session, cwd, argv).await,
        "tmux" => local_tmux_attach(session, argv).await,
        other => unreachable!("unsupported provider {other}"),
    }
}

async fn local_zmx_attach(session: &str, cwd: Option<&str>, argv: &[String]) -> Result<ExitCode> {
    let path = local_zmx_path()?;
    eprintln!("portl: using local session provider zmx");
    eprintln!("portl: attaching to local session \"{session}\"");
    let mut command = Command::new(path);
    command.arg("attach").arg(session).args(argv);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = command.status().await.context("run zmx attach")?;
    Ok(exit_code_from_i32(status.code().unwrap_or(1)))
}

async fn local_tmux_attach(session: &str, argv: &[String]) -> Result<ExitCode> {
    let path = local_tmux_path()?;
    eprintln!("portl: using local session provider tmux");
    eprintln!("portl: attaching to local session \"{session}\"");
    let mut command = Command::new(path);
    if argv.is_empty() {
        command.args(["attach-session", "-t", session]);
    } else {
        command
            .args(["new-session", "-A", "-s", session])
            .args(argv);
    }
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = command.status().await.context("run tmux attach")?;
    Ok(exit_code_from_i32(status.code().unwrap_or(1)))
}

async fn resolve_local_provider_for_session(
    provider: Option<&str>,
    session: &str,
    create_if_missing: bool,
) -> Result<String> {
    if let Some(provider) = provider {
        match provider {
            "zmx" | "tmux" => return Ok(provider.to_owned()),
            other => {
                anyhow::bail!("unsupported local session provider '{other}' (supported: zmx, tmux)")
            }
        }
    }

    let mut providers = Vec::new();
    if local_zmx_path_opt().is_some() && local_zmx_list().await?.iter().any(|name| name == session)
    {
        providers.push("zmx".to_owned());
    }
    let tmux_session = session.split_once(':').map_or(session, |(name, _)| name);
    if local_tmux_path_opt().is_some()
        && local_tmux_list()
            .await?
            .iter()
            .any(|name| name == tmux_session)
    {
        providers.push("tmux".to_owned());
    }

    match providers.as_slice() {
        [provider] => Ok(provider.clone()),
        [] if create_if_missing => local_default_provider(),
        [] => anyhow::bail!("persistent session '{session}' was not found locally"),
        _ => anyhow::bail!(
            "persistent session '{session}' exists in multiple providers: {}; rerun with --provider or PORTL_SESSION_PROVIDER",
            providers.join(", ")
        ),
    }
}

fn local_default_provider() -> Result<String> {
    if local_zmx_path_opt().is_some() {
        Ok("zmx".to_owned())
    } else if local_tmux_path_opt().is_some() {
        Ok("tmux".to_owned())
    } else {
        anyhow::bail!("no local persistent session provider is installed")
    }
}

async fn run_local_zmx_capture(args: &[&str]) -> Result<portl_proto::session_v1::SessionRunResult> {
    let path = local_zmx_path()?;
    run_local_capture(&path, args).await
}

async fn run_local_tmux_capture(
    args: &[&str],
) -> Result<portl_proto::session_v1::SessionRunResult> {
    let path = local_tmux_path()?;
    run_local_capture(&path, args).await
}

async fn run_local_capture(
    path: &PathBuf,
    args: &[&str],
) -> Result<portl_proto::session_v1::SessionRunResult> {
    let output = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("run {} {}", path.display(), args.join(" ")))?;
    Ok(portl_proto::session_v1::SessionRunResult {
        code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn ensure_local_provider_success(
    context: &str,
    output: &portl_proto::session_v1::SessionRunResult,
) -> Result<()> {
    if output.code == 0 {
        Ok(())
    } else {
        anyhow::bail!(
            "{context} failed with code {}: {}",
            output.code,
            output.stderr.trim()
        )
    }
}

fn local_zmx_path() -> Result<PathBuf> {
    local_zmx_path_opt().ok_or_else(|| anyhow!("zmx is not installed locally"))
}

fn local_zmx_path_opt() -> Option<PathBuf> {
    configured_session_provider_path()
        .filter(|path| !path_is_program(path, "tmux"))
        .filter(|path| path.exists())
        .or_else(|| find_on_safe_path("zmx"))
}

fn local_tmux_path() -> Result<PathBuf> {
    local_tmux_path_opt().ok_or_else(|| anyhow!("tmux is not installed locally"))
}

fn local_tmux_path_opt() -> Option<PathBuf> {
    configured_session_provider_path()
        .filter(|path| path_is_program(path, "tmux"))
        .filter(|path| path.exists())
        .or_else(|| find_on_safe_path("tmux"))
}

fn configured_session_provider_path() -> Option<PathBuf> {
    crate::client_endpoint::load_client_config()
        .ok()
        .and_then(|cfg| cfg.session_provider_path)
}

fn path_is_program(path: &std::path::Path, program: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == program)
}

fn find_on_safe_path(program: &str) -> Option<PathBuf> {
    let mut dirs = [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/bin",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect::<Vec<_>>();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        dirs.extend([
            home.join(".local/bin"),
            home.join("bin"),
            home.join(".cargo/bin"),
            home.join(".local/share/mise/shims"),
        ]);
    }
    dirs.into_iter()
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.exists())
}

fn attach_session_defaults(
    target: &str,
    session: Option<&str>,
    provider: Option<&str>,
) -> Result<(String, Option<String>)> {
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    Ok(attach_session_defaults_from_store(
        target, session, provider, &tickets,
    ))
}

fn attach_session_defaults_from_store(
    target: &str,
    session: Option<&str>,
    provider: Option<&str>,
    tickets: &TicketStore,
) -> (String, Option<String>) {
    if let Some(session) = session {
        return (session.to_owned(), provider.map(ToOwned::to_owned));
    }

    if let Some(metadata) = tickets
        .get(target)
        .and_then(|entry| entry.session_share.as_ref())
    {
        return (
            metadata.provider_session.clone(),
            provider
                .map(ToOwned::to_owned)
                .or_else(|| metadata.provider.clone()),
        );
    }

    (
        default_session_name(target, None),
        provider.map(ToOwned::to_owned),
    )
}

pub fn attach(
    session: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
    user: Option<&str>,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let provider = effective_provider(provider);
    let resolved = resolve_session_ref(session, target)?;
    let (session_name, provider_name) = attach_session_defaults(
        &resolved.target,
        Some(&resolved.session),
        provider.as_deref(),
    )?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        if resolved_target_is_local(&resolved.target)? {
            return local_session_attach(provider_name.as_deref(), &session_name, user, cwd, argv)
                .await;
        }

        let connected = connect_peer(&resolved.target, session_caps()).await?;
        let (cols, rows) = size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        eprintln!(
            "portl: using session provider {}",
            provider_name.as_deref().unwrap_or("target default")
        );
        eprintln!("portl: attaching to session \"{session_name}\"");
        let session = open_session_attach(
            &connected.connection,
            &connected.session,
            provider_name,
            session_name,
            (!argv.is_empty()).then_some(argv.to_vec()),
            user.map(ToOwned::to_owned),
            cwd.map(ToOwned::to_owned),
            portl_core::net::shell_client::PtyCfg { term, cols, rows },
        )
        .await?;
        let code = bridge_attach(session, cols, rows).await?;
        close_connected(connected, b"session complete").await;
        Ok(exit_code_from_i32(code))
    });
    runtime.shutdown_background();
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedSessionRef {
    target: String,
    session: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedTargetHint {
    label: String,
    endpoint_id_hex: Option<String>,
}

fn resolve_target_only(target: Option<&str>) -> Result<String> {
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    let aliases = crate::alias_store::AliasStore::default();
    if let Some(hint) = target.map(str::trim).filter(|value| !value.is_empty()) {
        return resolve_target_hint_with_stores(hint, &peers, &tickets, &aliases)
            .map(|resolved| resolved.label);
    }
    if let Some(hint) = env_target() {
        return resolve_target_hint_with_stores(&hint, &peers, &tickets, &aliases)
            .map(|resolved| resolved.label);
    }
    local_target_label()
}

fn resolve_session_ref(
    session_ref: Option<&str>,
    target: Option<&str>,
) -> Result<ResolvedSessionRef> {
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    let aliases = crate::alias_store::AliasStore::default();
    let env = env_target();
    resolve_session_ref_with_stores(
        session_ref,
        target,
        env.as_deref(),
        &peers,
        &tickets,
        &aliases,
    )
}

fn resolve_session_ref_with_stores(
    session_ref: Option<&str>,
    target: Option<&str>,
    env_target: Option<&str>,
    peers: &PeerStore,
    tickets: &TicketStore,
    aliases: &crate::alias_store::AliasStore,
) -> Result<ResolvedSessionRef> {
    let session_ref = session_ref.map(str::trim).filter(|value| !value.is_empty());
    if let Some(session_ref) = session_ref
        && target.is_none()
        && let Some(metadata) = tickets
            .get(session_ref)
            .and_then(|entry| entry.session_share.as_ref())
    {
        return Ok(ResolvedSessionRef {
            target: session_ref.to_owned(),
            session: metadata.provider_session.clone(),
        });
    }

    let (host_from_ref, session_name) = split_session_ref(session_ref)?;
    let target_from_ref = host_from_ref
        .map(|hint| resolve_target_hint_with_stores(hint, peers, tickets, aliases))
        .transpose()?;
    let target_from_flag = target
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|hint| resolve_target_hint_with_stores(hint, peers, tickets, aliases))
        .transpose()?;

    if let (Some(left), Some(right)) = (&target_from_ref, &target_from_flag)
        && !same_target(left, right)
    {
        anyhow::bail!(
            "conflicting session targets: ref selects '{}' but --target selects '{}'",
            left.label,
            right.label
        );
    }

    let explicit_target = target_from_flag.or(target_from_ref);
    let env_target = if explicit_target.is_none() {
        env_target
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|hint| resolve_target_hint_with_stores(hint, peers, tickets, aliases))
            .transpose()?
    } else {
        None
    };
    let target_hint = explicit_target.or(env_target);

    let session = session_name.unwrap_or_else(|| "default".to_owned());
    let target = if let Some(target_hint) = target_hint {
        session_share_ticket_label(tickets, &target_hint.label, &session)
            .unwrap_or(target_hint.label)
    } else {
        local_target_label()?
    };

    Ok(ResolvedSessionRef { target, session })
}

fn split_session_ref(session_ref: Option<&str>) -> Result<(Option<&str>, Option<String>)> {
    let Some(session_ref) = session_ref else {
        return Ok((None, None));
    };
    if let Some((host, session)) = session_ref.split_once('/') {
        let host = host.trim();
        let session = session.trim();
        if host.is_empty() || session.is_empty() || session.contains('/') {
            anyhow::bail!("session refs must use HOST/SESSION with non-empty host and session");
        }
        Ok((Some(host), Some(session.to_owned())))
    } else {
        Ok((None, Some(session_ref.to_owned())))
    }
}

fn env_target() -> Option<String> {
    std::env::var("PORTL_TARGET")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn local_target_label() -> Result<String> {
    let identity = load_identity(None)?;
    Ok(crate::commands::local_machine_label(&hex::encode(
        identity.verifying_key(),
    )))
}

fn resolve_target_hint_with_stores(
    hint: &str,
    peers: &PeerStore,
    tickets: &TicketStore,
    aliases: &crate::alias_store::AliasStore,
) -> Result<ResolvedTargetHint> {
    if let Some(entry) = peers.get_by_label(hint) {
        return Ok(ResolvedTargetHint {
            label: entry.label.clone(),
            endpoint_id_hex: Some(entry.endpoint_id_hex.clone()),
        });
    }
    if let Some(entry) = tickets.get(hint) {
        return Ok(ResolvedTargetHint {
            label: hint.to_owned(),
            endpoint_id_hex: Some(entry.endpoint_id_hex.clone()),
        });
    }
    if let Some(alias) = aliases.get(hint)? {
        return Ok(ResolvedTargetHint {
            label: alias.name,
            endpoint_id_hex: Some(alias.endpoint_id),
        });
    }
    if hint.len() == 64 && hint.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(ResolvedTargetHint {
            label: hint.to_ascii_lowercase(),
            endpoint_id_hex: Some(hint.to_ascii_lowercase()),
        });
    }

    resolve_unique_hostname(hint, peers, tickets)
}

fn resolve_unique_hostname(
    host: &str,
    peers: &PeerStore,
    tickets: &TicketStore,
) -> Result<ResolvedTargetHint> {
    let mut matches: Vec<ResolvedTargetHint> = Vec::new();
    for entry in peers.iter() {
        if label_hostname(&entry.label).as_deref() == Some(host) {
            matches.push(ResolvedTargetHint {
                label: entry.label.clone(),
                endpoint_id_hex: Some(entry.endpoint_id_hex.clone()),
            });
        }
    }
    for (label, entry) in tickets.iter() {
        if let Some((ticket_host, _)) = label.split_once('/')
            && label_hostname(ticket_host).as_deref() == Some(host)
        {
            matches.push(ResolvedTargetHint {
                label: ticket_host.to_owned(),
                endpoint_id_hex: Some(entry.endpoint_id_hex.clone()),
            });
        }
    }
    matches.sort_by(|a, b| a.label.cmp(&b.label));
    matches.dedup_by(|a, b| same_target(a, b));

    match matches.as_slice() {
        [only] => Ok(only.clone()),
        [] => anyhow::bail!(
            "unsupported session target '{host}'. Use a peer label, saved ticket label, endpoint_id, or unique host shorthand"
        ),
        many => {
            let labels = many
                .iter()
                .map(|item| format!("  {}", item.label))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!("ambiguous target shorthand '{host}'\n\nMatches:\n{labels}")
        }
    }
}

fn label_hostname(label: &str) -> Option<String> {
    let (host, suffix) = label.rsplit_once('-')?;
    (suffix.len() == 4 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())).then(|| host.to_owned())
}

fn same_target(left: &ResolvedTargetHint, right: &ResolvedTargetHint) -> bool {
    match (&left.endpoint_id_hex, &right.endpoint_id_hex) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => left.label == right.label,
    }
}

fn session_share_ticket_label(
    tickets: &TicketStore,
    target_label: &str,
    session_name: &str,
) -> Option<String> {
    let label = portl_core::labels::session_share_label(target_label, session_name);
    tickets
        .get(&label)
        .and_then(|entry| entry.session_share.as_ref())
        .map(|_| label)
}

async fn bridge_attach(session: SessionClient, cols: u16, rows: u16) -> Result<i32> {
    let raw_guard = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::new()?)
    } else {
        None
    };
    let SessionClient {
        control_send: _control_send,
        control_recv: _control_recv,
        stdin,
        stdout: mut stdout_recv,
        stderr: mut stderr_recv,
        mut exit,
        signal: _signal,
        resize,
    } = session;
    let stdin_task = maybe_spawn_stdin_task(stdin)?;
    let stdout_task = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        copy(&mut stdout_recv, &mut stdout)
            .await
            .context("copy remote stdout")?;
        stdout.flush().await.context("flush local stdout")?;
        Ok::<_, anyhow::Error>(())
    });
    let stderr_task = tokio::spawn(async move {
        let mut stderr = tokio::io::stderr();
        copy(&mut stderr_recv, &mut stderr)
            .await
            .context("copy remote stderr")?;
        stderr.flush().await.context("flush local stderr")?;
        Ok::<_, anyhow::Error>(())
    });
    let resize_task = tokio::spawn(async move {
        let mut resize = resize;
        let mut last = (cols, rows);
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(now) = size()
                && now != last
            {
                let frame = portl_proto::shell_v1::ResizeFrame {
                    cols: now.0,
                    rows: now.1,
                };
                resize
                    .write_all(&postcard::to_stdvec(&frame).context("encode resize frame")?)
                    .await
                    .context("write resize frame")?;
                last = now;
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });
    let code = read_exit(&mut exit).await?;
    resize_task.abort();
    if let Some(stdin_task) = stdin_task {
        stdin_task.abort();
        let _ = stdin_task.await;
    }
    await_output_task(stdout_task, "stdout").await?;
    await_output_task(stderr_task, "stderr").await?;
    drop(raw_guard);
    Ok(code)
}

fn session_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Merge { allow: None },
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn default_session_name(target: &str, session: Option<&str>) -> String {
    session.map_or_else(
        || {
            if looks_like_raw_target(target) {
                "default".to_owned()
            } else {
                target.to_owned()
            }
        },
        ToOwned::to_owned,
    )
}

fn looks_like_raw_target(target: &str) -> bool {
    target.starts_with("portl")
        || (target.len() == 64 && target.chars().all(|c| c.is_ascii_hexdigit()))
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Result<Self> {
        enable_raw_mode().context("enable raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

async fn await_output_task(
    mut task: tokio::task::JoinHandle<Result<()>>,
    stream_name: &str,
) -> Result<()> {
    if let Ok(joined) = tokio::time::timeout(Duration::from_millis(250), &mut task).await {
        joined.with_context(|| format!("join {stream_name} task"))??;
    } else {
        debug!(
            stream = stream_name,
            "timed out waiting for output drain; aborting task"
        );
        task.abort();
    }
    Ok(())
}

fn maybe_spawn_stdin_task(mut send: SendStream) -> Result<Option<tokio::task::JoinHandle<()>>> {
    if should_close_idle_stdin()? {
        if let Err(err) = send.finish().context("finish remote stdin") {
            debug!(%err, "remote stdin already closed");
        }
        return Ok(None);
    }
    Ok(Some(tokio::spawn(async move {
        let mut stdin_src = tokio::io::stdin();
        let _ = stdin_loop(&mut send, &mut stdin_src).await;
    })))
}

fn should_close_idle_stdin() -> Result<bool> {
    if std::io::stdin().is_terminal() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        stdin_ready_within(Duration::from_millis(50)).map(|ready| !ready)
    }
    #[cfg(not(unix))]
    {
        Ok(false)
    }
}

#[cfg(unix)]
fn stdin_ready_within(timeout: Duration) -> Result<bool> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::os::fd::AsFd;
    let stdin = std::io::stdin();
    let mut pollfds = [PollFd::new(stdin.as_fd(), PollFlags::POLLIN)];
    let ready = poll(
        &mut pollfds,
        PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX),
    )
    .context("poll local stdin")?;
    if ready == 0 {
        return Ok(false);
    }
    let events = pollfds[0].revents().unwrap_or(PollFlags::empty());
    Ok(events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
}

async fn stdin_loop(send: &mut SendStream, stdin: &mut tokio::io::Stdin) -> Result<()> {
    if let Err(err) = copy(stdin, send).await.context("copy local stdin") {
        debug!(%err, "stdin loop ended after remote stdin closed");
        return Ok(());
    }
    if let Err(err) = send.finish().context("finish remote stdin") {
        debug!(%err, "remote stdin already closed");
    }
    Ok(())
}

async fn read_exit(recv: &mut BufferedRecv) -> Result<i32> {
    let frame = recv
        .read_frame::<portl_proto::shell_v1::ExitFrame>(128)
        .await?
        .context("missing exit frame")?;
    Ok(frame.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore};
    use portl_core::ticket_store::{SessionShareMetadata, TicketEntry};
    use tempfile::TempDir;

    #[test]
    fn attach_defaults_infer_session_share_metadata() {
        let mut tickets = TicketStore::new();
        tickets
            .insert(
                "max-b265/dotfiles".to_owned(),
                TicketEntry {
                    endpoint_id_hex: hex::encode([1u8; 32]),
                    ticket_string: "portl-redacted".to_owned(),
                    expires_at: 2_000_000,
                    saved_at: 1_000_000,
                    session_share: Some(SessionShareMetadata {
                        friendly_name: "dotfiles".to_owned(),
                        provider_session: "dotfiles".to_owned(),
                        provider: Some("zmx".to_owned()),
                        origin_label_hint: Some("max-b265".to_owned()),
                        target_label_hint: Some("max-b265".to_owned()),
                    }),
                },
            )
            .unwrap();

        let (session, provider) =
            attach_session_defaults_from_store("max-b265/dotfiles", None, None, &tickets);

        assert_eq!(session, "dotfiles");
        assert_eq!(provider.as_deref(), Some("zmx"));
    }

    #[test]
    fn provider_env_precedence_matches_provider_flag_semantics() {
        assert_eq!(
            effective_provider_from_env(Some("zmx"), Some("tmux")).as_deref(),
            Some("zmx")
        );
        assert_eq!(
            effective_provider_from_env(None, Some("tmux")).as_deref(),
            Some("tmux")
        );
        assert_eq!(effective_provider_from_env(None, Some("  ")), None);
        assert_eq!(effective_provider_from_env(None, None), None);
    }

    #[test]
    fn provider_aware_list_formatting_and_json_are_structured() {
        let entries = ListedSessions::Entries(vec![SessionEntry {
            provider: "zmx".to_owned(),
            name: "dev".to_owned(),
        }]);
        assert_eq!(
            listed_sessions_human(&entries),
            "PROVIDER  SESSION\nzmx       dev\n"
        );
        assert_eq!(
            serde_json::to_value(&entries).unwrap(),
            serde_json::json!([{ "provider": "zmx", "name": "dev" }])
        );

        let names = ListedSessions::Names(vec!["dev".to_owned()]);
        assert_eq!(listed_sessions_human(&names), "dev\n");
        assert_eq!(
            serde_json::to_value(&names).unwrap(),
            serde_json::json!(["dev"])
        );
    }

    #[test]
    fn attach_defaults_honor_explicit_session_and_provider() {
        let tickets = TicketStore::new();

        let (session, provider) = attach_session_defaults_from_store(
            "max-b265/dotfiles",
            Some("override"),
            Some("manual"),
            &tickets,
        );

        assert_eq!(session, "override");
        assert_eq!(provider.as_deref(), Some("manual"));
    }

    struct ResolverFixture {
        _dir: TempDir,
        peers: PeerStore,
        tickets: TicketStore,
        aliases: crate::alias_store::AliasStore,
    }

    fn seed_peer_and_share() -> ResolverFixture {
        let dir = TempDir::new().unwrap();
        let mut peers = PeerStore::new();
        peers
            .insert_or_update(PeerEntry {
                label: "max-b265".to_owned(),
                endpoint_id_hex: hex::encode([0x2a; 32]),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 1,
                origin: PeerOrigin::Paired,
                last_hold_at: None,
                is_self: false,
                relay_hint: None,
                schema_version: PeerEntry::default_schema_version(),
            })
            .unwrap();

        let mut tickets = TicketStore::new();
        tickets
            .insert(
                "max-b265/dotfiles".to_owned(),
                TicketEntry {
                    endpoint_id_hex: hex::encode([0x2a; 32]),
                    ticket_string: "portl-redacted".to_owned(),
                    expires_at: 2_000_000,
                    saved_at: 1_000_000,
                    session_share: Some(SessionShareMetadata {
                        friendly_name: "dotfiles".to_owned(),
                        provider_session: "dotfiles".to_owned(),
                        provider: Some("zmx".to_owned()),
                        origin_label_hint: Some("max-b265".to_owned()),
                        target_label_hint: Some("max-b265".to_owned()),
                    }),
                },
            )
            .unwrap();
        ResolverFixture {
            aliases: crate::alias_store::AliasStore::new(dir.path().join("aliases.json")),
            _dir: dir,
            peers,
            tickets,
        }
    }

    #[test]
    fn session_ref_accepts_unique_host_shorthand() {
        let fixture = seed_peer_and_share();
        let resolved = resolve_session_ref_with_stores(
            Some("max/dotfiles"),
            None,
            None,
            &fixture.peers,
            &fixture.tickets,
            &fixture.aliases,
        )
        .unwrap();
        assert_eq!(resolved.target, "max-b265/dotfiles");
        assert_eq!(resolved.session, "dotfiles");
    }

    #[test]
    fn portl_target_accepts_unique_host_shorthand() {
        let fixture = seed_peer_and_share();
        let resolved = resolve_session_ref_with_stores(
            Some("dotfiles"),
            None,
            Some("max"),
            &fixture.peers,
            &fixture.tickets,
            &fixture.aliases,
        )
        .unwrap();
        assert_eq!(resolved.target, "max-b265/dotfiles");
        assert_eq!(resolved.session, "dotfiles");
    }

    #[test]
    fn session_ref_and_target_may_duplicate_same_target() {
        let fixture = seed_peer_and_share();
        let resolved = resolve_session_ref_with_stores(
            Some("max/dotfiles"),
            Some("max-b265"),
            None,
            &fixture.peers,
            &fixture.tickets,
            &fixture.aliases,
        )
        .unwrap();
        assert_eq!(resolved.target, "max-b265/dotfiles");
        assert_eq!(resolved.session, "dotfiles");
    }

    #[test]
    fn resolved_targets_detect_local_self_endpoint() {
        let dir = TempDir::new().unwrap();
        let mut peers = PeerStore::new();
        peers
            .insert_or_update(PeerEntry {
                label: "max-b265".to_owned(),
                endpoint_id_hex: hex::encode([0xb2; 32]),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 1,
                origin: PeerOrigin::Zelf,
                last_hold_at: None,
                is_self: true,
                relay_hint: Some("https://relay.example/".to_owned()),
                schema_version: PeerEntry::default_schema_version(),
            })
            .unwrap();
        let tickets = TicketStore::new();
        let aliases = crate::alias_store::AliasStore::new(dir.path().join("aliases.json"));

        assert!(resolved_target_is_local_with_stores(
            "max-b265",
            "max-b265",
            &hex::encode([0xb2; 32]),
            &peers,
            &tickets,
            &aliases,
        ));
        assert!(resolved_target_is_local_with_stores(
            "max-b265/dotfiles",
            "max-b265",
            &hex::encode([0xb2; 32]),
            &peers,
            &tickets,
            &aliases,
        ));
    }

    #[test]
    fn human_session_list_reports_empty_provider_filter() {
        let listing = SessionListing {
            target: "max-b265".to_owned(),
            provider_filter: Some("zmx".to_owned()),
            total: 0,
            providers: BTreeMap::new(),
        };

        assert_eq!(
            render_session_listing_human(&listing),
            "0 existing zmx sessions found.\n"
        );
    }

    #[test]
    fn json_session_list_groups_sessions_by_provider_with_metadata() {
        let mut providers = BTreeMap::new();
        providers.insert(
            "tmux".to_owned(),
            SessionProviderListing {
                available: true,
                is_default: false,
                count: 2,
                sessions: vec![
                    SessionListingEntry {
                        name: "dev".to_owned(),
                        provider: "tmux".to_owned(),
                        metadata: serde_json::json!({
                            "id": "$1",
                            "attached": false,
                            "windows": 2
                        }),
                    },
                    SessionListingEntry {
                        name: "frontend".to_owned(),
                        provider: "tmux".to_owned(),
                        metadata: serde_json::json!({}),
                    },
                ],
            },
        );
        let listing = SessionListing {
            target: "max-b265".to_owned(),
            provider_filter: None,
            total: 2,
            providers,
        };

        let value = serde_json::to_value(&listing).unwrap();
        assert_eq!(value["target"], "max-b265");
        assert_eq!(value["provider_filter"], serde_json::Value::Null);
        assert_eq!(value["total"], 2);
        assert_eq!(value["providers"]["tmux"]["count"], 2);
        assert_eq!(value["providers"]["tmux"]["sessions"][0]["name"], "dev");
        assert_eq!(
            value["providers"]["tmux"]["sessions"][0]["metadata"]["attached"],
            false
        );
    }

    #[test]
    fn session_ref_and_target_reject_conflicts() {
        let mut fixture = seed_peer_and_share();
        fixture
            .peers
            .insert_or_update(PeerEntry {
                label: "onyx-7310".to_owned(),
                endpoint_id_hex: hex::encode([0x31; 32]),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 1,
                origin: PeerOrigin::Paired,
                last_hold_at: None,
                is_self: false,
                relay_hint: None,
                schema_version: PeerEntry::default_schema_version(),
            })
            .unwrap();

        let err = resolve_session_ref_with_stores(
            Some("max/dotfiles"),
            Some("onyx"),
            None,
            &fixture.peers,
            &fixture.tickets,
            &fixture.aliases,
        )
        .unwrap_err();
        assert!(err.to_string().contains("conflicting session targets"));
    }
}

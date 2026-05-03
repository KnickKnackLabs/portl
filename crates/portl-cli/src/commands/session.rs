use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use futures_util::stream::{FuturesUnordered, StreamExt};
use iroh::endpoint::SendStream;
use portl_core::attach_control::{
    RenderBarOptions, fit_visible, is_ctrl_backslash_sequence, render_bar,
};
use portl_core::io::BufferedRecv;
use portl_core::net::{
    SessionClient, open_session_attach, open_session_history, open_session_kill,
    open_session_list_detailed, open_session_providers, open_session_run,
};
use portl_core::terminal::{tmux_cc, zmx_control};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use portl_core::wire::session::{SessionControlAction, SessionControlFrame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tracing::debug;

use crate::commands::peer_resolve::{close_connected, connect_peer, connect_peer_quiet};
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
use tokio::sync::mpsc;

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
    reference: String,
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
                    .map(|session| SessionListingEntry::from_session(target, session))
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

impl SessionListingEntry {
    fn from_session(target: &str, session: SessionInfo) -> Self {
        let reference = canonical_session_ref(target, &session.provider, &session.name);
        Self {
            name: session.name,
            provider: session.provider,
            reference,
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
                out.push_str(&session.reference);
                out.push('\n');
            }
        }
    } else {
        out.push_str("PROVIDER  REF\n");
        for (provider_name, provider) in &listing.providers {
            for session in &provider.sessions {
                let _ = writeln!(out, "{provider_name:<8}  {}", session.reference);
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
        .map(normalize_session_provider_alias)
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

pub fn ls(
    target_ref: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let (target, provider) = resolve_ls_ref_filters(target_ref, target, provider)?;
    let target = resolve_target_only(target.as_deref())?;
    let provider = effective_provider(provider.as_deref());
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

fn resolve_ls_ref_filters(
    target_ref: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    let aliases = crate::alias_store::AliasStore::default();
    resolve_ls_ref_filters_with_stores(target_ref, target, provider, &peers, &tickets, &aliases)
}

fn resolve_ls_ref_filters_with_stores(
    target_ref: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
    peers: &PeerStore,
    tickets: &TicketStore,
    aliases: &crate::alias_store::AliasStore,
) -> Result<(Option<String>, Option<String>)> {
    let (target_from_ref, provider_from_ref) = split_ls_ref(target_ref)?;
    let target_from_flag = target
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let (Some(left), Some(right)) = (&target_from_ref, &target_from_flag) {
        let left_target = resolve_target_hint_with_stores(left, peers, tickets, aliases)?;
        let right_target = resolve_target_hint_with_stores(right, peers, tickets, aliases)?;
        if !same_target(&left_target, &right_target) {
            anyhow::bail!(
                "conflicting session list targets: positional ref selects '{left}' but --target selects '{right}'"
            );
        }
    }
    let provider_from_flag = provider
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_session_provider)
        .transpose()?;
    let provider = merge_session_providers(provider_from_flag, provider_from_ref)?;
    Ok((target_from_flag.or(target_from_ref), provider))
}

fn split_ls_ref(target_ref: Option<&str>) -> Result<(Option<String>, Option<String>)> {
    let Some(target_ref) = target_ref.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok((None, None));
    };
    let parts = target_ref.split('/').map(str::trim).collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        anyhow::bail!("session list refs must use non-empty path components");
    }
    match parts.as_slice() {
        [target] => Ok((Some((*target).to_owned()), None)),
        [target, provider] => Ok((
            Some((*target).to_owned()),
            Some(normalize_session_provider(provider)?),
        )),
        _ => anyhow::bail!("session list refs must use TARGET or TARGET/PROVIDER"),
    }
}

pub fn run(
    session: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let provider = effective_provider(provider);
    let resolved = resolve_session_ref(session, target)?;
    let provider = merge_session_providers(provider, resolved.provider.clone())?;
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
    let provider = merge_session_providers(provider, resolved.provider.clone())?;
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
    let provider = merge_session_providers(provider, resolved.provider.clone())?;
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
    let (target_from_ref, _provider_from_ref, session_name) = split_session_ref(Some(raw_session))?;
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
    let mut providers = Vec::new();
    #[cfg(feature = "ghostty-vt")]
    providers.push(portl_agent::ghostty_provider_status());
    providers.extend(discovery.providers.into_iter().map(|provider| {
        ProviderStatus {
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
        }
    }));
    ProviderReport {
        #[cfg(feature = "ghostty-vt")]
        default_provider: Some("ghostty".to_owned()),
        #[cfg(not(feature = "ghostty-vt"))]
        default_provider: discovery.default_provider,
        providers,
    }
}

fn provider_capabilities(provider: &str) -> ProviderCapabilities {
    match provider {
        #[cfg(feature = "ghostty-vt")]
        "ghostty" => ProviderCapabilities::ghostty(),
        "zmx" => ProviderCapabilities::zmx(),
        "tmux" => ProviderCapabilities::tmux(),
        _ => ProviderCapabilities::raw(),
    }
}

async fn local_session_list_detailed(
    provider: Option<&str>,
) -> Result<Vec<SessionProviderSessions>> {
    match provider {
        #[cfg(feature = "ghostty-vt")]
        Some("ghostty") => Ok(vec![local_ghostty_session_group(true).await?]),
        Some("zmx") => Ok(vec![local_zmx_session_group(true).await?]),
        Some("tmux") => Ok(vec![
            local_tmux_session_group(local_zmx_path_opt().is_none()).await?,
        ]),
        Some(other) => {
            anyhow::bail!(
                "unsupported local session provider '{other}' (supported: ghostty, zmx, tmux)"
            )
        }
        None => {
            let default_provider = local_default_provider().ok();
            let mut groups = Vec::new();
            #[cfg(feature = "ghostty-vt")]
            groups.push(
                local_ghostty_session_group(default_provider.as_deref() == Some("ghostty")).await?,
            );
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

#[cfg(feature = "ghostty-vt")]
async fn local_ghostty_session_group(is_default: bool) -> Result<SessionProviderSessions> {
    Ok(SessionProviderSessions {
        provider: "ghostty".to_owned(),
        available: true,
        default: is_default,
        sessions: portl_agent::ghostty_session_list().await?,
    })
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
    if output.code == 0
        && let Some(sessions) = parse_local_zmx_json_sessions(&output.stdout)
    {
        return Ok(sessions);
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
                .map_or_else(|| value.to_string(), ToOwned::to_owned);
            (key.clone(), value)
        })
        .collect()
}

async fn local_session_run(
    provider: Option<&str>,
    session: &str,
    argv: &[String],
) -> Result<portl_proto::session_v1::SessionRunResult> {
    if provider.is_none() {
        #[cfg(feature = "ghostty-vt")]
        return portl_agent::ghostty_session_run(session, None, argv).await;
        #[cfg(not(feature = "ghostty-vt"))]
        {
            let mut zmx_args = vec!["run", session];
            zmx_args.extend(argv.iter().map(String::as_str));
            return run_local_zmx_capture(&zmx_args).await;
        }
    }
    match provider {
        #[cfg(feature = "ghostty-vt")]
        Some("ghostty") => portl_agent::ghostty_session_run(session, None, argv).await,
        Some("zmx") => {
            let mut zmx_args = vec!["run", session];
            zmx_args.extend(argv.iter().map(String::as_str));
            run_local_zmx_capture(&zmx_args).await
        }
        Some("tmux") => anyhow::bail!("persistent session provider 'tmux' does not support run"),
        Some(other) => {
            anyhow::bail!(
                "unsupported local session provider '{other}' (supported: ghostty, zmx, tmux)"
            )
        }
        None => unreachable!("handled above"),
    }
}

async fn local_session_history(provider: Option<&str>, session: &str) -> Result<String> {
    match resolve_local_provider_for_session(provider, session, false)
        .await?
        .as_str()
    {
        #[cfg(feature = "ghostty-vt")]
        "ghostty" => portl_agent::ghostty_session_history(session).await,
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
        #[cfg(feature = "ghostty-vt")]
        "ghostty" => portl_agent::ghostty_session_kill(session).await,
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
    target: &str,
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
        #[cfg(feature = "ghostty-vt")]
        "ghostty" => local_ghostty_attach(target, session, cwd, argv).await,
        "zmx" => local_zmx_attach(target, session, cwd, argv).await,
        "tmux" => local_tmux_attach(target, session, cwd, argv).await,
        other => unreachable!("unsupported provider {other}"),
    }
}

#[cfg(feature = "ghostty-vt")]
async fn local_ghostty_attach(
    target: &str,
    session: &str,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let (cols, rows) = size().unwrap_or((80, 24));
    let canonical_ref = canonical_session_ref(target, "ghostty", session);
    eprintln!("portl: using local session provider ghostty");
    eprintln!("portl: attaching to local session \"{canonical_ref}\"");
    let mut attach = portl_agent::ghostty_session_attach(session, cwd, rows, cols, argv).await?;
    let raw_guard = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::new()?)
    } else {
        None
    };
    let display = AttachDisplay::new(cols, rows);
    let stdin_task = maybe_spawn_stdin_task(
        AttachInputSink {
            kind: AttachInputSinkKind::Ghostty {
                stdin: attach.stdin_tx.clone(),
                control: attach.control_tx.clone(),
            },
        },
        AttachControlUi {
            canonical_ref: canonical_ref.clone(),
            supports_kick_others: false,
            display: display.clone(),
        },
    )
    .await?;
    let stdout_display = display.clone();
    let mut stdout_rx = attach.stdout_rx;
    let stdout_task = tokio::spawn(async move {
        copy_mpsc_output(&mut stdout_rx, &stdout_display, AttachOutputStream::Stdout).await
    });
    let stderr_display = display.clone();
    let mut stderr_rx = attach.stderr_rx;
    let stderr_task = tokio::spawn(async move {
        copy_mpsc_output(&mut stderr_rx, &stderr_display, AttachOutputStream::Stderr).await
    });
    let (code, detached) = wait_ghostty_attach_completion(&mut attach.exit_rx, stdin_task).await?;
    if detached {
        stdout_task.abort();
        stderr_task.abort();
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        display.clear_bar().await?;
        drop(raw_guard);
        eprintln!("portl: detached from session \"{canonical_ref}\"");
        eprintln!();
        eprintln!("The session is still running. To reconnect, run:");
        eprintln!("  portl attach {canonical_ref}");
    } else {
        await_output_task(stdout_task, "stdout").await?;
        await_output_task(stderr_task, "stderr").await?;
        display.clear_bar().await?;
        drop(raw_guard);
    }
    Ok(exit_code_from_i32(code))
}

async fn local_zmx_attach(
    target: &str,
    session: &str,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let path = local_zmx_path()?;
    if local_zmx_control_available(&path).await.unwrap_or(false) {
        return local_zmx_control_attach(path, target, session, cwd, argv).await;
    }
    local_zmx_direct_attach(path, session, cwd, argv).await
}

async fn local_zmx_control_available(path: &std::path::Path) -> Result<bool> {
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        Command::new(path)
            .args(["control", "--protocol", zmx_control::PROTOCOL, "--probe"])
            .stdin(Stdio::null())
            .output(),
    )
    .await;
    let Ok(Ok(output)) = output else {
        return Ok(false);
    };
    if !output.status.success() {
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let protocol_ok = stdout.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == "protocol" && value.trim() == zmx_control::PROTOCOL
        })
    });
    let tier_ok = stdout.lines().any(|line| {
        line.split_once('=')
            .is_some_and(|(key, value)| key.trim() == "tier" && value.trim() == "control")
    });
    Ok(protocol_ok && tier_ok)
}

async fn local_zmx_direct_attach(
    path: PathBuf,
    session: &str,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
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

async fn local_zmx_control_attach(
    path: PathBuf,
    target: &str,
    session: &str,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let (cols, rows) = size().unwrap_or((80, 24));
    let canonical_ref = canonical_session_ref(target, "zmx", session);
    eprintln!("portl: using local session provider zmx");
    eprintln!("portl: attaching to local session \"{canonical_ref}\"");
    let mut command = Command::new(path);
    command.kill_on_drop(true);
    command
        .args(["control", "--protocol", zmx_control::PROTOCOL])
        .arg("--rows")
        .arg(rows.to_string())
        .arg("--cols")
        .arg(cols.to_string())
        .arg(session)
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().context("spawn zmx control attach")?;
    let stdin = child.stdin.take().context("missing zmx-control stdin")?;
    let mut stdout = child.stdout.take().context("missing zmx-control stdout")?;
    let mut stderr = child.stderr.take().context("missing zmx-control stderr")?;

    let raw_guard = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::new()?)
    } else {
        None
    };
    let display = AttachDisplay::new(cols, rows);
    let stdin_task = maybe_spawn_stdin_task(
        AttachInputSink {
            kind: AttachInputSinkKind::Zmx { stdin },
        },
        AttachControlUi {
            canonical_ref: canonical_ref.clone(),
            supports_kick_others: false,
            display: display.clone(),
        },
    )
    .await?;
    let stdout_display = display.clone();
    let stdout_task =
        tokio::spawn(async move { copy_zmx_control_output(&mut stdout, &stdout_display).await });
    let stderr_display = display.clone();
    let stderr_task = tokio::spawn(async move {
        copy_remote_output(&mut stderr, &stderr_display, AttachOutputStream::Stderr).await
    });
    let (code, detached) = wait_local_attach_completion(&mut child, stdin_task).await?;
    if detached {
        reap_local_child_after_detach(&mut child).await;
        stdout_task.abort();
        stderr_task.abort();
        let _ = stdout_task.await;
        let _ = stderr_task.await;
    } else {
        await_output_task(stdout_task, "stdout").await?;
        await_output_task(stderr_task, "stderr").await?;
    }
    display.clear_bar().await?;
    drop(raw_guard);
    if detached {
        eprintln!("portl: detached from session \"{canonical_ref}\"");
        eprintln!();
        eprintln!("The session is still running. To reconnect, run:");
        eprintln!("  portl attach {canonical_ref}");
    }
    Ok(exit_code_from_i32(code))
}

async fn local_tmux_attach(
    target: &str,
    session: &str,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let path = local_tmux_path()?;
    local_tmux_control_attach(path, target, session, cwd, argv).await
}

async fn local_tmux_control_attach(
    path: PathBuf,
    target: &str,
    session: &str,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let (cols, rows) = size().unwrap_or((80, 24));
    let tmux_session = tmux_lookup_session(session);
    validate_tmux_control_target(session)?;
    let canonical_ref = canonical_session_ref(target, "tmux", session);
    eprintln!("portl: using local session provider tmux");
    eprintln!("portl: attaching to local session \"{canonical_ref}\"");
    let initial_viewport = local_tmux_viewport_snapshot(&path, session).await.ok();
    let mut tmux_args = vec![
        "-CC".to_owned(),
        "new-session".to_owned(),
        "-A".to_owned(),
        "-s".to_owned(),
        tmux_session.to_owned(),
        "-x".to_owned(),
        cols.to_string(),
        "-y".to_owned(),
        rows.to_string(),
    ];
    tmux_args.extend(argv.iter().cloned());
    let winsize = nix::libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let program = path
        .to_str()
        .ok_or_else(|| anyhow!("tmux path is not valid UTF-8"))?;
    let (master, mut child) =
        spawn_local_pty_blocking(program, &tmux_args, winsize, Vec::new(), cwd)
            .context("spawn tmux -CC attach pty")?;

    let raw_guard = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::new()?)
    } else {
        None
    };
    let display = AttachDisplay::new(cols, rows);
    if let Some(initial_viewport) = initial_viewport {
        display
            .write_output(AttachOutputStream::Stdout, &initial_viewport)
            .await?;
    }
    let (tmux_pty_tx, tmux_pty_rx) = mpsc::unbounded_channel();
    if session != tmux_session {
        tmux_pty_tx
            .send(format!("switch-client -t {session}\n").into_bytes())
            .context("queue tmux -CC target switch")?;
    }
    let stdin_task = maybe_spawn_stdin_task(
        AttachInputSink {
            kind: AttachInputSinkKind::TmuxPty {
                tx: tmux_pty_tx.clone(),
            },
        },
        AttachControlUi {
            canonical_ref: canonical_ref.clone(),
            supports_kick_others: true,
            display: display.clone(),
        },
    )
    .await?;
    let stdout_display = display.clone();
    let stdout_task = tokio::spawn(async move {
        pump_local_tmux_control_pty(master, &stdout_display, tmux_pty_rx).await
    });
    let (code, detached) = wait_local_attach_completion(&mut child, stdin_task).await?;
    if detached {
        reap_local_child_after_detach(&mut child).await;
        stdout_task.abort();
        let _ = stdout_task.await;
    } else {
        await_output_task(stdout_task, "stdout").await?;
    }
    display.clear_bar().await?;
    drop(raw_guard);
    if detached {
        eprintln!("portl: detached from session \"{canonical_ref}\"");
        eprintln!();
        eprintln!("The session is still running. To reconnect, run:");
        eprintln!("  portl attach {canonical_ref}");
    }
    Ok(exit_code_from_i32(code))
}

async fn resolve_local_provider_for_session(
    provider: Option<&str>,
    session: &str,
    create_if_missing: bool,
) -> Result<String> {
    if let Some(provider) = provider {
        match provider {
            #[cfg(feature = "ghostty-vt")]
            "ghostty" => return Ok(provider.to_owned()),
            "zmx" | "tmux" => return Ok(provider.to_owned()),
            other => {
                anyhow::bail!(
                    "unsupported local session provider '{other}' (supported: ghostty, zmx, tmux)"
                )
            }
        }
    }

    let mut providers = Vec::new();
    #[cfg(feature = "ghostty-vt")]
    if portl_agent::ghostty_session_list()
        .await?
        .iter()
        .any(|entry| entry.name == session)
    {
        providers.push("ghostty".to_owned());
    }
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

#[allow(clippy::unnecessary_wraps)]
fn local_default_provider() -> Result<String> {
    #[cfg(feature = "ghostty-vt")]
    {
        Ok("ghostty".to_owned())
    }
    #[cfg(not(feature = "ghostty-vt"))]
    {
        if local_zmx_path_opt().is_some() {
            Ok("zmx".to_owned())
        } else if local_tmux_path_opt().is_some() {
            Ok("tmux".to_owned())
        } else {
            anyhow::bail!("no local persistent session provider is installed")
        }
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

async fn local_tmux_viewport_snapshot(path: &PathBuf, target: &str) -> Result<Vec<u8>> {
    let output = run_local_capture(
        path,
        &[
            "display-message",
            "-p",
            "-t",
            target,
            "PORTL_CURSOR #{cursor_x} #{cursor_y}",
            ";",
            "capture-pane",
            "-p",
            "-e",
            "-N",
            "-S",
            "0",
            "-E",
            "-",
            "-t",
            target,
        ],
    )
    .await?;
    ensure_local_provider_success("tmux capture-pane", &output)?;
    let mut lines = output.stdout.lines();
    let (cursor_x, cursor_y) = lines
        .next()
        .and_then(parse_tmux_cursor_line)
        .unwrap_or((0, 0));
    let snapshot = lines.collect::<Vec<_>>().join("\n");
    Ok(tmux_cc::render_viewport_snapshot(
        snapshot.as_bytes(),
        cursor_x,
        cursor_y,
    ))
}

fn parse_tmux_cursor_line(line: &str) -> Option<(u16, u16)> {
    let rest = line.strip_prefix("PORTL_CURSOR ")?;
    let mut parts = rest.split_whitespace();
    let x = parts.next()?.parse().ok()?;
    let y = parts.next()?.parse().ok()?;
    Some((x, y))
}

fn tmux_lookup_session(input: &str) -> &str {
    input.split_once(':').map_or(input, |(session, _)| session)
}

fn validate_tmux_control_target(target: &str) -> Result<()> {
    if target.is_empty()
        || !target.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b':' | b'.' | b'_' | b'-' | b'#' | b'@' | b'%' | b'$')
        })
    {
        anyhow::bail!("unsafe tmux target {target:?}");
    }
    Ok(())
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
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let resolved = resolve_attach_session_ref(session, target, provider.as_deref()).await?;
        let provider = merge_session_providers(provider, resolved.provider.clone())?;
        let (session_name, provider_name) = attach_session_defaults(
            &resolved.target,
            Some(&resolved.session),
            provider.as_deref(),
        )?;
        if resolved_target_is_local(&resolved.target)? {
            return local_session_attach(
                provider_name.as_deref(),
                &resolved.target,
                &session_name,
                user,
                cwd,
                argv,
            )
            .await;
        }

        let connected = connect_peer(&resolved.target, session_caps()).await?;
        let (cols, rows) = size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        if let Some(provider) = provider_name.as_deref() {
            eprintln!(
                "portl: attaching to session \"{}\"",
                canonical_session_ref(&resolved.target, provider, &session_name)
            );
        } else {
            eprintln!(
                "portl: attaching to session \"{}\"",
                target_session_ref(&resolved.target, &session_name)
            );
        }
        let session = open_session_attach(
            &connected.connection,
            &connected.session,
            provider_name,
            session_name.clone(),
            (!argv.is_empty()).then_some(argv.to_vec()),
            user.map(ToOwned::to_owned),
            cwd.map(ToOwned::to_owned),
            portl_core::net::shell_client::PtyCfg { term, cols, rows },
        )
        .await?;
        let provider = session.provider.clone();
        let canonical_ref = canonical_session_ref(&resolved.target, &provider, &session_name);
        let code = bridge_attach(session, cols, rows, canonical_ref).await?;
        close_connected(connected, b"session complete").await;
        Ok(exit_code_from_i32(code))
    });
    runtime.shutdown_background();
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedSessionRef {
    target: String,
    provider: Option<String>,
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

async fn resolve_attach_session_ref(
    session_ref: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
) -> Result<ResolvedSessionRef> {
    let env = env_target();
    if should_discover_bare_attach(session_ref, target, provider, env.as_deref()) {
        let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
        let tickets =
            TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
        let aliases = crate::alias_store::AliasStore::default();
        if let Some(session_ref) = session_ref
            && tickets
                .get(session_ref)
                .and_then(|entry| entry.session_share.as_ref())
                .is_some()
        {
            return resolve_session_ref_with_stores(
                Some(session_ref),
                target,
                env.as_deref(),
                &peers,
                &tickets,
                &aliases,
            );
        }
        let targets = session_discovery_targets(&peers, &tickets)?;
        let groups_by_target = discover_session_groups_for_targets(&targets).await;
        if let Some(session) = session_ref
            && let Some(resolved) = resolve_existing_session_match(session, &groups_by_target)?
        {
            return Ok(resolved);
        }
        return resolve_session_ref_with_stores(
            session_ref,
            target,
            env.as_deref(),
            &peers,
            &tickets,
            &aliases,
        );
    }
    resolve_session_ref_with_env(session_ref, target, env.as_deref())
}

fn should_discover_bare_attach(
    session_ref: Option<&str>,
    target: Option<&str>,
    provider: Option<&str>,
    env_target: Option<&str>,
) -> bool {
    if target.map(str::trim).is_some_and(|value| !value.is_empty())
        || provider.is_some()
        || env_target.is_some()
    {
        return false;
    }
    session_ref
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| !value.contains('/'))
}

fn session_discovery_targets(peers: &PeerStore, tickets: &TicketStore) -> Result<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut targets = Vec::new();
    push_discovery_target(&mut targets, &mut seen, local_target_label()?);
    for entry in peers.iter() {
        if entry.last_hold_at.is_none() && (entry.they_accept_from_me || entry.is_self) {
            push_discovery_target(&mut targets, &mut seen, entry.label.clone());
        }
    }
    for (label, entry) in tickets.iter() {
        if entry.session_share.is_none() {
            push_discovery_target(&mut targets, &mut seen, label.clone());
        }
    }
    Ok(targets)
}

fn push_discovery_target(
    targets: &mut Vec<String>,
    seen: &mut std::collections::BTreeSet<String>,
    target: String,
) {
    if seen.insert(target.clone()) {
        targets.push(target);
    }
}

async fn discover_session_groups_for_targets(
    targets: &[String],
) -> Vec<(String, Vec<SessionProviderSessions>)> {
    let mut pending = FuturesUnordered::new();
    for target in targets {
        pending.push(discover_session_groups_for_target(target.clone()));
    }
    let mut groups_by_target = Vec::new();
    while let Some(result) = pending.next().await {
        if let Some(result) = result {
            groups_by_target.push(result);
        }
    }
    groups_by_target
}

async fn discover_session_groups_for_target(
    target: String,
) -> Option<(String, Vec<SessionProviderSessions>)> {
    let list = async {
        if resolved_target_is_local(&target)? {
            local_session_list_detailed(None).await
        } else {
            let connected = connect_peer_quiet(&target, session_caps()).await?;
            let groups =
                open_session_list_detailed(&connected.connection, &connected.session, None).await?;
            close_connected(connected, b"session complete").await;
            Ok(groups)
        }
    };
    match tokio::time::timeout(Duration::from_secs(2), list).await {
        Ok(Ok(groups)) => Some((target, groups)),
        Ok(Err(err)) => {
            debug!(target, error = %err, "skip session discovery target");
            None
        }
        Err(_) => {
            debug!(target, "skip timed-out session discovery target");
            None
        }
    }
}

fn resolve_existing_session_match(
    session: &str,
    groups_by_target: &[(String, Vec<SessionProviderSessions>)],
) -> Result<Option<ResolvedSessionRef>> {
    let tmux_lookup = session.split_once(':').map_or(session, |(name, _)| name);
    let mut matches: Vec<ResolvedSessionRef> = Vec::new();
    for (target, groups) in groups_by_target {
        for group in groups.iter().filter(|group| group.available) {
            let found = group.sessions.iter().any(|entry| {
                if group.provider == "tmux" {
                    entry.name == tmux_lookup
                } else {
                    entry.name == session
                }
            });
            if found {
                let candidate = ResolvedSessionRef {
                    target: target.clone(),
                    provider: Some(group.provider.clone()),
                    session: session.to_owned(),
                };
                if !matches.contains(&candidate) {
                    matches.push(candidate);
                }
            }
        }
    }

    match matches.as_slice() {
        [] => Ok(None),
        [resolved] => Ok(Some(resolved.clone())),
        many => {
            let refs = many
                .iter()
                .map(|item| {
                    canonical_session_ref(
                        &item.target,
                        item.provider.as_deref().unwrap_or("unknown"),
                        &item.session,
                    )
                })
                .collect::<Vec<_>>()
                .join("\n  ");
            anyhow::bail!(
                "ambiguous session name '{session}'\n\nMatches:\n  {refs}\n\nRerun with HOST/PROVIDER/SESSION."
            )
        }
    }
}

fn resolve_session_ref(
    session_ref: Option<&str>,
    target: Option<&str>,
) -> Result<ResolvedSessionRef> {
    let env = env_target();
    resolve_session_ref_with_env(session_ref, target, env.as_deref())
}

fn resolve_session_ref_with_env(
    session_ref: Option<&str>,
    target: Option<&str>,
    env: Option<&str>,
) -> Result<ResolvedSessionRef> {
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    let aliases = crate::alias_store::AliasStore::default();
    resolve_session_ref_with_stores(session_ref, target, env, &peers, &tickets, &aliases)
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
            provider: metadata.provider.clone(),
            session: metadata.provider_session.clone(),
        });
    }

    let (host_from_ref, provider_from_ref, session_name) = split_session_ref(session_ref)?;
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

    Ok(ResolvedSessionRef {
        target,
        provider: provider_from_ref,
        session,
    })
}

fn split_session_ref(
    session_ref: Option<&str>,
) -> Result<(Option<&str>, Option<String>, Option<String>)> {
    let Some(session_ref) = session_ref else {
        return Ok((None, None, None));
    };
    let parts = session_ref.split('/').map(str::trim).collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        anyhow::bail!("session refs must use non-empty path components");
    }
    match parts.as_slice() {
        [session] => Ok((None, None, Some((*session).to_owned()))),
        [host, session] => Ok((Some(*host), None, Some((*session).to_owned()))),
        [host, provider, session] => Ok((
            Some(*host),
            Some(normalize_session_provider(provider)?),
            Some((*session).to_owned()),
        )),
        _ => anyhow::bail!("session refs must use SESSION, HOST/SESSION, or HOST/PROVIDER/SESSION"),
    }
}

fn normalize_session_provider(provider: &str) -> Result<String> {
    let normalized = normalize_session_provider_alias(provider);
    match normalized.as_str() {
        #[cfg(feature = "ghostty-vt")]
        "ghostty" => Ok(normalized),
        "tmux" | "zmx" | "raw" => Ok(normalized),
        other => {
            #[cfg(feature = "ghostty-vt")]
            anyhow::bail!(
                "unsupported session provider '{other}' (supported: ghostty, zmx, tmux, raw)"
            );
            #[cfg(not(feature = "ghostty-vt"))]
            anyhow::bail!("unsupported session provider '{other}' (supported: zmx, tmux, raw)");
        }
    }
}

fn normalize_session_provider_alias(provider: &str) -> String {
    match provider.trim() {
        "g" => "ghostty".to_owned(),
        "t" => "tmux".to_owned(),
        "z" => "zmx".to_owned(),
        other => other.to_owned(),
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

fn merge_session_providers(
    explicit: Option<String>,
    from_ref: Option<String>,
) -> Result<Option<String>> {
    match (explicit, from_ref) {
        (Some(left), Some(right)) if left != right => {
            anyhow::bail!(
                "conflicting session providers: option selects '{left}' but ref selects '{right}'"
            )
        }
        (Some(provider), _) | (_, Some(provider)) => Ok(Some(provider)),
        (None, None) => Ok(None),
    }
}

fn canonical_session_ref(target: &str, provider: &str, session: &str) -> String {
    format!("{}/{provider}/{session}", canonical_target_label(target))
}

fn target_session_ref(target: &str, session: &str) -> String {
    format!("{}/{session}", canonical_target_label(target))
}

fn canonical_target_label(target: &str) -> &str {
    target.split_once('/').map_or(target, |(host, _)| host)
}

async fn bridge_attach(
    session: SessionClient,
    cols: u16,
    rows: u16,
    canonical_ref: String,
) -> Result<i32> {
    let raw_guard = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::new()?)
    } else {
        None
    };
    let SessionClient {
        provider,
        control_send: _control_send,
        control_recv: _control_recv,
        stdin,
        stdout: mut stdout_recv,
        stderr: mut stderr_recv,
        mut exit,
        signal: _signal,
        resize,
        control,
    } = session;
    let display = AttachDisplay::new(cols, rows);
    let stdin_task = maybe_spawn_stdin_task(
        AttachInputSink {
            kind: AttachInputSinkKind::Remote {
                send: stdin,
                resize,
                control,
            },
        },
        AttachControlUi {
            canonical_ref: canonical_ref.clone(),
            supports_kick_others: provider == "tmux",
            display: display.clone(),
        },
    )
    .await?;
    let stdout_display = display.clone();
    let stdout_task = tokio::spawn(async move {
        copy_remote_output(
            &mut stdout_recv,
            &stdout_display,
            AttachOutputStream::Stdout,
        )
        .await
    });
    let stderr_display = display.clone();
    let stderr_task = tokio::spawn(async move {
        copy_remote_output(
            &mut stderr_recv,
            &stderr_display,
            AttachOutputStream::Stderr,
        )
        .await
    });
    let (code, detached) = wait_attach_completion(&mut exit, stdin_task).await?;
    if detached {
        stdout_task.abort();
        stderr_task.abort();
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        display.clear_bar().await?;
        drop(raw_guard);
        eprintln!("portl: detached from session \"{canonical_ref}\"");
        eprintln!();
        eprintln!("The session is still running. To reconnect, run:");
        eprintln!("  portl attach {canonical_ref}");
    } else {
        await_output_task(stdout_task, "stdout").await?;
        await_output_task(stderr_task, "stderr").await?;
        display.clear_bar().await?;
        drop(raw_guard);
    }
    Ok(code)
}

async fn reap_local_child_after_detach(child: &mut Child) {
    if tokio::time::timeout(Duration::from_millis(500), child.wait())
        .await
        .is_err()
    {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_millis(500), child.wait()).await;
    }
}

async fn wait_local_attach_completion(
    child: &mut Child,
    stdin_task: Option<tokio::task::JoinHandle<Result<StdinTaskResult>>>,
) -> Result<(i32, bool)> {
    let mut exit_fut = Box::pin(child.wait());
    let Some(mut stdin_task) = stdin_task else {
        let status = exit_fut.await.context("wait for local provider exit")?;
        return Ok((status.code().unwrap_or(1), false));
    };

    tokio::select! {
        status = &mut exit_fut => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok((status.context("wait for local provider exit")?.code().unwrap_or(1), false))
        }
        stdin_result = &mut stdin_task => {
            match stdin_result.context("join stdin task")?? {
                StdinTaskResult::Detached => Ok((0, true)),
                StdinTaskResult::Closed => {
                    let status = exit_fut.await.context("wait for local provider exit")?;
                    Ok((status.code().unwrap_or(1), false))
                }
            }
        }
    }
}

#[cfg(feature = "ghostty-vt")]
async fn wait_ghostty_attach_completion(
    exit: &mut tokio::sync::watch::Receiver<Option<i32>>,
    stdin_task: Option<tokio::task::JoinHandle<Result<StdinTaskResult>>>,
) -> Result<(i32, bool)> {
    async fn wait_exit(exit: &mut tokio::sync::watch::Receiver<Option<i32>>) -> Result<i32> {
        loop {
            if let Some(code) = *exit.borrow_and_update() {
                return Ok(code);
            }
            if exit.changed().await.is_err() {
                return Ok(0);
            }
        }
    }

    let mut exit_fut = Box::pin(wait_exit(exit));
    let Some(mut stdin_task) = stdin_task else {
        return Ok((exit_fut.await?, false));
    };

    tokio::select! {
        code = &mut exit_fut => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok((code?, false))
        }
        stdin_result = &mut stdin_task => {
            match stdin_result.context("join stdin task")?? {
                StdinTaskResult::Detached => Ok((0, true)),
                StdinTaskResult::Closed => Ok((exit_fut.await?, false)),
            }
        }
    }
}

async fn wait_attach_completion(
    exit: &mut BufferedRecv,
    stdin_task: Option<tokio::task::JoinHandle<Result<StdinTaskResult>>>,
) -> Result<(i32, bool)> {
    let mut exit_fut = Box::pin(read_exit(exit));
    let Some(mut stdin_task) = stdin_task else {
        return Ok((exit_fut.await?, false));
    };

    tokio::select! {
        code = &mut exit_fut => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok((code?, false))
        }
        stdin_result = &mut stdin_task => {
            match stdin_result.context("join stdin task")?? {
                StdinTaskResult::Detached => Ok((0, true)),
                StdinTaskResult::Closed => Ok((exit_fut.await?, false)),
            }
        }
    }
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

#[derive(Debug, Clone, Copy)]
enum AttachOutputStream {
    Stdout,
    Stderr,
}

#[cfg(feature = "ghostty-vt")]
async fn copy_mpsc_output(
    recv: &mut mpsc::Receiver<Vec<u8>>,
    display: &AttachDisplay,
    stream: AttachOutputStream,
) -> Result<()> {
    while let Some(bytes) = recv.recv().await {
        if bytes.is_empty() {
            break;
        }
        display.write_output(stream, &bytes).await?;
    }
    display.flush(stream).await
}

async fn copy_remote_output<R>(
    recv: &mut R,
    display: &AttachDisplay,
    stream: AttachOutputStream,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let read = recv.read(&mut buf).await.context("read remote output")?;
        if read == 0 {
            display.flush(stream).await?;
            return Ok(());
        }
        display.write_output(stream, &buf[..read]).await?;
    }
}

#[cfg(unix)]
async fn pump_local_tmux_control_pty(
    master: OwnedFd,
    display: &AttachDisplay,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    set_fd_nonblocking(&master)?;
    let master = tokio::io::unix::AsyncFd::new(master).context("register tmux -CC pty")?;
    let mut decoder = tmux_cc::Decoder::default();
    let mut read_buf = vec![0_u8; 16 * 1024];
    let mut line_buf = Vec::new();

    loop {
        tokio::select! {
            Some(command) = write_rx.recv() => {
                write_pty_all(&master, &command).await.context("write tmux -CC pty")?;
            }
            read = read_pty_chunk(&master, &mut read_buf) => {
                let Some(read) = read.context("read tmux -CC pty")? else {
                    display.flush(AttachOutputStream::Stdout).await?;
                    return Ok(());
                };
                let control_bytes = decoder.decode(&read_buf[..read]);
                for byte in control_bytes {
                    line_buf.push(byte);
                    if byte == b'\n' {
                        let line = String::from_utf8_lossy(&line_buf).into_owned();
                        line_buf.clear();
                        match tmux_cc::parse_control_line(&line) {
                            tmux_cc::TmuxControlEvent::Output(bytes) => {
                                display
                                    .write_output(AttachOutputStream::Stdout, &bytes)
                                    .await?;
                            }
                            tmux_cc::TmuxControlEvent::Error(error) => {
                                display
                                    .write_output(
                                        AttachOutputStream::Stderr,
                                        format!("tmux: {error}\n").as_bytes(),
                                    )
                                    .await?;
                            }
                            tmux_cc::TmuxControlEvent::Exit => return Ok(()),
                            tmux_cc::TmuxControlEvent::Ignore => {}
                        }
                    }
                }
            }
            else => return Ok(()),
        }
    }
}

#[cfg(unix)]
fn set_fd_nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)
        .map(nix::fcntl::OFlag::from_bits_truncate)
        .map_err(std::io::Error::from)?;
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFL(flags | nix::fcntl::OFlag::O_NONBLOCK),
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(unix)]
async fn read_pty_chunk(
    fd: &tokio::io::unix::AsyncFd<OwnedFd>,
    buf: &mut [u8],
) -> std::io::Result<Option<usize>> {
    loop {
        let mut guard = fd.readable().await?;
        match guard
            .try_io(|inner| nix::unistd::read(inner.get_ref(), buf).map_err(std::io::Error::from))
        {
            Ok(Ok(0)) => return Ok(None),
            Ok(Ok(read)) => return Ok(Some(read)),
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(Err(err)) => return Err(err),
            Err(_would_block) => {}
        }
    }
}

#[cfg(unix)]
async fn write_pty_all(
    fd: &tokio::io::unix::AsyncFd<OwnedFd>,
    mut bytes: &[u8],
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| {
            nix::unistd::write(inner.get_ref(), bytes).map_err(std::io::Error::from)
        }) {
            Ok(Ok(0)) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(Ok(written)) => bytes = &bytes[written..],
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(Err(err)) => return Err(err),
            Err(_would_block) => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_local_pty_blocking(
    program: &str,
    argv: &[String],
    size: nix::libc::winsize,
    env: Vec<(String, String)>,
    cwd: Option<&str>,
) -> std::io::Result<(OwnedFd, Child)> {
    let nix::pty::OpenptyResult { master, slave } =
        nix::pty::openpty(Some(&size), None).map_err(std::io::Error::from)?;
    nix::fcntl::fcntl(
        &master,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .map_err(std::io::Error::from)?;
    let slave_fd = slave.as_raw_fd();

    let mut command = Command::new(program);
    command.kill_on_drop(true);
    command.args(argv);
    command.envs(env);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }

    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
            let req = nix::libc::TIOCSCTTY
                .try_into()
                .expect("TIOCSCTTY fits in ioctl request type");
            if nix::libc::ioctl(slave_fd, req, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for target in [0, 1, 2] {
                if nix::libc::dup2(slave_fd, target) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if slave_fd > 2 {
                let _ = nix::libc::close(slave_fd);
            }
            Ok(())
        });
    }

    let child = command.spawn()?;
    drop(slave);
    Ok((master, child))
}

async fn copy_zmx_control_output<R>(recv: &mut R, display: &AttachDisplay) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    while let Some((tag, payload)) = zmx_control::read_frame(recv)
        .await
        .context("read zmx-control output")?
    {
        if matches!(
            tag,
            zmx_control::TAG_OUTPUT
                | zmx_control::TAG_VIEWPORT_SNAPSHOT
                | zmx_control::TAG_LIVE_OUTPUT
        ) {
            display
                .write_output(AttachOutputStream::Stdout, &payload)
                .await?;
        }
    }
    display.flush(AttachOutputStream::Stdout).await
}

#[derive(Clone)]
struct AttachDisplay {
    inner: Arc<tokio::sync::Mutex<AttachDisplayState>>,
}

struct AttachDisplayState {
    cols: u16,
    rows: u16,
    bar: Option<String>,
    gate: AttachOutputGate,
    stdout: tokio::io::Stdout,
    stderr: tokio::io::Stderr,
}

#[derive(Debug, Default)]
struct AttachOutputGate {
    holding: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl AttachOutputGate {
    fn set_holding(&mut self, holding: bool) {
        self.holding = holding;
    }

    fn hold(&mut self, stream: AttachOutputStream, bytes: &[u8]) -> Option<&[u8]> {
        if !self.holding {
            return None;
        }
        match stream {
            AttachOutputStream::Stdout => self.stdout.extend_from_slice(bytes),
            AttachOutputStream::Stderr => self.stderr.extend_from_slice(bytes),
        }
        Some(&[])
    }

    fn take_stdout(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stderr)
    }
}

impl AttachDisplay {
    fn new(cols: u16, rows: u16) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(AttachDisplayState {
                cols,
                rows,
                bar: None,
                gate: AttachOutputGate::default(),
                stdout: tokio::io::stdout(),
                stderr: tokio::io::stderr(),
            })),
        }
    }

    async fn write_output(&self, stream: AttachOutputStream, bytes: &[u8]) -> Result<()> {
        let mut state = self.inner.lock().await;
        if state.gate.hold(stream, bytes).is_some() {
            state.redraw_bar().await?;
            return Ok(());
        }
        let had_bar = state.bar.is_some();
        if had_bar {
            state.clear_bar().await?;
        }
        match stream {
            AttachOutputStream::Stdout => state
                .stdout
                .write_all(bytes)
                .await
                .context("copy remote stdout")?,
            AttachOutputStream::Stderr => state
                .stderr
                .write_all(bytes)
                .await
                .context("copy remote stderr")?,
        }
        state.flush(stream).await?;
        if had_bar {
            state.redraw_bar().await?;
        }
        Ok(())
    }

    async fn flush(&self, stream: AttachOutputStream) -> Result<()> {
        let mut state = self.inner.lock().await;
        state.flush(stream).await
    }

    async fn set_bar(&self, text: String) -> Result<()> {
        let mut state = self.inner.lock().await;
        state.gate.set_holding(true);
        state.bar = Some(text);
        state.redraw_bar().await
    }

    async fn clear_bar(&self) -> Result<()> {
        let mut state = self.inner.lock().await;
        state.bar = None;
        state.clear_bar().await?;
        state.gate.set_holding(false);
        state.flush_held_output().await
    }

    async fn print_message(&self, message: &str) -> Result<()> {
        let mut state = self.inner.lock().await;
        state.clear_bar().await?;
        state
            .stderr
            .write_all(format!("\r\n{message}\r\n").as_bytes())
            .await
            .context("write attach control message")?;
        state
            .stderr
            .flush()
            .await
            .context("flush attach control message")?;
        state.redraw_bar().await
    }
}

impl AttachDisplayState {
    async fn flush(&mut self, stream: AttachOutputStream) -> Result<()> {
        match stream {
            AttachOutputStream::Stdout => self.stdout.flush().await.context("flush local stdout"),
            AttachOutputStream::Stderr => self.stderr.flush().await.context("flush local stderr"),
        }
    }

    async fn clear_bar(&mut self) -> Result<()> {
        draw_attach_control_bar_to(&mut self.stderr, self.rows, self.cols, "").await
    }

    async fn redraw_bar(&mut self) -> Result<()> {
        if let Some(text) = self.bar.as_deref() {
            draw_attach_control_bar_to(&mut self.stderr, self.rows, self.cols, text).await?;
        }
        Ok(())
    }

    async fn flush_held_output(&mut self) -> Result<()> {
        let stdout = self.gate.take_stdout();
        if !stdout.is_empty() {
            self.stdout
                .write_all(&stdout)
                .await
                .context("flush held attach stdout")?;
            self.stdout
                .flush()
                .await
                .context("flush held attach stdout")?;
        }
        let stderr = self.gate.take_stderr();
        if !stderr.is_empty() {
            self.stderr
                .write_all(&stderr)
                .await
                .context("flush held attach stderr")?;
            self.stderr
                .flush()
                .await
                .context("flush held attach stderr")?;
        }
        Ok(())
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

#[derive(Debug, Clone, Copy)]
struct PasteConfig {
    burst_threshold_bytes: usize,
    burst_window: Duration,
    detail_after: Duration,
}

impl PasteConfig {
    fn default() -> Self {
        Self {
            burst_threshold_bytes: 64 * 1024,
            burst_window: Duration::from_millis(250),
            detail_after: Duration::from_secs(2),
        }
    }

    #[cfg(test)]
    fn for_test(burst_threshold_bytes: usize, burst_window: Duration) -> Self {
        Self {
            burst_threshold_bytes,
            burst_window,
            detail_after: Duration::from_millis(10),
        }
    }
}

#[derive(Debug)]
struct PasteState {
    config: PasteConfig,
    active: bool,
    burst_start: Option<Instant>,
    burst_bytes: usize,
    pending_bytes: usize,
    backpressured: bool,
    active_since: Option<Instant>,
}

impl PasteState {
    fn new(config: PasteConfig) -> Self {
        Self {
            config,
            active: false,
            burst_start: None,
            burst_bytes: 0,
            pending_bytes: 0,
            backpressured: false,
            active_since: None,
        }
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    fn observe_read(&mut self, bytes: usize, now: Instant) {
        match self.burst_start {
            Some(start) if now.duration_since(start) < self.config.burst_window => {
                self.burst_bytes += bytes;
            }
            _ => {
                self.burst_start = Some(now);
                self.burst_bytes = bytes;
            }
        }
        if self.burst_bytes >= self.config.burst_threshold_bytes {
            self.active = true;
            self.active_since.get_or_insert(now);
        }
    }

    fn activate(&mut self, now: Instant) {
        self.active = true;
        self.active_since.get_or_insert(now);
    }

    fn deactivate_if_idle(&mut self) {
        if self.pending_bytes == 0 && !self.backpressured {
            self.active = false;
            self.active_since = None;
        }
    }

    fn observe_queued(&mut self, bytes: usize) {
        self.pending_bytes += bytes;
    }

    fn observe_sent(&mut self, bytes: usize) {
        self.pending_bytes = self.pending_bytes.saturating_sub(bytes);
    }

    fn set_backpressured(&mut self, value: bool) {
        self.backpressured = value;
        if value {
            self.active = true;
            self.active_since.get_or_insert_with(Instant::now);
        }
    }

    fn cancel_pending(&mut self) -> usize {
        let dropped = self.pending_bytes;
        self.pending_bytes = 0;
        self.backpressured = false;
        self.active = false;
        self.active_since = None;
        dropped
    }

    fn should_show_detail(&self, now: Instant) -> bool {
        self.active_since
            .is_some_and(|started| now.duration_since(started) >= self.config.detail_after)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BracketedPasteEvent {
    None,
    Begin,
    End,
}

#[derive(Debug, Default)]
struct BracketedPasteScanner {
    tail: Vec<u8>,
    in_paste: bool,
}

impl BracketedPasteScanner {
    #[cfg_attr(not(test), allow(dead_code))]
    fn in_bracketed_paste(&self) -> bool {
        self.in_paste
    }

    fn force_end(&mut self) {
        self.in_paste = false;
    }

    fn scan(&mut self, bytes: &[u8]) -> BracketedPasteEvent {
        const BEGIN: &[u8] = b"\x1b[200~";
        const END: &[u8] = b"\x1b[201~";
        let mut combined = self.tail.clone();
        combined.extend_from_slice(bytes);
        let last_begin = combined
            .windows(BEGIN.len())
            .enumerate()
            .filter_map(|(i, w)| (w == BEGIN).then_some(i))
            .last();
        let last_end = combined
            .windows(END.len())
            .enumerate()
            .filter_map(|(i, w)| (w == END).then_some(i))
            .last();
        let event = match (last_begin, last_end) {
            (None, None) => BracketedPasteEvent::None,
            (Some(_), None) => {
                self.in_paste = true;
                BracketedPasteEvent::Begin
            }
            (None, Some(_)) => {
                self.in_paste = false;
                BracketedPasteEvent::End
            }
            (Some(b), Some(e)) if b > e => {
                self.in_paste = true;
                BracketedPasteEvent::Begin
            }
            _ => {
                self.in_paste = false;
                BracketedPasteEvent::End
            }
        };
        let keep = BEGIN.len().max(END.len()).saturating_sub(1);
        self.tail = combined[combined.len().saturating_sub(keep)..].to_vec();
        event
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinTaskResult {
    Closed,
    Detached,
}

struct AttachInputSink {
    kind: AttachInputSinkKind,
}

impl AttachInputSink {
    async fn send_stdin(&mut self, bytes: &[u8]) -> Result<()> {
        match &mut self.kind {
            AttachInputSinkKind::Remote { send, .. } => {
                send.write_all(bytes).await.context("write remote stdin")
            }
            AttachInputSinkKind::Zmx { stdin } => {
                zmx_control::write_frame(stdin, zmx_control::TAG_INPUT, bytes)
                    .await
                    .context("write zmx-control input")
            }
            AttachInputSinkKind::TmuxPty { tx } => tx
                .send(tmux_cc::send_keys_command(bytes))
                .map_err(|_| anyhow!("tmux -CC pty closed")),
            #[cfg(feature = "ghostty-vt")]
            AttachInputSinkKind::Ghostty { stdin, .. } => stdin
                .send(portl_agent::GhosttyAttachInput::Data(bytes.to_vec()))
                .await
                .map_err(|_| anyhow!("ghostty attach stdin closed")),
        }
    }

    async fn close_stdin(&mut self) -> Result<()> {
        match &mut self.kind {
            AttachInputSinkKind::Remote { send, .. } => {
                send.finish().context("finish remote stdin")
            }
            AttachInputSinkKind::Zmx { stdin } => {
                let _ = zmx_control::write_frame(stdin, zmx_control::TAG_CLOSE, &[]).await;
                stdin.shutdown().await.context("shutdown zmx-control stdin")
            }
            AttachInputSinkKind::TmuxPty { tx } => tx
                .send(b"detach-client\n".to_vec())
                .map_err(|_| anyhow!("tmux -CC pty closed")),
            #[cfg(feature = "ghostty-vt")]
            AttachInputSinkKind::Ghostty { stdin, .. } => stdin
                .send(portl_agent::GhosttyAttachInput::Close)
                .await
                .map_err(|_| anyhow!("ghostty attach stdin closed")),
        }
    }

    async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        match &mut self.kind {
            AttachInputSinkKind::Remote { resize, .. } => {
                let frame = portl_proto::shell_v1::ResizeFrame { cols, rows };
                resize
                    .write_all(&postcard::to_stdvec(&frame).context("encode resize frame")?)
                    .await
                    .context("write resize frame")
            }
            AttachInputSinkKind::Zmx { stdin } => {
                let payload = zmx_control::resize_payload(rows, cols);
                zmx_control::write_frame(stdin, zmx_control::TAG_RESIZE, &payload)
                    .await
                    .context("write zmx-control resize")
            }
            AttachInputSinkKind::TmuxPty { tx } => tx
                .send(tmux_cc::resize_commands(rows, cols))
                .map_err(|_| anyhow!("tmux -CC pty closed")),
            #[cfg(feature = "ghostty-vt")]
            AttachInputSinkKind::Ghostty { control, .. } => control
                .send(portl_agent::GhosttyAttachControl::Resize { rows, cols })
                .map_err(|_| anyhow!("ghostty attach control closed")),
        }
    }

    async fn kick_others(&mut self) -> Result<()> {
        match &mut self.kind {
            AttachInputSinkKind::Remote { control, .. } => {
                let frame = SessionControlFrame {
                    action: SessionControlAction::KickOthers,
                };
                control
                    .write_all(&postcard::to_stdvec(&frame).context("encode kick-others frame")?)
                    .await
                    .context("write session control frame")
            }
            AttachInputSinkKind::Zmx { .. } => Ok(()),
            AttachInputSinkKind::TmuxPty { tx } => tx
                .send(b"detach-client -a\n".to_vec())
                .map_err(|_| anyhow!("tmux -CC pty closed")),
            #[cfg(feature = "ghostty-vt")]
            AttachInputSinkKind::Ghostty { .. } => Ok(()),
        }
    }
}

enum AttachInputSinkKind {
    Remote {
        send: SendStream,
        resize: SendStream,
        control: SendStream,
    },
    Zmx {
        stdin: ChildStdin,
    },
    TmuxPty {
        tx: mpsc::UnboundedSender<Vec<u8>>,
    },
    #[cfg(feature = "ghostty-vt")]
    Ghostty {
        stdin: mpsc::Sender<portl_agent::GhosttyAttachInput>,
        control: mpsc::UnboundedSender<portl_agent::GhosttyAttachControl>,
    },
}

#[derive(Clone)]
struct AttachControlUi {
    canonical_ref: String,
    supports_kick_others: bool,
    display: AttachDisplay,
}

async fn maybe_spawn_stdin_task(
    mut sink: AttachInputSink,
    ui: AttachControlUi,
) -> Result<Option<tokio::task::JoinHandle<Result<StdinTaskResult>>>> {
    if should_close_idle_stdin()? {
        if let Err(err) = sink.close_stdin().await.context("close idle stdin") {
            debug!(%err, "provider stdin already closed");
        }
        return Ok(None);
    }
    Ok(Some(tokio::spawn(async move {
        let mut stdin_src = tokio::io::stdin();
        Box::pin(stdin_loop(&mut sink, &mut stdin_src, &ui)).await
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

async fn stdin_loop<R>(
    sink: &mut AttachInputSink,
    stdin: &mut R,
    ui: &AttachControlUi,
) -> Result<StdinTaskResult>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0_u8; 8192];
    let mut last_size = size().unwrap_or((80, 24));
    let mut paste = PasteState::new(PasteConfig::default());
    let mut bracketed = BracketedPasteScanner::default();
    loop {
        tokio::select! {
            read = stdin.read(&mut buf) => {
                let read = read.context("read local stdin")?;
                if read == 0 {
                    if let Err(err) = sink.close_stdin().await.context("finish local stdin") {
                        debug!(%err, "provider stdin already closed");
                    }
                    return Ok(StdinTaskResult::Closed);
                }
                let chunk = &buf[..read];
                let now = Instant::now();
                paste.observe_read(read, now);
                match bracketed.scan(chunk) {
                    BracketedPasteEvent::Begin => paste.activate(now),
                    BracketedPasteEvent::End => paste.deactivate_if_idle(),
                    BracketedPasteEvent::None => {}
                }
                if is_ctrl_backslash_sequence(chunk) {
                    match run_attach_control_mode(sink, stdin, ui, &mut paste).await? {
                        AttachControlOutcome::Continue => continue,
                        AttachControlOutcome::Detached => return Ok(StdinTaskResult::Detached),
                        AttachControlOutcome::CancelPaste => {
                            paste.cancel_pending();
                            if bracketed.in_bracketed_paste() {
                                bracketed.force_end();
                                let _ = sink.send_stdin(b"\x1b[201~").await;
                            }
                            ui.display.clear_bar().await?;
                            continue;
                        }
                    }
                }
                if paste.is_active() && chunk == b"\x1b" {
                    paste.cancel_pending();
                    if bracketed.in_bracketed_paste() {
                        bracketed.force_end();
                        let _ = sink.send_stdin(b"\x1b[201~").await;
                    }
                    ui.display.clear_bar().await?;
                    continue;
                }
                paste.observe_queued(read);
                update_paste_bar(ui, &paste).await?;
                let send_started = Instant::now();
                if let Err(err) = sink.send_stdin(chunk).await.context("copy local stdin") {
                    debug!(%err, "stdin loop ended after provider stdin closed");
                    return Ok(StdinTaskResult::Closed);
                }
                paste.set_backpressured(send_started.elapsed() >= Duration::from_millis(100));
                paste.observe_sent(read);
                update_paste_bar(ui, &paste).await?;
            }
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                if let Ok(now) = size()
                    && now != last_size
                {
                    if let Err(err) = sink.resize(now.0, now.1).await.context("resize attached session") {
                        debug!(%err, "resize loop ended after provider stdin closed");
                        return Ok(StdinTaskResult::Closed);
                    }
                    last_size = now;
                }
            }
        }
    }
}

async fn update_paste_bar(ui: &AttachControlUi, paste: &PasteState) -> Result<()> {
    if !paste.is_active() {
        return Ok(());
    }
    let now = Instant::now();
    let unicode = terminal_locale_supports_unicode();
    let sep = if unicode { "·" } else { "|" };
    let lead = if unicode { "▌" } else { "|" };
    let arrow = if unicode { "›" } else { ">" };
    if !paste.should_show_detail(now) {
        return ui
            .display
            .set_bar(format!(
                "{lead} Portl {arrow} {} {sep} Esc cancel paste",
                ui.canonical_ref
            ))
            .await;
    }
    let pending = paste.pending_bytes();
    if pending > 0 {
        ui.display
            .set_bar(format!(
                "{lead} Portl {arrow} {} {sep} pasting {pending} bytes {sep} Esc cancel",
                ui.canonical_ref
            ))
            .await
    } else {
        ui.display.clear_bar().await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachControlOutcome {
    Continue,
    Detached,
    CancelPaste,
}

async fn run_attach_control_mode<R>(
    sink: &mut AttachInputSink,
    stdin: &mut R,
    ui: &AttachControlUi,
    paste: &PasteState,
) -> Result<AttachControlOutcome>
where
    R: AsyncRead + Unpin,
{
    const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
    const CONTROL_TICK: Duration = Duration::from_millis(100);

    let started = Instant::now();
    let mut buf = [0_u8; 8192];
    loop {
        let elapsed = started.elapsed();
        if elapsed >= CONTROL_TIMEOUT {
            clear_attach_control_bar(ui).await?;
            return Ok(AttachControlOutcome::Continue);
        }
        render_attach_control_bar(ui, CONTROL_TIMEOUT.saturating_sub(elapsed), paste).await?;
        if let Ok(read) = tokio::time::timeout(CONTROL_TICK, stdin.read(&mut buf)).await {
            let read = read.context("read local stdin in attach control mode")?;
            if read == 0 {
                clear_attach_control_bar(ui).await?;
                if let Err(err) = sink.close_stdin().await.context("finish provider stdin") {
                    debug!(%err, "provider stdin already closed");
                }
                return Ok(AttachControlOutcome::Continue);
            }
            let command = &buf[..read];
            clear_attach_control_bar(ui).await?;
            if command == b"d" {
                if let Err(err) = sink
                    .close_stdin()
                    .await
                    .context("finish provider stdin for detach")
                {
                    debug!(%err, "provider stdin already closed during detach");
                }
                return Ok(AttachControlOutcome::Detached);
            }
            if command == b"k" && ui.supports_kick_others {
                sink.kick_others().await.context("send kick-others frame")?;
                ui.display
                    .print_message(&format!(
                        "portl: detached other clients from session \"{}\"",
                        ui.canonical_ref
                    ))
                    .await?;
                return Ok(AttachControlOutcome::Continue);
            }
            if command == b"c" && paste.is_active() {
                return Ok(AttachControlOutcome::CancelPaste);
            }
            if command == b"\x1b" {
                return Ok(AttachControlOutcome::Continue);
            }
            if is_ctrl_backslash_sequence(command) {
                sink.send_stdin(command)
                    .await
                    .context("send literal attach detach sequence")?;
                return Ok(AttachControlOutcome::Continue);
            }
            sink.send_stdin(command)
                .await
                .context("forward attach control command as stdin")?;
            return Ok(AttachControlOutcome::Continue);
        }
    }
}

async fn render_attach_control_bar(
    ui: &AttachControlUi,
    remaining: Duration,
    paste: &PasteState,
) -> Result<()> {
    ui.display
        .set_bar(render_bar(RenderBarOptions {
            canonical_ref: &ui.canonical_ref,
            supports_kick_others: ui.supports_kick_others,
            paste_cancellable: paste.is_active(),
            remaining,
            unicode: terminal_locale_supports_unicode(),
            color: terminal_color_enabled(),
        }))
        .await
}

async fn clear_attach_control_bar(ui: &AttachControlUi) -> Result<()> {
    ui.display.clear_bar().await
}

async fn draw_attach_control_bar_to(
    stderr: &mut tokio::io::Stderr,
    row: u16,
    cols: u16,
    text: &str,
) -> Result<()> {
    let row = row.max(1);
    if text.is_empty() {
        stderr
            .write_all(format!("\x1b[0m\x1b7\x1b[{row};1H\x1b[2K\x1b8\x1b[0m").as_bytes())
            .await
            .context("clear attach control bar")?;
    } else {
        let text = fit_visible(text, cols);
        stderr
            .write_all(
                format!("\x1b[0m\x1b7\x1b[{row};1H\x1b[2K{text}\x1b[0m\x1b8\x1b[0m").as_bytes(),
            )
            .await
            .context("draw attach control bar")?;
    }
    stderr.flush().await.context("flush attach control bar")
}

fn terminal_color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").map_or(true, |term| term != "dumb")
}

fn terminal_locale_supports_unicode() -> bool {
    let locale = std::env::var("LC_ALL")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("LC_CTYPE")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .or_else(|| std::env::var("LANG").ok().filter(|value| !value.is_empty()));
    locale.is_none_or(|value| {
        let upper = value.to_ascii_uppercase();
        upper.contains("UTF-8") || upper.contains("UTF8")
    })
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
    fn attach_control_bar_fits_terminal_width() {
        assert_eq!(fit_visible("abcdef", 10), "abcdef");
        assert_eq!(fit_visible("abcdef", 4), "abc…\x1b[0m");
        assert_eq!(fit_visible("abcdef", 1), "…");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_pty_spawn_gives_child_a_real_tty() {
        let winsize = nix::libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let (_master, mut child) = spawn_local_pty_blocking(
            "/bin/sh",
            &[
                "-c".to_owned(),
                "test -t 0 && test -t 1 && test -t 2".to_owned(),
            ],
            winsize,
            Vec::new(),
            None,
        )
        .expect("spawn pty child");

        let status = child.wait().await.expect("wait child");
        assert!(status.success(), "child stdio was not a tty: {status}");
    }

    #[test]
    fn attach_output_gate_buffers_while_control_bar_is_visible() {
        let mut gate = AttachOutputGate::default();

        assert_eq!(gate.hold(AttachOutputStream::Stdout, b"frame1"), None);
        gate.set_holding(true);
        assert_eq!(
            gate.hold(AttachOutputStream::Stdout, b"frame2"),
            Some(&[][..])
        );
        assert_eq!(gate.hold(AttachOutputStream::Stderr, b"err"), Some(&[][..]));
        assert_eq!(gate.take_stdout(), b"frame2".to_vec());
        assert_eq!(gate.take_stderr(), b"err".to_vec());
        gate.set_holding(false);
        assert_eq!(gate.hold(AttachOutputStream::Stdout, b"frame3"), None);
    }

    #[test]
    fn attach_control_bar_fits_ansi_styled_text_by_visible_width() {
        let text = "\x1b[1;36mPortl ›\x1b[0m abcdef";
        assert_eq!(
            portl_core::attach_control::visible_width(text),
            "Portl › abcdef".chars().count()
        );
        assert_eq!(fit_visible(text, 10), "\x1b[1;36mPortl ›\x1b[0m a…\x1b[0m");
    }

    #[test]
    fn detects_raw_and_kitty_ctrl_backslash_attach_detach() {
        assert!(is_ctrl_backslash_sequence(b"\x1c"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;5u"));
        assert!(is_ctrl_backslash_sequence(b"prefix\x1b[92;5:1usuffix"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92:124;5u"));

        assert!(!is_ctrl_backslash_sequence(b"\\"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;6u"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;5:3u"));
        assert!(!is_ctrl_backslash_sequence(b"not-detach"));
    }

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

    #[cfg(feature = "ghostty-vt")]
    #[test]
    fn local_provider_report_prefers_ghostty_when_feature_enabled() {
        let report = local_session_providers();

        assert_eq!(report.default_provider.as_deref(), Some("ghostty"));
        let ghostty = report
            .providers
            .iter()
            .find(|provider| provider.name == "ghostty")
            .expect("ghostty provider reported");
        assert!(ghostty.available);
        assert!(ghostty.capabilities.create_on_attach);
        assert!(ghostty.capabilities.run);
        assert_eq!(ghostty.tier.as_deref(), Some("native"));
    }

    #[test]
    fn provider_env_precedence_matches_provider_flag_semantics() {
        assert_eq!(
            effective_provider_from_env(Some("zmx"), Some("tmux")).as_deref(),
            Some("zmx")
        );
        assert_eq!(
            effective_provider_from_env(Some("t"), Some("zmx")).as_deref(),
            Some("tmux")
        );
        assert_eq!(
            effective_provider_from_env(None, Some("z")).as_deref(),
            Some("zmx")
        );
        assert_eq!(
            effective_provider_from_env(None, Some("tmux")).as_deref(),
            Some("tmux")
        );
        assert_eq!(effective_provider_from_env(None, Some("  ")), None);
        assert_eq!(effective_provider_from_env(None, None), None);
    }

    fn test_session_group(provider: &str, names: &[&str]) -> SessionProviderSessions {
        SessionProviderSessions {
            provider: provider.to_owned(),
            available: true,
            default: false,
            sessions: names
                .iter()
                .map(|name| SessionInfo {
                    name: (*name).to_owned(),
                    provider: provider.to_owned(),
                    metadata: BTreeMap::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn ls_ref_target_and_provider_prefixes() {
        let fixture = seed_peer_and_share();
        assert_eq!(
            resolve_ls_ref_filters_with_stores(
                Some("max"),
                None,
                None,
                &fixture.peers,
                &fixture.tickets,
                &fixture.aliases,
            )
            .unwrap(),
            (Some("max".to_owned()), None)
        );
        assert_eq!(
            resolve_ls_ref_filters_with_stores(
                Some("max/t"),
                None,
                None,
                &fixture.peers,
                &fixture.tickets,
                &fixture.aliases,
            )
            .unwrap(),
            (Some("max".to_owned()), Some("tmux".to_owned()))
        );
        assert_eq!(
            resolve_ls_ref_filters_with_stores(
                Some("max/zmx"),
                None,
                None,
                &fixture.peers,
                &fixture.tickets,
                &fixture.aliases,
            )
            .unwrap(),
            (Some("max".to_owned()), Some("zmx".to_owned()))
        );
    }

    #[test]
    fn ls_ref_accepts_equivalent_target_shorthand_and_flag() {
        let fixture = seed_peer_and_share();
        assert_eq!(
            resolve_ls_ref_filters_with_stores(
                Some("max"),
                Some("max-b265"),
                None,
                &fixture.peers,
                &fixture.tickets,
                &fixture.aliases,
            )
            .unwrap(),
            (Some("max-b265".to_owned()), None)
        );
    }

    #[test]
    fn ls_ref_rejects_conflicting_filters() {
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
        let target_err = resolve_ls_ref_filters_with_stores(
            Some("max"),
            Some("onyx"),
            None,
            &fixture.peers,
            &fixture.tickets,
            &fixture.aliases,
        )
        .unwrap_err();
        assert!(
            target_err
                .to_string()
                .contains("conflicting session list targets")
        );

        let provider_err = resolve_ls_ref_filters_with_stores(
            Some("max/tmux"),
            None,
            Some("zmx"),
            &fixture.peers,
            &fixture.tickets,
            &fixture.aliases,
        )
        .unwrap_err();
        assert!(
            provider_err
                .to_string()
                .contains("conflicting session providers")
        );
    }

    #[test]
    fn bare_attach_match_selects_unique_provider_qualified_session() {
        let resolved = resolve_existing_session_match(
            "session2",
            &[
                (
                    "machine-a".to_owned(),
                    vec![test_session_group("zmx", &["session2"])],
                ),
                (
                    "machine-b".to_owned(),
                    vec![test_session_group("tmux", &["other"])],
                ),
            ],
        )
        .unwrap()
        .expect("unique match");

        assert_eq!(resolved.target, "machine-a");
        assert_eq!(resolved.provider.as_deref(), Some("zmx"));
        assert_eq!(resolved.session, "session2");
    }

    #[test]
    fn bare_attach_match_reports_ambiguous_targets_and_providers() {
        let err = resolve_existing_session_match(
            "session2",
            &[
                (
                    "machine-a".to_owned(),
                    vec![test_session_group("zmx", &["session2"])],
                ),
                (
                    "machine-b".to_owned(),
                    vec![test_session_group("tmux", &["session2"])],
                ),
            ],
        )
        .unwrap_err();

        let text = err.to_string();
        assert!(text.contains("ambiguous session name 'session2'"), "{text}");
        assert!(text.contains("machine-a/zmx/session2"), "{text}");
        assert!(text.contains("machine-b/tmux/session2"), "{text}");
    }

    #[test]
    fn bare_attach_match_returns_none_for_missing_session() {
        let resolved = resolve_existing_session_match(
            "missing",
            &[(
                "machine-a".to_owned(),
                vec![test_session_group("zmx", &["other"])],
            )],
        )
        .unwrap();

        assert!(resolved.is_none());
    }

    #[test]
    fn provider_aware_list_formatting_and_json_are_structured() {
        let mut providers = BTreeMap::new();
        providers.insert(
            "zmx".to_owned(),
            SessionProviderListing {
                available: true,
                is_default: true,
                count: 1,
                sessions: vec![SessionListingEntry {
                    provider: "zmx".to_owned(),
                    name: "dev".to_owned(),
                    reference: "max-b265/zmx/dev".to_owned(),
                    metadata: serde_json::json!({}),
                }],
            },
        );
        let listing = SessionListing {
            target: "max-b265".to_owned(),
            provider_filter: None,
            total: 1,
            providers,
        };

        assert_eq!(
            render_session_listing_human(&listing),
            "PROVIDER  REF\nzmx       max-b265/zmx/dev\n"
        );
        assert_eq!(
            serde_json::to_value(&listing).unwrap()["providers"]["zmx"]["sessions"][0]["name"],
            "dev"
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
    fn session_ref_accepts_provider_qualified_canonical_form() {
        let fixture = seed_peer_and_share();
        let resolved = resolve_session_ref_with_stores(
            Some("max/t/dotfiles"),
            None,
            None,
            &fixture.peers,
            &fixture.tickets,
            &fixture.aliases,
        )
        .unwrap();

        assert_eq!(resolved.target, "max-b265/dotfiles");
        assert_eq!(resolved.provider.as_deref(), Some("tmux"));
        assert_eq!(resolved.session, "dotfiles");
    }

    #[test]
    fn session_provider_refs_conflict_with_explicit_provider() {
        let err =
            merge_session_providers(Some("zmx".to_owned()), Some("tmux".to_owned())).unwrap_err();

        assert!(
            err.to_string().contains("conflicting session providers"),
            "unexpected error: {err:#}"
        );
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
                        reference: "max-b265/tmux/dev".to_owned(),
                        metadata: serde_json::json!({
                            "id": "$1",
                            "attached": false,
                            "windows": 2
                        }),
                    },
                    SessionListingEntry {
                        name: "frontend".to_owned(),
                        provider: "tmux".to_owned(),
                        reference: "max-b265/tmux/frontend".to_owned(),
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
            value["providers"]["tmux"]["sessions"][0]["reference"],
            "max-b265/tmux/dev"
        );
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

    #[test]
    fn paste_state_enters_on_large_burst_and_cancels_pending() {
        let mut state = PasteState::new(PasteConfig::for_test(16, Duration::from_secs(1)));
        state.observe_read(32, Instant::now());
        assert!(state.is_active());
        state.observe_queued(32);
        assert_eq!(state.pending_bytes(), 32);
        assert_eq!(state.cancel_pending(), 32);
        assert_eq!(state.pending_bytes(), 0);
        assert!(!state.is_active());
    }

    #[test]
    fn paste_state_observe_queued_alone_does_not_activate() {
        let mut state = PasteState::new(PasteConfig::for_test(16, Duration::from_secs(1)));
        state.observe_queued(1024);
        assert!(!state.is_active());
        assert_eq!(state.pending_bytes(), 1024);
    }

    #[test]
    fn paste_state_cancel_pending_deactivates() {
        let mut state = PasteState::new(PasteConfig::for_test(16, Duration::from_secs(1)));
        state.observe_read(32, Instant::now());
        assert!(state.is_active());
        state.cancel_pending();
        assert!(!state.is_active());
    }

    #[test]
    fn bracketed_paste_scanner_detects_begin_and_end_across_chunks() {
        let mut scanner = BracketedPasteScanner::default();
        assert_eq!(scanner.scan(b"abc\x1b[200"), BracketedPasteEvent::None);
        assert_eq!(scanner.scan(b"~payload"), BracketedPasteEvent::Begin);
        assert!(scanner.in_bracketed_paste());
        assert_eq!(scanner.scan(b"more\x1b[201~"), BracketedPasteEvent::End);
        assert!(!scanner.in_bracketed_paste());
    }

    #[test]
    fn bracketed_paste_scanner_handles_begin_and_end_in_same_chunk() {
        let mut scanner = BracketedPasteScanner::default();
        // Both markers in one chunk — End comes after Begin, so net state is not-in-paste.
        let event = scanner.scan(b"\x1b[200~content\x1b[201~");
        assert_eq!(event, BracketedPasteEvent::End);
        assert!(!scanner.in_bracketed_paste());
    }

    #[test]
    fn bracketed_paste_scanner_force_end_clears_in_paste() {
        let mut scanner = BracketedPasteScanner::default();
        scanner.scan(b"\x1b[200~");
        assert!(scanner.in_bracketed_paste());
        scanner.force_end();
        assert!(!scanner.in_bracketed_paste());
    }
}

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::future::Future;
use std::io::{IsTerminal, Write as IoWrite};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::sync::{
    Arc, Mutex as StdMutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use futures_util::stream::{FuturesUnordered, StreamExt};
use iroh::endpoint::{Connection, SendStream};
use iroh_base::TransportAddr;
use portl_core::StdinResponseFilter;
use portl_core::attach_control::{
    RenderBarOptions, fit_visible, is_ctrl_backslash_sequence, render_bar,
};
use portl_core::io::BufferedRecv;
use portl_core::net::{
    SessionClient, SessionClientV2, SessionOpenError, open_session_attach_checked,
    open_session_attach_v2_checked, open_session_history, open_session_kill,
    open_session_list_detailed, open_session_list_detailed_checked, open_session_providers,
    open_session_run,
};
use portl_core::terminal::{tmux_cc, zmx_control};
use portl_core::terminal_mode_tracker::TerminalModeTracker;
#[cfg(test)]
use portl_core::terminal_mode_tracker::{AltScreenMode, TerminalModeState};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use portl_core::wire::session::{
    ATTACH_V2_MAX_DECODED_PAYLOAD, AttachV2ClientFrame, AttachV2Config, AttachV2Payload,
    AttachV2Progress, AttachV2ServerFrame, SessionControlAction, SessionControlFrame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tracing::{debug, trace};

use crate::commands::peer_resolve::{
    bind_client_endpoint, close_client_endpoint, close_connected, connect_peer, connect_peer_quiet,
    connect_peer_with_endpoint, resolve_identity_path,
};
use crate::commands::session_share::{
    BuiltEnvelope, EnvelopeInputs, ResolveTargetError, ShareTargetForm,
    build_session_share_envelope, classify_share_target, fresh_workspace_handles, load_identity,
    resolve_rendezvous_url, run_offer_against_transport, unix_now,
};
use portl_core::id::store as identity_store;
use portl_core::peer_store::PeerStore;
use portl_core::rendezvous::ws::WsRendezvousBackend;
use portl_core::ticket_store::TicketStore;
use portl_proto::session_v1::{
    ProviderCapabilities, ProviderReport, ProviderStatus, SessionInfo, SessionProviderSessions,
};
use rand::Rng;
use tokio::sync::{mpsc, oneshot};

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
            close_client_endpoint(client_endpoint, "share resolve").await;
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
                "unsupported local session provider '{other}' (supported: default, ghostty, zmx, tmux)"
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
                "unsupported local session provider '{other}' (supported: default, ghostty, zmx, tmux)"
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
    #[cfg(feature = "panic-inject-attach")]
    maybe_panic_inject_attach();
    let mut signal_watcher = AttachSignalWatcher::new()?;
    let display = AttachDisplay::new(cols, rows);
    let mode_tracker = new_terminal_mode_tracker();
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
    let stdout_tracker = Arc::clone(&mode_tracker);
    let stdout_task = tokio::spawn(async move {
        copy_mpsc_output(
            &mut stdout_rx,
            &stdout_display,
            AttachOutputStream::Stdout,
            &stdout_tracker,
        )
        .await
    });
    let stderr_display = display.clone();
    let mut stderr_rx = attach.stderr_rx;
    let stderr_tracker = Arc::clone(&mode_tracker);
    let stderr_task = tokio::spawn(async move {
        copy_mpsc_output(
            &mut stderr_rx,
            &stderr_display,
            AttachOutputStream::Stderr,
            &stderr_tracker,
        )
        .await
    });
    let completion =
        wait_ghostty_attach_completion(&mut attach.exit_rx, stdin_task, &mut signal_watcher)
            .await?;
    if matches!(
        completion,
        AttachCompletion::Detached | AttachCompletion::Signal(_)
    ) {
        stdout_task.abort();
        stderr_task.abort();
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        display.clear_bar().await?;
        Ok(finish_local_attach(raw_guard, completion, &canonical_ref))
    } else {
        await_output_task(stdout_task, "stdout").await?;
        await_output_task(stderr_task, "stderr").await?;
        display.clear_bar().await?;
        Ok(finish_local_attach(raw_guard, completion, &canonical_ref))
    }
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
    let mut signal_watcher = AttachSignalWatcher::new()?;
    let display = AttachDisplay::new(cols, rows);
    let mode_tracker = new_terminal_mode_tracker();
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
    let stdout_tracker = Arc::clone(&mode_tracker);
    let stdout_task = tokio::spawn(async move {
        copy_zmx_control_output(&mut stdout, &stdout_display, &stdout_tracker).await
    });
    let stderr_display = display.clone();
    let stderr_tracker = Arc::clone(&mode_tracker);
    let stderr_task = tokio::spawn(async move {
        copy_remote_output(
            &mut stderr,
            &stderr_display,
            AttachOutputStream::Stderr,
            &stderr_tracker,
        )
        .await
    });
    let completion =
        wait_local_attach_completion(&mut child, stdin_task, &mut signal_watcher).await?;
    if matches!(
        completion,
        AttachCompletion::Detached | AttachCompletion::Signal(_)
    ) {
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
    Ok(finish_local_attach(raw_guard, completion, &canonical_ref))
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
    let mut signal_watcher = AttachSignalWatcher::new()?;
    let display = AttachDisplay::new(cols, rows);
    let mode_tracker = new_terminal_mode_tracker();
    if let Some(initial_viewport) = initial_viewport {
        write_tracked_output(
            &display,
            AttachOutputStream::Stdout,
            &initial_viewport,
            &mode_tracker,
        )
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
    let stdout_tracker = Arc::clone(&mode_tracker);
    let stdout_task = tokio::spawn(async move {
        pump_local_tmux_control_pty(master, &stdout_display, tmux_pty_rx, &stdout_tracker).await
    });
    let completion =
        wait_local_attach_completion(&mut child, stdin_task, &mut signal_watcher).await?;
    if matches!(
        completion,
        AttachCompletion::Detached | AttachCompletion::Signal(_)
    ) {
        reap_local_child_after_detach(&mut child).await;
        stdout_task.abort();
        let _ = stdout_task.await;
    } else {
        await_output_task(stdout_task, "stdout").await?;
    }
    display.clear_bar().await?;
    Ok(finish_local_attach(raw_guard, completion, &canonical_ref))
}

fn finish_local_attach(
    raw_guard: Option<RawModeGuard>,
    completion: AttachCompletion,
    canonical_ref: &str,
) -> ExitCode {
    match completion {
        AttachCompletion::Detached => {
            finish_raw_guard(raw_guard, RawModeExitVariant::Normal);
            eprintln!("portl: detached from session \"{canonical_ref}\"");
            eprintln!();
            eprintln!("The session is still running. To reconnect, run:");
            eprintln!("  portl attach {canonical_ref}");
            ExitCode::SUCCESS
        }
        AttachCompletion::Signal(variant) => {
            finish_raw_guard(raw_guard, variant);
            ExitCode::from(1)
        }
        AttachCompletion::Exited(code) => {
            finish_raw_guard(raw_guard, RawModeExitVariant::Normal);
            exit_code_from_i32(code)
        }
    }
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
                    "unsupported local session provider '{other}' (supported: default, ghostty, zmx, tmux)"
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

        let (cols, rows) = size().unwrap_or((80, 24));
        let request = RemoteSessionAttachRequest {
            target: resolved.target,
            provider: provider_name,
            session_name,
            user: user.map(ToOwned::to_owned),
            cwd: cwd.map(ToOwned::to_owned),
            argv: argv.to_vec(),
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned()),
            cols,
            rows,
        };
        if session_reconnect_enabled() && std::io::stdin().is_terminal() {
            remote_session_attach_with_reconnect(request).await
        } else {
            remote_session_attach_once_without_reconnect(request).await
        }
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
    if normalized == "raw" {
        return Ok(normalized);
    }
    if let Some(provider) = portl_agent::config::normalize_session_provider_override(&normalized) {
        return Ok(provider.to_owned());
    }
    let supported = format!("{}, raw", portl_agent::config::SESSION_PROVIDER_HELP_VALUES);
    anyhow::bail!("unsupported session provider '{normalized}' (supported: {supported})")
}

fn normalize_session_provider_alias(provider: &str) -> String {
    match provider.trim() {
        "default" | "g" => "ghostty".to_owned(),
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

#[derive(Debug, Clone)]
struct RemoteSessionAttachRequest {
    target: String,
    provider: Option<String>,
    session_name: String,
    user: Option<String>,
    cwd: Option<String>,
    argv: Vec<String>,
    term: String,
    cols: u16,
    rows: u16,
}

enum RemoteAttachSession {
    V1(SessionClient),
    V2(SessionClientV2),
}

impl RemoteAttachSession {
    fn provider(&self) -> &str {
        match self {
            Self::V1(session) => &session.provider,
            Self::V2(session) => &session.provider,
        }
    }
}

fn attach_v2_config_from_env() -> AttachV2Config {
    let mut config = AttachV2Config::default();
    if let Some(value) = parse_env_u64("PORTL_ATTACH_PRELUDE_MAX_WAIT_MS") {
        config.prelude_max_wait_ms = value;
    }
    if let Some(value) = parse_env_u64("PORTL_ATTACH_PRELUDE_MAX_BYTES") {
        config.prelude_max_bytes = value;
    }
    config
}

fn parse_env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn should_try_attach_v2(provider: Option<&str>) -> bool {
    !matches!(provider, Some("zmx" | "tmux" | "raw"))
}

fn should_fallback_to_attach_v1(provider: Option<&str>, err: &SessionOpenError) -> bool {
    provider.is_none()
        && matches!(
            err.reason(),
            Some(
                portl_core::wire::session::SessionReason::CapabilityUnsupported { .. }
                    | portl_core::wire::session::SessionReason::ProviderUnavailable(_)
                    | portl_core::wire::session::SessionReason::ProviderNotFound(_)
            )
        )
}

#[allow(clippy::too_many_arguments)]
async fn open_remote_attach_session_checked(
    connection: &Connection,
    session: &portl_core::net::PeerSession,
    provider: Option<String>,
    session_name: String,
    argv: Option<Vec<String>>,
    user: Option<String>,
    cwd: Option<String>,
    pty: portl_core::net::shell_client::PtyCfg,
) -> std::result::Result<RemoteAttachSession, SessionOpenError> {
    if should_try_attach_v2(provider.as_deref()) {
        match open_session_attach_v2_checked(
            connection,
            session,
            provider.clone(),
            session_name.clone(),
            argv.clone(),
            user.clone(),
            cwd.clone(),
            pty.clone(),
            attach_v2_config_from_env(),
        )
        .await
        {
            Ok(session) => return Ok(RemoteAttachSession::V2(session)),
            Err(err) if should_fallback_to_attach_v1(provider.as_deref(), &err) => {}
            Err(err) => return Err(err),
        }
    }
    open_session_attach_checked(
        connection,
        session,
        provider,
        session_name,
        argv,
        user,
        cwd,
        pty,
    )
    .await
    .map(RemoteAttachSession::V1)
}

fn session_reconnect_enabled() -> bool {
    std::env::var("PORTL_SESSION_RECONNECT").map_or(true, |value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        )
    })
}

async fn remote_session_attach_once_without_reconnect(
    request: RemoteSessionAttachRequest,
) -> Result<ExitCode> {
    let connected = connect_peer(&request.target, session_caps()).await?;
    print_remote_attach_start(&request, request.provider.as_deref());
    let session = open_remote_attach_session_checked(
        &connected.connection,
        &connected.session,
        request.provider.clone(),
        request.session_name.clone(),
        (!request.argv.is_empty()).then_some(request.argv.clone()),
        request.user.clone(),
        request.cwd.clone(),
        portl_core::net::shell_client::PtyCfg {
            term: request.term.clone(),
            cols: request.cols,
            rows: request.rows,
        },
    )
    .await?;
    let provider = session.provider().to_owned();
    let canonical_ref = canonical_session_ref(&request.target, &provider, &request.session_name);
    let code = bridge_attach(session, request.cols, request.rows, canonical_ref).await?;
    close_connected(connected, b"session complete").await;
    Ok(exit_code_from_i32(code))
}

async fn remote_session_attach_with_reconnect(
    request: RemoteSessionAttachRequest,
) -> Result<ExitCode> {
    let identity_path = resolve_identity_path(None);
    let identity = identity_store::load(&identity_path).context("load local identity")?;
    let endpoint = bind_client_endpoint(&identity).await?;
    let result =
        remote_session_attach_with_reconnect_on_endpoint(request, &identity, &endpoint).await;
    close_client_endpoint(endpoint, "session reconnect").await;
    result
}

#[allow(clippy::too_many_lines)]
async fn remote_session_attach_with_reconnect_on_endpoint(
    request: RemoteSessionAttachRequest,
    identity: &portl_core::id::Identity,
    endpoint: &iroh::Endpoint,
) -> Result<ExitCode> {
    print_remote_attach_start(&request, request.provider.as_deref());
    let mut connected =
        connect_peer_with_endpoint(&request.target, session_caps(), identity, endpoint, false)
            .await?;
    let mut session = open_remote_attach_session_checked(
        &connected.connection,
        &connected.session,
        request.provider.clone(),
        request.session_name.clone(),
        (!request.argv.is_empty()).then_some(request.argv.clone()),
        request.user.clone(),
        request.cwd.clone(),
        portl_core::net::shell_client::PtyCfg {
            term: request.term.clone(),
            cols: request.cols,
            rows: request.rows,
        },
    )
    .await?;
    let provider = session.provider().to_owned();
    let canonical_ref = canonical_session_ref(&request.target, &provider, &request.session_name);
    let mut flight_recorder = AttachFlightRecorder::new();
    flight_recorder.record_with_path(
        "initial attach opened",
        attach_path_snapshot(&connected.connection),
    );
    let raw_guard = RawModeGuard::new()?;
    let mut signal_watcher = AttachSignalWatcher::new()?;
    let display = AttachDisplay::new(request.cols, request.rows);
    let mode_tracker = new_terminal_mode_tracker();
    let mut coordinator = AttachInputCoordinator::spawn(
        AttachControlUi {
            canonical_ref: canonical_ref.clone(),
            supports_kick_others: provider == "tmux",
            display: display.clone(),
        },
        (request.cols, request.rows),
    );

    let mut reconnect_state = ReconnectAttemptState::new();
    let mut attach_started = Instant::now();
    #[cfg(feature = "test-reconnect-injection")]
    let mut injected_initial_disconnect = test_reconnect_scenario()?;
    loop {
        #[cfg(feature = "test-reconnect-injection")]
        let attach_end = if let Some(scenario) = injected_initial_disconnect.take() {
            connected
                .connection
                .close(0u32.into(), b"test reconnect injection");
            if matches!(scenario, TestReconnectScenario::Transient) {
                write_reconnect_test_marker(&display, b"DISCONNECT_WINDOW_BEGIN\r\n").await?;
            }
            AttachEnd::Disconnected(anyhow!("test reconnect injection"))
        } else {
            run_remote_attach_once(
                session,
                &display,
                &mut coordinator,
                &mode_tracker,
                &mut signal_watcher,
            )
            .await
        };
        #[cfg(not(feature = "test-reconnect-injection"))]
        let attach_end = run_remote_attach_once(
            session,
            &display,
            &mut coordinator,
            &mode_tracker,
            &mut signal_watcher,
        )
        .await;

        match attach_end {
            AttachEnd::Exited(code) => {
                display.clear_bar().await?;
                coordinator.stop().await;
                raw_guard.finish(RawModeExitVariant::Normal);
                connected.connection.close(0u32.into(), b"session complete");
                return Ok(exit_code_from_i32(code));
            }
            AttachEnd::Detached => {
                display.clear_bar().await?;
                coordinator.stop().await;
                raw_guard.finish(RawModeExitVariant::Normal);
                connected.connection.close(0u32.into(), b"session detached");
                print_detached_message(&canonical_ref);
                return Ok(ExitCode::SUCCESS);
            }
            AttachEnd::QuitReconnect => {
                display.clear_bar().await?;
                coordinator.stop().await;
                raw_guard.finish(RawModeExitVariant::Normal);
                connected
                    .connection
                    .close(0u32.into(), b"session reconnect quit");
                print_reconnect_quit_message(&canonical_ref);
                return Ok(ExitCode::SUCCESS);
            }
            AttachEnd::Signal(variant) => {
                display.clear_bar().await?;
                coordinator.stop().await;
                raw_guard.finish(variant);
                connected
                    .connection
                    .close(0u32.into(), b"session attach signal");
                return Ok(ExitCode::from(1));
            }
            AttachEnd::Disconnected(err) => {
                debug!(%err, "remote session attach disconnected");
                let disconnected_path = attach_path_snapshot(&connected.connection);
                if attach_started.elapsed() >= Duration::from_secs(30) {
                    reconnect_state = ReconnectAttemptState::new();
                }
                reconnect_state.observe_path(disconnected_path.as_ref());
                flight_recorder.record_with_path(
                    format!("attach stream disconnected: {err}"),
                    disconnected_path,
                );
                let reattached = reconnect_remote_session(
                    &request,
                    &provider,
                    connected,
                    identity,
                    endpoint,
                    &display,
                    &canonical_ref,
                    &mut coordinator,
                    &mut reconnect_state,
                    &mut flight_recorder,
                    &mut signal_watcher,
                )
                .await?;
                match reattached {
                    ReconnectOutcome::Reattached {
                        connected: next_connected,
                        session: next_session,
                    } => {
                        connected = *next_connected;
                        session = *next_session;
                        attach_started = Instant::now();
                    }
                    ReconnectOutcome::Detached => {
                        display.clear_bar().await?;
                        coordinator.stop().await;
                        raw_guard.finish(RawModeExitVariant::Normal);
                        print_detached_message(&canonical_ref);
                        return Ok(ExitCode::SUCCESS);
                    }
                    ReconnectOutcome::Quit => {
                        display.clear_bar().await?;
                        coordinator.stop().await;
                        raw_guard.finish(RawModeExitVariant::Normal);
                        print_reconnect_quit_message(&canonical_ref);
                        return Ok(ExitCode::SUCCESS);
                    }
                    ReconnectOutcome::Expired => {
                        display.clear_bar().await?;
                        coordinator.stop().await;
                        eprintln!(
                            "portl: could not reconnect to session \"{canonical_ref}\" after 2m"
                        );
                        if let Some(events) = flight_recorder.render_recent() {
                            eprintln!();
                            eprintln!("{events}");
                        }
                        eprintln!();
                        eprintln!("The session may still be running. To reconnect, run:");
                        eprintln!("  portl attach {canonical_ref}");
                        raw_guard.finish(RawModeExitVariant::ReconnectExhausted);
                        return Ok(ExitCode::from(1));
                    }
                    ReconnectOutcome::Signal(variant) => {
                        display.clear_bar().await?;
                        coordinator.stop().await;
                        raw_guard.finish(variant);
                        return Ok(ExitCode::from(1));
                    }
                }
            }
        }
    }
}

fn print_remote_attach_start(request: &RemoteSessionAttachRequest, provider: Option<&str>) {
    if let Some(provider) = provider {
        eprintln!(
            "portl: attaching to session \"{}\"",
            canonical_session_ref(&request.target, provider, &request.session_name)
        );
    } else {
        eprintln!(
            "portl: attaching to session \"{}\"",
            target_session_ref(&request.target, &request.session_name)
        );
    }
}

fn print_detached_message(canonical_ref: &str) {
    eprintln!("portl: detached from session \"{canonical_ref}\"");
    eprintln!();
    eprintln!("The session is still running. To reconnect, run:");
    eprintln!("  portl attach {canonical_ref}");
}

fn print_reconnect_quit_message(canonical_ref: &str) {
    eprintln!("portl: stopped reconnecting to session \"{canonical_ref}\"");
    eprintln!();
    eprintln!("The session is still running. To reconnect, run:");
    eprintln!("  portl attach {canonical_ref}");
}

#[allow(clippy::too_many_lines)]
async fn bridge_attach(
    session: RemoteAttachSession,
    cols: u16,
    rows: u16,
    canonical_ref: String,
) -> Result<i32> {
    let session = match session {
        RemoteAttachSession::V1(session) => session,
        RemoteAttachSession::V2(session) => {
            return bridge_attach_v2(session, cols, rows, canonical_ref).await;
        }
    };
    let raw_guard = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::new()?)
    } else {
        None
    };
    let mut signal_watcher = AttachSignalWatcher::new()?;
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
    let mode_tracker = new_terminal_mode_tracker();
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
    let stdout_tracker = Arc::clone(&mode_tracker);
    let stdout_task = tokio::spawn(async move {
        copy_remote_output(
            &mut stdout_recv,
            &stdout_display,
            AttachOutputStream::Stdout,
            &stdout_tracker,
        )
        .await
    });
    let stderr_display = display.clone();
    let stderr_tracker = Arc::clone(&mode_tracker);
    let stderr_task = tokio::spawn(async move {
        copy_remote_output(
            &mut stderr_recv,
            &stderr_display,
            AttachOutputStream::Stderr,
            &stderr_tracker,
        )
        .await
    });
    let completion = wait_attach_completion(&mut exit, stdin_task, &mut signal_watcher).await?;
    if matches!(
        completion,
        AttachCompletion::Detached | AttachCompletion::Signal(_)
    ) {
        stdout_task.abort();
        stderr_task.abort();
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        display.clear_bar().await?;
        match completion {
            AttachCompletion::Detached => {
                if let Some(raw_guard) = raw_guard {
                    raw_guard.finish(RawModeExitVariant::Normal);
                }
                eprintln!("portl: detached from session \"{canonical_ref}\"");
                eprintln!();
                eprintln!("The session is still running. To reconnect, run:");
                eprintln!("  portl attach {canonical_ref}");
                Ok(0)
            }
            AttachCompletion::Signal(variant) => {
                if let Some(raw_guard) = raw_guard {
                    raw_guard.finish(variant);
                }
                Ok(1)
            }
            AttachCompletion::Exited(_) => unreachable!("matches excludes exited"),
        }
    } else {
        await_output_task(stdout_task, "stdout").await?;
        await_output_task(stderr_task, "stderr").await?;
        display.clear_bar().await?;
        if let Some(raw_guard) = raw_guard {
            raw_guard.finish(RawModeExitVariant::Normal);
        }
        match completion {
            AttachCompletion::Exited(code) => Ok(code),
            AttachCompletion::Detached | AttachCompletion::Signal(_) => {
                unreachable!("handled before output await")
            }
        }
    }
}

async fn bridge_attach_v2(
    session: SessionClientV2,
    cols: u16,
    rows: u16,
    canonical_ref: String,
) -> Result<i32> {
    let raw_guard = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::new()?)
    } else {
        None
    };
    let mut signal_watcher = AttachSignalWatcher::new()?;
    let display = AttachDisplay::new(cols, rows);
    let mode_tracker = new_terminal_mode_tracker();
    let mut coordinator = AttachInputCoordinator::spawn(
        AttachControlUi {
            canonical_ref: canonical_ref.clone(),
            supports_kick_others: false,
            display: display.clone(),
        },
        (cols, rows),
    );
    let end = run_remote_attach_v2_once(
        session,
        &display,
        &mut coordinator,
        &mode_tracker,
        &mut signal_watcher,
    )
    .await;
    display.clear_bar().await?;
    coordinator.stop().await;
    if let Some(raw_guard) = raw_guard {
        raw_guard.finish(
            end.raw_mode_exit_variant()
                .unwrap_or(RawModeExitVariant::Normal),
        );
    }
    match end {
        AttachEnd::Exited(code) => Ok(code),
        AttachEnd::Detached | AttachEnd::QuitReconnect => {
            print_detached_message(&canonical_ref);
            Ok(0)
        }
        AttachEnd::Signal(_) => Ok(1),
        AttachEnd::Disconnected(err) => Err(err),
    }
}

const ATTACH_FLIGHT_RECORDER_CAPACITY: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachPathSnapshot {
    label: String,
    rtt: Option<Duration>,
}

impl AttachPathSnapshot {
    fn from_connection(connection: &Connection) -> Option<Self> {
        let paths: Vec<_> = connection
            .paths()
            .into_iter()
            .filter(|path| !path.is_closed())
            .collect();
        let path = paths
            .iter()
            .find(|path| path.is_selected())
            .or_else(|| paths.first())?;
        let label = match path.remote_addr() {
            TransportAddr::Relay(url) => format!("relay {url}"),
            _ => "direct".to_owned(),
        };
        Some(Self {
            label,
            rtt: path.rtt(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachFlightEvent {
    elapsed: Duration,
    message: String,
    path: Option<AttachPathSnapshot>,
}

#[derive(Debug)]
struct AttachFlightRecorder {
    started: Instant,
    events: VecDeque<AttachFlightEvent>,
}

impl AttachFlightRecorder {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            events: VecDeque::with_capacity(ATTACH_FLIGHT_RECORDER_CAPACITY),
        }
    }

    fn record(&mut self, message: impl Into<String>) {
        self.record_with_path(message, None);
    }

    fn record_with_path(&mut self, message: impl Into<String>, path: Option<AttachPathSnapshot>) {
        self.record_at(self.started.elapsed(), message, path);
    }

    fn record_at(
        &mut self,
        elapsed: Duration,
        message: impl Into<String>,
        path: Option<AttachPathSnapshot>,
    ) {
        if self.events.len() == ATTACH_FLIGHT_RECORDER_CAPACITY {
            self.events.pop_front();
        }
        let event = AttachFlightEvent {
            elapsed,
            message: message.into(),
            path,
        };
        trace!(
            elapsed_ms = event.elapsed.as_millis(),
            message = %event.message,
            path = ?event.path,
            "session attach flight recorder event"
        );
        self.events.push_back(event);
    }

    fn render_recent(&self) -> Option<String> {
        if self.events.is_empty() {
            return None;
        }
        let mut out = String::from("Recent reconnect events:\n");
        for event in &self.events {
            let _ = write!(
                out,
                "  - +{} {}",
                format_compact_duration(event.elapsed),
                event.message
            );
            if let Some(path) = &event.path {
                let _ = write!(out, " (path: {}", path.label);
                if let Some(rtt) = path.rtt {
                    let _ = write!(out, ", rtt: {}", format_compact_duration(rtt));
                }
                out.push(')');
            }
            out.push('\n');
        }
        Some(out.trim_end().to_owned())
    }
}

fn attach_path_snapshot(connection: &Connection) -> Option<AttachPathSnapshot> {
    AttachPathSnapshot::from_connection(connection)
}

fn format_compact_duration(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{:.1}s", duration.as_secs_f64())
    }
}

#[derive(Debug, Clone, Copy)]
struct ReconnectAttemptState {
    started: Instant,
    attempt: u32,
    last_rtt: Option<Duration>,
}

impl ReconnectAttemptState {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            attempt: 0,
            last_rtt: None,
        }
    }

    fn next_attempt(&mut self) -> u32 {
        self.attempt = self.attempt.saturating_add(1);
        self.attempt
    }

    fn observe_path(&mut self, path: Option<&AttachPathSnapshot>) {
        if let Some(rtt) = path.and_then(|path| path.rtt).filter(|rtt| !rtt.is_zero()) {
            self.last_rtt = Some(rtt);
        }
    }
}

enum ReconnectOutcome {
    Reattached {
        connected: Box<crate::commands::peer_resolve::ConnectedPeer>,
        session: Box<RemoteAttachSession>,
    },
    Detached,
    Quit,
    Expired,
    Signal(RawModeExitVariant),
}

impl ReconnectOutcome {
    #[cfg(test)]
    fn raw_mode_exit_variant(&self) -> Option<RawModeExitVariant> {
        match self {
            Self::Expired => Some(RawModeExitVariant::ReconnectExhausted),
            Self::Signal(variant) => Some(*variant),
            Self::Reattached { .. } | Self::Detached | Self::Quit => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconnectDelayOutcome {
    Retry,
    Detached,
    Quit,
    Signal(RawModeExitVariant),
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn reconnect_remote_session(
    request: &RemoteSessionAttachRequest,
    provider: &str,
    current_connected: crate::commands::peer_resolve::ConnectedPeer,
    identity: &portl_core::id::Identity,
    endpoint: &iroh::Endpoint,
    display: &AttachDisplay,
    canonical_ref: &str,
    coordinator: &mut AttachInputCoordinator,
    state: &mut ReconnectAttemptState,
    flight_recorder: &mut AttachFlightRecorder,
    signal_watcher: &mut AttachSignalWatcher,
) -> Result<ReconnectOutcome> {
    let policy = reconnect_policy_for_environment(ReconnectPolicy::default_interactive())
        .with_observed_rtt(state.last_rtt);
    if !policy.retry_budget_remaining(state.started.elapsed()) {
        flight_recorder.record(format!(
            "reconnect expired after {}",
            format_compact_duration(state.started.elapsed())
        ));
        #[cfg(feature = "test-reconnect-injection")]
        if matches!(
            test_reconnect_scenario()?,
            Some(TestReconnectScenario::Exhausted)
        ) {
            write_reconnect_test_marker(display, b"RECONNECT_BUDGET_EXHAUSTED\r\n").await?;
        }
        return Ok(ReconnectOutcome::Expired);
    }

    let same_connection_outcome = tokio::select! {
        outcome = try_same_connection_reattach(
            request,
            provider,
            current_connected,
            canonical_ref,
            state,
            flight_recorder,
        ) => outcome?,
        signal = signal_watcher.next() => return Ok(ReconnectOutcome::Signal(signal)),
    };
    if let Some(outcome) = same_connection_outcome {
        return Ok(outcome);
    }

    loop {
        let policy = reconnect_policy_for_environment(ReconnectPolicy::default_interactive())
            .with_observed_rtt(state.last_rtt);
        let attempt = state.next_attempt();
        if !policy.retry_budget_remaining(state.started.elapsed()) {
            flight_recorder.record(format!(
                "reconnect budget expired after {} attempts",
                attempt.saturating_sub(1)
            ));
            #[cfg(feature = "test-reconnect-injection")]
            if matches!(
                test_reconnect_scenario()?,
                Some(TestReconnectScenario::Exhausted)
            ) {
                write_reconnect_test_marker(display, b"RECONNECT_BUDGET_EXHAUSTED\r\n").await?;
            }
            return Ok(ReconnectOutcome::Expired);
        }
        let visible = state.started.elapsed() >= policy.transparent_grace;
        let delay = reconnect_attempt_delay(attempt, &policy);
        flight_recorder.record(format!(
            "reconnect attempt {attempt} scheduled after {}{}",
            format_compact_duration(delay),
            if visible { " (visible)" } else { "" }
        ));
        #[cfg(feature = "test-reconnect-injection")]
        if matches!(
            test_reconnect_scenario()?,
            Some(TestReconnectScenario::SighupWait)
        ) && attempt == 1
        {
            write_reconnect_test_marker(display, b"RECONNECT_WAIT_READY\r\n").await?;
        }
        match wait_reconnect_delay(
            delay,
            visible,
            attempt,
            canonical_ref,
            display,
            coordinator,
            signal_watcher,
        )
        .await?
        {
            ReconnectDelayOutcome::Retry => {}
            ReconnectDelayOutcome::Detached => return Ok(ReconnectOutcome::Detached),
            ReconnectDelayOutcome::Quit => return Ok(ReconnectOutcome::Quit),
            ReconnectDelayOutcome::Signal(variant) => return Ok(ReconnectOutcome::Signal(variant)),
        }
        #[cfg(feature = "test-reconnect-injection")]
        if let Some(scenario) = test_reconnect_scenario()?
            && test_reconnect_forces_connect_failure(scenario, attempt)
        {
            flight_recorder.record(format!(
                "reconnect attempt {attempt} test-injected connect failure"
            ));
            continue;
        }
        if visible {
            if !coordinator.set_reconnect_visible(true).await? {
                return Ok(ReconnectOutcome::Quit);
            }
            display
                .set_bar(format!(
                    "▌ Portl › {canonical_ref} · reconnecting now · d detach · Ctrl-C quit"
                ))
                .await?;
        }
        let connected = match tokio::select! {
            connected = async {
                #[cfg(feature = "test-reconnect-injection")]
                test_reconnect_block_connect_attempt(display, attempt).await?;
                connect_peer_with_endpoint(
                    &request.target,
                    session_caps(),
                    identity,
                    endpoint,
                    true,
                )
                .await
            } => connected,
            signal = signal_watcher.next() => return Ok(ReconnectOutcome::Signal(signal)),
        } {
            Ok(connected) => connected,
            Err(err) => {
                debug!(%err, attempt, "session reconnect connect failed");
                flight_recorder
                    .record(format!("reconnect attempt {attempt} connect failed: {err}"));
                continue;
            }
        };
        let groups = match tokio::select! {
            groups = open_session_list_detailed_checked(
                &connected.connection,
                &connected.session,
                Some(provider.to_owned()),
            ) => groups,
            signal = signal_watcher.next() => return Ok(ReconnectOutcome::Signal(signal)),
        } {
            Ok(groups) => groups,
            Err(err @ SessionOpenError::Rejected { .. }) => return Err(anyhow::Error::from(err)),
            Err(SessionOpenError::Transport(err)) => {
                debug!(%err, attempt, "session reconnect preflight failed");
                let path = attach_path_snapshot(&connected.connection);
                state.observe_path(path.as_ref());
                flight_recorder.record_with_path(
                    format!("reconnect attempt {attempt} preflight failed: {err}"),
                    path,
                );
                connected
                    .connection
                    .close(0u32.into(), b"session reconnect preflight failed");
                continue;
            }
        };
        if !session_exists_for_reconnect(&groups, provider, &request.session_name) {
            let path = attach_path_snapshot(&connected.connection);
            state.observe_path(path.as_ref());
            flight_recorder.record_with_path(
                format!(
                    "reconnect attempt {attempt} session '{}' disappeared",
                    request.session_name
                ),
                path,
            );
            connected
                .connection
                .close(0u32.into(), b"session disappeared during reconnect");
            anyhow::bail!(
                "persistent session '{}' was not found on the target",
                request.session_name
            );
        }
        match tokio::select! {
            session = open_remote_attach_session_checked(
                &connected.connection,
                &connected.session,
                Some(provider.to_owned()),
                request.session_name.clone(),
                None,
                request.user.clone(),
                request.cwd.clone(),
                portl_core::net::shell_client::PtyCfg {
                    term: request.term.clone(),
                    cols: request.cols,
                    rows: request.rows,
                },
            ) => session,
            signal = signal_watcher.next() => return Ok(ReconnectOutcome::Signal(signal)),
        } {
            Ok(session) => {
                let path = attach_path_snapshot(&connected.connection);
                state.observe_path(path.as_ref());
                flight_recorder
                    .record_with_path(format!("reconnect attempt {attempt} reattached"), path);
                #[cfg(feature = "test-reconnect-injection")]
                if matches!(
                    test_reconnect_scenario()?,
                    Some(TestReconnectScenario::Transient)
                ) {
                    write_reconnect_test_marker(display, b"RECONNECT_SUCCESS\r\n").await?;
                }
                if visible {
                    display
                        .set_bar(format!("▌ Portl › {canonical_ref} · reattached"))
                        .await?;
                }
                return Ok(ReconnectOutcome::Reattached {
                    connected: Box::new(connected),
                    session: Box::new(session),
                });
            }
            Err(err @ SessionOpenError::Rejected { .. }) => return Err(anyhow::Error::from(err)),
            Err(SessionOpenError::Transport(err)) => {
                debug!(%err, attempt, "session reconnect attach failed");
                let path = attach_path_snapshot(&connected.connection);
                state.observe_path(path.as_ref());
                flight_recorder.record_with_path(
                    format!("reconnect attempt {attempt} attach failed: {err}"),
                    path,
                );
                connected
                    .connection
                    .close(0u32.into(), b"session reconnect attach failed");
            }
        }
    }
}

async fn try_same_connection_reattach(
    request: &RemoteSessionAttachRequest,
    provider: &str,
    connected: crate::commands::peer_resolve::ConnectedPeer,
    canonical_ref: &str,
    state: &mut ReconnectAttemptState,
    flight_recorder: &mut AttachFlightRecorder,
) -> Result<Option<ReconnectOutcome>> {
    let path = attach_path_snapshot(&connected.connection);
    state.observe_path(path.as_ref());
    flight_recorder.record_with_path("same-connection reattach preflight", path);

    let groups = match open_session_list_detailed_checked(
        &connected.connection,
        &connected.session,
        Some(provider.to_owned()),
    )
    .await
    {
        Ok(groups) => groups,
        Err(err @ SessionOpenError::Rejected { .. }) => {
            connected
                .connection
                .close(0u32.into(), b"same-connection preflight rejected");
            return Err(anyhow::Error::from(err));
        }
        Err(SessionOpenError::Transport(err)) => {
            let path = attach_path_snapshot(&connected.connection);
            state.observe_path(path.as_ref());
            flight_recorder.record_with_path(
                format!("same-connection reattach preflight failed: {err}"),
                path,
            );
            connected
                .connection
                .close(0u32.into(), b"same-connection preflight failed");
            return Ok(None);
        }
    };

    if !session_exists_for_reconnect(&groups, provider, &request.session_name) {
        let path = attach_path_snapshot(&connected.connection);
        state.observe_path(path.as_ref());
        flight_recorder.record_with_path(
            format!(
                "same-connection reattach session '{}' disappeared",
                request.session_name
            ),
            path,
        );
        connected.connection.close(
            0u32.into(),
            b"session disappeared during same-connection reconnect",
        );
        anyhow::bail!(
            "persistent session '{}' was not found on the target",
            request.session_name
        );
    }

    match open_remote_attach_session_checked(
        &connected.connection,
        &connected.session,
        Some(provider.to_owned()),
        request.session_name.clone(),
        None,
        request.user.clone(),
        request.cwd.clone(),
        portl_core::net::shell_client::PtyCfg {
            term: request.term.clone(),
            cols: request.cols,
            rows: request.rows,
        },
    )
    .await
    {
        Ok(session) => {
            let path = attach_path_snapshot(&connected.connection);
            state.observe_path(path.as_ref());
            flight_recorder
                .record_with_path(format!("same-connection reattached {canonical_ref}"), path);
            Ok(Some(ReconnectOutcome::Reattached {
                connected: Box::new(connected),
                session: Box::new(session),
            }))
        }
        Err(err @ SessionOpenError::Rejected { .. }) => {
            connected
                .connection
                .close(0u32.into(), b"same-connection attach rejected");
            Err(anyhow::Error::from(err))
        }
        Err(SessionOpenError::Transport(err)) => {
            let path = attach_path_snapshot(&connected.connection);
            state.observe_path(path.as_ref());
            flight_recorder
                .record_with_path(format!("same-connection reattach failed: {err}"), path);
            connected
                .connection
                .close(0u32.into(), b"same-connection attach failed");
            Ok(None)
        }
    }
}

fn reconnect_attempt_delay(attempt: u32, policy: &ReconnectPolicy) -> Duration {
    match attempt {
        1 => Duration::ZERO,
        2 => random_duration_between(Duration::from_millis(150), Duration::from_millis(300)),
        _ => {
            let capped = policy
                .base_delay
                .saturating_mul(1_u32 << attempt.saturating_sub(3).min(12))
                .min(policy.max_delay);
            // Apply jitter first, then reuse the visible-delay floor/cap logic so
            // transparent retries stay fast while visible retries never spin.
            policy.visible_delay(
                attempt.saturating_sub(2),
                random_duration_between(Duration::ZERO, capped),
            )
        }
    }
}

fn random_duration_between(min: Duration, max: Duration) -> Duration {
    if max <= min {
        return min;
    }
    let min_ms = u64::try_from(min.as_millis()).unwrap_or(u64::MAX);
    let max_ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
}

async fn wait_reconnect_delay(
    delay: Duration,
    visible: bool,
    attempt: u32,
    canonical_ref: &str,
    display: &AttachDisplay,
    coordinator: &mut AttachInputCoordinator,
    signal_watcher: &mut AttachSignalWatcher,
) -> Result<ReconnectDelayOutcome> {
    if delay.is_zero() {
        return Ok(ReconnectDelayOutcome::Retry);
    }
    if visible {
        if !coordinator.set_reconnect_visible(true).await? {
            return Ok(ReconnectDelayOutcome::Quit);
        }
        display
            .set_bar(format!(
                "▌ Portl › {canonical_ref} · disconnected · retry {attempt} in {:.1}s · Enter retry now · d detach · Ctrl-C quit",
                delay.as_secs_f32()
            ))
            .await?;
    } else if !coordinator.set_reconnect_visible(false).await? {
        return Ok(ReconnectDelayOutcome::Quit);
    }
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            () = &mut sleep => return Ok(ReconnectDelayOutcome::Retry),
            event = coordinator.next_event() => {
                match event {
                    Some(AttachInputEvent::RetryNow) => return Ok(ReconnectDelayOutcome::Retry),
                    Some(AttachInputEvent::Detached) => return Ok(ReconnectDelayOutcome::Detached),
                    Some(AttachInputEvent::QuitReconnect | AttachInputEvent::Closed) | None => return Ok(ReconnectDelayOutcome::Quit),
                    Some(AttachInputEvent::BufferFull) => {
                        if !coordinator.set_reconnect_visible(true).await? {
                            return Ok(ReconnectDelayOutcome::Quit);
                        }
                        display
                            .set_bar(format!(
                                "▌ Portl › {canonical_ref} · disconnected · input buffer full · Enter retry now · d detach · Ctrl-C quit"
                            ))
                            .await?;
                    }
                    Some(AttachInputEvent::SinkFailed(err)) => {
                        debug!(%err, "ignored stale sink failure during reconnect backoff");
                    }
                }
            }
            signal = signal_watcher.next() => return Ok(ReconnectDelayOutcome::Signal(signal)),
        }
    }
}

async fn run_remote_attach_once(
    session: RemoteAttachSession,
    display: &AttachDisplay,
    coordinator: &mut AttachInputCoordinator,
    mode_tracker: &SharedTerminalModeTracker,
    signal_watcher: &mut AttachSignalWatcher,
) -> AttachEnd {
    match session {
        RemoteAttachSession::V1(session) => {
            run_remote_attach_v1_once(session, display, coordinator, mode_tracker, signal_watcher)
                .await
        }
        RemoteAttachSession::V2(session) => {
            run_remote_attach_v2_once(session, display, coordinator, mode_tracker, signal_watcher)
                .await
        }
    }
}

async fn run_remote_attach_v1_once(
    session: SessionClient,
    display: &AttachDisplay,
    coordinator: &mut AttachInputCoordinator,
    mode_tracker: &SharedTerminalModeTracker,
    signal_watcher: &mut AttachSignalWatcher,
) -> AttachEnd {
    if let Some(end) = coordinator.drain_before_attach() {
        return end;
    }
    let SessionClient {
        provider: _,
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
    if let Err(err) = coordinator
        .set_sink(AttachInputSink {
            kind: AttachInputSinkKind::Remote {
                send: stdin,
                resize,
                control,
            },
        })
        .await
    {
        return AttachEnd::Disconnected(err);
    }
    if let Err(err) = display.clear_bar().await {
        return AttachEnd::Disconnected(err);
    }
    let stdout_display = display.clone();
    let stdout_tracker = Arc::clone(mode_tracker);
    let mut stdout_task = tokio::spawn(async move {
        copy_remote_output(
            &mut stdout_recv,
            &stdout_display,
            AttachOutputStream::Stdout,
            &stdout_tracker,
        )
        .await
    });
    let stderr_display = display.clone();
    let stderr_tracker = Arc::clone(mode_tracker);
    let mut stderr_task = tokio::spawn(async move {
        copy_remote_output(
            &mut stderr_recv,
            &stderr_display,
            AttachOutputStream::Stderr,
            &stderr_tracker,
        )
        .await
    });
    let mut exit_fut = Box::pin(read_exit(&mut exit));
    let end = loop {
        tokio::select! {
            code = &mut exit_fut => {
                break match code {
                    Ok(code) => AttachEnd::Exited(code),
                    Err(err) => AttachEnd::Disconnected(err),
                };
            }
            event = coordinator.next_event() => {
                break match event {
                    Some(AttachInputEvent::Detached) => AttachEnd::Detached,
                    Some(AttachInputEvent::QuitReconnect) => AttachEnd::QuitReconnect,
                    Some(AttachInputEvent::Closed) => {
                        match tokio::time::timeout(Duration::from_millis(500), &mut exit_fut).await {
                            Ok(Ok(code)) => AttachEnd::Exited(code),
                            Ok(Err(err)) => AttachEnd::Disconnected(err),
                            Err(_) => AttachEnd::Disconnected(anyhow!("local stdin closed before exit frame")),
                        }
                    }
                    Some(AttachInputEvent::SinkFailed(err)) => AttachEnd::Disconnected(err),
                    Some(AttachInputEvent::RetryNow | AttachInputEvent::BufferFull) => continue,
                    None => AttachEnd::Disconnected(anyhow!("attach input coordinator stopped")),
                };
            }
            stdout = &mut stdout_task => {
                let stdout = stdout.context("join stdout task").and_then(|result| result);
                break output_task_end_to_attach_end(stdout, "stdout", &mut exit_fut).await;
            }
            stderr = &mut stderr_task => {
                let stderr = stderr.context("join stderr task").and_then(|result| result);
                break output_task_end_to_attach_end(stderr, "stderr", &mut exit_fut).await;
            }
            signal = signal_watcher.next() => break AttachEnd::Signal(signal),
        }
    };
    stdout_task.abort();
    stderr_task.abort();
    let _ = coordinator.clear_sink().await;
    end
}

#[allow(clippy::too_many_lines)]
async fn run_remote_attach_v2_once(
    session: SessionClientV2,
    display: &AttachDisplay,
    coordinator: &mut AttachInputCoordinator,
    mode_tracker: &SharedTerminalModeTracker,
    signal_watcher: &mut AttachSignalWatcher,
) -> AttachEnd {
    if let Some(end) = coordinator.drain_before_attach() {
        return end;
    }
    let SessionClientV2 {
        provider: _,
        attach_id,
        control_send,
        mut control_recv,
        input,
        resize,
        mut viewport,
        mut live,
        mut history,
    } = session;
    let reload_state = Arc::new(StdMutex::new(ReloadCoordinator::default()));
    let (initial_cols, initial_rows) = display.size().await;
    let resize_state = Arc::new(StdMutex::new(AttachV2ResizeState {
        resize_id: 0,
        cols: initial_cols,
        rows: initial_rows,
    }));
    if let Err(err) = coordinator
        .set_sink(AttachInputSink {
            kind: AttachInputSinkKind::RemoteV2 {
                input,
                resize,
                control: control_send,
                attach_id,
                next_resize_id: 0,
                next_reload_id: 0,
                resize_state: Arc::clone(&resize_state),
                reload_state: Arc::clone(&reload_state),
            },
        })
        .await
    {
        return AttachEnd::Disconnected(err);
    }
    if let Err(err) = display.clear_bar().await {
        return AttachEnd::Disconnected(err);
    }
    let mut covered_live_seq = 0_u64;
    let mut last_viewport_generation = 0_u64;
    let mut opening_state = AttachV2OpeningState::default();
    let mut data_streams = AttachV2DataStreamStatus::default();
    let mut resync_pending = false;
    let end = loop {
        tokio::select! {
            frame = read_attach_v2_frame(&mut control_recv) => {
                match frame {
                    Ok(Some(frame)) if attach_v2_frame_matches(&frame, attach_id) => match handle_attach_v2_control_frame(
                        frame,
                        display,
                        &reload_state,
                        &mut resync_pending,
                        mode_tracker,
                    ).await {
                        Ok(Some(end)) => break end,
                        Ok(None) => {}
                        Err(err) => break AttachEnd::Disconnected(err),
                    },
                    Ok(Some(_)) => {}
                    Ok(None) => break AttachEnd::Disconnected(anyhow!("attach v2 control stream ended before exit frame")),
                    Err(err) => break AttachEnd::Disconnected(err),
                }
            }
            frame = read_attach_v2_frame(&mut viewport), if data_streams.viewport_open() => {
                match frame {
                    Ok(Some(AttachV2ServerFrame::ViewportSnapshot { attach_id: frame_attach_id, generation, covers_live_seq, cols, rows, resize_id, payload, .. })) if frame_attach_id == attach_id => {
                        match attach_v2_viewport_decision(
                            generation,
                            last_viewport_generation,
                            resize_id,
                            cols,
                            rows,
                            current_resize_state(&resize_state),
                            reload_state.lock().map_or(AttachV2ReloadState::Idle, |state| state.state()),
                        ) {
                            AttachV2ViewportDecision::Render => {
                                match payload.decode(ATTACH_V2_MAX_DECODED_PAYLOAD) {
                                    Ok(bytes) => {
                                        last_viewport_generation = generation;
                                        covered_live_seq = covered_live_seq.max(covers_live_seq);
                                        resync_pending = false;
                                        opening_state.mark_viewport_seen();
                                        trace!(
                                            lane = "viewport",
                                            generation,
                                            covers_live_seq,
                                            resize_id,
                                            cols,
                                            rows,
                                            bytes = bytes.len(),
                                            "render attach v2 viewport snapshot"
                                        );
                                        if let Err(err) = write_tracked_output(display, AttachOutputStream::Stdout, &bytes, mode_tracker).await {
                                            break AttachEnd::Disconnected(err);
                                        }
                                        let queued_live = finish_reload_after_viewport(
                                            &reload_state,
                                            covers_live_seq,
                                            bytes,
                                        );
                                        let mut queued_live_end = None;
                                        for live in queued_live {
                                            if live.start_seq > covered_live_seq {
                                                let _ = display
                                                    .set_bar("▌ Portl › resyncing after reload live sequence gap".to_owned())
                                                    .await;
                                                resync_pending = true;
                                                if let Err(err) = coordinator.request_viewport("reload_live_seq_gap").await {
                                                    queued_live_end =
                                                        Some(AttachEnd::Disconnected(err));
                                                    break;
                                                }
                                                break;
                                            }
                                            covered_live_seq = live.end_seq;
                                            trace!(
                                                lane = "live",
                                                start_seq = live.start_seq,
                                                end_seq = live.end_seq,
                                                bytes = live.bytes.len(),
                                                "render queued attach v2 live output after reload"
                                            );
                                            if let Err(err) = write_tracked_output(display, AttachOutputStream::Stdout, &live.bytes, mode_tracker).await {
                                                queued_live_end =
                                                    Some(AttachEnd::Disconnected(err));
                                                break;
                                            }
                                        }
                                        if let Some(end) = queued_live_end {
                                            break end;
                                        }
                                        let _ = display.clear_bar().await;
                                    }
                                    Err(err) => break AttachEnd::Disconnected(err),
                                }
                            }
                            AttachV2ViewportDecision::DeferForReload => {
                                debug!(
                                    generation,
                                    resize_id,
                                    cols,
                                    rows,
                                    reload_state = ?reload_state.lock().map(|state| state.state()).ok(),
                                    "ignored attach v2 viewport snapshot while reload is loading"
                                );
                            }
                            AttachV2ViewportDecision::Stale => {
                                if generation > last_viewport_generation {
                                    opening_state.mark_viewport_barrier_seen();
                                    debug!(
                                        generation,
                                        resize_id,
                                        cols,
                                        rows,
                                        current_resize = ?current_resize_state(&resize_state),
                                        "ignored stale attach v2 viewport snapshot"
                                    );
                                }
                            }
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        data_streams.close(AttachV2DataStream::Viewport);
                        debug!("attach v2 viewport stream ended; waiting for control terminal frame");
                    }
                    Err(err) => break AttachEnd::Disconnected(err),
                }
            }
            frame = read_attach_v2_frame(&mut history), if data_streams.history_open() => {
                match frame {
                    Ok(Some(AttachV2ServerFrame::PreludeChunk { attach_id: frame_attach_id, payload, .. })) if frame_attach_id == attach_id => {
                        if opening_state.should_render_prelude() {
                            match payload.decode(ATTACH_V2_MAX_DECODED_PAYLOAD) {
                                Ok(bytes) => {
                                    trace!(lane = "history", frame = "prelude", bytes = bytes.len(), "render attach v2 prelude");
                                    if let Err(err) = write_tracked_output(display, AttachOutputStream::Stdout, &bytes, mode_tracker).await {
                                        break AttachEnd::Disconnected(err);
                                    }
                                }
                                Err(err) => break AttachEnd::Disconnected(err),
                            }
                        } else {
                            debug!("ignored late attach v2 prelude after viewport snapshot");
                        }
                    }
                    Ok(Some(AttachV2ServerFrame::ReloadChunk { attach_id: frame_attach_id, reload_id, progress, payload, .. })) if frame_attach_id == attach_id => {
                        if let Err(err) = handle_attach_v2_reload_chunk_frame(
                            display,
                            &reload_state,
                            reload_id,
                            progress,
                            payload,
                        )
                        .await
                        {
                            break AttachEnd::Disconnected(err);
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        data_streams.close(AttachV2DataStream::History);
                        debug!("attach v2 history stream ended; waiting for control terminal frame");
                    }
                    Err(err) => break AttachEnd::Disconnected(err),
                }
            }
            frame = read_attach_v2_frame(&mut live), if data_streams.live_open() => {
                match frame {
                    Ok(Some(AttachV2ServerFrame::LiveOutput { attach_id: frame_attach_id, start_seq, end_seq, payload, .. })) if frame_attach_id == attach_id && !resync_pending && end_seq > covered_live_seq => {
                        if active_reload_id(&reload_state).is_some() {
                            match payload.decode(ATTACH_V2_MAX_DECODED_PAYLOAD) {
                                Ok(bytes) => {
                                    if let Ok(mut coordinator) = reload_state.lock() {
                                        let _ = coordinator.handle_live_output(start_seq, end_seq, bytes);
                                    }
                                }
                                Err(err) => break AttachEnd::Disconnected(err),
                            }
                            continue;
                        }
                        if start_seq > covered_live_seq {
                            let _ = display
                                .set_bar("▌ Portl › resyncing after live sequence gap".to_owned())
                                .await;
                            resync_pending = true;
                            if let Err(err) = coordinator.request_viewport("live_seq_gap").await {
                                break AttachEnd::Disconnected(err);
                            }
                            continue;
                        }
                        match payload.decode(ATTACH_V2_MAX_DECODED_PAYLOAD) {
                            Ok(bytes) => {
                                let skip = usize::try_from(covered_live_seq.saturating_sub(start_seq))
                                    .unwrap_or(usize::MAX);
                                let skipped = skip.min(bytes.len());
                                let bytes = &bytes[skipped..];
                                trace!(
                                    lane = "live",
                                    start_seq,
                                    end_seq,
                                    covered_live_seq,
                                    skipped,
                                    bytes = bytes.len(),
                                    "render attach v2 live output"
                                );
                                covered_live_seq = end_seq;
                                if let Err(err) = write_tracked_output(display, AttachOutputStream::Stdout, bytes, mode_tracker).await {
                                    break AttachEnd::Disconnected(err);
                                }
                            }
                            Err(err) => break AttachEnd::Disconnected(err),
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        data_streams.close(AttachV2DataStream::Live);
                        debug!("attach v2 live stream ended; waiting for control terminal frame");
                    }
                    Err(err) => break AttachEnd::Disconnected(err),
                }
            }
            event = coordinator.next_event() => {
                break match event {
                    Some(AttachInputEvent::Detached | AttachInputEvent::Closed) => AttachEnd::Detached,
                    Some(AttachInputEvent::QuitReconnect) => AttachEnd::QuitReconnect,
                    Some(AttachInputEvent::SinkFailed(err)) => AttachEnd::Disconnected(err),
                    Some(AttachInputEvent::RetryNow | AttachInputEvent::BufferFull) => continue,
                    None => AttachEnd::Disconnected(anyhow!("attach input coordinator stopped")),
                };
            }
            signal = signal_watcher.next() => break AttachEnd::Signal(signal),
        }
    };
    let _ = coordinator.clear_sink().await;
    end
}

async fn read_attach_v2_frame(recv: &mut BufferedRecv) -> Result<Option<AttachV2ServerFrame>> {
    recv.read_frame::<AttachV2ServerFrame>(ATTACH_V2_MAX_DECODED_PAYLOAD)
        .await
}

fn active_reload_id(reload_state: &Arc<StdMutex<ReloadCoordinator>>) -> Option<u64> {
    reload_state
        .lock()
        .map_or(None, |state| state.active_reload_id())
}

fn cancellable_reload_id(reload_state: &Arc<StdMutex<ReloadCoordinator>>) -> Option<u64> {
    reload_state
        .lock()
        .map_or(None, |state| state.cancellable_reload_id())
}

fn active_reload_accepts_chunk(
    reload_state: &Arc<StdMutex<ReloadCoordinator>>,
    reload_id: u64,
) -> bool {
    reload_state
        .lock()
        .is_ok_and(|state| state.accepts_chunk(reload_id))
}

async fn handle_attach_v2_reload_chunk_frame(
    display: &AttachDisplay,
    reload_state: &Arc<StdMutex<ReloadCoordinator>>,
    reload_id: u64,
    progress: AttachV2Progress,
    payload: AttachV2Payload,
) -> Result<()> {
    if !active_reload_accepts_chunk(reload_state, reload_id) {
        return Ok(());
    }
    let text = if let Some(total) = progress.total_bytes {
        format!(
            "▌ Portl › reloading {} / {} bytes · Esc cancel",
            progress.loaded_bytes, total
        )
    } else {
        format!(
            "▌ Portl › reloading {} bytes · Esc cancel",
            progress.loaded_bytes
        )
    };
    let _ = display.set_bar(text).await;
    let bytes = payload.decode(ATTACH_V2_MAX_DECODED_PAYLOAD)?;
    trace!(
        lane = "history",
        frame = "reload_chunk",
        reload_id,
        bytes = bytes.len(),
        complete = progress.complete,
        "suppress attach v2 reload chunk until viewport snapshot"
    );
    Ok(())
}

fn start_active_reload(reload_state: &Arc<StdMutex<ReloadCoordinator>>, reload_id: u64) {
    if let Ok(mut state) = reload_state.lock() {
        state.start(reload_id);
    }
}

fn mark_reload_done(reload_state: &Arc<StdMutex<ReloadCoordinator>>, reload_id: u64) -> bool {
    reload_state
        .lock()
        .is_ok_and(|mut state| state.mark_done(reload_id))
}

fn mark_reload_cancelled(reload_state: &Arc<StdMutex<ReloadCoordinator>>, reload_id: u64) -> bool {
    reload_state
        .lock()
        .is_ok_and(|mut state| state.mark_cancelled(reload_id))
}

fn finish_reload_after_viewport(
    reload_state: &Arc<StdMutex<ReloadCoordinator>>,
    covers_live_seq: u64,
    bytes: Vec<u8>,
) -> Vec<QueuedLiveOutput> {
    reload_state
        .lock()
        .map(|mut state| {
            state.record_post_reload_viewport(covers_live_seq, bytes);
            state.drain_queued_live(covers_live_seq)
        })
        .unwrap_or_default()
}

#[derive(Debug, Default)]
struct AttachV2OpeningState {
    viewport_seen: bool,
}

impl AttachV2OpeningState {
    fn should_render_prelude(&self) -> bool {
        !self.viewport_seen
    }

    fn mark_viewport_seen(&mut self) {
        self.viewport_seen = true;
    }

    fn mark_viewport_barrier_seen(&mut self) {
        self.viewport_seen = true;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedLiveOutput {
    start_seq: u64,
    end_seq: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostReloadViewport {
    covers_live_seq: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadLiveDecision {
    Render,
    Queued,
}

#[derive(Debug, Default)]
struct ReloadCoordinator {
    state: AttachV2ReloadState,
    queued_live: VecDeque<QueuedLiveOutput>,
    post_reload_viewport: Option<PostReloadViewport>,
}

impl ReloadCoordinator {
    fn state(&self) -> AttachV2ReloadState {
        self.state
    }

    fn start(&mut self, reload_id: u64) {
        if self.active_reload_id() == Some(reload_id) {
            return;
        }
        self.state.start(reload_id);
        self.queued_live.clear();
        self.post_reload_viewport = None;
    }

    fn active_reload_id(&self) -> Option<u64> {
        self.state.active_reload_id()
    }

    fn cancellable_reload_id(&self) -> Option<u64> {
        self.state.cancellable_reload_id()
    }

    fn accepts_chunk(&self, reload_id: u64) -> bool {
        self.state.accepts_chunk(reload_id)
    }

    fn mark_done(&mut self, reload_id: u64) -> bool {
        self.state.mark_done(reload_id)
    }

    fn mark_cancelled(&mut self, reload_id: u64) -> bool {
        self.queued_live.clear();
        self.state.mark_cancelled(reload_id)
    }

    fn is_reloading(&self) -> bool {
        self.active_reload_id().is_some()
    }

    fn handle_live_output(
        &mut self,
        start_seq: u64,
        end_seq: u64,
        bytes: Vec<u8>,
    ) -> ReloadLiveDecision {
        if !self.is_reloading() {
            return ReloadLiveDecision::Render;
        }
        self.queued_live.push_back(QueuedLiveOutput {
            start_seq,
            end_seq,
            bytes,
        });
        ReloadLiveDecision::Queued
    }

    fn record_post_reload_viewport(&mut self, covers_live_seq: u64, bytes: Vec<u8>) {
        if matches!(self.state, AttachV2ReloadState::AwaitingViewport { .. }) {
            self.post_reload_viewport = Some(PostReloadViewport {
                covers_live_seq,
                bytes,
            });
        }
    }

    fn drain_queued_live(&mut self, covered_live_seq: u64) -> Vec<QueuedLiveOutput> {
        let mut covered = self
            .post_reload_viewport
            .as_ref()
            .map_or(covered_live_seq, |viewport| {
                let _ = viewport.bytes.len();
                covered_live_seq.max(viewport.covers_live_seq)
            });
        let mut drained = Vec::new();
        while let Some(mut live) = self.queued_live.pop_front() {
            if live.end_seq <= covered {
                continue;
            }
            if live.start_seq < covered {
                let skip = usize::try_from(covered.saturating_sub(live.start_seq))
                    .unwrap_or(usize::MAX)
                    .min(live.bytes.len());
                live.bytes = live.bytes[skip..].to_vec();
                live.start_seq = covered;
            }
            covered = live.end_seq;
            if !live.bytes.is_empty() {
                drained.push(live);
            }
        }
        let _ = self.state.clear_after_viewport();
        drained
    }

    #[cfg(test)]
    fn queued_live_len(&self) -> usize {
        self.queued_live.len()
    }

    #[cfg(test)]
    fn post_reload_viewport_len(&self) -> Option<usize> {
        self.post_reload_viewport
            .as_ref()
            .map(|viewport| viewport.bytes.len())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum AttachV2ReloadState {
    #[default]
    Idle,
    Loading {
        reload_id: u64,
    },
    AwaitingViewport {
        reload_id: u64,
    },
}

impl AttachV2ReloadState {
    fn start(&mut self, reload_id: u64) {
        *self = Self::Loading { reload_id };
    }

    fn active_reload_id(&self) -> Option<u64> {
        match self {
            Self::Idle => None,
            Self::Loading { reload_id } | Self::AwaitingViewport { reload_id } => Some(*reload_id),
        }
    }

    fn cancellable_reload_id(&self) -> Option<u64> {
        match self {
            Self::Loading { reload_id } => Some(*reload_id),
            Self::Idle | Self::AwaitingViewport { .. } => None,
        }
    }

    fn accepts_chunk(&self, reload_id: u64) -> bool {
        matches!(self, Self::Loading { reload_id: active } if *active == reload_id)
    }

    fn mark_done(&mut self, reload_id: u64) -> bool {
        match self {
            Self::Loading { reload_id: active } if *active == reload_id => {
                *self = Self::AwaitingViewport { reload_id };
                true
            }
            Self::AwaitingViewport { reload_id: active } if *active == reload_id => true,
            Self::Idle | Self::Loading { .. } | Self::AwaitingViewport { .. } => false,
        }
    }

    fn mark_cancelled(&mut self, reload_id: u64) -> bool {
        match self {
            Self::Loading { reload_id: active } | Self::AwaitingViewport { reload_id: active }
                if *active == reload_id =>
            {
                // The agent always follows ReloadCancelled with a viewport request;
                // keep live output suppressed until that final barrier is applied.
                *self = Self::AwaitingViewport { reload_id };
                true
            }
            Self::Idle | Self::Loading { .. } | Self::AwaitingViewport { .. } => false,
        }
    }

    fn clear_after_viewport(&mut self) -> bool {
        if matches!(self, Self::AwaitingViewport { .. }) {
            *self = Self::Idle;
            true
        } else {
            false
        }
    }

    fn allows_viewport_render(&self) -> bool {
        !matches!(self, Self::Loading { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachV2DataStream {
    Viewport,
    History,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AttachV2DataStreamStatus {
    viewport_open: bool,
    history_open: bool,
    live_open: bool,
}

impl Default for AttachV2DataStreamStatus {
    fn default() -> Self {
        Self {
            viewport_open: true,
            history_open: true,
            live_open: true,
        }
    }
}

impl AttachV2DataStreamStatus {
    fn close(&mut self, stream: AttachV2DataStream) {
        match stream {
            AttachV2DataStream::Viewport => self.viewport_open = false,
            AttachV2DataStream::History => self.history_open = false,
            AttachV2DataStream::Live => self.live_open = false,
        }
    }

    fn viewport_open(self) -> bool {
        self.viewport_open
    }

    fn history_open(self) -> bool {
        self.history_open
    }

    fn live_open(self) -> bool {
        self.live_open
    }

    #[cfg(test)]
    fn data_eof_requires_disconnect(self) -> bool {
        if !self.viewport_open && !self.history_open && !self.live_open {
            return false;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AttachV2ResizeState {
    resize_id: u64,
    cols: u16,
    rows: u16,
}

fn current_resize_state(resize_state: &Arc<StdMutex<AttachV2ResizeState>>) -> AttachV2ResizeState {
    resize_state.lock().map_or(
        AttachV2ResizeState {
            resize_id: 0,
            cols: 80,
            rows: 24,
        },
        |state| *state,
    )
}

fn attach_v2_viewport_matches_resize_state(
    resize_id: u64,
    cols: u16,
    rows: u16,
    current: AttachV2ResizeState,
) -> bool {
    resize_id == current.resize_id && cols == current.cols && rows == current.rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachV2ViewportDecision {
    Render,
    DeferForReload,
    Stale,
}

fn attach_v2_viewport_decision(
    generation: u64,
    last_viewport_generation: u64,
    resize_id: u64,
    cols: u16,
    rows: u16,
    current_resize: AttachV2ResizeState,
    reload_state: AttachV2ReloadState,
) -> AttachV2ViewportDecision {
    if generation <= last_viewport_generation
        || !attach_v2_viewport_matches_resize_state(resize_id, cols, rows, current_resize)
    {
        return AttachV2ViewportDecision::Stale;
    }
    if !reload_state.allows_viewport_render() {
        return AttachV2ViewportDecision::DeferForReload;
    }
    AttachV2ViewportDecision::Render
}

fn attach_v2_frame_matches(frame: &AttachV2ServerFrame, attach_id: [u8; 16]) -> bool {
    match frame {
        AttachV2ServerFrame::AttachReady {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::PreludeChunk {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::ViewportSnapshot {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::LiveOutput {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::ReloadStarted {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::ReloadChunk {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::ReloadDone {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::ReloadCancelled {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::BackpressureNotice {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::ResyncRequired {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::Heartbeat {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::Exit {
            attach_id: frame_attach_id,
            ..
        }
        | AttachV2ServerFrame::Error {
            attach_id: frame_attach_id,
            ..
        } => *frame_attach_id == attach_id,
    }
}

async fn handle_attach_v2_control_frame(
    frame: AttachV2ServerFrame,
    display: &AttachDisplay,
    reload_state: &Arc<StdMutex<ReloadCoordinator>>,
    resync_pending: &mut bool,
    mode_tracker: &SharedTerminalModeTracker,
) -> Result<Option<AttachEnd>> {
    match frame {
        AttachV2ServerFrame::ReloadStarted {
            reload_id,
            total_bytes,
            ..
        } => {
            start_active_reload(reload_state, reload_id);
            write_tracked_output(
                display,
                AttachOutputStream::Stdout,
                b"\x1b[0m",
                mode_tracker,
            )
            .await?;
            let text = total_bytes.map_or_else(
                || "▌ Portl › reloading · Esc cancel".to_owned(),
                |total| format!("▌ Portl › reloading 0 / {total} bytes · Esc cancel"),
            );
            display.set_bar(text).await?;
            Ok(None)
        }
        AttachV2ServerFrame::ReloadDone { reload_id, .. } => {
            if mark_reload_done(reload_state, reload_id) {
                write_tracked_output(
                    display,
                    AttachOutputStream::Stdout,
                    b"\x1b[0m",
                    mode_tracker,
                )
                .await?;
                display
                    .set_bar("▌ Portl › reload complete · refreshing viewport".to_owned())
                    .await?;
            }
            Ok(None)
        }
        AttachV2ServerFrame::ReloadCancelled { reload_id, .. } => {
            if mark_reload_cancelled(reload_state, reload_id) {
                *resync_pending = true;
                display
                    .set_bar("▌ Portl › reload cancelled · refreshing viewport".to_owned())
                    .await?;
            }
            Ok(None)
        }
        AttachV2ServerFrame::BackpressureNotice { reason, .. }
        | AttachV2ServerFrame::ResyncRequired { reason, .. } => {
            *resync_pending = true;
            display
                .set_bar(format!("▌ Portl › resyncing after {reason}"))
                .await?;
            Ok(None)
        }
        AttachV2ServerFrame::Exit { code, .. } => Ok(Some(AttachEnd::Exited(code))),
        AttachV2ServerFrame::Error { message, .. } => {
            Ok(Some(AttachEnd::Disconnected(anyhow!(message))))
        }
        AttachV2ServerFrame::Heartbeat { .. }
        | AttachV2ServerFrame::AttachReady { .. }
        | AttachV2ServerFrame::PreludeChunk { .. }
        | AttachV2ServerFrame::ViewportSnapshot { .. }
        | AttachV2ServerFrame::LiveOutput { .. }
        | AttachV2ServerFrame::ReloadChunk { .. } => Ok(None),
    }
}

async fn output_task_end_to_attach_end(
    output: Result<()>,
    stream_name: &str,
    exit_fut: &mut std::pin::Pin<Box<impl Future<Output = Result<i32>> + '_>>,
) -> AttachEnd {
    match tokio::time::timeout(Duration::from_secs(2), exit_fut).await {
        Ok(Ok(code)) => AttachEnd::Exited(code),
        Ok(Err(err)) => AttachEnd::Disconnected(err),
        Err(_) => match output {
            Ok(()) => {
                AttachEnd::Disconnected(anyhow!("{stream_name} stream ended before exit frame"))
            }
            Err(err) => AttachEnd::Disconnected(err),
        },
    }
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
    signal_watcher: &mut AttachSignalWatcher,
) -> Result<AttachCompletion> {
    let mut exit_fut = Box::pin(child.wait());
    let Some(mut stdin_task) = stdin_task else {
        return tokio::select! {
            status = &mut exit_fut => Ok(AttachCompletion::Exited(status.context("wait for local provider exit")?.code().unwrap_or(1))),
            signal = signal_watcher.next() => Ok(AttachCompletion::Signal(signal)),
        };
    };

    tokio::select! {
        status = &mut exit_fut => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok(AttachCompletion::Exited(status.context("wait for local provider exit")?.code().unwrap_or(1)))
        }
        stdin_result = &mut stdin_task => {
            match stdin_result.context("join stdin task")?? {
                StdinTaskResult::Detached => Ok(AttachCompletion::Detached),
                StdinTaskResult::Closed => {
                    tokio::select! {
                        status = &mut exit_fut => Ok(AttachCompletion::Exited(status.context("wait for local provider exit")?.code().unwrap_or(1))),
                        signal = signal_watcher.next() => Ok(AttachCompletion::Signal(signal)),
                    }
                }
            }
        }
        signal = signal_watcher.next() => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok(AttachCompletion::Signal(signal))
        }
    }
}

#[cfg(feature = "ghostty-vt")]
async fn wait_ghostty_attach_completion(
    exit: &mut tokio::sync::watch::Receiver<Option<i32>>,
    stdin_task: Option<tokio::task::JoinHandle<Result<StdinTaskResult>>>,
    signal_watcher: &mut AttachSignalWatcher,
) -> Result<AttachCompletion> {
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
        return tokio::select! {
            code = &mut exit_fut => Ok(AttachCompletion::Exited(code?)),
            signal = signal_watcher.next() => Ok(AttachCompletion::Signal(signal)),
        };
    };

    tokio::select! {
        code = &mut exit_fut => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok(AttachCompletion::Exited(code?))
        }
        stdin_result = &mut stdin_task => {
            match stdin_result.context("join stdin task")?? {
                StdinTaskResult::Detached => Ok(AttachCompletion::Detached),
                StdinTaskResult::Closed => {
                    tokio::select! {
                        code = &mut exit_fut => Ok(AttachCompletion::Exited(code?)),
                        signal = signal_watcher.next() => Ok(AttachCompletion::Signal(signal)),
                    }
                }
            }
        }
        signal = signal_watcher.next() => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok(AttachCompletion::Signal(signal))
        }
    }
}

async fn wait_attach_completion(
    exit: &mut BufferedRecv,
    stdin_task: Option<tokio::task::JoinHandle<Result<StdinTaskResult>>>,
    signal_watcher: &mut AttachSignalWatcher,
) -> Result<AttachCompletion> {
    let mut exit_fut = Box::pin(read_exit(exit));
    let Some(mut stdin_task) = stdin_task else {
        return tokio::select! {
            code = &mut exit_fut => Ok(AttachCompletion::Exited(code?)),
            signal = signal_watcher.next() => Ok(AttachCompletion::Signal(signal)),
        };
    };

    tokio::select! {
        code = &mut exit_fut => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok(AttachCompletion::Exited(code?))
        }
        stdin_result = &mut stdin_task => {
            match stdin_result.context("join stdin task")?? {
                StdinTaskResult::Detached => Ok(AttachCompletion::Detached),
                StdinTaskResult::Closed => Ok(AttachCompletion::Exited(exit_fut.await?)),
            }
        }
        signal = signal_watcher.next() => {
            stdin_task.abort();
            let _ = stdin_task.await;
            Ok(AttachCompletion::Signal(signal))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachCompletion {
    Exited(i32),
    Detached,
    Signal(RawModeExitVariant),
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

pub(crate) struct RawModeGuard {
    cleanup: RawModeCleanupWriter,
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

static PANIC_HOOK_ARMED: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();
static PREVIOUS_PANIC_HOOK: OnceLock<PanicHook> = OnceLock::new();

const DEFERRED_DEFENSIVE_KITTY_RESET_WINDOW_BYTES: usize = 256;
// A 100 ms idle fallback keeps Symptom-2 recovery bounded for silent guests
// while preserving a short window for a split Kitty pop to arrive.
const DEFERRED_DEFENSIVE_KITTY_RESET_IDLE: Duration = Duration::from_millis(100);

struct HostBoundModeTracker {
    tracker: TerminalModeTracker,
    stdout_sanitizer: HostOutputSanitizer,
    stderr_sanitizer: HostOutputSanitizer,
    deferred_alt_screen_kitty_reset: bool,
    deferred_bytes_seen: usize,
}

impl HostBoundModeTracker {
    fn new() -> Self {
        Self {
            tracker: TerminalModeTracker::new(),
            stdout_sanitizer: HostOutputSanitizer::new(),
            stderr_sanitizer: HostOutputSanitizer::new(),
            deferred_alt_screen_kitty_reset: false,
            deferred_bytes_seen: 0,
        }
    }

    #[cfg(test)]
    fn state(&self) -> TerminalModeState {
        self.tracker.state()
    }

    fn track(&mut self, bytes: &[u8]) -> Vec<u8> {
        let pending_at_start = self.deferred_alt_screen_kitty_reset
            || self.tracker.has_pending_alt_screen_leave_kitty_reset();
        if !pending_at_start {
            self.tracker.feed(bytes);
            if self.tracker.has_pending_alt_screen_leave_kitty_reset() {
                self.deferred_alt_screen_kitty_reset = true;
                self.deferred_bytes_seen = 0;
            }
            return Vec::new();
        }

        for (index, &byte) in bytes.iter().enumerate() {
            self.tracker.feed(&[byte]);
            if !self.tracker.has_pending_alt_screen_leave_kitty_reset() {
                self.deferred_alt_screen_kitty_reset = false;
                self.deferred_bytes_seen = 0;
                self.tracker.feed(&bytes[index + 1..]);
                if self.tracker.has_pending_alt_screen_leave_kitty_reset() {
                    self.deferred_alt_screen_kitty_reset = true;
                    self.deferred_bytes_seen = 0;
                }
                return Vec::new();
            }
            self.deferred_bytes_seen = self.deferred_bytes_seen.saturating_add(1);
            if self.deferred_bytes_seen >= DEFERRED_DEFENSIVE_KITTY_RESET_WINDOW_BYTES {
                let reset = self.take_deferred_reset();
                self.tracker.feed(&bytes[index + 1..]);
                if self.tracker.has_pending_alt_screen_leave_kitty_reset() {
                    self.deferred_alt_screen_kitty_reset = true;
                    self.deferred_bytes_seen = 0;
                }
                return reset;
            }
        }

        // Defer across the leave chunk so a clean Kitty pop split into the next
        // transport read can suppress the defensive reset, but do not wait for
        // an unbounded stream: if a following chunk/frame contains no pop in the
        // small byte window above, flush the Symptom-2 reset.
        self.take_deferred_reset()
    }

    fn flush_deferred_reset(&mut self) -> Vec<u8> {
        if self.deferred_alt_screen_kitty_reset
            && self.tracker.has_pending_alt_screen_leave_kitty_reset()
        {
            return self.take_deferred_reset();
        }
        Vec::new()
    }

    fn take_deferred_reset(&mut self) -> Vec<u8> {
        self.deferred_alt_screen_kitty_reset = false;
        self.deferred_bytes_seen = 0;
        self.tracker.take_alt_screen_leave_kitty_reset()
    }

    fn sanitize(&mut self, stream: AttachOutputStream, bytes: &[u8]) -> Vec<u8> {
        self.sanitizer_for(stream).feed(bytes)
    }

    fn finish_sanitizer(&mut self, stream: AttachOutputStream) -> Vec<u8> {
        self.sanitizer_for(stream).finish()
    }

    fn sanitizer_for(&mut self, stream: AttachOutputStream) -> &mut HostOutputSanitizer {
        match stream {
            AttachOutputStream::Stdout => &mut self.stdout_sanitizer,
            AttachOutputStream::Stderr => &mut self.stderr_sanitizer,
        }
    }
}

const HOST_OUTPUT_SANITIZER_BUFFER_CAPACITY: usize = 128;

#[derive(Debug)]
struct HostOutputSanitizer {
    state: HostOutputSanitizerState,
    buffer: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostOutputSanitizerState {
    Ground,
    Escape,
    Csi,
}

impl HostOutputSanitizer {
    fn new() -> Self {
        Self {
            state: HostOutputSanitizerState::Ground,
            buffer: Vec::with_capacity(HOST_OUTPUT_SANITIZER_BUFFER_CAPACITY),
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            self.feed_byte(byte, &mut output);
        }
        output
    }

    fn finish(&mut self) -> Vec<u8> {
        self.state = HostOutputSanitizerState::Ground;
        std::mem::take(&mut self.buffer)
    }

    fn feed_byte(&mut self, byte: u8, output: &mut Vec<u8>) {
        match self.state {
            HostOutputSanitizerState::Ground => {
                if byte == 0x1b {
                    self.buffer.push(byte);
                    self.state = HostOutputSanitizerState::Escape;
                } else {
                    output.push(byte);
                }
            }
            HostOutputSanitizerState::Escape => match byte {
                b'[' => {
                    self.buffer.push(byte);
                    self.state = HostOutputSanitizerState::Csi;
                }
                0x1b => {
                    output.extend_from_slice(&self.buffer);
                    self.buffer.clear();
                    self.buffer.push(byte);
                }
                _ => {
                    output.extend_from_slice(&self.buffer);
                    self.buffer.clear();
                    output.push(byte);
                    self.state = HostOutputSanitizerState::Ground;
                }
            },
            HostOutputSanitizerState::Csi => {
                if byte == 0x1b {
                    output.extend_from_slice(&self.buffer);
                    self.buffer.clear();
                    self.buffer.push(byte);
                    self.state = HostOutputSanitizerState::Escape;
                    return;
                }

                self.buffer.push(byte);
                if self.buffer.len() > HOST_OUTPUT_SANITIZER_BUFFER_CAPACITY {
                    output.extend_from_slice(&self.buffer);
                    self.buffer.clear();
                    self.state = HostOutputSanitizerState::Ground;
                    return;
                }

                if (0x40..=0x7e).contains(&byte) {
                    if !host_output_is_stripped_response_or_query(&self.buffer) {
                        output.extend_from_slice(&self.buffer);
                    }
                    self.buffer.clear();
                    self.state = HostOutputSanitizerState::Ground;
                }
            }
        }
    }
}

fn host_output_is_stripped_response_or_query(csi: &[u8]) -> bool {
    let Some((&final_byte, body_with_intro)) = csi.split_last() else {
        return false;
    };
    let Some(params) = body_with_intro.strip_prefix(b"\x1b[") else {
        return false;
    };

    if host_output_is_stripped_query(params, final_byte) {
        return true;
    }

    match (params.first().copied(), final_byte) {
        (Some(b'?'), b'u') => host_output_params_match(&params[1..], b";:", true),
        (Some(b'?' | b'>'), b'c') | (Some(b'?'), b'R') => {
            host_output_params_match(&params[1..], b";", true)
        }
        (_, b'R') => host_output_params_match(params, b";", true),
        _ => false,
    }
}

fn host_output_is_stripped_query(params: &[u8], final_byte: u8) -> bool {
    match (params, final_byte) {
        (b"" | b">", b'c') | (b"6", b'n') | (b"?" | b"<", b'u') => true,
        ([b'>' | b'=', rest @ ..], b'u') => {
            !rest.is_empty()
                && rest
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || *byte == b';')
        }
        _ => false,
    }
}

fn host_output_params_match(params: &[u8], separators: &[u8], require_digit: bool) -> bool {
    let mut saw_digit = false;
    for &byte in params {
        match byte {
            b'0'..=b'9' => saw_digit = true,
            other if separators.contains(&other) => {}
            _ => return false,
        }
    }
    !require_digit || saw_digit
}

type SharedTerminalModeTracker = Arc<StdMutex<HostBoundModeTracker>>;

fn new_terminal_mode_tracker() -> SharedTerminalModeTracker {
    Arc::new(StdMutex::new(HostBoundModeTracker::new()))
}

fn track_host_bound_bytes(tracker: &SharedTerminalModeTracker, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut tracker = tracker
        .lock()
        .map_err(|_| anyhow!("terminal mode tracker lock poisoned"))?;
    Ok(tracker.track(bytes))
}

fn sanitize_host_bound_bytes(
    tracker: &SharedTerminalModeTracker,
    stream: AttachOutputStream,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let mut tracker = tracker
        .lock()
        .map_err(|_| anyhow!("terminal mode tracker lock poisoned"))?;
    Ok(tracker.sanitize(stream, bytes))
}

fn finish_host_output_sanitizer(
    tracker: &SharedTerminalModeTracker,
    stream: AttachOutputStream,
) -> Result<Vec<u8>> {
    let mut tracker = tracker
        .lock()
        .map_err(|_| anyhow!("terminal mode tracker lock poisoned"))?;
    Ok(tracker.finish_sanitizer(stream))
}

fn flush_host_bound_mode_tracker(tracker: &SharedTerminalModeTracker) -> Result<Vec<u8>> {
    let mut tracker = tracker
        .lock()
        .map_err(|_| anyhow!("terminal mode tracker lock poisoned"))?;
    Ok(tracker.flush_deferred_reset())
}

fn host_bound_mode_tracker_has_deferred_reset(tracker: &SharedTerminalModeTracker) -> Result<bool> {
    let tracker = tracker
        .lock()
        .map_err(|_| anyhow!("terminal mode tracker lock poisoned"))?;
    Ok(tracker.deferred_alt_screen_kitty_reset
        && tracker.tracker.has_pending_alt_screen_leave_kitty_reset())
}

#[cfg(test)]
fn tracked_terminal_mode_state(tracker: &SharedTerminalModeTracker) -> TerminalModeState {
    tracker.lock().expect("terminal mode tracker lock").state()
}

async fn write_tracked_output(
    display: &AttachDisplay,
    stream: AttachOutputStream,
    bytes: &[u8],
    tracker: &SharedTerminalModeTracker,
) -> Result<()> {
    let defensive_reset = track_host_bound_bytes(tracker, bytes)?;
    let sanitized = sanitize_host_bound_bytes(tracker, stream, bytes)?;
    if !sanitized.is_empty() {
        display.write_output(stream, &sanitized).await?;
    }
    if !defensive_reset.is_empty() {
        display.write_output(stream, &defensive_reset).await?;
    } else if host_bound_mode_tracker_has_deferred_reset(tracker)? {
        schedule_deferred_mode_reset_flush(display.clone(), stream, Arc::clone(tracker));
    }
    Ok(())
}

fn schedule_deferred_mode_reset_flush(
    display: AttachDisplay,
    stream: AttachOutputStream,
    tracker: SharedTerminalModeTracker,
) {
    tokio::spawn(async move {
        tokio::time::sleep(DEFERRED_DEFENSIVE_KITTY_RESET_IDLE).await;
        if let Err(err) = flush_deferred_mode_reset_output(&display, stream, &tracker).await {
            debug!(error = %err, "failed to flush deferred terminal mode reset");
        }
    });
}

async fn flush_deferred_mode_reset_output(
    display: &AttachDisplay,
    stream: AttachOutputStream,
    tracker: &SharedTerminalModeTracker,
) -> Result<()> {
    let defensive_reset = flush_host_bound_mode_tracker(tracker)?;
    if !defensive_reset.is_empty() {
        display.write_output(stream, &defensive_reset).await?;
    }
    display.flush(stream).await
}

async fn flush_tracked_output(
    display: &AttachDisplay,
    stream: AttachOutputStream,
    tracker: &SharedTerminalModeTracker,
) -> Result<()> {
    let sanitized = finish_host_output_sanitizer(tracker, stream)?;
    if !sanitized.is_empty() {
        display.write_output(stream, &sanitized).await?;
    }
    flush_deferred_mode_reset_output(display, stream, tracker).await
}

impl RawModeGuard {
    pub(crate) fn new() -> Result<Self> {
        enable_raw_mode().context("enable raw mode")?;
        set_panic_hook_armed(true);
        Ok(Self {
            cleanup: RawModeCleanupWriter::default(),
        })
    }

    pub(crate) fn finish(mut self, variant: RawModeExitVariant) {
        set_panic_hook_armed(false);
        let _ = disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = self.cleanup.write_to(&mut stdout, variant);
    }
}

fn finish_raw_guard(raw_guard: Option<RawModeGuard>, variant: RawModeExitVariant) {
    if let Some(raw_guard) = raw_guard {
        raw_guard.finish(variant);
    }
}

#[cfg(feature = "panic-inject-attach")]
fn maybe_panic_inject_attach() {
    if std::env::var_os("PORTL_PANIC_INJECT_ATTACH").is_some() {
        let _ = std::panic::catch_unwind(|| panic!("inject attach panic"));
        std::process::exit(101);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawModeExitVariant {
    Normal,
    ReconnectExhausted,
    Sighup,
    Sigterm,
    Sigint,
    Panic,
}

const _: [RawModeExitVariant; 6] = [
    RawModeExitVariant::Normal,
    RawModeExitVariant::ReconnectExhausted,
    RawModeExitVariant::Sighup,
    RawModeExitVariant::Sigterm,
    RawModeExitVariant::Sigint,
    RawModeExitVariant::Panic,
];

impl RawModeExitVariant {
    pub(crate) const fn is_emergency(self) -> bool {
        matches!(
            self,
            Self::Sighup | Self::Sigterm | Self::Sigint | Self::Panic
        )
    }
}

const RAW_MODE_CLEANUP_NORMAL: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\n";
const RAW_MODE_CLEANUP_EMERGENCY: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\n\x1bc";

pub(crate) fn raw_mode_cleanup_sequence(variant: RawModeExitVariant) -> &'static [u8] {
    if variant.is_emergency() {
        RAW_MODE_CLEANUP_EMERGENCY
    } else {
        RAW_MODE_CLEANUP_NORMAL
    }
}

pub(crate) fn install_panic_hook() {
    PANIC_HOOK_INSTALLED.get_or_init(|| {
        let previous = std::panic::take_hook();
        let _ = PREVIOUS_PANIC_HOOK.set(previous);
        std::panic::set_hook(Box::new(|info| {
            if PANIC_HOOK_ARMED.load(Ordering::SeqCst) {
                write_panic_cleanup_to_fd_if_armed(nix::libc::STDERR_FILENO);
            } else if let Some(previous) = PREVIOUS_PANIC_HOOK.get() {
                previous(info);
            }
        }));
    });
}

fn set_panic_hook_armed(armed: bool) {
    PANIC_HOOK_ARMED.store(armed, Ordering::SeqCst);
}

fn panic_hook_cleanup_bytes() -> &'static [u8] {
    raw_mode_cleanup_sequence(RawModeExitVariant::Panic)
}

#[allow(unsafe_code)]
fn write_panic_cleanup_to_fd_if_armed(fd: i32) {
    if !PANIC_HOOK_ARMED.load(Ordering::SeqCst) {
        return;
    }

    let cleanup = panic_hook_cleanup_bytes();
    let _ = unsafe { nix::libc::write(fd, cleanup.as_ptr().cast(), cleanup.len()) };
}

#[derive(Debug, Default)]
struct RawModeCleanupWriter {
    written: bool,
}

impl RawModeCleanupWriter {
    fn write_to<W: IoWrite>(
        &mut self,
        writer: &mut W,
        variant: RawModeExitVariant,
    ) -> std::io::Result<()> {
        if self.written {
            return Ok(());
        }
        self.written = true;
        writer.write_all(raw_mode_cleanup_sequence(variant))?;
        writer.flush()
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        set_panic_hook_armed(false);
        let _ = disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = self
            .cleanup
            .write_to(&mut stdout, RawModeExitVariant::Normal);
    }
}

#[cfg(unix)]
pub(crate) struct AttachSignalWatcher {
    sighup: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
    sigint: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl AttachSignalWatcher {
    pub(crate) fn new() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            sighup: signal(SignalKind::hangup()).context("install SIGHUP handler")?,
            sigterm: signal(SignalKind::terminate()).context("install SIGTERM handler")?,
            sigint: signal(SignalKind::interrupt()).context("install SIGINT handler")?,
        })
    }

    pub(crate) async fn next(&mut self) -> RawModeExitVariant {
        tokio::select! {
            _ = self.sighup.recv() => RawModeExitVariant::Sighup,
            _ = self.sigterm.recv() => RawModeExitVariant::Sigterm,
            _ = self.sigint.recv() => RawModeExitVariant::Sigint,
        }
    }
}

#[cfg(not(unix))]
pub(crate) struct AttachSignalWatcher;

#[cfg(not(unix))]
impl AttachSignalWatcher {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self)
    }

    pub(crate) async fn next(&mut self) -> RawModeExitVariant {
        std::future::pending().await
    }
}

#[derive(Debug, Clone, Copy)]
enum AttachOutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy)]
struct ReconnectPolicy {
    base_delay: Duration,
    max_delay: Duration,
    max_elapsed: Duration,
    delay_floor: Duration,
    transparent_grace: Duration,
}

impl ReconnectPolicy {
    fn default_interactive() -> Self {
        Self {
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            max_elapsed: Duration::from_mins(2),
            delay_floor: Duration::from_millis(100),
            transparent_grace: Duration::from_millis(1500),
        }
    }

    #[cfg(test)]
    fn for_test(
        base_delay: Duration,
        max_delay: Duration,
        max_elapsed: Duration,
        delay_floor: Duration,
    ) -> Self {
        Self {
            base_delay,
            max_delay,
            max_elapsed,
            delay_floor,
            transparent_grace: Duration::from_millis(1500),
        }
    }

    fn with_observed_rtt(mut self, rtt: Option<Duration>) -> Self {
        let Some(rtt) = rtt.filter(|rtt| !rtt.is_zero()) else {
            return self;
        };
        self.transparent_grace = self
            .transparent_grace
            .max(rtt.saturating_mul(8))
            .min(Duration::from_secs(4));
        self.delay_floor = self.delay_floor.max(rtt).min(Duration::from_secs(1));
        self
    }

    fn visible_delay(&self, attempt: u32, jitter: Duration) -> Duration {
        let multiplier = 1_u32
            .checked_shl(attempt.saturating_sub(1).min(16))
            .unwrap_or(1);
        let capped = self
            .base_delay
            .saturating_mul(multiplier)
            .min(self.max_delay);
        jitter.min(capped).max(self.delay_floor).min(self.max_delay)
    }

    fn retry_budget_remaining(&self, elapsed: Duration) -> bool {
        elapsed < self.max_elapsed
    }
}

#[cfg(feature = "test-reconnect-injection")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestReconnectScenario {
    SighupWait,
    Exhausted,
    Transient,
    SignalConnectAttempt,
}

#[cfg(feature = "test-reconnect-injection")]
fn test_reconnect_scenario() -> Result<Option<TestReconnectScenario>> {
    match std::env::var("PORTL_TEST_RECONNECT_SCENARIO") {
        Ok(value) => match value.as_str() {
            "sighup-wait" => Ok(Some(TestReconnectScenario::SighupWait)),
            "exhausted" => Ok(Some(TestReconnectScenario::Exhausted)),
            "transient" => Ok(Some(TestReconnectScenario::Transient)),
            "signal-connect-attempt" => Ok(Some(TestReconnectScenario::SignalConnectAttempt)),
            other => anyhow::bail!("unknown PORTL_TEST_RECONNECT_SCENARIO '{other}'"),
        },
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(err).context("read PORTL_TEST_RECONNECT_SCENARIO"),
    }
}

#[cfg(feature = "test-reconnect-injection")]
fn reconnect_policy_for_environment(mut policy: ReconnectPolicy) -> ReconnectPolicy {
    if test_reconnect_scenario().ok().flatten().is_some() {
        policy.base_delay = Duration::from_millis(25);
        policy.max_delay = Duration::from_millis(25);
        policy.max_elapsed = Duration::from_millis(90);
        policy.delay_floor = Duration::from_millis(25);
        policy.transparent_grace = Duration::ZERO;
    }
    policy
}

#[cfg(not(feature = "test-reconnect-injection"))]
fn reconnect_policy_for_environment(policy: ReconnectPolicy) -> ReconnectPolicy {
    policy
}

#[cfg(feature = "test-reconnect-injection")]
async fn write_reconnect_test_marker(display: &AttachDisplay, marker: &[u8]) -> Result<()> {
    display
        .write_output(AttachOutputStream::Stdout, marker)
        .await
        .context("write reconnect test marker")
}

#[cfg(feature = "test-reconnect-injection")]
async fn test_reconnect_block_connect_attempt(display: &AttachDisplay, attempt: u32) -> Result<()> {
    if matches!(
        test_reconnect_scenario()?,
        Some(TestReconnectScenario::SignalConnectAttempt)
    ) && attempt == 1
    {
        write_reconnect_test_marker(display, b"RECONNECT_CONNECT_ATTEMPT_READY\r\n").await?;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
    Ok(())
}

#[cfg(feature = "test-reconnect-injection")]
fn test_reconnect_forces_connect_failure(scenario: TestReconnectScenario, attempt: u32) -> bool {
    matches!(scenario, TestReconnectScenario::Exhausted)
        || (matches!(scenario, TestReconnectScenario::Transient) && attempt == 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconnectControl {
    RetryNow,
    Detach,
    Quit,
}

impl ReconnectControl {
    fn from_visible_input(input: &[u8]) -> Option<Self> {
        if input.contains(&0x03) {
            return Some(Self::Quit);
        }
        if input.contains(&b'\r') || input.contains(&b'\n') {
            return Some(Self::RetryNow);
        }
        (input == b"d").then_some(Self::Detach)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconnectBufferPush {
    Accepted,
    Full,
}

#[derive(Debug, Clone)]
struct ReconnectInputBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl ReconnectInputBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> ReconnectBufferPush {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if bytes.len() > remaining {
            self.bytes.extend_from_slice(&bytes[..remaining]);
            return ReconnectBufferPush::Full;
        }
        self.bytes.extend_from_slice(bytes);
        ReconnectBufferPush::Accepted
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn is_full(&self) -> bool {
        self.bytes.len() >= self.limit
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

fn session_exists_for_reconnect(
    groups: &[SessionProviderSessions],
    provider: &str,
    session_name: &str,
) -> bool {
    let lookup = if provider == "tmux" {
        session_name
            .split_once(':')
            .map_or(session_name, |(name, _)| name)
    } else {
        session_name
    };
    groups
        .iter()
        .filter(|group| group.available && group.provider == provider)
        .any(|group| group.sessions.iter().any(|session| session.name == lookup))
}

#[derive(Debug)]
enum AttachEnd {
    Exited(i32),
    Detached,
    QuitReconnect,
    Disconnected(anyhow::Error),
    Signal(RawModeExitVariant),
}

impl AttachEnd {
    fn raw_mode_exit_variant(&self) -> Option<RawModeExitVariant> {
        match self {
            Self::Signal(variant) => Some(*variant),
            Self::Exited(_) | Self::Detached | Self::QuitReconnect | Self::Disconnected(_) => None,
        }
    }

    #[cfg(test)]
    fn exit_code(&self) -> Option<ExitCode> {
        match self {
            Self::Exited(code) => Some(exit_code_from_i32(*code)),
            Self::Detached | Self::QuitReconnect => Some(ExitCode::SUCCESS),
            Self::Signal(_) => Some(ExitCode::from(1)),
            Self::Disconnected(_) => None,
        }
    }
}

enum AttachInputCommand {
    SetSink {
        sink: AttachInputSink,
        ack: oneshot::Sender<Result<()>>,
    },
    ClearSink {
        ack: oneshot::Sender<Result<()>>,
    },
    SetReconnectVisible {
        visible: bool,
        ack: oneshot::Sender<Result<()>>,
    },
    RequestViewport {
        reason: String,
        ack: oneshot::Sender<Result<()>>,
    },
    Stop,
}

#[derive(Debug)]
enum AttachInputEvent {
    Closed,
    Detached,
    QuitReconnect,
    RetryNow,
    BufferFull,
    SinkFailed(anyhow::Error),
}

#[derive(Debug, Clone, Copy)]
enum AttachInputMode {
    Connected,
    Disconnected { visible: bool },
}

struct AttachInputCoordinator {
    tx: mpsc::Sender<AttachInputCommand>,
    rx: mpsc::Receiver<AttachInputEvent>,
    handle: tokio::task::JoinHandle<()>,
}

impl AttachInputCoordinator {
    fn spawn(ui: AttachControlUi, initial_size: (u16, u16)) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        let handle = tokio::spawn(async move {
            if let Err(err) = Box::pin(attach_input_coordinator_loop(
                cmd_rx,
                event_tx,
                ui,
                initial_size,
            ))
            .await
            {
                debug!(%err, "attach input coordinator stopped");
            }
        });
        Self {
            tx: cmd_tx,
            rx: event_rx,
            handle,
        }
    }

    async fn set_sink(&self, sink: AttachInputSink) -> Result<()> {
        let (ack, done) = oneshot::channel();
        self.tx
            .send(AttachInputCommand::SetSink { sink, ack })
            .await
            .map_err(|_| anyhow!("attach input coordinator closed"))?;
        done.await
            .map_err(|_| anyhow!("attach input coordinator closed"))?
    }

    async fn clear_sink(&self) -> Result<()> {
        let (ack, done) = oneshot::channel();
        self.tx
            .send(AttachInputCommand::ClearSink { ack })
            .await
            .map_err(|_| anyhow!("attach input coordinator closed"))?;
        done.await
            .map_err(|_| anyhow!("attach input coordinator closed"))?
    }

    async fn request_viewport(&self, reason: &str) -> Result<()> {
        let (ack, done) = oneshot::channel();
        self.tx
            .send(AttachInputCommand::RequestViewport {
                reason: reason.to_owned(),
                ack,
            })
            .await
            .map_err(|_| anyhow!("attach input coordinator closed"))?;
        done.await
            .map_err(|_| anyhow!("attach input coordinator closed"))?
    }

    async fn set_reconnect_visible(&self, visible: bool) -> Result<bool> {
        let (ack, done) = oneshot::channel();
        if self
            .tx
            .send(AttachInputCommand::SetReconnectVisible { visible, ack })
            .await
            .is_err()
        {
            return Ok(false);
        }
        match done.await {
            Ok(Ok(())) => Ok(true),
            Ok(Err(err)) => Err(err),
            Err(_) => Ok(false),
        }
    }

    async fn next_event(&mut self) -> Option<AttachInputEvent> {
        self.rx.recv().await
    }

    fn drain_before_attach(&mut self) -> Option<AttachEnd> {
        loop {
            match self.rx.try_recv() {
                Ok(AttachInputEvent::SinkFailed(err)) => {
                    debug!(%err, "drained stale sink failure before attach");
                }
                Ok(AttachInputEvent::RetryNow | AttachInputEvent::BufferFull) => {}
                Ok(AttachInputEvent::Detached) => return Some(AttachEnd::Detached),
                Ok(AttachInputEvent::QuitReconnect | AttachInputEvent::Closed) => {
                    return Some(AttachEnd::QuitReconnect);
                }
                Err(mpsc::error::TryRecvError::Empty) => return None,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Some(AttachEnd::Disconnected(anyhow!(
                        "attach input coordinator stopped"
                    )));
                }
            }
        }
    }

    async fn stop(self) {
        let _ = self.tx.send(AttachInputCommand::Stop).await;
        let _ = self.handle.await;
    }
}

async fn attach_input_coordinator_loop(
    mut cmd_rx: mpsc::Receiver<AttachInputCommand>,
    event_tx: mpsc::Sender<AttachInputEvent>,
    ui: AttachControlUi,
    initial_size: (u16, u16),
) -> Result<()> {
    let mut stdin_src = tokio::io::stdin();
    let mut sink: Option<AttachInputSink> = None;
    let mut mode = AttachInputMode::Disconnected { visible: false };
    let mut buffer = ReconnectInputBuffer::new(256 * 1024);
    let mut last_size = initial_size;
    let mut pending_size = initial_pending_attach_size(initial_size);
    let mut paste = PasteState::new(PasteConfig::default());
    let mut bracketed = BracketedPasteScanner::default();
    let mut stdin_response_filter = StdinResponseFilter::new();
    let mut read_buf = [0_u8; 8192];

    loop {
        let read_limit = match mode {
            AttachInputMode::Connected | AttachInputMode::Disconnected { visible: false } => {
                read_buf.len()
            }
            AttachInputMode::Disconnected { visible: true } => 1,
        };
        tokio::select! {
            command = cmd_rx.recv() => {
                let Some(command) = command else { return Ok(()); };
                if handle_attach_input_command(
                    command,
                    &mut sink,
                    &mut mode,
                    &mut buffer,
                    &event_tx,
                    pending_size,
                ).await? {
                    return Ok(());
                }
                if sink.is_some() {
                    pending_size = None;
                }
            }
            read = stdin_src.read(&mut read_buf[..read_limit]) => {
                let read = read.context("read local stdin")?;
                if read == 0 {
                    if let Some(sink) = sink.as_mut()
                        && let Err(err) = sink.close_stdin().await.context("finish local stdin")
                    {
                        debug!(%err, "provider stdin already closed");
                    }
                    let _ = event_tx.send(AttachInputEvent::Closed).await;
                    return Ok(());
                }
                handle_attach_input_bytes(
                    &read_buf[..read],
                    &mut sink,
                    &mut mode,
                    &mut buffer,
                    &event_tx,
                    &ui,
                    &mut stdin_src,
                    &mut paste,
                    &mut bracketed,
                    &mut stdin_response_filter,
                ).await?;
            }
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                let flushed = flush_attach_stdin_filter_timeout(&mut stdin_response_filter);
                if !flushed.is_empty() {
                    match mode {
                        AttachInputMode::Connected => {
                            if let Some(active_sink) = sink.as_mut()
                                && let Err(err) = active_sink.send_stdin(&flushed).await.context("flush stdin response filter")
                            {
                                sink_failed(&event_tx, err).await;
                                sink.take();
                                mode = AttachInputMode::Disconnected { visible: false };
                            }
                        }
                        AttachInputMode::Disconnected { visible: false } => {
                            let _ = buffer.push(&flushed);
                        }
                        AttachInputMode::Disconnected { visible: true } => {}
                    }
                }
                if let Ok(now) = size()
                    && now != last_size
                {
                    ui.display.update_size(now.0, now.1).await?;
                    pending_size = Some(now);
                    if let Some(active_sink) = sink.as_mut()
                        && let Err(err) = active_sink.resize(now.0, now.1).await.context("resize attached session")
                    {
                        sink_failed(&event_tx, err).await;
                        sink.take();
                        mode = AttachInputMode::Disconnected { visible: false };
                    } else if sink.is_some() {
                        pending_size = None;
                    }
                    last_size = now;
                }
            }
        }
    }
}

fn initial_pending_attach_size(_initial_size: (u16, u16)) -> Option<(u16, u16)> {
    None
}

async fn handle_attach_input_command(
    command: AttachInputCommand,
    sink: &mut Option<AttachInputSink>,
    mode: &mut AttachInputMode,
    buffer: &mut ReconnectInputBuffer,
    event_tx: &mpsc::Sender<AttachInputEvent>,
    pending_size: Option<(u16, u16)>,
) -> Result<bool> {
    match command {
        AttachInputCommand::SetSink {
            sink: mut next_sink,
            ack,
        } => {
            *mode = AttachInputMode::Connected;
            if let Some((cols, rows)) = pending_size
                && let Err(err) = next_sink
                    .resize(cols, rows)
                    .await
                    .context("flush pending resize")
            {
                let message = format!("{err:#}");
                sink_failed(event_tx, err).await;
                *mode = AttachInputMode::Disconnected { visible: false };
                let _ = ack.send(Err(anyhow!(message)));
                return Ok(false);
            }
            let buffered = buffer.take();
            if !buffered.is_empty()
                && let Err(err) = next_sink
                    .send_stdin(&buffered)
                    .await
                    .context("flush reconnect input buffer")
            {
                let message = format!("{err:#}");
                sink_failed(event_tx, err).await;
                *mode = AttachInputMode::Disconnected { visible: false };
                let _ = ack.send(Err(anyhow!(message)));
                return Ok(false);
            }
            *sink = Some(next_sink);
            let _ = ack.send(Ok(()));
        }
        AttachInputCommand::ClearSink { ack } => {
            sink.take();
            *mode = AttachInputMode::Disconnected { visible: false };
            let _ = ack.send(Ok(()));
        }
        AttachInputCommand::SetReconnectVisible { visible, ack } => {
            if sink.is_none() {
                *mode = AttachInputMode::Disconnected { visible };
            }
            let _ = ack.send(Ok(()));
        }
        AttachInputCommand::RequestViewport { reason, ack } => {
            let result = match sink.as_mut() {
                Some(active_sink) => active_sink.request_viewport(reason).await,
                None => Err(anyhow!("attach input sink is not connected")),
            };
            let _ = ack.send(result);
        }
        AttachInputCommand::Stop => return Ok(true),
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn handle_attach_input_bytes(
    chunk: &[u8],
    sink: &mut Option<AttachInputSink>,
    mode: &mut AttachInputMode,
    buffer: &mut ReconnectInputBuffer,
    event_tx: &mpsc::Sender<AttachInputEvent>,
    ui: &AttachControlUi,
    stdin_src: &mut tokio::io::Stdin,
    paste: &mut PasteState,
    bracketed: &mut BracketedPasteScanner,
    stdin_response_filter: &mut StdinResponseFilter,
) -> Result<()> {
    match *mode {
        AttachInputMode::Connected => {
            let Some(active_sink) = sink.as_mut() else {
                *mode = AttachInputMode::Disconnected { visible: false };
                return Ok(());
            };
            let now = Instant::now();
            paste.observe_read(chunk.len(), now);
            match bracketed.scan(chunk) {
                BracketedPasteEvent::Begin => paste.activate(now),
                BracketedPasteEvent::End => paste.deactivate_if_idle(),
                BracketedPasteEvent::None => {}
            }
            if is_ctrl_backslash_sequence(chunk) {
                match run_attach_control_mode(active_sink, stdin_src, ui, paste).await? {
                    AttachControlOutcome::Continue => return Ok(()),
                    AttachControlOutcome::Detached => {
                        let _ = event_tx.send(AttachInputEvent::Detached).await;
                        return Ok(());
                    }
                    AttachControlOutcome::CancelPaste => {
                        paste.cancel_pending();
                        if bracketed.in_bracketed_paste() {
                            bracketed.force_end();
                            let _ = active_sink.send_stdin(b"\x1b[201~").await;
                        }
                        ui.display.clear_bar().await?;
                        return Ok(());
                    }
                }
            }
            if paste.is_active() && chunk == b"\x1b" {
                paste.cancel_pending();
                if bracketed.in_bracketed_paste() {
                    bracketed.force_end();
                    let _ = active_sink.send_stdin(b"\x1b[201~").await;
                }
                ui.display.clear_bar().await?;
                return Ok(());
            }
            let mut outbound = chunk.to_vec();
            if chunk == b"\x1b" && active_sink.has_active_reload() {
                let mut escape_tail = [0_u8; 16];
                if let Ok(Ok(read)) = tokio::time::timeout(
                    Duration::from_millis(20),
                    stdin_src.read(&mut escape_tail),
                )
                .await
                    && read > 0
                {
                    outbound.extend_from_slice(&escape_tail[..read]);
                }
            }
            let outbound =
                filter_attach_stdin_outbound(stdin_response_filter, active_sink, &outbound);
            paste.observe_queued(outbound.len());
            update_paste_bar(ui, paste).await?;
            let send_started = Instant::now();
            if !outbound.is_empty()
                && let Err(err) = active_sink
                    .send_stdin(&outbound)
                    .await
                    .context("copy local stdin")
            {
                debug!(%err, "stdin loop ended after provider stdin closed");
                sink.take();
                *mode = AttachInputMode::Disconnected { visible: false };
                sink_failed(event_tx, err).await;
                return Ok(());
            }
            paste.set_backpressured(send_started.elapsed() >= Duration::from_millis(100));
            paste.observe_sent(outbound.len());
            update_paste_bar(ui, paste).await?;
        }
        AttachInputMode::Disconnected { visible } => {
            if visible {
                match ReconnectControl::from_visible_input(chunk) {
                    Some(ReconnectControl::RetryNow) => {
                        let _ = event_tx.send(AttachInputEvent::RetryNow).await;
                    }
                    Some(ReconnectControl::Detach) => {
                        let _ = event_tx.send(AttachInputEvent::Detached).await;
                    }
                    Some(ReconnectControl::Quit) => {
                        let _ = event_tx.send(AttachInputEvent::QuitReconnect).await;
                    }
                    None => {}
                }
            } else {
                let filtered = stdin_response_filter.feed(chunk);
                if filtered.is_empty() {
                    return Ok(());
                }
                match buffer.push(&filtered) {
                    ReconnectBufferPush::Accepted => {
                        if buffer.is_full() {
                            *mode = AttachInputMode::Disconnected { visible: true };
                            let _ = event_tx.send(AttachInputEvent::BufferFull).await;
                        }
                    }
                    ReconnectBufferPush::Full => {
                        *mode = AttachInputMode::Disconnected { visible: true };
                        let _ = event_tx.send(AttachInputEvent::BufferFull).await;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn sink_failed(event_tx: &mpsc::Sender<AttachInputEvent>, err: anyhow::Error) {
    let _ = event_tx.send(AttachInputEvent::SinkFailed(err)).await;
}

#[cfg(feature = "ghostty-vt")]
async fn copy_mpsc_output(
    recv: &mut mpsc::Receiver<Vec<u8>>,
    display: &AttachDisplay,
    stream: AttachOutputStream,
    mode_tracker: &SharedTerminalModeTracker,
) -> Result<()> {
    while let Some(bytes) = recv.recv().await {
        if bytes.is_empty() {
            break;
        }
        write_tracked_output(display, stream, &bytes, mode_tracker).await?;
    }
    flush_tracked_output(display, stream, mode_tracker).await
}

async fn copy_remote_output<R>(
    recv: &mut R,
    display: &AttachDisplay,
    stream: AttachOutputStream,
    mode_tracker: &SharedTerminalModeTracker,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let read = recv.read(&mut buf).await.context("read remote output")?;
        if read == 0 {
            flush_tracked_output(display, stream, mode_tracker).await?;
            return Ok(());
        }
        write_tracked_output(display, stream, &buf[..read], mode_tracker).await?;
    }
}

#[cfg(unix)]
async fn pump_local_tmux_control_pty(
    master: OwnedFd,
    display: &AttachDisplay,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mode_tracker: &SharedTerminalModeTracker,
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
                    flush_tracked_output(display, AttachOutputStream::Stdout, mode_tracker).await?;
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
                                write_tracked_output(
                                    display,
                                    AttachOutputStream::Stdout,
                                    &bytes,
                                    mode_tracker,
                                )
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
                            tmux_cc::TmuxControlEvent::Exit => {
                                flush_tracked_output(
                                    display,
                                    AttachOutputStream::Stdout,
                                    mode_tracker,
                                )
                                .await?;
                                return Ok(());
                            }
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

async fn copy_zmx_control_output<R>(
    recv: &mut R,
    display: &AttachDisplay,
    mode_tracker: &SharedTerminalModeTracker,
) -> Result<()>
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
            write_tracked_output(display, AttachOutputStream::Stdout, &payload, mode_tracker)
                .await?;
        }
    }
    flush_tracked_output(display, AttachOutputStream::Stdout, mode_tracker).await
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

const ATTACH_OUTPUT_GATE_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachOutputGateDecision {
    NotHolding,
    Held,
    Overflow,
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

    fn hold(&mut self, stream: AttachOutputStream, bytes: &[u8]) -> AttachOutputGateDecision {
        if !self.holding {
            return AttachOutputGateDecision::NotHolding;
        }
        let target_len = match stream {
            AttachOutputStream::Stdout => self.stdout.len(),
            AttachOutputStream::Stderr => self.stderr.len(),
        };
        if target_len.saturating_add(bytes.len()) > ATTACH_OUTPUT_GATE_LIMIT {
            return AttachOutputGateDecision::Overflow;
        }
        match stream {
            AttachOutputStream::Stdout => self.stdout.extend_from_slice(bytes),
            AttachOutputStream::Stderr => self.stderr.extend_from_slice(bytes),
        }
        AttachOutputGateDecision::Held
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
        match state.gate.hold(stream, bytes) {
            AttachOutputGateDecision::Held => {
                state.redraw_bar().await?;
                return Ok(());
            }
            AttachOutputGateDecision::Overflow => {
                state.clear_bar().await?;
                state.flush_held_output().await?;
            }
            AttachOutputGateDecision::NotHolding => {}
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

    async fn size(&self) -> (u16, u16) {
        let state = self.inner.lock().await;
        (state.cols, state.rows)
    }

    async fn update_size(&self, cols: u16, rows: u16) -> Result<()> {
        let mut state = self.inner.lock().await;
        if state.cols == cols && state.rows == rows {
            return Ok(());
        }
        let had_bar = state.bar.is_some();
        if had_bar {
            state.clear_bar().await?;
        }
        state.cols = cols;
        state.rows = rows;
        if had_bar {
            state.redraw_bar().await?;
        }
        Ok(())
    }

    async fn set_bar(&self, text: String) -> Result<()> {
        let mut state = self.inner.lock().await;
        state.gate.set_holding(true);
        state.bar = Some(text);
        state.redraw_bar().await
    }

    async fn clear_bar(&self) -> Result<()> {
        let mut state = self.inner.lock().await;
        if state.bar.is_none() {
            return Ok(());
        }
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

impl Default for PasteConfig {
    fn default() -> Self {
        Self {
            burst_threshold_bytes: 64 * 1024,
            burst_window: Duration::from_millis(250),
            detail_after: Duration::from_secs(2),
        }
    }
}

impl PasteConfig {
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
        if self.pending_bytes == 0 {
            self.backpressured = false;
            self.deactivate_if_idle();
        }
    }

    fn set_backpressured(&mut self, value: bool) {
        self.backpressured = value;
        if value {
            self.active = true;
            self.active_since.get_or_insert_with(Instant::now);
        } else {
            self.deactivate_if_idle();
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
            .next_back();
        let last_end = combined
            .windows(END.len())
            .enumerate()
            .filter_map(|(i, w)| (w == END).then_some(i))
            .next_back();
        let event = match (last_begin, last_end) {
            (None, None) => BracketedPasteEvent::None,
            (Some(_), None) => {
                self.in_paste = true;
                BracketedPasteEvent::Begin
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

fn attach_v2_input_trace_class(bytes: &[u8]) -> &'static str {
    if bytes.is_empty() {
        "empty"
    } else if bytes == b"\x0f" {
        "ctrl_o"
    } else {
        "data"
    }
}

fn filter_attach_stdin_outbound(
    filter: &mut StdinResponseFilter,
    sink: &AttachInputSink,
    bytes: &[u8],
) -> Vec<u8> {
    if bytes == b"\x1b" && sink.has_active_reload() {
        bytes.to_vec()
    } else {
        filter.feed(bytes)
    }
}

fn flush_attach_stdin_filter_timeout(filter: &mut StdinResponseFilter) -> Vec<u8> {
    filter.flush_timeout()
}

impl AttachInputSink {
    fn has_active_reload(&self) -> bool {
        matches!(
            &self.kind,
            AttachInputSinkKind::RemoteV2 { reload_state, .. }
                if cancellable_reload_id(reload_state).is_some()
        )
    }

    async fn send_stdin(&mut self, bytes: &[u8]) -> Result<()> {
        match &mut self.kind {
            AttachInputSinkKind::Remote { send, .. } => {
                send.write_all(bytes).await.context("write remote stdin")
            }
            AttachInputSinkKind::RemoteV2 {
                input,
                control,
                attach_id,
                reload_state,
                ..
            } => {
                trace!(
                    lane = "input",
                    input_class = attach_v2_input_trace_class(bytes),
                    bytes = bytes.len(),
                    "forward attach v2 stdin"
                );
                if bytes == b"\x1b"
                    && let Some(reload_id) = cancellable_reload_id(reload_state)
                {
                    return control
                        .write_all(
                            &postcard::to_stdvec(&AttachV2ClientFrame::CancelReload {
                                attach_id: *attach_id,
                                reload_id,
                            })
                            .context("encode attach v2 cancel reload frame")?,
                        )
                        .await
                        .context("write attach v2 cancel reload frame");
                }
                input
                    .write_all(
                        &postcard::to_stdvec(&AttachV2ClientFrame::Input {
                            attach_id: *attach_id,
                            bytes: bytes.to_vec(),
                        })
                        .context("encode attach v2 input frame")?,
                    )
                    .await
                    .context("write attach v2 input frame")
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
            AttachInputSinkKind::RemoteV2 {
                control, attach_id, ..
            } => {
                control
                    .write_all(
                        &postcard::to_stdvec(&AttachV2ClientFrame::Detach {
                            attach_id: *attach_id,
                        })
                        .context("encode attach v2 detach frame")?,
                    )
                    .await
                    .context("write attach v2 detach frame")?;
                control.finish().context("finish attach v2 control")
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
            AttachInputSinkKind::RemoteV2 {
                resize,
                attach_id,
                next_resize_id,
                resize_state,
                ..
            } => {
                *next_resize_id = next_resize_id.saturating_add(1);
                if let Ok(mut state) = resize_state.lock() {
                    *state = AttachV2ResizeState {
                        resize_id: *next_resize_id,
                        cols,
                        rows,
                    };
                }
                resize
                    .write_all(
                        &postcard::to_stdvec(&AttachV2ClientFrame::Resize {
                            attach_id: *attach_id,
                            resize_id: *next_resize_id,
                            cols,
                            rows,
                        })
                        .context("encode attach v2 resize frame")?,
                    )
                    .await
                    .context("write attach v2 resize frame")
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

    async fn reload(&mut self) -> Result<()> {
        match &mut self.kind {
            AttachInputSinkKind::RemoteV2 {
                control,
                attach_id,
                next_reload_id,
                reload_state,
                ..
            } => {
                *next_reload_id = next_reload_id.saturating_add(1);
                start_active_reload(reload_state, *next_reload_id);
                control
                    .write_all(
                        &postcard::to_stdvec(&AttachV2ClientFrame::Reload {
                            attach_id: *attach_id,
                            reload_id: *next_reload_id,
                        })
                        .context("encode attach v2 reload frame")?,
                    )
                    .await
                    .context("write attach v2 reload frame")
            }
            _ => Ok(()),
        }
    }

    async fn request_viewport(&mut self, reason: String) -> Result<()> {
        match &mut self.kind {
            AttachInputSinkKind::RemoteV2 {
                control,
                attach_id,
                resize_state,
                ..
            } => control
                .write_all(
                    &postcard::to_stdvec(&AttachV2ClientFrame::RequestViewport {
                        attach_id: *attach_id,
                        reason,
                        resize_id: current_resize_state(resize_state).resize_id,
                    })
                    .context("encode attach v2 viewport request frame")?,
                )
                .await
                .context("write attach v2 viewport request frame"),
            _ => Ok(()),
        }
    }

    fn supports_reload(&self) -> bool {
        matches!(self.kind, AttachInputSinkKind::RemoteV2 { .. })
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
            AttachInputSinkKind::RemoteV2 { .. } => Ok(()),
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
    RemoteV2 {
        input: SendStream,
        resize: SendStream,
        control: SendStream,
        attach_id: [u8; 16],
        next_resize_id: u64,
        next_reload_id: u64,
        resize_state: Arc<StdMutex<AttachV2ResizeState>>,
        reload_state: Arc<StdMutex<ReloadCoordinator>>,
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
    let mut stdin_response_filter = StdinResponseFilter::new();
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
                    match run_attach_control_mode(sink, stdin, ui, &paste).await? {
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
                let filtered =
                    filter_attach_stdin_outbound(&mut stdin_response_filter, sink, chunk);
                paste.observe_queued(filtered.len());
                update_paste_bar(ui, &paste).await?;
                let send_started = Instant::now();
                if !filtered.is_empty()
                    && let Err(err) = sink.send_stdin(&filtered).await.context("copy local stdin")
                {
                    debug!(%err, "stdin loop ended after provider stdin closed");
                    return Ok(StdinTaskResult::Closed);
                }
                paste.set_backpressured(send_started.elapsed() >= Duration::from_millis(100));
                paste.observe_sent(filtered.len());
                update_paste_bar(ui, &paste).await?;
            }
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                let flushed = flush_attach_stdin_filter_timeout(&mut stdin_response_filter);
                if !flushed.is_empty()
                    && let Err(err) = sink.send_stdin(&flushed).await.context("flush stdin response filter")
                {
                    debug!(%err, "stdin loop ended after provider stdin closed");
                    return Ok(StdinTaskResult::Closed);
                }
                if let Ok(now) = size()
                    && now != last_size
                {
                    ui.display.update_size(now.0, now.1).await?;
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
        return ui.display.clear_bar().await;
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
        render_attach_control_bar(
            ui,
            CONTROL_TIMEOUT.saturating_sub(elapsed),
            paste,
            sink.supports_reload(),
        )
        .await?;
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
            if command == b"r" && sink.supports_reload() {
                sink.reload().await.context("send attach v2 reload frame")?;
                ui.display
                    .set_bar(format!(
                        "▌ Portl › {} · reload requested · Esc cancel",
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
    supports_reload: bool,
) -> Result<()> {
    ui.display
        .set_bar(render_bar(RenderBarOptions {
            canonical_ref: &ui.canonical_ref,
            supports_kick_others: ui.supports_kick_others,
            supports_reload,
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

        assert_eq!(
            gate.hold(AttachOutputStream::Stdout, b"frame1"),
            AttachOutputGateDecision::NotHolding
        );
        gate.set_holding(true);
        assert_eq!(
            gate.hold(AttachOutputStream::Stdout, b"frame2"),
            AttachOutputGateDecision::Held
        );
        assert_eq!(
            gate.hold(AttachOutputStream::Stderr, b"err"),
            AttachOutputGateDecision::Held
        );
        assert_eq!(gate.take_stdout(), b"frame2".to_vec());
        assert_eq!(gate.take_stderr(), b"err".to_vec());
        gate.set_holding(false);
        assert_eq!(
            gate.hold(AttachOutputStream::Stdout, b"frame3"),
            AttachOutputGateDecision::NotHolding
        );
    }

    #[test]
    fn attach_output_gate_overflow_keeps_bar_holding() {
        let mut gate = AttachOutputGate::default();
        gate.set_holding(true);
        assert_eq!(
            gate.hold(
                AttachOutputStream::Stdout,
                &vec![b'x'; ATTACH_OUTPUT_GATE_LIMIT]
            ),
            AttachOutputGateDecision::Held
        );
        assert_eq!(
            gate.hold(AttachOutputStream::Stdout, b"y"),
            AttachOutputGateDecision::Overflow
        );
        assert_eq!(
            gate.hold(AttachOutputStream::Stdout, b"z"),
            AttachOutputGateDecision::Overflow
        );
        assert_eq!(gate.take_stdout(), vec![b'x'; ATTACH_OUTPUT_GATE_LIMIT]);
        assert_eq!(
            gate.hold(AttachOutputStream::Stdout, b"after-flush"),
            AttachOutputGateDecision::Held
        );
    }

    #[test]
    fn attach_v2_initial_size_is_not_pending_resize() {
        assert_eq!(initial_pending_attach_size((80, 24)), None);
    }

    #[test]
    fn attach_v2_opening_drops_late_prelude_after_viewport() {
        let mut opening = AttachV2OpeningState::default();

        assert!(opening.should_render_prelude());
        opening.mark_viewport_seen();
        assert!(!opening.should_render_prelude());
    }

    #[test]
    fn attach_v2_opening_drops_late_prelude_after_stale_viewport_barrier() {
        let mut opening = AttachV2OpeningState::default();

        assert!(opening.should_render_prelude());
        opening.mark_viewport_barrier_seen();
        assert!(!opening.should_render_prelude());
    }

    #[test]
    fn attach_v2_reload_state_waits_for_final_viewport() {
        let mut state = AttachV2ReloadState::default();

        state.start(7);
        assert_eq!(state.active_reload_id(), Some(7));
        assert_eq!(state.cancellable_reload_id(), Some(7));
        assert!(state.accepts_chunk(7));
        assert!(!state.clear_after_viewport());
        assert_eq!(state.active_reload_id(), Some(7));

        assert!(state.mark_done(7));
        assert_eq!(state.active_reload_id(), Some(7));
        assert_eq!(state.cancellable_reload_id(), None);
        assert!(!state.accepts_chunk(7));
        assert!(state.clear_after_viewport());
        assert_eq!(state.active_reload_id(), None);
    }

    #[test]
    fn attach_v2_reload_loading_blocks_viewport_rendering() {
        let mut state = AttachV2ReloadState::default();

        assert!(state.allows_viewport_render());
        state.start(7);
        assert!(!state.allows_viewport_render());
        assert!(state.mark_done(7));
        assert!(state.allows_viewport_render());
    }

    #[test]
    fn attach_v2_reload_cancelled_allows_final_viewport_rendering() {
        let mut state = AttachV2ReloadState::default();

        state.start(8);
        assert!(!state.allows_viewport_render());
        assert!(state.mark_cancelled(8));
        assert!(state.allows_viewport_render());
    }

    #[test]
    fn reload_coordinator_queues_live_until_post_reload_viewport_and_dedups() {
        let mut coordinator = ReloadCoordinator::default();

        coordinator.start(42);
        assert!(coordinator.is_reloading());
        assert_eq!(
            coordinator.handle_live_output(3, 8, b"loNEW".to_vec()),
            ReloadLiveDecision::Queued
        );
        coordinator.start(42);
        assert_eq!(coordinator.queued_live_len(), 1);

        assert!(coordinator.mark_done(42));
        coordinator.record_post_reload_viewport(5, b"hello".to_vec());

        let drained = coordinator.drain_queued_live(5);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].bytes, b"NEW");
        assert_eq!(drained[0].end_seq, 8);
        assert!(!coordinator.is_reloading());
        assert_eq!(coordinator.queued_live_len(), 0);
        assert_eq!(coordinator.post_reload_viewport_len(), Some(5));
    }

    #[test]
    fn reload_coordinator_suppresses_catching_up_live_covered_by_viewport() {
        let mut coordinator = ReloadCoordinator::default();

        coordinator.start(7);
        assert_eq!(
            coordinator.handle_live_output(0, 5, b"hello".to_vec()),
            ReloadLiveDecision::Queued
        );
        assert!(coordinator.mark_done(7));
        coordinator.record_post_reload_viewport(5, b"hello".to_vec());

        let drained = coordinator.drain_queued_live(5);
        assert!(drained.is_empty());
        assert!(!coordinator.is_reloading());
    }

    #[test]
    fn reload_coordinator_empty_history_completes_after_viewport() {
        let mut coordinator = ReloadCoordinator::default();

        coordinator.start(11);
        assert!(coordinator.mark_done(11));
        coordinator.record_post_reload_viewport(0, Vec::new());
        assert!(coordinator.drain_queued_live(0).is_empty());

        assert!(!coordinator.is_reloading());
        assert_eq!(
            coordinator.handle_live_output(0, 4, b"live".to_vec()),
            ReloadLiveDecision::Render
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn attach_v2_reload_control_frames_emit_one_sgr_reset_each() {
        let display = AttachDisplay::new(80, 24);
        display.inner.lock().await.gate.set_holding(true);
        let reload_state = Arc::new(StdMutex::new(ReloadCoordinator::default()));
        let tracker = new_terminal_mode_tracker();
        let mut resync_pending = false;
        let attach_id = [7_u8; 16];

        handle_attach_v2_control_frame(
            AttachV2ServerFrame::ReloadStarted {
                attach_id,
                reload_id: 1,
                total_bytes: Some(10),
            },
            &display,
            &reload_state,
            &mut resync_pending,
            &tracker,
        )
        .await
        .unwrap();
        handle_attach_v2_control_frame(
            AttachV2ServerFrame::ReloadDone {
                attach_id,
                reload_id: 1,
                final_generation: 2,
            },
            &display,
            &reload_state,
            &mut resync_pending,
            &tracker,
        )
        .await
        .unwrap();

        let output = display.inner.lock().await.gate.take_stdout();
        let reset_count = output
            .windows(b"\x1b[0m".len())
            .filter(|window| *window == b"\x1b[0m")
            .count();
        assert_eq!(reset_count, 2, "stdout output: {output:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reload_edge_control_frames_preserve_terminal_modes_without_defensive_resets() {
        let display = AttachDisplay::new(80, 24);
        display.inner.lock().await.gate.set_holding(true);
        let reload_state = Arc::new(StdMutex::new(ReloadCoordinator::default()));
        let tracker = new_terminal_mode_tracker();
        let mut resync_pending = false;
        let attach_id = [9_u8; 16];

        write_tracked_output(
            &display,
            AttachOutputStream::Stdout,
            b"\x1b[?1049h\x1b[>1u\x1b[=15u\x1b[>4;2m\x1b[?2004h\x1b[?1006h\x1b[?7l\x1b[5;20r",
            &tracker,
        )
        .await
        .unwrap();
        let _ = display.inner.lock().await.gate.take_stdout();

        handle_attach_v2_control_frame(
            AttachV2ServerFrame::ReloadStarted {
                attach_id,
                reload_id: 3,
                total_bytes: Some(0),
            },
            &display,
            &reload_state,
            &mut resync_pending,
            &tracker,
        )
        .await
        .unwrap();
        handle_attach_v2_control_frame(
            AttachV2ServerFrame::ReloadDone {
                attach_id,
                reload_id: 3,
                final_generation: 4,
            },
            &display,
            &reload_state,
            &mut resync_pending,
            &tracker,
        )
        .await
        .unwrap();

        let reload_output = display.inner.lock().await.gate.take_stdout();
        assert_eq!(reload_output, b"\x1b[0m\x1b[0m");
        for reset in [
            b"\x1b[?1049l".as_slice(),
            b"\x1b[<u",
            b"\x1b[=0u",
            b"\x1b[>4;0m",
            b"\x1b[?2004l",
            b"\x1b[?1006l",
            b"\x1b[?7h",
            b"\x1b[r",
        ] {
            assert!(
                !contains_bytes(&reload_output, reset),
                "reload emitted defensive reset {reset:?}: {reload_output:?}"
            );
        }

        let state = tracked_terminal_mode_state(&tracker);
        assert_eq!(state.alt_screen, Some(AltScreenMode::Mode1049));
        assert_eq!(state.kitty_keyboard_depth, 1);
        assert_eq!(state.kitty_flags, 15);
        assert_eq!(state.modify_other_keys, 2);
        assert!(state.bracketed_paste);
        assert!(state.mouse_modes[3]);
        assert!(!state.decawm);
        assert!(state.scroll_region_non_default);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reload_edge_suppresses_tail_history_before_post_reload_viewport() {
        let display = AttachDisplay::new(80, 24);
        display.inner.lock().await.gate.set_holding(true);
        let reload_state = Arc::new(StdMutex::new(ReloadCoordinator::default()));
        let tracker = new_terminal_mode_tracker();

        start_active_reload(&reload_state, 21);
        handle_attach_v2_reload_chunk_frame(
            &display,
            &reload_state,
            21,
            AttachV2Progress {
                loaded_bytes: 17,
                total_bytes: Some(17),
                retained_history_truncated: false,
                complete: true,
            },
            AttachV2Payload::raw(b"TAIL_FULL_SCREEN".to_vec()),
        )
        .await
        .unwrap();
        assert!(mark_reload_done(&reload_state, 21));
        write_tracked_output(
            &display,
            AttachOutputStream::Stdout,
            b"VIEWPORT_SCREEN",
            &tracker,
        )
        .await
        .unwrap();
        let queued = finish_reload_after_viewport(&reload_state, 17, b"VIEWPORT_SCREEN".to_vec());
        assert!(queued.is_empty());

        let output = display.inner.lock().await.gate.take_stdout();
        assert!(!contains_bytes(&output, b"TAIL_FULL_SCREEN"));
        assert_eq!(
            output
                .windows(b"VIEWPORT_SCREEN".len())
                .filter(|window| *window == b"VIEWPORT_SCREEN")
                .count(),
            1,
            "host-bound output should contain exactly one post-reload viewport: {output:?}"
        );
    }

    #[test]
    fn reload_edge_cancelled_reload_queues_live_until_recovery_viewport() {
        let mut coordinator = ReloadCoordinator::default();

        coordinator.start(13);
        assert!(coordinator.mark_cancelled(13));
        assert_eq!(
            coordinator.handle_live_output(0, 4, b"live".to_vec()),
            ReloadLiveDecision::Queued
        );
        assert_eq!(coordinator.queued_live_len(), 1);
        coordinator.record_post_reload_viewport(4, b"live".to_vec());

        assert!(coordinator.drain_queued_live(4).is_empty());
        assert!(!coordinator.is_reloading());
    }

    #[test]
    fn reload_edge_back_to_back_reload_supersedes_older_reload() {
        let mut coordinator = ReloadCoordinator::default();

        coordinator.start(1);
        assert!(coordinator.accepts_chunk(1));
        coordinator.start(2);

        assert!(!coordinator.accepts_chunk(1));
        assert!(coordinator.accepts_chunk(2));
        assert!(!coordinator.mark_done(1));
        assert!(coordinator.mark_done(2));
        coordinator.record_post_reload_viewport(0, b"latest".to_vec());
        assert!(coordinator.drain_queued_live(0).is_empty());
        assert!(!coordinator.is_reloading());
        assert_eq!(coordinator.post_reload_viewport_len(), Some(6));
    }

    #[test]
    fn attach_v2_data_stream_eof_is_non_terminal() {
        let mut streams = AttachV2DataStreamStatus::default();

        streams.close(AttachV2DataStream::Viewport);
        streams.close(AttachV2DataStream::History);
        streams.close(AttachV2DataStream::Live);

        assert!(!streams.viewport_open());
        assert!(!streams.history_open());
        assert!(!streams.live_open());
        assert!(!streams.data_eof_requires_disconnect());
    }

    #[test]
    fn attach_v2_viewport_acceptance_requires_current_resize_epoch() {
        let current = AttachV2ResizeState {
            resize_id: 2,
            cols: 80,
            rows: 40,
        };

        assert!(attach_v2_viewport_matches_resize_state(2, 80, 40, current));
        assert!(!attach_v2_viewport_matches_resize_state(1, 80, 40, current));
        assert!(!attach_v2_viewport_matches_resize_state(0, 80, 40, current));
        assert!(!attach_v2_viewport_matches_resize_state(2, 80, 24, current));
        assert!(!attach_v2_viewport_matches_resize_state(
            2, 100, 40, current
        ));
        assert!(!attach_v2_viewport_matches_resize_state(3, 80, 40, current));
    }

    #[test]
    fn attach_v2_viewport_decision_covers_resize_and_reload_state() {
        let current = AttachV2ResizeState {
            resize_id: 2,
            cols: 80,
            rows: 40,
        };
        let mut reload = AttachV2ReloadState::default();

        assert_eq!(
            attach_v2_viewport_decision(3, 2, 2, 80, 40, current, reload),
            AttachV2ViewportDecision::Render
        );
        assert_eq!(
            attach_v2_viewport_decision(2, 2, 2, 80, 40, current, reload),
            AttachV2ViewportDecision::Stale
        );
        assert_eq!(
            attach_v2_viewport_decision(3, 2, 1, 80, 40, current, reload),
            AttachV2ViewportDecision::Stale
        );
        reload.start(9);
        assert_eq!(
            attach_v2_viewport_decision(3, 2, 2, 80, 40, current, reload),
            AttachV2ViewportDecision::DeferForReload
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn attach_display_update_size_moves_bar_to_new_bottom_row() {
        let capture = StderrCapture::start();
        let display = AttachDisplay::new(80, 20);

        display.set_bar("first".to_owned()).await.unwrap();
        display.update_size(80, 30).await.unwrap();
        display.set_bar("second".to_owned()).await.unwrap();

        let output = capture.finish();
        assert!(
            output
                .windows(b"\x1b[20;1H".len())
                .any(|w| w == b"\x1b[20;1H"),
            "initial bar draw should target row 20: {:?}",
            String::from_utf8_lossy(&output)
        );
        assert!(
            output
                .windows(b"\x1b[30;1H".len())
                .any(|w| w == b"\x1b[30;1H"),
            "bar redraw after resize should target row 30: {:?}",
            String::from_utf8_lossy(&output)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn inactive_paste_bar_update_does_not_clear_application_row() {
        let capture = StderrCapture::start();
        let ui = AttachControlUi {
            canonical_ref: "local/ghostty/dev".to_owned(),
            supports_kick_others: false,
            display: AttachDisplay::new(80, 24),
        };
        let paste = PasteState::new(PasteConfig::default());

        update_paste_bar(&ui, &paste).await.unwrap();

        let output = capture.finish();
        assert_eq!(
            output,
            b"",
            "inactive paste updates must not erase the application's last row; wrote {:?}",
            String::from_utf8_lossy(&output)
        );
    }

    #[cfg(unix)]
    struct StderrCapture {
        saved: std::os::fd::RawFd,
        read: std::os::fd::RawFd,
    }

    #[cfg(unix)]
    impl StderrCapture {
        #[allow(unsafe_code)]
        fn start() -> Self {
            let mut fds = [0; 2];
            assert_eq!(
                unsafe { nix::libc::pipe(fds.as_mut_ptr()) },
                0,
                "pipe stderr capture"
            );
            let saved = unsafe { nix::libc::dup(nix::libc::STDERR_FILENO) };
            assert!(saved >= 0, "dup stderr");
            assert_eq!(
                unsafe { nix::libc::dup2(fds[1], nix::libc::STDERR_FILENO) },
                nix::libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { nix::libc::close(fds[1]) }, 0, "close pipe writer");
            Self {
                saved,
                read: fds[0],
            }
        }

        #[allow(unsafe_code)]
        fn finish(self) -> Vec<u8> {
            assert_eq!(
                unsafe { nix::libc::dup2(self.saved, nix::libc::STDERR_FILENO) },
                nix::libc::STDERR_FILENO,
                "restore stderr"
            );
            assert_eq!(
                unsafe { nix::libc::close(self.saved) },
                0,
                "close saved stderr"
            );
            let mut output = Vec::new();
            loop {
                let mut buf = [0_u8; 1024];
                let read =
                    unsafe { nix::libc::read(self.read, buf.as_mut_ptr().cast(), buf.len()) };
                if read == 0 {
                    break;
                }
                assert!(read > 0, "read stderr capture");
                output.extend_from_slice(&buf[..usize::try_from(read).unwrap()]);
            }
            assert_eq!(
                unsafe { nix::libc::close(self.read) },
                0,
                "close pipe reader"
            );
            output
        }
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
    fn default_session_provider_alias_normalizes_to_ghostty() {
        assert_eq!(normalize_session_provider("default").unwrap(), "ghostty");
        assert_eq!(
            effective_provider_from_env(None, Some("default")).as_deref(),
            Some("ghostty")
        );
        assert_eq!(
            effective_provider_from_env(Some("default"), Some("tmux")).as_deref(),
            Some("ghostty")
        );
    }

    #[test]
    fn attach_v2_input_trace_class_identifies_ctrl_o() {
        assert_eq!(attach_v2_input_trace_class(b"\x0f"), "ctrl_o");
        assert_eq!(attach_v2_input_trace_class(b"abc"), "data");
        assert_eq!(attach_v2_input_trace_class(b""), "empty");
    }

    #[test]
    fn raw_mode_cleanup_resets_enhanced_keyboard_protocols() {
        let cleanup = raw_mode_cleanup_sequence(RawModeExitVariant::Normal);
        assert!(
            cleanup.windows(b"\x1b[<u".len()).any(|w| w == b"\x1b[<u"),
            "cleanup should pop kitty keyboard protocol state"
        );
        assert!(
            cleanup
                .windows(b"\x1b[>4;0m".len())
                .any(|w| w == b"\x1b[>4;0m"),
            "cleanup should disable xterm modifyOtherKeys"
        );
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn byte_index(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap_or_else(|| panic!("missing cleanup component: {needle:?}"))
    }

    #[test]
    fn raw_mode_cleanup_normal_exit_uses_ordered_extended_template_without_ris() {
        let cleanup = raw_mode_cleanup_sequence(RawModeExitVariant::Normal);

        assert_eq!(
            cleanup,
            b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\n"
        );
        for component in [
            b"\x1b[0m".as_slice(),
            b"\x1b[?1049l",
            b"\x1b[r",
            b"\x1b[?7h",
            b"\x1b[!p",
            b"\x1b[?25h",
            b"\x1b[<u",
            b"\x1b[=0u",
            b"\x1b[>4;0m",
            b"\x1b[?2004l",
            b"\x1b[?1000l",
            b"\x1b[?1002l",
            b"\x1b[?1003l",
            b"\x1b[?1006l",
        ] {
            assert!(contains_bytes(cleanup, component));
        }
        assert!(!contains_bytes(cleanup, b"\x1bc"));
        assert!(cleanup.ends_with(b"\r\n"));
    }

    #[test]
    fn raw_mode_cleanup_emits_ris_only_for_emergency_variants() {
        for variant in [
            RawModeExitVariant::Normal,
            RawModeExitVariant::ReconnectExhausted,
        ] {
            let cleanup = raw_mode_cleanup_sequence(variant);
            assert_eq!(cleanup, RAW_MODE_CLEANUP_NORMAL);
            assert!(!contains_bytes(cleanup, b"\x1bc"));
            assert!(cleanup.ends_with(b"\r\n"));
        }

        for variant in [
            RawModeExitVariant::Sighup,
            RawModeExitVariant::Sigterm,
            RawModeExitVariant::Sigint,
            RawModeExitVariant::Panic,
        ] {
            let cleanup = raw_mode_cleanup_sequence(variant);
            assert_eq!(cleanup, RAW_MODE_CLEANUP_EMERGENCY);
            assert!(cleanup.ends_with(b"\x1bc"));
            assert_eq!(&cleanup[cleanup.len() - b"\r\n\x1bc".len()..], b"\r\n\x1bc");
        }
    }

    #[test]
    fn panic_hook_cleanup_bytes_match_panic_cleanup_variant() {
        assert_eq!(
            panic_hook_cleanup_bytes(),
            raw_mode_cleanup_sequence(RawModeExitVariant::Panic)
        );
    }

    #[cfg(unix)]
    #[test]
    fn panic_hook_write_is_noop_when_not_armed() {
        let _guard = panic_hook_test_lock().lock().expect("panic hook test lock");
        set_panic_hook_armed(false);
        let capture = StderrCapture::start();

        write_panic_cleanup_to_fd_if_armed(nix::libc::STDERR_FILENO);

        let output = capture.finish();
        assert_eq!(output, b"");
    }

    #[cfg(unix)]
    #[test]
    fn panic_hook_write_emits_panic_cleanup_when_armed() {
        let _guard = panic_hook_test_lock().lock().expect("panic hook test lock");
        set_panic_hook_armed(true);
        let capture = StderrCapture::start();

        write_panic_cleanup_to_fd_if_armed(nix::libc::STDERR_FILENO);

        set_panic_hook_armed(false);
        let output = capture.finish();
        assert_eq!(output, raw_mode_cleanup_sequence(RawModeExitVariant::Panic));
    }

    #[cfg(unix)]
    #[test]
    fn panic_hook_armed_writer_source_uses_single_raw_write() {
        let source = include_str!("session.rs");
        let function_start = source
            .find("fn write_panic_cleanup_to_fd_if_armed")
            .expect("panic cleanup writer source");
        let function_body = &source[function_start..];
        let function_end = function_body
            .find("\n\n#[derive(Debug, Default)]")
            .expect("end of panic cleanup writer source");
        let function_body = &function_body[..function_end];

        assert!(
            !function_body.contains("while "),
            "armed panic cleanup writer must not retry short writes with while"
        );
        assert!(
            !function_body.contains("loop "),
            "armed panic cleanup writer must not retry short writes with loop"
        );
        assert_eq!(
            function_body.matches("nix::libc::write(fd,").count(),
            1,
            "armed panic cleanup writer must perform exactly one raw libc::write"
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn installed_panic_hook_armed_path_writes_only_cleanup_bytes() {
        let _guard = panic_hook_test_lock().lock().expect("panic hook test lock");
        std::panic::set_hook(Box::new(|_| {
            let text = b"previous panic text";
            let _ = unsafe {
                nix::libc::write(nix::libc::STDERR_FILENO, text.as_ptr().cast(), text.len())
            };
        }));
        install_panic_hook();
        set_panic_hook_armed(true);
        let capture = StderrCapture::start();

        let _ = std::panic::catch_unwind(|| panic!("armed panic hook test"));

        set_panic_hook_armed(false);
        let output = capture.finish();
        assert_eq!(output, raw_mode_cleanup_sequence(RawModeExitVariant::Panic));
        assert!(output.ends_with(b"\x1bc"));
    }

    #[cfg(unix)]
    fn panic_hook_test_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    #[test]
    fn raw_mode_cleanup_ordering_is_visually_safe() {
        for variant in [
            RawModeExitVariant::Normal,
            RawModeExitVariant::ReconnectExhausted,
            RawModeExitVariant::Sighup,
            RawModeExitVariant::Sigterm,
            RawModeExitVariant::Sigint,
            RawModeExitVariant::Panic,
        ] {
            let cleanup = raw_mode_cleanup_sequence(variant);
            let sgr = byte_index(cleanup, b"\x1b[0m");
            let alt_leave = byte_index(cleanup, b"\x1b[?1049l");
            let scroll_region = byte_index(cleanup, b"\x1b[r");
            let autowrap = byte_index(cleanup, b"\x1b[?7h");
            let decstr = byte_index(cleanup, b"\x1b[!p");
            let show_cursor = byte_index(cleanup, b"\x1b[?25h");
            let kitty_pop = byte_index(cleanup, b"\x1b[<u");
            let modify_other_keys = byte_index(cleanup, b"\x1b[>4;0m");
            let first_mouse = byte_index(cleanup, b"\x1b[?1000l");

            assert!(sgr < alt_leave);
            assert!(alt_leave < scroll_region);
            assert!(alt_leave < autowrap);
            assert!(scroll_region < decstr);
            assert!(autowrap < decstr);
            assert!(decstr < show_cursor);
            assert!(show_cursor < kitty_pop);
            assert!(kitty_pop < modify_other_keys);
            assert!(modify_other_keys < first_mouse);

            if variant.is_emergency() {
                assert!(cleanup.ends_with(b"\x1bc"));
            } else {
                assert!(cleanup.ends_with(b"\r\n"));
            }
        }
    }

    #[test]
    fn raw_mode_cleanup_writer_is_idempotent_for_each_variant() {
        for variant in [
            RawModeExitVariant::Normal,
            RawModeExitVariant::ReconnectExhausted,
            RawModeExitVariant::Sighup,
            RawModeExitVariant::Sigterm,
            RawModeExitVariant::Sigint,
            RawModeExitVariant::Panic,
        ] {
            let mut writer = RawModeCleanupWriter::default();
            let mut sink = Vec::new();

            writer.write_to(&mut sink, variant).unwrap();
            assert_eq!(sink, raw_mode_cleanup_sequence(variant));

            let first_len = sink.len();
            writer.write_to(&mut sink, variant).unwrap();
            assert_eq!(&sink[first_len..], b"");
        }
    }

    #[test]
    fn signal_attach_end_maps_to_emergency_cleanup_and_failure_exit() {
        for variant in [
            RawModeExitVariant::Sighup,
            RawModeExitVariant::Sigterm,
            RawModeExitVariant::Sigint,
        ] {
            let end = AttachEnd::Signal(variant);

            assert_eq!(end.raw_mode_exit_variant(), Some(variant));
            assert_eq!(end.exit_code(), Some(ExitCode::from(1)));
            assert!(raw_mode_cleanup_sequence(variant).ends_with(b"\x1bc"));
        }
    }

    #[test]
    fn local_raw_mode_lifecycles_install_signal_watcher() {
        let session_source = include_str!("session.rs");
        let shell_source = include_str!("shell.rs");

        assert_signal_watcher_signature(
            function_body(session_source, "local_ghostty_attach"),
            "wait_ghostty_attach_completion(&mut attach.exit_rx, stdin_task, &mut signal_watcher)",
        );
        assert_signal_watcher_signature(
            function_body(session_source, "local_zmx_control_attach"),
            "wait_local_attach_completion(&mut child, stdin_task, &mut signal_watcher)",
        );
        assert_signal_watcher_signature(
            function_body(session_source, "local_tmux_control_attach"),
            "wait_local_attach_completion(&mut child, stdin_task, &mut signal_watcher)",
        );
        assert_signal_watcher_signature(
            function_body(shell_source, "run"),
            "signal_watcher.next()",
        );
    }

    #[test]
    fn stdin_response_filter_wiring_covers_raw_mode_attach_paths() {
        let source = include_str!("session.rs");

        assert_stdin_response_filter_signature(
            function_body(source, "stdin_loop"),
            "local stdin_loop",
        );
        assert_coordinator_stdin_response_filter_signature(function_body(
            source,
            "attach_input_coordinator_loop",
        ));

        for (path, body, driver) in [
            (
                "remote v1",
                function_body(source, "bridge_attach"),
                "maybe_spawn_stdin_task(",
            ),
            (
                "remote v2",
                function_body(source, "bridge_attach_v2"),
                "AttachInputCoordinator::spawn(",
            ),
            (
                "local Ghostty",
                function_body(source, "local_ghostty_attach"),
                "maybe_spawn_stdin_task(",
            ),
            (
                "local zmx",
                function_body(source, "local_zmx_control_attach"),
                "maybe_spawn_stdin_task(",
            ),
            (
                "local tmux",
                function_body(source, "local_tmux_control_attach"),
                "maybe_spawn_stdin_task(",
            ),
        ] {
            assert!(
                body.contains(driver),
                "{path} attach path must route stdin through the filtered input driver:\n{body}"
            );
        }
    }

    #[test]
    fn stdin_response_filter_cleans_production_leak_before_send_stdin_tap() {
        let mut filter = StdinResponseFilter::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let sink = AttachInputSink {
            kind: AttachInputSinkKind::TmuxPty { tx },
        };
        let mut sent = Vec::new();

        for chunk in [
            b"type".as_slice(),
            b"\x1b[?0u\x1b[?",
            b"62;52;c\x1b[>1;100;0c",
            b"\x1b[10;5R",
            b"d",
        ] {
            sent.extend_from_slice(&filter_attach_stdin_outbound(&mut filter, &sink, chunk));
        }
        sent.extend_from_slice(&flush_attach_stdin_filter_timeout(&mut filter));

        assert_eq!(sent, b"typed");
        for forbidden in [
            b"0u".as_slice(),
            b"62;52;c",
            b"\x1b[?62;52;c",
            b"\x1b[>1;100;0c",
            b"\x1b[10;5R",
        ] {
            assert!(!contains_bytes(&sent, forbidden));
        }
    }

    #[test]
    fn stdin_response_filter_preserves_detach_hotkey_bytes_if_seen() {
        let mut filter = StdinResponseFilter::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let sink = AttachInputSink {
            kind: AttachInputSinkKind::TmuxPty { tx },
        };

        assert_eq!(
            filter_attach_stdin_outbound(&mut filter, &sink, b"\x1cr"),
            b"\x1cr"
        );
    }

    fn assert_stdin_response_filter_signature(body: &str, label: &str) {
        assert!(
            body.contains("StdinResponseFilter::new()"),
            "{label} must instantiate a per-stream stdin response filter:\n{body}"
        );
        assert!(
            body.contains("filter_attach_stdin_outbound("),
            "{label} must filter bytes immediately before send_stdin:\n{body}"
        );
        assert!(
            body.contains("flush_attach_stdin_filter_timeout("),
            "{label} must flush lone Esc after the disambiguation timeout:\n{body}"
        );
    }

    fn assert_coordinator_stdin_response_filter_signature(body: &str) {
        assert!(
            body.contains("StdinResponseFilter::new()"),
            "remote attach input coordinator must instantiate a per-stream stdin response filter:\n{body}"
        );
        assert!(
            body.contains("&mut stdin_response_filter"),
            "remote attach input coordinator must pass filter state into the byte handler:\n{body}"
        );
        assert!(
            body.contains("flush_attach_stdin_filter_timeout("),
            "remote attach input coordinator must flush lone Esc after the disambiguation timeout:\n{body}"
        );
    }

    fn assert_signal_watcher_signature(body: &str, completion_signature: &str) {
        assert!(
            body.contains("AttachSignalWatcher::new()?"),
            "raw-mode lifecycle must install AttachSignalWatcher:\n{body}"
        );
        assert!(
            body.contains(completion_signature),
            "raw-mode lifecycle must select on the installed signal watcher:\n{body}"
        );
    }

    fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
        let marker = format!("fn {name}");
        let start = source.find(&marker).expect("function marker");
        let after_start = start + marker.len();
        let next = source[after_start..]
            .find("\nasync fn ")
            .or_else(|| source[after_start..].find("\nfn "))
            .map_or(source.len(), |offset| after_start + offset);
        &source[start..next]
    }

    #[test]
    fn signal_feature_reconnect_expired_maps_to_planned_cleanup_without_ris() {
        assert_eq!(
            ReconnectOutcome::Expired.raw_mode_exit_variant(),
            Some(RawModeExitVariant::ReconnectExhausted)
        );
        assert_eq!(
            raw_mode_cleanup_sequence(RawModeExitVariant::ReconnectExhausted),
            RAW_MODE_CLEANUP_NORMAL
        );
    }

    #[test]
    fn attach_mode_tracker_persists_across_reconnect_and_resets_for_fresh_attach() {
        let tracker = new_terminal_mode_tracker();

        assert_eq!(
            track_host_bound_bytes(&tracker, b"\x1b[>1u\x1b[?1049h").unwrap(),
            b""
        );
        assert!(tracked_terminal_mode_state(&tracker).kitty_keyboard_depth > 0);
        assert!(tracked_terminal_mode_state(&tracker).alt_screen.is_some());

        assert_eq!(
            track_host_bound_bytes(&tracker, b"reconnected output").unwrap(),
            b""
        );
        assert!(tracked_terminal_mode_state(&tracker).kitty_keyboard_depth > 0);
        assert!(tracked_terminal_mode_state(&tracker).alt_screen.is_some());

        let fresh_attach_tracker = new_terminal_mode_tracker();
        assert_eq!(
            tracked_terminal_mode_state(&fresh_attach_tracker),
            TerminalModeState::default()
        );
    }

    #[test]
    fn attach_mode_tracker_defensive_emit_fires_once_per_symptom2_transition() {
        let tracker = new_terminal_mode_tracker();

        assert_eq!(
            track_host_bound_bytes(&tracker, b"\x1b[>1u\x1b[=15u\x1b[>4;2m\x1b[?1049h").unwrap(),
            b""
        );
        assert_eq!(
            track_host_bound_bytes(&tracker, b"\x1b[?1049l").unwrap(),
            b""
        );
        assert_eq!(
            track_host_bound_bytes(&tracker, b"prompt").unwrap(),
            b"\x1b[<u\x1b[=0u\x1b[>4;0m"
        );
        assert_eq!(flush_host_bound_mode_tracker(&tracker).unwrap(), b"");

        let clean_tracker = new_terminal_mode_tracker();
        assert_eq!(
            track_host_bound_bytes(&clean_tracker, b"\x1b[>1u\x1b[?1049h\x1b[?1049l\x1b[<u",)
                .unwrap(),
            b""
        );
    }

    #[test]
    fn attach_mode_tracker_defers_defensive_emit_for_split_kitty_pop() {
        let tracker = new_terminal_mode_tracker();

        assert_eq!(
            track_host_bound_bytes(&tracker, b"\x1b[>1u\x1b[?1049h").unwrap(),
            b""
        );
        assert_eq!(
            track_host_bound_bytes(&tracker, b"\x1b[?1049l").unwrap(),
            b""
        );
        assert_eq!(track_host_bound_bytes(&tracker, b"\x1b[<u").unwrap(), b"");
        assert_eq!(flush_host_bound_mode_tracker(&tracker).unwrap(), b"");
    }

    #[test]
    fn attach_mode_tracker_emits_defensive_reset_after_bounded_window_without_pop() {
        let tracker = new_terminal_mode_tracker();

        assert_eq!(
            track_host_bound_bytes(&tracker, b"\x1b[>1u\x1b[?1049h").unwrap(),
            b""
        );
        assert_eq!(
            track_host_bound_bytes(&tracker, b"\x1b[?1049l").unwrap(),
            b""
        );
        assert_eq!(
            track_host_bound_bytes(&tracker, b"next frame without pop").unwrap(),
            b"\x1b[<u"
        );
        assert_eq!(flush_host_bound_mode_tracker(&tracker).unwrap(), b"");
    }

    fn sanitize_host_output_chunks(chunks: &[&[u8]]) -> Vec<u8> {
        let mut sanitizer = HostOutputSanitizer::new();
        let mut output = Vec::new();
        for chunk in chunks {
            output.extend_from_slice(&sanitizer.feed(chunk));
        }
        output.extend_from_slice(&sanitizer.finish());
        output
    }

    fn assert_sanitizes_to(input: &[u8], expected: &[u8]) {
        let output = sanitize_host_output_chunks(&[input]);
        assert_eq!(
            output,
            expected,
            "sanitized output mismatch for {:?}",
            String::from_utf8_lossy(input)
        );
    }

    #[test]
    fn host_output_sanitizer_drops_da1_response() {
        let input = b"hello\x1b[?62;52;cworld";
        assert_sanitizes_to(input, b"helloworld");
        assert_eq!(input.len() - b"\x1b[?62;52;c".len(), b"helloworld".len());
    }

    #[test]
    fn host_output_sanitizer_drops_da2_response() {
        let output = sanitize_host_output_chunks(&[b"before\x1b[>1;100;0cafter"]);
        assert_eq!(output, b"beforeafter");
        assert!(!contains_bytes(&output, b"\x1b[>1;100;0c"));
    }

    #[test]
    fn host_output_sanitizer_drops_kitty_csi_u_response_values() {
        for response in [b"\x1b[?0u".as_slice(), b"\x1b[?15u", b"\x1b[?1;2:3u"] {
            let mut input = b"pre".to_vec();
            input.extend_from_slice(response);
            input.extend_from_slice(b"post");
            let output = sanitize_host_output_chunks(&[&input]);
            assert_eq!(output, b"prepost");
            assert!(!contains_bytes(&output, b"\x1b[?"));
            assert!(!contains_bytes(&output, response));
        }
    }

    #[test]
    fn host_output_sanitizer_drops_dsr_cpr_responses() {
        assert_sanitizes_to(b"pre\x1b[12;40Rpost", b"prepost");
        assert_sanitizes_to(b"pre\x1b[?12;40Rpost", b"prepost");
    }

    #[test]
    fn host_output_sanitizer_drops_da_query_shapes() {
        assert_sanitizes_to(b"pre\x1b[cpost", b"prepost");
        assert_sanitizes_to(b"before\x1b[>cafter", b"beforeafter");
    }

    #[test]
    fn host_output_sanitizer_drops_dsr_cpr_query_shape() {
        assert_sanitizes_to(b"x\x1b[6ny", b"xy");
    }

    #[test]
    fn host_output_sanitizer_drops_kitty_query_shapes() {
        for query in [
            b"\x1b[?u".as_slice(),
            b"\x1b[>1u",
            b"\x1b[>15u",
            b"\x1b[=15u",
            b"\x1b[=0u",
            b"\x1b[<u",
        ] {
            let mut input = b"pre".to_vec();
            input.extend_from_slice(query);
            input.extend_from_slice(b"post");
            let output = sanitize_host_output_chunks(&[&input]);
            assert_eq!(
                output,
                b"prepost",
                "query leaked: {:?}",
                String::from_utf8_lossy(query)
            );
            assert!(!contains_bytes(&output, query));
        }
    }

    #[test]
    fn host_output_sanitizer_is_chunk_boundary_safe_inside_responses() {
        for response in [
            b"\x1b[?62;52;c".as_slice(),
            b"\x1b[>1;100;0c",
            b"\x1b[?1;2:3u",
            b"\x1b[12;40R",
            b"\x1b[?12;40R",
        ] {
            let mut input = b"pre".to_vec();
            let response_start = input.len();
            input.extend_from_slice(response);
            let response_end = input.len();
            input.extend_from_slice(b"post");

            for split in response_start..=response_end {
                let output = sanitize_host_output_chunks(&[&input[..split], &input[split..]]);
                assert_eq!(
                    output,
                    b"prepost",
                    "response {:?} leaked with split {split}",
                    String::from_utf8_lossy(response)
                );
            }
        }
    }

    #[test]
    fn host_output_sanitizer_preserves_unrelated_csi_and_osc_traffic() {
        let inputs = [
            b"cursor\x1b[10;20Hdone".as_slice(),
            b"sgr\x1b[31mdone",
            b"altscreen\x1b[?1049h\x1b[?1049ldone",
            b"title\x1b]0;Portl title\x07done",
            b"title-st\x1b]0;Portl title\x1b\\done",
            b"paste\x1b[?2004h\x1b[?2004ldone",
            b"modify-other-keys\x1b[>4;0mdone",
        ];
        for input in inputs {
            let output = sanitize_host_output_chunks(&[input]);
            assert_eq!(
                output,
                input,
                "unrelated sequence must be preserved: {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn host_output_sanitizer_preserves_unrelated_csi_osc_while_stripping_queries() {
        let input = b"pre\x1b[31mred\x1b[c\x1b[10;20Hpos\x1b[>c\x1b[?1049halt\x1b[6n\x1b]0;Portl title\x07title\x1b[?u\x1b[?2004hpaste\x1b[>15u\x1b[?2004lpost";
        let expected = b"pre\x1b[31mred\x1b[10;20Hpos\x1b[?1049halt\x1b]0;Portl title\x07title\x1b[?2004hpaste\x1b[?2004lpost";
        assert_sanitizes_to(input, expected);
    }

    #[test]
    fn host_output_sanitizer_query_branch_is_chunk_boundary_safe() {
        for query in [
            b"\x1b[c".as_slice(),
            b"\x1b[>c",
            b"\x1b[6n",
            b"\x1b[?u",
            b"\x1b[>15u",
            b"\x1b[=15u",
            b"\x1b[<u",
        ] {
            let mut input = b"pre".to_vec();
            let query_start = input.len();
            input.extend_from_slice(query);
            let query_end = input.len();
            input.extend_from_slice(b"post");

            for split in query_start..=query_end {
                let output = sanitize_host_output_chunks(&[&input[..split], &input[split..]]);
                assert_eq!(
                    output,
                    b"prepost",
                    "query {:?} leaked with split {split}",
                    String::from_utf8_lossy(query)
                );
            }
        }
    }

    #[test]
    fn host_output_sanitizer_preserves_partial_non_query_csi_after_split() {
        let output = sanitize_host_output_chunks(&[b"pre\x1b[", b"31mred\x1b[10;20Hpost"]);
        assert_eq!(output, b"pre\x1b[31mred\x1b[10;20Hpost");
    }

    #[test]
    fn host_output_sanitizer_keeps_buffer_bounded_under_dense_queries() {
        let mut sanitizer = HostOutputSanitizer::new();
        let queries = [
            b"\x1b[c".as_slice(),
            b"\x1b[>c",
            b"\x1b[6n",
            b"\x1b[?u",
            b"\x1b[>15u",
            b"\x1b[=15u",
            b"\x1b[<u",
        ];
        let initial_capacity = sanitizer.buffer.capacity();
        let mut output = Vec::new();
        for index in 0..16_384 {
            output.extend_from_slice(&sanitizer.feed(queries[index % queries.len()]));
            assert!(sanitizer.buffer.len() <= HOST_OUTPUT_SANITIZER_BUFFER_CAPACITY);
            assert_eq!(sanitizer.buffer.capacity(), initial_capacity);
        }
        output.extend_from_slice(&sanitizer.finish());
        assert!(output.is_empty());
    }

    #[test]
    fn host_output_sanitizer_strips_multiple_sequential_responses() {
        assert_sanitizes_to(b"pre\x1b[?62;52;c\x1b[>1;100;0c\x1b[?0upost", b"prepost");
        assert_sanitizes_to(b"a\x1b[?62;52;cb\x1b[12;40Rc\x1b[?15ud", b"abcd");
    }

    #[tokio::test]
    async fn host_output_sanitizer_composes_with_host_write_path() {
        let display = AttachDisplay::new(80, 24);
        hold_stdout(&display).await;
        let tracker = new_terminal_mode_tracker();

        for chunk in [
            b"pre\x1b".as_slice(),
            b"[?62;52;c\x1b[>1",
            b";100;0c\x1b[?0u",
            b"\x1b[12;40Rpost",
        ] {
            write_tracked_output(&display, AttachOutputStream::Stdout, chunk, &tracker)
                .await
                .unwrap();
        }
        flush_tracked_output(&display, AttachOutputStream::Stdout, &tracker)
            .await
            .unwrap();

        let output = take_held_stdout(&display).await;
        assert_eq!(output, b"prepost");
        for forbidden in [
            b"\x1b[?62;52;c".as_slice(),
            b"\x1b[>1;100;0c",
            b"\x1b[?0u",
            b"\x1b[12;40R",
        ] {
            assert!(!contains_bytes(&output, forbidden));
        }
    }

    #[tokio::test]
    async fn host_output_sanitizer_deferred_mode_reset_does_not_emit_response_prefix() {
        let display = AttachDisplay::new(80, 24);
        hold_stdout(&display).await;
        let tracker = new_terminal_mode_tracker();

        write_tracked_output(
            &display,
            AttachOutputStream::Stdout,
            b"\x1b[>1u\x1b[?1049h\x1b[?1049lpre\x1b[?62",
            &tracker,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let output = take_held_stdout(&display).await;
        assert!(!contains_bytes(&output, b"\x1b[?62"));
        assert!(contains_bytes(&output, b"\x1b[<u"));
        assert!(!contains_bytes(&output, b"\x1b[=0u"));
        assert!(!contains_bytes(&output, b"\x1b[>4;0m"));

        write_tracked_output(&display, AttachOutputStream::Stdout, b";52;cpost", &tracker)
            .await
            .unwrap();
        flush_tracked_output(&display, AttachOutputStream::Stdout, &tracker)
            .await
            .unwrap();
        let output = take_held_stdout(&display).await;
        assert_eq!(output, b"post");
    }

    async fn hold_stdout(display: &AttachDisplay) {
        let mut state = display.inner.lock().await;
        state.gate.set_holding(true);
    }

    async fn take_held_stdout(display: &AttachDisplay) -> Vec<u8> {
        let mut state = display.inner.lock().await;
        state.gate.take_stdout()
    }

    async fn take_held_stderr(display: &AttachDisplay) -> Vec<u8> {
        let mut state = display.inner.lock().await;
        state.gate.take_stderr()
    }

    #[tokio::test]
    async fn host_output_sanitizer_keeps_stdout_and_stderr_state_isolated() {
        let display = AttachDisplay::new(80, 24);
        hold_stdout(&display).await;
        let tracker = new_terminal_mode_tracker();

        write_tracked_output(
            &display,
            AttachOutputStream::Stderr,
            b"err-pre\x1b[?",
            &tracker,
        )
        .await
        .unwrap();
        write_tracked_output(
            &display,
            AttachOutputStream::Stdout,
            b"out-pre\x1b[?62;52;c",
            &tracker,
        )
        .await
        .unwrap();
        flush_tracked_output(&display, AttachOutputStream::Stdout, &tracker)
            .await
            .unwrap();

        let stdout = take_held_stdout(&display).await;
        let stderr = take_held_stderr(&display).await;
        assert_eq!(stdout, b"out-pre");
        assert_eq!(stderr, b"err-pre");
        for stream in [&stdout, &stderr] {
            assert!(!contains_bytes(stream, b";c"));
            assert!(!contains_bytes(stream, b";u"));
            assert!(!contains_bytes(stream, b";R"));
            assert!(!contains_bytes(stream, b"\x1b[?"));
        }

        write_tracked_output(&display, AttachOutputStream::Stderr, b"62;52;c", &tracker)
            .await
            .unwrap();
        flush_tracked_output(&display, AttachOutputStream::Stderr, &tracker)
            .await
            .unwrap();
        let stderr = take_held_stderr(&display).await;
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn attach_mode_tracker_idle_timer_flushes_silent_guest_defensive_reset() {
        let display = AttachDisplay::new(80, 24);
        hold_stdout(&display).await;
        let tracker = new_terminal_mode_tracker();

        write_tracked_output(
            &display,
            AttachOutputStream::Stdout,
            b"\x1b[>1u\x1b[?1049h",
            &tracker,
        )
        .await
        .unwrap();
        write_tracked_output(
            &display,
            AttachOutputStream::Stdout,
            b"\x1b[?1049l",
            &tracker,
        )
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(250)).await;

        let output = take_held_stdout(&display).await;
        assert!(
            output
                .windows(b"\x1b[<u".len())
                .any(|window| window == b"\x1b[<u"),
            "idle timer should flush defensive reset before any later output: {output:?}"
        );
        assert!(!contains_bytes(&output, b"\x1b[=0u"));
        assert!(!contains_bytes(&output, b"\x1b[>4;0m"));
    }

    #[tokio::test]
    async fn zmx_control_eof_flushes_deferred_defensive_reset() {
        let display = AttachDisplay::new(80, 24);
        hold_stdout(&display).await;
        let tracker = new_terminal_mode_tracker();
        let mut frames = Vec::new();
        zmx_control::write_frame(
            &mut frames,
            zmx_control::TAG_OUTPUT,
            b"\x1b[>1u\x1b[?1049h\x1b[?1049l",
        )
        .await
        .unwrap();
        let mut reader = frames.as_slice();

        copy_zmx_control_output(&mut reader, &display, &tracker)
            .await
            .unwrap();

        let output = take_held_stdout(&display).await;
        assert!(
            output
                .windows(b"\x1b[<u".len())
                .any(|window| window == b"\x1b[<u"),
            "zmx EOF should flush defensive reset before stream closes: {output:?}"
        );
        assert!(!contains_bytes(&output, b"\x1b[=0u"));
        assert!(!contains_bytes(&output, b"\x1b[>4;0m"));
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
    fn attach_flight_recorder_caps_and_renders_recent_path_context() {
        let mut recorder = AttachFlightRecorder::new();
        for idx in 0..ATTACH_FLIGHT_RECORDER_CAPACITY + 2 {
            recorder.record_at(
                Duration::from_millis((idx as u64) * 100),
                format!("event {idx}"),
                (idx == ATTACH_FLIGHT_RECORDER_CAPACITY + 1).then_some(AttachPathSnapshot {
                    label: "direct".to_owned(),
                    rtt: Some(Duration::from_millis(234)),
                }),
            );
        }

        let rendered = recorder.render_recent().expect("events render");

        let lines = rendered.lines().collect::<Vec<_>>();
        assert!(
            !lines.iter().any(|line| line.ends_with("event 0")),
            "{rendered}"
        );
        assert!(
            !lines.iter().any(|line| line.ends_with("event 1")),
            "{rendered}"
        );
        assert!(
            lines.iter().any(|line| line.ends_with("event 2")),
            "{rendered}"
        );
        assert!(
            rendered.contains("event 13 (path: direct, rtt: 234ms)"),
            "{rendered}"
        );
    }

    #[test]
    fn attach_flight_recorder_omits_empty_render() {
        let recorder = AttachFlightRecorder::new();

        assert_eq!(recorder.render_recent(), None);
    }

    #[test]
    fn reconnect_policy_scales_ui_debounce_from_observed_rtt() {
        let default = ReconnectPolicy::default_interactive();
        assert_eq!(default.transparent_grace, Duration::from_millis(1500));
        assert_eq!(default.delay_floor, Duration::from_millis(100));

        let high_latency = default.with_observed_rtt(Some(Duration::from_millis(250)));
        assert_eq!(high_latency.transparent_grace, Duration::from_secs(2));
        assert_eq!(high_latency.delay_floor, Duration::from_millis(250));
        assert_eq!(
            high_latency.visible_delay(1, Duration::ZERO),
            Duration::from_millis(250)
        );

        let capped = default.with_observed_rtt(Some(Duration::from_secs(2)));
        assert_eq!(capped.transparent_grace, Duration::from_secs(4));
        assert_eq!(capped.delay_floor, Duration::from_secs(1));
    }

    #[test]
    fn reconnect_attempt_state_tracks_last_observed_rtt() {
        let mut state = ReconnectAttemptState::new();
        state.observe_path(Some(&AttachPathSnapshot {
            label: "direct".to_owned(),
            rtt: Some(Duration::from_millis(220)),
        }));

        assert_eq!(state.last_rtt, Some(Duration::from_millis(220)));

        state.observe_path(Some(&AttachPathSnapshot {
            label: "direct".to_owned(),
            rtt: None,
        }));
        assert_eq!(state.last_rtt, Some(Duration::from_millis(220)));
    }

    #[test]
    fn reconnect_policy_applies_floor_after_transparent_phase() {
        let policy = ReconnectPolicy::for_test(
            Duration::from_millis(500),
            Duration::from_secs(10),
            Duration::from_mins(2),
            Duration::from_millis(100),
        );

        assert_eq!(
            policy.visible_delay(1, Duration::from_millis(0)),
            Duration::from_millis(100)
        );
        assert_eq!(
            policy.visible_delay(8, Duration::from_secs(30)),
            Duration::from_secs(10)
        );
        assert!(policy.retry_budget_remaining(Duration::from_secs(119)));
        assert!(!policy.retry_budget_remaining(Duration::from_mins(2)));
    }

    #[test]
    fn reconnect_control_from_visible_input_recognizes_retry_and_detach() {
        assert_eq!(
            ReconnectControl::from_visible_input(b"\r"),
            Some(ReconnectControl::RetryNow)
        );
        assert_eq!(
            ReconnectControl::from_visible_input(b"\n"),
            Some(ReconnectControl::RetryNow)
        );
        assert_eq!(
            ReconnectControl::from_visible_input(b"d"),
            Some(ReconnectControl::Detach)
        );
        assert_eq!(
            ReconnectControl::from_visible_input(&[0x03]),
            Some(ReconnectControl::Quit)
        );
        assert_eq!(ReconnectControl::from_visible_input(b"x"), None);
    }

    #[test]
    fn reconnect_buffer_caps_without_dropping_accepted_bytes() {
        let mut buffer = ReconnectInputBuffer::new(4);

        assert_eq!(buffer.push(b"ab"), ReconnectBufferPush::Accepted);
        assert_eq!(buffer.push(b"cdef"), ReconnectBufferPush::Full);
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.take(), b"abcd".to_vec());

        assert_eq!(buffer.push(b"ab"), ReconnectBufferPush::Accepted);
        assert_eq!(buffer.push(b"cd"), ReconnectBufferPush::Accepted);
        assert_eq!(buffer.push(b"e"), ReconnectBufferPush::Full);
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.take(), b"abcd".to_vec());
    }

    #[test]
    fn reconnect_session_exists_matches_provider_and_tmux_base_session() {
        let groups = vec![
            test_session_group("zmx", &["dev"]),
            test_session_group("tmux", &["work"]),
        ];

        assert!(session_exists_for_reconnect(&groups, "zmx", "dev"));
        assert!(session_exists_for_reconnect(&groups, "tmux", "work:1.2"));
        assert!(!session_exists_for_reconnect(&groups, "zmx", "missing"));
        assert!(!session_exists_for_reconnect(&groups, "ghostty", "dev"));
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
    fn paste_state_deactivates_after_backpressured_drain() {
        let mut state = PasteState::new(PasteConfig::for_test(16, Duration::from_secs(1)));
        state.activate(Instant::now());
        state.observe_queued(32);
        state.set_backpressured(true);
        assert!(state.is_active());

        state.observe_sent(32);
        assert!(!state.is_active());
        state.set_backpressured(false);
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

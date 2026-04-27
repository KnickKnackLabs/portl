use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use iroh::endpoint::SendStream;
use portl_core::io::BufferedRecv;
use portl_core::net::{
    SessionClient, open_session_attach, open_session_history, open_session_kill, open_session_list,
    open_session_providers, open_session_run,
};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use tokio::io::{AsyncWriteExt, copy};
use tracing::debug;

use crate::commands::peer_resolve::{close_connected, connect_peer};
use crate::commands::session_share::{
    BuiltEnvelope, EnvelopeInputs, ResolveTargetError, build_session_share_envelope,
    classify_share_target, fresh_workspace_handles, load_identity, resolve_rendezvous_url,
    run_offer_against_transport, unix_now,
};
use portl_core::peer_store::PeerStore;
use portl_core::rendezvous::ws::WsRendezvousBackend;
use portl_core::ticket_store::TicketStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SessionHistoryFormat {
    Plain,
    Vt,
    Html,
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

pub fn providers(target: &str, json: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer(target, session_caps()).await?;
        let report = open_session_providers(&connected.connection, &connected.session).await?;
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
        close_connected(connected, b"session complete").await;
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_background();
    result
}

pub fn ls(target: &str, provider: Option<&str>, json: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer(target, session_caps()).await?;
        let sessions = open_session_list(
            &connected.connection,
            &connected.session,
            provider.map(ToOwned::to_owned),
        )
        .await?;
        if json {
            println!("{}", serde_json::to_string_pretty(&sessions)?);
        } else {
            for session in sessions {
                println!("{session}");
            }
        }
        close_connected(connected, b"session complete").await;
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_background();
    result
}

pub fn run(
    target: &str,
    session: Option<&str>,
    provider: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer(target, session_caps()).await?;
        let run = open_session_run(
            &connected.connection,
            &connected.session,
            provider.map(ToOwned::to_owned),
            default_session_name(target, session),
            argv.to_vec(),
        )
        .await?;
        print!("{}", run.stdout);
        eprint!("{}", run.stderr);
        close_connected(connected, b"session complete").await;
        Ok(exit_code_from_i32(run.code))
    });
    runtime.shutdown_background();
    result
}

pub fn history(
    target: &str,
    session: Option<&str>,
    provider: Option<&str>,
    format: SessionHistoryFormat,
) -> Result<ExitCode> {
    if format != SessionHistoryFormat::Plain {
        anyhow::bail!(
            "persistent session history format '{}' is not supported by the zmx provider yet",
            format.as_str()
        );
    }
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer(target, session_caps()).await?;
        let output = open_session_history(
            &connected.connection,
            &connected.session,
            provider.map(ToOwned::to_owned),
            default_session_name(target, session),
        )
        .await?;
        print!("{output}");
        close_connected(connected, b"session complete").await;
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_background();
    result
}

pub fn kill(target: &str, session: Option<&str>, provider: Option<&str>) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer(target, session_caps()).await?;
        open_session_kill(
            &connected.connection,
            &connected.session,
            provider.map(ToOwned::to_owned),
            default_session_name(target, session),
        )
        .await?;
        close_connected(connected, b"session complete").await;
        Ok(ExitCode::SUCCESS)
    });
    runtime.shutdown_background();
    result
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn share(
    target: &str,
    session: Option<&str>,
    provider: Option<&str>,
    ttl: Duration,
    access_ttl: Duration,
    label: Option<&str>,
    rendezvous_url: Option<&str>,
    _yes: bool,
    allow_bearer_fallback: bool,
) -> Result<ExitCode> {
    // Classify target up-front so unsupported forms fail fast without
    // ever echoing the raw input (which may be a ticket credential).
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    let aliases = crate::alias_store::AliasStore::default();
    let form = match classify_share_target(target, &peers, &tickets, &aliases) {
        Ok(form) => form,
        Err(ResolveTargetError::TicketCredential) => {
            anyhow::bail!(
                "session share cannot delegate a ticket credential passed as <TARGET>. \
                 Use a peer-store label, alias, or `endpoint_id` instead."
            );
        }
        Err(err) => return Err(err.into()),
    };

    let session_name = default_session_name(target, session);
    let url = resolve_rendezvous_url(rendezvous_url);
    let identity = load_identity(None)?;
    let origin_label_hint = Some(label.map_or_else(
        || crate::commands::local_machine_label(&hex::encode(identity.verifying_key())),
        ToOwned::to_owned,
    ));
    let target_label_hint = Some(form.target_label_hint());
    let (workspace_id, conflict_handle) = fresh_workspace_handles();

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        // Resolve the target endpoint address so we can mint into it.
        let client_endpoint =
            crate::commands::peer_resolve::bind_client_endpoint(&identity).await?;
        let endpoint_id = form.endpoint_id();
        let resolved_addr = crate::commands::peer_resolve::resolve_endpoint_addr(
            &client_endpoint,
            endpoint_id,
            false,
        )
        .await;
        crate::commands::peer_resolve::close_client_endpoint(client_endpoint, "share resolve")
            .await;
        let (target_addr, _provenance) = resolved_addr?;

        let share_result = tokio::time::timeout(ttl, async {
            // Open the rendezvous transport.
            let backend = WsRendezvousBackend::new(&url)
                .map_err(|e| anyhow!("rendezvous backend: {e}"))?
                .with_timeout(ttl);
            let mut transport = backend
                .connect_transport()
                .await
                .map_err(|e| anyhow!("connect to rendezvous server: {e}"))?;

            eprintln!(
                "portl: sharing {} as session \"{session_name}\"",
                form.safe_display()
            );

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
                        provider,
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

pub fn attach(
    target: &str,
    session: Option<&str>,
    provider: Option<&str>,
    user: Option<&str>,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer(target, session_caps()).await?;
        let (cols, rows) = size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        let session_name = default_session_name(target, session);
        eprintln!(
            "portl: using session provider {}",
            provider.unwrap_or("target default")
        );
        eprintln!("portl: attaching to session \"{session_name}\"");
        let session = open_session_attach(
            &connected.connection,
            &connected.session,
            provider.map(ToOwned::to_owned),
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

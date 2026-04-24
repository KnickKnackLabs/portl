use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
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

use crate::commands::peer_resolve::connect_peer;

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
            println!("PROVIDER  AVAILABLE  DEFAULT  NOTES");
            for provider in &report.providers {
                let available = if provider.available { "yes" } else { "no" };
                let default = if report.default_provider.as_deref() == Some(provider.name.as_str())
                {
                    "yes"
                } else {
                    "no"
                };
                println!(
                    "{:<8}  {:<9}  {:<7}  {}",
                    provider.name,
                    available,
                    default,
                    provider.notes.as_deref().unwrap_or("")
                );
            }
        }
        close_connected(connected).await;
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
        close_connected(connected).await;
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
        close_connected(connected).await;
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
        close_connected(connected).await;
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
        close_connected(connected).await;
        Ok(ExitCode::SUCCESS)
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
        close_connected(connected).await;
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

async fn close_connected(connected: crate::commands::peer_resolve::ConnectedPeer) {
    connected.connection.close(0u32.into(), b"session complete");
    if tokio::time::timeout(Duration::from_millis(250), connected.endpoint.close())
        .await
        .is_err()
    {
        debug!("timed out closing session endpoint");
    }
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

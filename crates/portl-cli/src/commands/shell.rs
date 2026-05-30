use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::terminal::size;
use iroh::endpoint::SendStream;
use portl_core::io::BufferedRecv;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{ShellClient, open_shell};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use tokio::io::{AsyncWriteExt, copy};
use tracing::debug;

use crate::commands::peer_resolve::{close_connected, connect_peer, connect_peer_quiet};
use crate::commands::session::{AttachSignalWatcher, RawModeExitVariant, RawModeGuard};

pub fn run(peer: &str, cwd: Option<&str>, user: Option<&str>) -> Result<ExitCode> {
    run_with_options(peer, cwd, user, ShellRunOptions::default())
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ShellRunOptions {
    pub(crate) quiet_resolve: bool,
    pub(crate) close_stdin: bool,
}

pub(crate) fn run_with_options(
    peer: &str,
    cwd: Option<&str>,
    user: Option<&str>,
    options: ShellRunOptions,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = if options.quiet_resolve {
            connect_peer_quiet(peer, shell_caps()).await?
        } else {
            connect_peer(peer, shell_caps()).await?
        };
        let (cols, rows) = size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        let shell = open_shell(
            &connected.connection,
            &connected.session,
            user.map(ToOwned::to_owned),
            cwd.map(ToOwned::to_owned),
            PtyCfg { term, cols, rows },
        )
        .await?;

        let raw_guard = if std::io::stdin().is_terminal() {
            Some(RawModeGuard::new()?)
        } else {
            None
        };
        let mut signal_watcher = AttachSignalWatcher::new()?;

        let ShellClient {
            control_send: _control_send,
            control_recv: _control_recv,
            stdin,
            stdout: mut stdout_recv,
            stderr: mut stderr_recv,
            mut exit,
            signal: _signal,
            resize,
        } = shell;

        let stdin_task = if options.close_stdin {
            close_remote_stdin(stdin);
            None
        } else {
            maybe_spawn_stdin_task(stdin)?
        };

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

        let resize_task = resize.map(|mut resize| {
            tokio::spawn(async move {
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
            })
        });

        let completion = tokio::select! {
            code = read_exit(&mut exit) => ShellCompletion::Exited(code?),
            signal = signal_watcher.next() => ShellCompletion::Signal(signal),
        };
        if let Some(task) = resize_task {
            task.abort();
        }
        if let Some(stdin_task) = stdin_task {
            stdin_task.abort();
            let _ = stdin_task.await;
        }
        let code = finish_shell_completion(completion, raw_guard, stdout_task, stderr_task).await?;
        close_connected(connected, b"shell complete").await;
        Ok(exit_code_from_i32(code))
    });
    runtime.shutdown_background();
    result
}

fn shell_caps() -> Capabilities {
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
        unix: None,
    }
}

enum ShellCompletion {
    Exited(i32),
    Signal(RawModeExitVariant),
}

async fn finish_shell_completion(
    completion: ShellCompletion,
    raw_guard: Option<RawModeGuard>,
    stdout_task: tokio::task::JoinHandle<Result<()>>,
    stderr_task: tokio::task::JoinHandle<Result<()>>,
) -> Result<i32> {
    match completion {
        ShellCompletion::Exited(code) => {
            await_output_task(stdout_task, "stdout").await?;
            await_output_task(stderr_task, "stderr").await?;
            if let Some(raw_guard) = raw_guard {
                raw_guard.finish(RawModeExitVariant::Normal);
            }
            Ok(code)
        }
        ShellCompletion::Signal(variant) => {
            stdout_task.abort();
            stderr_task.abort();
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            if let Some(raw_guard) = raw_guard {
                raw_guard.finish(variant);
            }
            Ok(1)
        }
    }
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    let code = u8::try_from(code).unwrap_or(1);
    ExitCode::from(code)
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
        close_remote_stdin(send);
        return Ok(None);
    }

    Ok(Some(tokio::spawn(async move {
        let mut stdin_src = tokio::io::stdin();
        let _ = stdin_loop(&mut send, &mut stdin_src).await;
    })))
}

fn close_remote_stdin(mut send: SendStream) {
    if let Err(err) = send.finish().context("finish remote stdin") {
        debug!(%err, "remote stdin already closed");
    }
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
mod ssh_shell_options_tests {
    use super::ShellRunOptions;

    #[test]
    fn default_shell_options_preserve_existing_behavior() {
        let options = ShellRunOptions::default();
        assert!(!options.quiet_resolve);
        assert!(!options.close_stdin);
    }
}

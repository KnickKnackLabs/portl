use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use portl_core::io::BufferedRecv;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{ShellClient, open_shell};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use tokio::io::{AsyncWriteExt, copy};

use crate::commands::peer::connect_peer;

pub fn run(peer: &str, cwd: Option<&str>, user: Option<&str>) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let connected = connect_peer(peer, shell_caps()).await?;
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

        let ShellClient {
            control_send: _control_send,
            control_recv: _control_recv,
            mut stdin,
            stdout: mut stdout_recv,
            stderr: mut stderr_recv,
            mut exit,
            signal: _signal,
            resize,
        } = shell;

        let stdin_task = tokio::spawn(async move {
            let mut stdin_src = tokio::io::stdin();
            copy(&mut stdin_src, &mut stdin)
                .await
                .context("copy local stdin")?;
            stdin.finish().context("finish remote stdin")?;
            Ok::<_, anyhow::Error>(())
        });

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

        let code = read_exit(&mut exit).await?;
        if let Some(task) = resize_task {
            task.abort();
        }
        stdin_task.await.context("join stdin task")??;
        stdout_task.await.context("join stdout task")??;
        stderr_task.await.context("join stderr task")??;
        drop(raw_guard);
        connected.connection.close(0u32.into(), b"shell complete");
        connected.endpoint.close().await;
        Ok(exit_code_from_i32(code))
    })
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
    }
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    let code = u8::try_from(code).unwrap_or(1);
    ExitCode::from(code)
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

async fn read_exit(recv: &mut BufferedRecv) -> Result<i32> {
    let frame = recv
        .read_frame::<portl_proto::shell_v1::ExitFrame>(128)
        .await?
        .context("missing exit frame")?;
    Ok(frame.code)
}

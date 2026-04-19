use std::process::ExitCode;

use anyhow::{Context, Result};
use portl_core::io::BufferedRecv;
use portl_core::net::{ShellClient, open_exec};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use tokio::io::{AsyncWriteExt, copy};

use crate::commands::peer::connect_peer;

pub fn run(peer: &str, cwd: Option<&str>, user: Option<&str>, argv: &[String]) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let connected = connect_peer(peer, exec_caps()).await?;
        let exec = open_exec(
            &connected.connection,
            &connected.session,
            user.map(ToOwned::to_owned),
            cwd.map(ToOwned::to_owned),
            argv.to_vec(),
        )
        .await?;

        let ShellClient {
            control_send: _control_send,
            control_recv: _control_recv,
            mut stdin,
            stdout: mut stdout_recv,
            stderr: mut stderr_recv,
            mut exit,
            signal: _,
            resize: _,
        } = exec;

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

        let code = read_exit(&mut exit).await?;
        stdin_task.await.context("join stdin task")??;
        stdout_task.await.context("join stdout task")??;
        stderr_task.await.context("join stderr task")??;
        connected.connection.close(0u32.into(), b"exec complete");
        connected.endpoint.close().await;
        Ok(exit_code_from_i32(code))
    })
}

fn exec_caps() -> Capabilities {
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

async fn read_exit(recv: &mut BufferedRecv) -> Result<i32> {
    let frame = recv
        .read_frame::<portl_proto::shell_v1::ExitFrame>(128)
        .await?
        .context("missing exit frame")?;
    Ok(frame.code)
}

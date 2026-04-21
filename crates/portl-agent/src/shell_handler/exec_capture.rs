use std::process::{Command as StdCommand, Stdio};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc;

use crate::shell_registry::StdinMessage;

use super::IO_CHUNK;
use super::spawn::install_exec_session_pre_exec;

/// Captured output of a single exec-path spawn. Used by the
/// `tests/rlimits.rs` integration test suite to observe
/// `apply_rlimits()` effects from outside the crate.
#[derive(Debug)]
pub struct ExecCapture {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Test helper that runs `program argv` through the same rlimits hook
/// the production exec path uses, then collects stdout/stderr.
#[cfg(unix)]
pub async fn run_exec_capture(
    program: &str,
    argv: &[&str],
    env: Vec<(String, String)>,
) -> std::io::Result<ExecCapture> {
    let mut command = StdCommand::new(program);
    command.args(argv);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.env_clear();
    for (k, v) in env {
        command.env(k, v);
    }
    // Inherit a minimal PATH so `/bin/sh` can resolve builtins.
    command.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    install_exec_session_pre_exec(&mut command);
    let output = TokioCommand::from(command).output().await?;
    Ok(ExecCapture {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

pub(super) async fn exec_stdin_task(
    mut stdin: tokio::process::ChildStdin,
    mut rx: mpsc::Receiver<StdinMessage>,
) -> Result<()> {
    while let Some(message) = rx.recv().await {
        match message {
            StdinMessage::Data(bytes) => {
                stdin.write_all(&bytes).await.context("write exec stdin")?;
            }
            StdinMessage::Close => break,
        }
    }
    Ok(())
}

pub(super) async fn output_reader_task<R>(mut reader: R, tx: mpsc::Sender<Vec<u8>>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0_u8; IO_CHUNK];
    loop {
        let read = reader.read(&mut buf).await.context("read child output")?;
        if read == 0 {
            return Ok(());
        }
        if tx.send(buf[..read].to_vec()).await.is_err() {
            return Ok(());
        }
    }
}

use std::os::fd::AsRawFd;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use iroh::endpoint::SendStream;
use tokio::io::AsyncReadExt;

use crate::shell_registry::{PtyCommand, ShellOutput, ShellProcess, StdinMessage};
use crate::stream_io::BufferedRecv;

use super::shutdown::send_signal;
use super::{IO_CHUNK, MAX_RESIZE_BYTES, MAX_SIGNAL_BYTES};

pub(crate) async fn pump_stdin(mut recv: BufferedRecv, process: Arc<ShellProcess>) -> Result<()> {
    let mut buf = vec![0_u8; IO_CHUNK];
    loop {
        let read = recv.read(&mut buf).await.context("read shell stdin")?;
        if read == 0 {
            let _ = process.stdin_tx.send(StdinMessage::Close).await;
            return Ok(());
        }
        process
            .stdin_tx
            .send(StdinMessage::Data(buf[..read].to_vec()))
            .await
            .context("forward shell stdin")?;
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ShellOutputKind {
    Stdout,
    Stderr,
}

fn output_for(process: &ShellProcess, kind: ShellOutputKind) -> &ShellOutput {
    match kind {
        ShellOutputKind::Stdout => &process.stdout,
        ShellOutputKind::Stderr => &process.stderr,
    }
}

async fn wait_process_exit(process: &ShellProcess) -> Result<i32> {
    let initial = *process
        .exit_code
        .lock()
        .map_err(|_| anyhow!("exit code mutex poisoned"))?;
    if let Some(code) = initial {
        return Ok(code);
    }

    let mut rx = process.exit_rx();
    if let Some(code) = *rx.borrow() {
        return Ok(code);
    }
    loop {
        rx.changed().await.context("wait for shell exit")?;
        if let Some(code) = *rx.borrow() {
            return Ok(code);
        }
    }
}

pub(crate) async fn pump_output(
    mut send: SendStream,
    process: &ShellProcess,
    kind: ShellOutputKind,
) -> Result<()> {
    let output = output_for(process, kind);
    if let Some(mut rx) = output.take_channel().await? {
        let mut query_stripper = matches!(kind, ShellOutputKind::Stdout)
            .then(|| process.strip_stdout_queries())
            .filter(|enabled| *enabled)
            .map(|_| portl_core::QueryStripper::new());
        while let Some(chunk) = rx.recv().await {
            let chunk = output_chunk_for_wire(&mut query_stripper, chunk);
            if !chunk.is_empty() {
                send.write_all(&chunk).await.context("write shell output")?;
            }
        }
        if let Some(stripper) = query_stripper.as_mut() {
            let tail = stripper.finish();
            if !tail.is_empty() {
                send.write_all(&tail).await.context("write shell output")?;
            }
        }
        send.finish().context("finish shell output")?;
        return Ok(());
    }

    let mut closed = output
        .empty_close_signal()
        .context("empty output stream missing close signal")?;
    loop {
        if *closed.borrow_and_update() {
            break;
        }
        closed
            .changed()
            .await
            .context("wait for empty output close")?;
    }
    send.finish().context("finish empty shell output")?;
    Ok(())
}

fn output_chunk_for_wire(
    query_stripper: &mut Option<portl_core::QueryStripper>,
    chunk: Vec<u8>,
) -> Vec<u8> {
    if let Some(stripper) = query_stripper.as_mut() {
        stripper.feed(&chunk)
    } else {
        chunk
    }
}

pub(crate) async fn pump_signals(mut recv: BufferedRecv, process: &ShellProcess) -> Result<()> {
    while let Some(frame) = recv
        .read_frame::<portl_proto::shell_v1::SignalFrame>(MAX_SIGNAL_BYTES)
        .await?
    {
        if process.signal_target.is_some() {
            send_signal(process.signal_target, frame.sig);
        } else if frame.sig == 2 {
            process
                .stdin_tx
                .send(StdinMessage::Data(vec![0x03]))
                .await
                .context("forward signal as terminal interrupt byte")?;
        }
    }
    Ok(())
}

pub(crate) async fn pump_resizes(mut recv: BufferedRecv, process: &ShellProcess) -> Result<()> {
    while let Some(frame) = recv
        .read_frame::<portl_proto::shell_v1::ResizeFrame>(MAX_RESIZE_BYTES)
        .await?
    {
        #[cfg(unix)]
        if let Some(pty_tx) = process.pty_tx.as_ref() {
            pty_tx
                .send(PtyCommand::Resize {
                    rows: frame.rows,
                    cols: frame.cols,
                })
                .map_err(|_| anyhow!("pty resize channel closed"))
                .context("forward pty resize")?;
        }
        #[cfg(not(unix))]
        let _ = frame;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn resize_pty(master: &impl AsRawFd, rows: u16, cols: u16) -> std::io::Result<()> {
    let ws = nix::libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY(unsafe_code): TIOCSWINSZ on a valid pty master fd is a
    // well-defined ioctl; we borrow the fd via AsRawFd for the duration
    // of the call only.
    #[allow(unsafe_code)]
    let rc = unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &ws) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) async fn pump_exit(mut send: SendStream, process: &ShellProcess) -> Result<()> {
    let frame = portl_proto::shell_v1::ExitFrame {
        code: wait_process_exit(process).await?,
    };
    send.write_all(&postcard::to_stdvec(&frame)?).await?;
    send.finish().context("finish shell exit stream")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::output_chunk_for_wire;

    #[test]
    fn zmx_stdout_query_stripper_removes_queries_and_keeps_surrounding_bytes() {
        let mut stripper = Some(portl_core::QueryStripper::new());
        let chunk = b"pre\x1b[c\x1b[>c\x1b[6n\x1b[?u\x1b[>1u\x1b[=15u\x1b[<upost".to_vec();

        let output = output_chunk_for_wire(&mut stripper, chunk);

        assert_eq!(output, b"prepost");
    }

    #[test]
    fn zmx_stdout_query_stripper_holds_split_queries() {
        let mut stripper = Some(portl_core::QueryStripper::new());

        let first = output_chunk_for_wire(&mut stripper, b"pre\x1b[=".to_vec());
        let second = output_chunk_for_wire(&mut stripper, b"15upost".to_vec());

        assert_eq!(first, b"pre");
        assert_eq!(second, b"post");
    }

    #[test]
    fn zmx_stdout_query_stripper_does_not_panic_on_malformed_bursts() {
        let mut stripper = Some(portl_core::QueryStripper::new());
        let mut burst = Vec::new();
        for _ in 0..120 {
            burst.extend_from_slice(b"\x1b[Xhello\x1b[?Xhello\x1b[?;;uhello\x1bZhello");
        }

        let output = output_chunk_for_wire(&mut stripper, burst);

        assert!(
            output
                .windows(b"hello".len())
                .any(|window| window == b"hello")
        );
    }
}

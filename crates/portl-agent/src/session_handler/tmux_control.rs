use std::os::fd::OwnedFd;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;

use portl_core::attach_control::is_ctrl_backslash_sequence;
use portl_core::terminal::tmux_cc::{
    self, Decoder as TmuxCcDecoder, TmuxControlEvent, parse_control_line,
};

use crate::shell_handler::pty_master::{
    PendingPtyWrite, read_pty_chunk, set_nonblocking, write_one_pending_pty_chunk, write_pty_all,
};
use crate::shell_registry::{PtyCommand, StdinMessage};

const TMUX_CC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Queue capacity for encoded tmux send-keys commands.
///
/// `send_keys_command` encodes each raw byte as ` XX` (3 ASCII chars) plus a
/// fixed `send-keys -H` prefix per 128-byte chunk — roughly a 3× expansion
/// ratio at full chunk size, much worse for small payloads.  Size this buffer
/// to absorb at least 1 MiB of raw paste input after hex encoding (≈ 4 MiB
/// encoded at worst-case small-chunk ratio).
const TMUX_PTY_INPUT_QUEUE_BYTES: usize = 4 * 1024 * 1024;

pub(crate) async fn pump_tmux_cc_pty(
    master: OwnedFd,
    stdout_tx: mpsc::Sender<Vec<u8>>,
    stderr_tx: mpsc::Sender<Vec<u8>>,
    mut stdin_rx: mpsc::Receiver<StdinMessage>,
    mut pty_rx: mpsc::UnboundedReceiver<PtyCommand>,
    initial_commands: Vec<Vec<u8>>,
) -> Result<()> {
    set_nonblocking(&master)?;
    let master = tokio::io::unix::AsyncFd::new(master).context("register tmux -CC pty")?;
    let mut decoder = TmuxCcDecoder::default();
    let mut read_buf = vec![0_u8; 16 * 1024];
    let mut line_buf = Vec::new();
    let mut drain_deadline = None;
    let mut pending_initial_commands = Some(initial_commands);
    let mut pending_input = PendingPtyWrite::new(TMUX_PTY_INPUT_QUEUE_BYTES);

    loop {
        let drain_sleep = async {
            if let Some(deadline) = drain_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            biased;
            Some(message) = stdin_rx.recv(), if drain_deadline.is_none() => {
                match message {
                    StdinMessage::Data(data) => {
                        if is_ctrl_backslash_sequence(&data) {
                            // Discard queued send-keys before issuing detach:
                            // the client is leaving and the buffered input
                            // would have no meaningful recipient.
                            pending_input.clear();
                            write_pty_all(&master, b"detach-client\n").await.context("detach tmux -CC client")?;
                            drain_deadline = Some(tokio::time::Instant::now() + TMUX_CC_DRAIN_TIMEOUT);
                        } else {
                            pending_input
                                .push(tmux_cc::send_keys_command(&data))
                                .context("queue tmux -CC input")?;
                        }
                    }
                    StdinMessage::Close => {
                        // Discard queued send-keys: detaching means this
                        // client is leaving; in-flight keystrokes have no
                        // meaningful recipient.
                        pending_input.clear();
                        write_pty_all(&master, b"detach-client\n").await.context("detach tmux -CC client")?;
                        drain_deadline = Some(tokio::time::Instant::now() + TMUX_CC_DRAIN_TIMEOUT);
                    }
                }
            }
            Some(command) = pty_rx.recv(), if drain_deadline.is_none() => {
                match command {
                    PtyCommand::Resize { rows, cols } => {
                        // Route resize through the same queue as send-keys so
                        // it cannot overtake a partially-flushed input command.
                        pending_input
                            .push(tmux_cc::resize_commands(rows, cols))
                            .context("queue tmux -CC resize")?;
                    }
                    PtyCommand::Close { .. } => {
                        // Discard queued send-keys before issuing detach:
                        // the client is leaving and buffered input would
                        // have no meaningful recipient.
                        pending_input.clear();
                        write_pty_all(&master, b"detach-client\n").await.context("detach tmux -CC client")?;
                        drain_deadline = Some(tokio::time::Instant::now() + TMUX_CC_DRAIN_TIMEOUT);
                    }
                    PtyCommand::KickOthers => {
                        // Queue behind any pending input so it does not
                        // interleave with a partially-written send-keys command.
                        pending_input
                            .push(b"detach-client -a\n".to_vec())
                            .context("queue tmux -CC kick-others")?;
                    }
                }
            }
            result = write_one_pending_pty_chunk(&master, &mut pending_input), if !pending_input.is_empty() && drain_deadline.is_none() => {
                result.context("write queued tmux -CC input")?;
            }
            () = drain_sleep => return Ok(()),
            chunk = read_pty_chunk(&master, &mut read_buf) => {
                let Some(chunk) = chunk.context("read tmux -CC output")? else {
                    return Ok(());
                };
                let control_bytes = decoder.decode(&chunk);
                if !control_bytes.is_empty()
                    && let Some(commands) = pending_initial_commands.take()
                {
                    for command in commands {
                        write_pty_all(&master, &command)
                            .await
                            .context("write initial tmux -CC command")?;
                    }
                }
                pump_control_bytes(&control_bytes, &mut line_buf, &stdout_tx, &stderr_tx).await?;
            }
            else => return Ok(()),
        }
    }
}

async fn queue_tmux_output(stdout_tx: &mpsc::Sender<Vec<u8>>, bytes: Vec<u8>) -> bool {
    stdout_tx.send(bytes).await.is_ok()
}

async fn pump_control_bytes(
    bytes: &[u8],
    line_buf: &mut Vec<u8>,
    stdout_tx: &mpsc::Sender<Vec<u8>>,
    stderr_tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    for byte in bytes {
        line_buf.push(*byte);
        if *byte == b'\n' {
            let line = String::from_utf8_lossy(line_buf).into_owned();
            line_buf.clear();
            match parse_control_line(&line) {
                TmuxControlEvent::Output(bytes) => {
                    queue_tmux_output(stdout_tx, bytes).await;
                }
                TmuxControlEvent::Error(error) => {
                    let _ = stderr_tx
                        .send(format!("tmux: {error}\n").into_bytes())
                        .await;
                }
                TmuxControlEvent::Exit | TmuxControlEvent::Ignore => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_tmux_octal_bytes() {
        assert_eq!(tmux_cc::unescape_tmux_bytes(r"hi\012\\\033"), b"hi\n\\\x1b");
    }

    #[test]
    fn decodes_cc_dcs_prefixes() {
        let mut decoder = TmuxCcDecoder::default();
        assert_eq!(
            decoder.decode(b"\x1bP1000p%output %1 hi\\012\r\n"),
            b"%output %1 hi\\012\r\n"
        );
        assert_eq!(decoder.decode(b"%exit\r\n\x1b\\"), b"%exit\r\n");
    }

    #[test]
    fn parses_output_notifications() {
        assert_eq!(
            parse_control_line(r"%output %1 hello\012"),
            TmuxControlEvent::Output(b"hello\n".to_vec())
        );
        assert_eq!(
            parse_control_line(r"%extended-output %1 12 ignored : hi\012"),
            TmuxControlEvent::Output(b"hi\n".to_vec())
        );
    }

    #[test]
    fn tmux_output_backpressure_preserves_split_utf8() {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let (stdout_tx, mut stdout_rx) = mpsc::channel(1);
            let (stderr_tx, _stderr_rx) = mpsc::channel(1);
            let mut line_buf = Vec::new();
            let pump = tokio::spawn(async move {
                pump_control_bytes(
                    b"%output %1 \\342\r\n%output %1 \\224\\200\r\n",
                    &mut line_buf,
                    &stdout_tx,
                    &stderr_tx,
                )
                .await
            });

            assert_eq!(stdout_rx.recv().await.expect("first output"), vec![0xe2]);
            assert_eq!(
                stdout_rx.recv().await.expect("second output"),
                vec![0x94, 0x80]
            );
            pump.await.expect("join pump").expect("pump output");
        });
    }

    #[test]
    fn detects_raw_and_kitty_ctrl_backslash_detach() {
        assert!(is_ctrl_backslash_sequence(b"\x1c"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;5u"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;5:1u"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;5:2u"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;69u"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92:124;5u"));

        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;5:3u"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;6u"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;7u"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[91;5u"));
        assert!(!is_ctrl_backslash_sequence(b"not-detach"));
    }

    #[test]
    fn tmux_pending_input_queues_encoded_send_keys_command() {
        let mut pending = PendingPtyWrite::new(1024);
        pending
            .push(tmux_cc::send_keys_command(b"hello"))
            .expect("queue tmux command");
        let queued = pending.front_chunk().expect("queued command");
        let text = String::from_utf8_lossy(queued);
        // Must use hex-literal send-keys form (-H flag).
        assert!(text.contains("send-keys -H"), "expected 'send-keys -H' in {text:?}");
        // 'h','e','l','l','o' → 68 65 6c 6c 6f
        assert!(text.contains("68"), "expected hex byte for 'h' in {text:?}");
        assert!(text.contains("65"), "expected hex byte for 'e' in {text:?}");
        assert!(text.contains("6c"), "expected hex byte for 'l' in {text:?}");
        assert!(text.contains("6f"), "expected hex byte for 'o' in {text:?}");
    }

    #[test]
    fn resize_command_queued_not_written_directly() {
        // Verifies that resize_commands output goes through PendingPtyWrite,
        // not bypassed — i.e. the push result is correct and in-order with
        // any preceding send-keys data.
        let mut pending = PendingPtyWrite::new(TMUX_PTY_INPUT_QUEUE_BYTES);
        pending
            .push(tmux_cc::send_keys_command(b"abc"))
            .expect("queue send-keys");
        pending
            .push(tmux_cc::resize_commands(24, 80))
            .expect("queue resize");

        // First chunk must be the send-keys command.
        let first = String::from_utf8_lossy(pending.front_chunk().expect("first chunk"));
        assert!(
            first.contains("send-keys -H"),
            "send-keys must precede resize; got {first:?}"
        );

        // After consuming the first chunk the resize command appears next.
        let first_len = pending.front_chunk().unwrap().len();
        pending.consume(first_len);
        let second = String::from_utf8_lossy(pending.front_chunk().expect("second chunk"));
        assert!(
            second.contains("refresh-client") || second.contains("resize-window"),
            "resize command must follow send-keys; got {second:?}"
        );
    }

    #[test]
    fn kick_others_queued_behind_pending_input() {
        // KickOthers must be ordered after any queued send-keys.
        let mut pending = PendingPtyWrite::new(TMUX_PTY_INPUT_QUEUE_BYTES);
        pending
            .push(tmux_cc::send_keys_command(b"x"))
            .expect("queue send-keys");
        pending
            .push(b"detach-client -a\n".to_vec())
            .expect("queue kick-others");

        let first = String::from_utf8_lossy(pending.front_chunk().expect("first chunk"));
        assert!(
            first.contains("send-keys"),
            "send-keys must precede kick-others; got {first:?}"
        );
    }

    #[test]
    fn parses_errors_and_exit() {
        assert_eq!(
            parse_control_line("%error 123 1 0 bad command"),
            TmuxControlEvent::Error("123 1 0 bad command".to_owned())
        );
        assert_eq!(parse_control_line("%exit"), TmuxControlEvent::Exit);
        assert_eq!(parse_control_line("%begin 1 2 0"), TmuxControlEvent::Ignore);
    }
}

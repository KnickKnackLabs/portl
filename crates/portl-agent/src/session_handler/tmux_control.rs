use std::os::fd::OwnedFd;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;

use portl_core::terminal::tmux_cc::{
    self, Decoder as TmuxCcDecoder, TmuxControlEvent, parse_control_line,
};

use crate::shell_handler::pty_master::{read_pty_chunk, set_nonblocking, write_pty_all};
use crate::shell_registry::{PtyCommand, StdinMessage};

const TMUX_CC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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
                        if is_ctrl_backslash(&data) {
                            write_pty_all(&master, b"detach-client\n").await.context("detach tmux -CC client")?;
                            drain_deadline = Some(tokio::time::Instant::now() + TMUX_CC_DRAIN_TIMEOUT);
                        } else {
                            write_pty_all(&master, &tmux_cc::send_keys_command(&data)).await.context("write tmux -CC input")?;
                        }
                    }
                    StdinMessage::Close => {
                        write_pty_all(&master, b"detach-client\n").await.context("detach tmux -CC client")?;
                        drain_deadline = Some(tokio::time::Instant::now() + TMUX_CC_DRAIN_TIMEOUT);
                    }
                }
            }
            Some(command) = pty_rx.recv(), if drain_deadline.is_none() => {
                match command {
                    PtyCommand::Resize { rows, cols } => {
                        write_pty_all(&master, &tmux_cc::resize_commands(rows, cols)).await.context("resize tmux -CC client")?;
                    }
                    PtyCommand::Close { .. } => {
                        write_pty_all(&master, b"detach-client\n").await.context("detach tmux -CC client")?;
                        drain_deadline = Some(tokio::time::Instant::now() + TMUX_CC_DRAIN_TIMEOUT);
                    }
                    PtyCommand::KickOthers => {
                        write_pty_all(&master, b"detach-client -a\n").await.context("detach other tmux -CC clients")?;
                    }
                }
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

fn is_ctrl_backslash(data: &[u8]) -> bool {
    data.first().is_some_and(|byte| *byte == 0x1c) || is_key_pressed(data, 0x5c, 0b100)
}

fn is_key_pressed(data: &[u8], expected_key: u32, expected_mods: u32) -> bool {
    data.windows(2).enumerate().any(|(index, window)| {
        window == b"\x1b[" && keypress_with_mod(&data[index + 2..], expected_key, expected_mods)
    })
}

fn keypress_with_mod(data: &[u8], expected_key: u32, expected_mods: u32) -> bool {
    let mut pos = 0;
    let Some(key_code) = parse_decimal(data, &mut pos) else {
        return false;
    };
    if key_code != expected_key {
        return false;
    }

    while data.get(pos).is_some_and(|byte| *byte == b':') {
        pos += 1;
        let _ = parse_decimal(data, &mut pos);
    }

    if data.get(pos).is_none_or(|byte| *byte != b';') {
        return false;
    }
    pos += 1;

    let Some(mod_encoded) = parse_decimal(data, &mut pos) else {
        return false;
    };
    if mod_encoded < 1 {
        return false;
    }
    let intentional_mods = (mod_encoded - 1) & 0b0011_1111;
    if intentional_mods != expected_mods {
        return false;
    }

    if data.get(pos).is_some_and(|byte| *byte == b':') {
        pos += 1;
        if parse_decimal(data, &mut pos) == Some(3) {
            return false;
        }
    }

    if data.get(pos).is_some_and(|byte| *byte == b';') {
        pos += 1;
        while data
            .get(pos)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b':')
        {
            pos += 1;
        }
    }

    data.get(pos).is_some_and(|byte| *byte == b'u')
}

fn parse_decimal(data: &[u8], pos: &mut usize) -> Option<u32> {
    let start = *pos;
    let mut value = 0_u32;
    while let Some(byte) = data.get(*pos).filter(|byte| byte.is_ascii_digit()) {
        value = value
            .saturating_mul(10)
            .saturating_add(u32::from(*byte - b'0'));
        *pos += 1;
    }
    (*pos != start).then_some(value)
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
        assert!(is_ctrl_backslash(b"\x1c"));
        assert!(is_ctrl_backslash(b"\x1b[92;5u"));
        assert!(is_ctrl_backslash(b"\x1b[92;5:1u"));
        assert!(is_ctrl_backslash(b"\x1b[92;5:2u"));
        assert!(is_ctrl_backslash(b"\x1b[92;69u"));
        assert!(is_ctrl_backslash(b"\x1b[92:124;5u"));

        assert!(!is_ctrl_backslash(b"\x1b[92;5:3u"));
        assert!(!is_ctrl_backslash(b"\x1b[92;6u"));
        assert!(!is_ctrl_backslash(b"\x1b[92;7u"));
        assert!(!is_ctrl_backslash(b"\x1b[91;5u"));
        assert!(!is_ctrl_backslash(b"not-detach"));
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

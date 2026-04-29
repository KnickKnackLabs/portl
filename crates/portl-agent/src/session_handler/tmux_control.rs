use std::os::fd::OwnedFd;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::shell_handler::pty_master::{read_pty_chunk, set_nonblocking, write_pty_all};
use crate::shell_registry::{PtyCommand, StdinMessage};

const TMUX_CC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TmuxControlEvent {
    Output(Vec<u8>),
    Error(String),
    Exit,
    Ignore,
}

pub(crate) fn parse_control_line(line: &str) -> TmuxControlEvent {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(rest) = line.strip_prefix("%output ") {
        let Some((_, escaped)) = rest.split_once(' ') else {
            return TmuxControlEvent::Ignore;
        };
        return TmuxControlEvent::Output(unescape_tmux_bytes(escaped));
    }
    if let Some(rest) = line.strip_prefix("%extended-output ") {
        let Some((_, escaped)) = rest.split_once(" : ") else {
            return TmuxControlEvent::Ignore;
        };
        return TmuxControlEvent::Output(unescape_tmux_bytes(escaped));
    }
    if let Some(rest) = line.strip_prefix("%error") {
        return TmuxControlEvent::Error(rest.trim().to_owned());
    }
    if line.starts_with("%exit") {
        return TmuxControlEvent::Exit;
    }
    TmuxControlEvent::Ignore
}

pub(crate) fn unescape_tmux_bytes(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1].is_ascii_digit()
            && bytes[index + 2].is_ascii_digit()
            && bytes[index + 3].is_ascii_digit()
        {
            let value = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            out.push(value);
            index += 4;
        } else if bytes[index] == b'\\' && index + 1 < bytes.len() {
            out.push(bytes[index + 1]);
            index += 2;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

#[derive(Debug, Default)]
pub(crate) struct TmuxCcDecoder {
    state: TmuxCcState,
}

#[derive(Debug, Default)]
enum TmuxCcState {
    #[default]
    Normal,
    Escape,
    DcsPrefix,
}

impl TmuxCcDecoder {
    pub(crate) fn decode(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for byte in input {
            match self.state {
                TmuxCcState::Normal => {
                    if *byte == 0x1b {
                        self.state = TmuxCcState::Escape;
                    } else {
                        out.push(*byte);
                    }
                }
                TmuxCcState::Escape => match *byte {
                    b'P' => self.state = TmuxCcState::DcsPrefix,
                    b'\\' => self.state = TmuxCcState::Normal,
                    other => {
                        out.push(0x1b);
                        out.push(other);
                        self.state = TmuxCcState::Normal;
                    }
                },
                TmuxCcState::DcsPrefix => {
                    if *byte == b'p' {
                        self.state = TmuxCcState::Normal;
                    }
                }
            }
        }
        out
    }
}

pub(crate) async fn pump_tmux_cc_pty(
    master: OwnedFd,
    stdout_tx: mpsc::Sender<Vec<u8>>,
    stderr_tx: mpsc::Sender<Vec<u8>>,
    mut stdin_rx: mpsc::Receiver<StdinMessage>,
    mut pty_rx: mpsc::UnboundedReceiver<PtyCommand>,
    overflow_tx: mpsc::Sender<()>,
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
                            write_pty_all(&master, &send_keys_command(&data)).await.context("write tmux -CC input")?;
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
                        write_pty_all(&master, &resize_commands(rows, cols)).await.context("resize tmux -CC client")?;
                    }
                    PtyCommand::Close { .. } => {
                        write_pty_all(&master, b"detach-client\n").await.context("detach tmux -CC client")?;
                        drain_deadline = Some(tokio::time::Instant::now() + TMUX_CC_DRAIN_TIMEOUT);
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
                pump_control_bytes(&control_bytes, &mut line_buf, &stdout_tx, &stderr_tx, &overflow_tx).await?;
            }
            else => return Ok(()),
        }
    }
}

fn queue_tmux_output(
    stdout_tx: &mpsc::Sender<Vec<u8>>,
    overflow_tx: &mpsc::Sender<()>,
    bytes: Vec<u8>,
) -> bool {
    match stdout_tx.try_send(bytes) {
        Ok(()) => true,
        Err(TrySendError::Full(_bytes)) => {
            let _ = overflow_tx.try_send(());
            false
        }
        Err(TrySendError::Closed(_bytes)) => false,
    }
}

async fn pump_control_bytes(
    bytes: &[u8],
    line_buf: &mut Vec<u8>,
    stdout_tx: &mpsc::Sender<Vec<u8>>,
    stderr_tx: &mpsc::Sender<Vec<u8>>,
    overflow_tx: &mpsc::Sender<()>,
) -> Result<()> {
    for byte in bytes {
        line_buf.push(*byte);
        if *byte == b'\n' {
            let line = String::from_utf8_lossy(line_buf).into_owned();
            line_buf.clear();
            match parse_control_line(&line) {
                TmuxControlEvent::Output(bytes) => {
                    queue_tmux_output(stdout_tx, overflow_tx, bytes);
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

fn send_keys_command(data: &[u8]) -> Vec<u8> {
    let mut command = Vec::new();
    for chunk in data.chunks(128) {
        command.extend_from_slice(b"send-keys -H");
        for byte in chunk {
            command.extend_from_slice(format!(" {byte:02x}").as_bytes());
        }
        command.push(b'\n');
    }
    command
}

fn resize_commands(rows: u16, cols: u16) -> Vec<u8> {
    format!("refresh-client -C {cols},{rows}\nresize-window -x {cols} -y {rows}\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_tmux_octal_bytes() {
        assert_eq!(unescape_tmux_bytes(r"hi\012\\\033"), b"hi\n\\\x1b");
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
    fn tmux_output_overflow_requests_snapshot_refresh() {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let (stdout_tx, mut stdout_rx) = mpsc::channel(1);
            let (overflow_tx, mut overflow_rx) = mpsc::channel(1);

            assert!(queue_tmux_output(
                &stdout_tx,
                &overflow_tx,
                b"first".to_vec()
            ));
            assert!(!queue_tmux_output(
                &stdout_tx,
                &overflow_tx,
                b"second".to_vec()
            ));

            assert_eq!(stdout_rx.recv().await.expect("first output"), b"first");
            assert!(overflow_rx.recv().await.is_some());
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

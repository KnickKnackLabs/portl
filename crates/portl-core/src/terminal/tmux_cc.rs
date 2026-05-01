#[derive(Debug, PartialEq, Eq)]
pub enum TmuxControlEvent {
    Output(Vec<u8>),
    Error(String),
    Exit,
    Ignore,
}

#[must_use]
pub fn parse_control_line(line: &str) -> TmuxControlEvent {
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

#[must_use]
pub fn unescape_tmux_bytes(input: &str) -> Vec<u8> {
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
pub struct Decoder {
    state: State,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Normal,
    Escape,
    DcsPrefix,
}

impl Decoder {
    #[must_use]
    pub fn decode(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for byte in input {
            match self.state {
                State::Normal => {
                    if *byte == 0x1b {
                        self.state = State::Escape;
                    } else {
                        out.push(*byte);
                    }
                }
                State::Escape => match *byte {
                    b'P' => self.state = State::DcsPrefix,
                    b'\\' => self.state = State::Normal,
                    other => {
                        out.push(0x1b);
                        out.push(other);
                        self.state = State::Normal;
                    }
                },
                State::DcsPrefix => {
                    if *byte == b'p' {
                        self.state = State::Normal;
                    }
                }
            }
        }
        out
    }
}

#[must_use]
pub fn send_keys_command(data: &[u8]) -> Vec<u8> {
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

#[must_use]
pub fn resize_commands(rows: u16, cols: u16) -> Vec<u8> {
    format!("refresh-client -C {cols},{rows}\nresize-window -x {cols} -y {rows}\n").into_bytes()
}

#[must_use]
pub fn render_viewport_snapshot(snapshot: &[u8], cursor_x: u16, cursor_y: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(snapshot.len() + 32);
    out.extend_from_slice(b"\x1b[H\x1b[2J");

    let mut lines = snapshot.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    for (index, line) in lines.into_iter().enumerate() {
        out.extend_from_slice(format!("\x1b[{};1H", index + 1).as_bytes());
        out.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
        out.extend_from_slice(b"\x1b[K");
    }
    out.extend_from_slice(format!("\x1b[{};{}H", cursor_y + 1, cursor_x + 1).as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tmux_output_notifications() {
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
    fn send_keys_command_encodes_bytes_as_hex() {
        assert_eq!(send_keys_command(b"A\x03"), b"send-keys -H 41 03\n");
    }

    #[test]
    fn renders_tmux_viewport_snapshot() {
        assert_eq!(
            render_viewport_snapshot(b"old spinner\nnext\n", 4, 0),
            b"\x1b[H\x1b[2J\x1b[1;1Hold spinner\x1b[K\x1b[2;1Hnext\x1b[K\x1b[1;5H"
        );
    }
}

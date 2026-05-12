const ESC: u8 = 0x1b;
const BRACKETED_PASTE_BEGIN: &[u8] = b"\x1b[200~";
const BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Ground,
    Escape,
    Csi,
}

pub struct QueryResponseFilter {
    mode: Mode,
    pending: [u8; Self::MAX_BUFFERED],
    pending_len: usize,
    in_bracketed_paste: bool,
    paste_end_match: usize,
}

impl Default for QueryResponseFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseFilter {
    pub const MAX_BUFFERED: usize = 32;

    pub fn new() -> Self {
        Self {
            mode: Mode::Ground,
            pending: [0; Self::MAX_BUFFERED],
            pending_len: 0,
            in_bracketed_paste: false,
            paste_end_match: 0,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            self.feed_byte(byte, &mut out);
        }
        out
    }

    pub fn flush_timeout(&mut self) -> Vec<u8> {
        if self.mode == Mode::Escape && self.pending_len == 1 {
            let mut out = Vec::with_capacity(1);
            self.flush_pending(&mut out);
            self.mode = Mode::Ground;
            out
        } else {
            Vec::new()
        }
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.pending_len);
        self.flush_pending(&mut out);
        self.mode = Mode::Ground;
        self.in_bracketed_paste = false;
        self.paste_end_match = 0;
        out
    }

    pub fn buffered_len(&self) -> usize {
        self.pending_len
    }

    fn feed_byte(&mut self, byte: u8, out: &mut Vec<u8>) {
        if self.in_bracketed_paste {
            out.push(byte);
            self.track_bracketed_paste_end(byte);
            return;
        }

        match self.mode {
            Mode::Ground => {
                if byte == ESC {
                    self.start_pending_escape();
                } else {
                    out.push(byte);
                }
            }
            Mode::Escape => match byte {
                b'[' => {
                    self.push_pending(byte, out);
                    self.mode = Mode::Csi;
                }
                ESC => {
                    self.flush_pending(out);
                    self.start_pending_escape();
                }
                _ => {
                    self.push_pending(byte, out);
                    self.flush_pending(out);
                    self.mode = Mode::Ground;
                }
            },
            Mode::Csi => self.feed_csi(byte, out),
        }
    }

    fn feed_csi(&mut self, byte: u8, out: &mut Vec<u8>) {
        if byte == ESC {
            self.flush_pending(out);
            self.start_pending_escape();
            return;
        }

        if self.pending_len == Self::MAX_BUFFERED {
            self.flush_pending(out);
            out.push(byte);
            self.mode = Mode::Ground;
            return;
        }

        self.push_pending(byte, out);
        if is_csi_final(byte) {
            if self.pending[..self.pending_len] == *BRACKETED_PASTE_BEGIN {
                self.flush_pending(out);
                self.in_bracketed_paste = true;
                self.paste_end_match = 0;
            } else if is_response(&self.pending[..self.pending_len]) {
                self.pending_len = 0;
            } else {
                self.flush_pending(out);
            }
            self.mode = Mode::Ground;
        }
    }

    fn start_pending_escape(&mut self) {
        self.pending[0] = ESC;
        self.pending_len = 1;
        self.mode = Mode::Escape;
    }

    fn push_pending(&mut self, byte: u8, out: &mut Vec<u8>) {
        if self.pending_len == Self::MAX_BUFFERED {
            self.flush_pending(out);
        }
        self.pending[self.pending_len] = byte;
        self.pending_len += 1;
    }

    fn flush_pending(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pending[..self.pending_len]);
        self.pending_len = 0;
    }

    fn track_bracketed_paste_end(&mut self, byte: u8) {
        if byte == BRACKETED_PASTE_END[self.paste_end_match] {
            self.paste_end_match += 1;
            if self.paste_end_match == BRACKETED_PASTE_END.len() {
                self.in_bracketed_paste = false;
                self.paste_end_match = 0;
            }
            return;
        }

        self.paste_end_match = usize::from(byte == BRACKETED_PASTE_END[0]);
    }
}

pub type StdinResponseFilter = QueryResponseFilter;

fn is_csi_final(byte: u8) -> bool {
    (0x40..=0x7e).contains(&byte)
}

fn is_response(bytes: &[u8]) -> bool {
    let Some((&final_byte, body_with_intro)) = bytes.split_last() else {
        return false;
    };
    let Some(params) = body_with_intro.strip_prefix(b"\x1b[") else {
        return false;
    };

    match (params.first().copied(), final_byte) {
        (Some(b'?'), b'u') => response_params_match(&params[1..], b";:", true),
        (Some(b'?' | b'>'), b'c') | (Some(b'?'), b'R') => {
            response_params_match(&params[1..], b";", true)
        }
        (_, b'R') => response_params_match(params, b";", true),
        _ => false,
    }
}

fn response_params_match(params: &[u8], separators: &[u8], require_digit: bool) -> bool {
    let mut saw_digit = false;
    for &byte in params {
        match byte {
            b'0'..=b'9' => saw_digit = true,
            other if separators.contains(&other) => {}
            _ => return false,
        }
    }
    !require_digit || saw_digit
}

#[cfg(test)]
mod tests {
    use super::QueryResponseFilter;

    fn filter(input: &[u8]) -> Vec<u8> {
        let mut filter = QueryResponseFilter::new();
        let mut out = filter.feed(input);
        out.extend_from_slice(&filter.finish());
        out
    }

    #[test]
    fn strips_response_shapes_and_preserves_surrounding_bytes() {
        let input = b"pre\x1b[?62;52;c\x1b[>0;0;0c\x1b[?0u\x1b[10;5R\x1b[?10;5Rpost";
        assert_eq!(filter(input), b"prepost");
    }

    #[test]
    fn strips_response_variants() {
        for response in [
            b"\x1b[?1c".as_slice(),
            b"\x1b[?62;1;6;22c",
            b"\x1b[>1;100;0c",
            b"\x1b[?15u",
            b"\x1b[?1:2u",
            b"\x1b[1;1R",
            b"\x1b[?24;80R",
        ] {
            let mut input = b"a".to_vec();
            input.extend_from_slice(response);
            input.extend_from_slice(b"b");
            assert_eq!(filter(&input), b"ab");
        }
    }

    #[test]
    fn preserves_real_keystrokes_byte_for_byte() {
        let input = b"abc\x01\x1cr\x1b[A\x1b[B\x1b[C\x1b[D\x1b[15~\x1ba\x1b0";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn flushes_lone_escape_on_timeout() {
        let mut filter = QueryResponseFilter::new();
        assert_eq!(filter.feed(b"\x1b"), b"");
        assert_eq!(filter.flush_timeout(), b"\x1b");
        assert_eq!(filter.feed(b"a"), b"a");
    }

    #[test]
    fn holds_split_responses_across_every_boundary() {
        for response in [
            b"\x1b[?62;52;c".as_slice(),
            b"\x1b[>0;0;0c",
            b"\x1b[?0u",
            b"\x1b[10;5R",
            b"\x1b[?10;5R",
        ] {
            for split in 1..response.len() {
                let mut filter = QueryResponseFilter::new();
                assert_eq!(filter.feed(b"pre"), b"pre");
                assert_eq!(filter.feed(&response[..split]), b"");
                assert!(filter.buffered_len() <= QueryResponseFilter::MAX_BUFFERED);
                assert_eq!(filter.feed(&response[split..]), b"");
                assert_eq!(filter.feed(b"post"), b"post");
                assert_eq!(filter.finish(), b"");
            }
        }
    }

    #[test]
    fn forwards_response_shapes_inside_bracketed_paste() {
        let input = b"pre\x1b[200~\x1b[?62;52;c\x1b[?0u\x1b[10;5R\x1b[201~post";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn bracketed_paste_boundaries_are_chunk_safe() {
        let mut filter = QueryResponseFilter::new();
        assert_eq!(filter.feed(b"\x1b[20"), b"");
        assert_eq!(filter.feed(b"0~\x1b[?62;52;c"), b"\x1b[200~\x1b[?62;52;c");
        assert_eq!(filter.feed(b"\x1b[201"), b"\x1b[201");
        assert_eq!(filter.feed(b"~\x1b[?0u"), b"~");
        assert_eq!(filter.finish(), b"");
    }

    #[test]
    fn high_bit_utf8_bytes_pass_through() {
        let input = "ime あ─🚀 \u{1b}[?0u".as_bytes();
        assert_eq!(filter(input), "ime あ─🚀 ".as_bytes());
    }

    #[test]
    fn malformed_and_unrelated_csi_sequences_are_forwarded() {
        for seq in [
            b"\x1b[31m".as_slice(),
            b"\x1b[10;20H",
            b"\x1b[?1049h",
            b"\x1b[?2004h",
            b"\x1b[?;c",
            b"\x1b[?Xu",
        ] {
            let mut input = b"pre".to_vec();
            input.extend_from_slice(seq);
            input.extend_from_slice(b"post");
            assert_eq!(filter(&input), input);
        }
    }

    #[test]
    fn bounded_buffer_under_malformed_stress() {
        let mut filter = QueryResponseFilter::new();
        let mut emitted = 0usize;
        for _ in 0..16 * 1024 {
            emitted += filter.feed(b"\x1b[????????????????????????????????X").len();
            assert!(filter.buffered_len() <= QueryResponseFilter::MAX_BUFFERED);
        }
        emitted += filter.finish().len();
        assert!(emitted > 0);
    }
}

const ESC: u8 = 0x1b;

#[cfg(feature = "test-attach-taps")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "test-attach-taps")]
static MAX_BUFFERED_WATERMARK: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Ground,
    EscapeIntermediate,
    CsiParam,
    OscString,
    DcsString,
}

pub struct QueryStripper {
    mode: Mode,
    pending: [u8; Self::MAX_BUFFERED],
    pending_len: usize,
    string_escape: bool,
}

impl Default for QueryStripper {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryStripper {
    pub const MAX_BUFFERED: usize = 32;

    pub fn new() -> Self {
        Self {
            mode: Mode::Ground,
            pending: [0; Self::MAX_BUFFERED],
            pending_len: 0,
            string_escape: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            self.feed_byte(byte, &mut out);
            self.record_buffered_watermark();
        }
        out
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.pending_len = 0;
        self.mode = Mode::Ground;
        self.string_escape = false;
        Vec::new()
    }

    pub fn buffered_len(&self) -> usize {
        self.pending_len
    }

    #[cfg(feature = "test-attach-taps")]
    pub fn reset_max_buffered_watermark_for_test() {
        MAX_BUFFERED_WATERMARK.store(0, Ordering::SeqCst);
    }

    #[cfg(feature = "test-attach-taps")]
    pub fn max_buffered_watermark_for_test() -> usize {
        MAX_BUFFERED_WATERMARK.load(Ordering::SeqCst)
    }

    #[cfg(feature = "test-attach-taps")]
    fn record_buffered_watermark(&self) {
        let mut current = MAX_BUFFERED_WATERMARK.load(Ordering::Relaxed);
        while self.pending_len > current {
            match MAX_BUFFERED_WATERMARK.compare_exchange_weak(
                current,
                self.pending_len,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(not(feature = "test-attach-taps"))]
    fn record_buffered_watermark(&self) {}

    fn feed_byte(&mut self, byte: u8, out: &mut Vec<u8>) {
        match self.mode {
            Mode::Ground => {
                if byte == ESC {
                    self.start_pending_escape();
                } else {
                    out.push(byte);
                }
            }
            Mode::EscapeIntermediate => self.feed_escape_intermediate(byte, out),
            Mode::CsiParam => self.feed_csi_param(byte, out),
            Mode::OscString => self.feed_string(byte, out, true),
            Mode::DcsString => self.feed_string(byte, out, false),
        }
    }

    fn feed_escape_intermediate(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            b'[' => {
                self.push_pending(byte, out);
                self.mode = Mode::CsiParam;
            }
            b']' => {
                self.push_pending(byte, out);
                self.flush_pending(out);
                self.mode = Mode::OscString;
                self.string_escape = false;
            }
            b'P' => {
                self.push_pending(byte, out);
                self.flush_pending(out);
                self.mode = Mode::DcsString;
                self.string_escape = false;
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
        }
    }

    fn feed_csi_param(&mut self, byte: u8, out: &mut Vec<u8>) {
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
            if is_query(&self.pending[..self.pending_len]) {
                self.pending_len = 0;
            } else {
                self.flush_pending(out);
            }
            self.mode = Mode::Ground;
        }
    }

    fn feed_string(&mut self, byte: u8, out: &mut Vec<u8>, osc: bool) {
        out.push(byte);
        if osc && byte == 0x07 {
            self.mode = Mode::Ground;
            self.string_escape = false;
            return;
        }

        if self.string_escape && byte == b'\\' {
            self.mode = Mode::Ground;
            self.string_escape = false;
            return;
        }

        self.string_escape = byte == ESC;
    }

    fn start_pending_escape(&mut self) {
        self.pending[0] = ESC;
        self.pending_len = 1;
        self.mode = Mode::EscapeIntermediate;
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
}

fn is_csi_final(byte: u8) -> bool {
    (0x40..=0x7e).contains(&byte)
}

fn is_query(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"\x1b[c" | b"\x1b[>c" | b"\x1b[6n" | b"\x1b[?u" | b"\x1b[<u"
    ) || is_kitty_numeric_query(bytes, b'>')
        || is_kitty_numeric_query(bytes, b'=')
}

fn is_kitty_numeric_query(bytes: &[u8], marker: u8) -> bool {
    let Some(body) = bytes
        .strip_prefix(&[ESC, b'[', marker])
        .and_then(|rest| rest.strip_suffix(b"u"))
    else {
        return false;
    };
    !body.is_empty()
        && body
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b';')
}

#[cfg(test)]
mod tests {
    use super::QueryStripper;

    fn strip(input: &[u8]) -> Vec<u8> {
        let mut stripper = QueryStripper::new();
        let mut out = stripper.feed(input);
        out.extend_from_slice(&stripper.finish());
        out
    }

    #[test]
    fn strips_all_query_forms_and_preserves_surrounding_bytes() {
        let input =
            b"pre\x1b[c\x1b[>c\x1b[6n\x1b[?u\x1b[>1u\x1b[=15u\x1b[<umiddle\x1b[c\x1b[?upost";
        assert_eq!(strip(input), b"premiddlepost");
    }

    #[test]
    fn strips_kitty_push_and_set_numeric_variants() {
        for query in [
            b"\x1b[>0u".as_slice(),
            b"\x1b[>15u",
            b"\x1b[=0u",
            b"\x1b[=15u",
        ] {
            let mut input = b"a".to_vec();
            input.extend_from_slice(query);
            input.extend_from_slice(b"b");
            assert_eq!(strip(&input), b"ab");
        }
    }

    #[test]
    fn holds_partial_queries_across_every_split() {
        for query in [
            b"\x1b[c".as_slice(),
            b"\x1b[>c",
            b"\x1b[6n",
            b"\x1b[?u",
            b"\x1b[>15u",
            b"\x1b[=15u",
            b"\x1b[<u",
        ] {
            for split in 1..query.len() {
                let mut stripper = QueryStripper::new();
                assert_eq!(stripper.feed(&query[..split]), b"");
                assert!(stripper.buffered_len() <= QueryStripper::MAX_BUFFERED);
                assert_eq!(stripper.feed(&query[split..]), b"");
                assert_eq!(stripper.finish(), b"");
            }
        }
    }

    #[test]
    fn flushes_partial_csi_that_is_not_a_query() {
        let mut stripper = QueryStripper::new();
        assert_eq!(stripper.feed(b"pre\x1b["), b"pre");
        assert_eq!(stripper.feed(b"31mpost"), b"\x1b[31mpost");
        assert_eq!(stripper.finish(), b"");
    }

    #[test]
    fn drops_trailing_partial_query_on_finish() {
        let mut stripper = QueryStripper::new();
        assert_eq!(stripper.feed(b"pre\x1b["), b"pre");
        assert_eq!(stripper.finish(), b"");
    }

    #[test]
    fn preserves_decset_and_decrst_sequences_with_question_prefix() {
        for seq in [
            b"\x1b[?1049h".as_slice(),
            b"\x1b[?1049l",
            b"\x1b[?2004h",
            b"\x1b[?2004l",
            b"\x1b[?25h",
            b"\x1b[?25l",
            b"\x1b[?7h",
            b"\x1b[?7l",
            b"\x1b[?1000h",
            b"\x1b[?1006h",
        ] {
            let mut input = b"pre".to_vec();
            input.extend_from_slice(seq);
            input.extend_from_slice(b"post");
            let mut expected = b"pre".to_vec();
            expected.extend_from_slice(seq);
            expected.extend_from_slice(b"post");
            assert_eq!(strip(&input), expected);
        }
    }

    #[test]
    fn preserves_osc_with_queries_inside() {
        for osc in [
            b"\x1b]0;title \x1b[c \x1b[?u\x07".as_slice(),
            b"\x1b]0;title \x1b[>c \x1b[6n\x1b\\",
        ] {
            assert_eq!(strip(osc), osc);
        }
    }

    #[test]
    fn preserves_dcs_with_queries_inside() {
        let dcs = b"\x1bP$qpre\x1b[c\x1b[?upost\x1b\\";
        assert_eq!(strip(dcs), dcs);
    }

    #[test]
    fn malformed_csi_inputs_do_not_panic_or_consume_following_data() {
        for malformed in [
            b"\x1b[Xhello".as_slice(),
            b"\x1b[?Xhello",
            b"\x1b[?;;uhello",
            b"\x1bZhello",
        ] {
            let mut input = malformed.to_vec();
            input.extend_from_slice(b"\x1b[cafter");
            let output = strip(&input);
            assert!(
                output
                    .windows(b"hello".len())
                    .any(|window| window == b"hello")
            );
            assert!(
                !output
                    .windows(b"\x1b[c".len())
                    .any(|window| window == b"\x1b[c")
            );
            assert!(output.ends_with(b"after"));
        }
    }

    #[test]
    fn high_bit_bytes_pass_through_outside_escape_context() {
        let input = "pre ─│🚀 post".as_bytes();
        assert_eq!(strip(input), input);
    }

    #[test]
    fn bounded_buffer_under_malformed_stress() {
        let mut stripper = QueryStripper::new();
        for _ in 0..16 * 1024 {
            let _ = stripper.feed(b"\x1b[????????????????????????????????X");
            assert!(stripper.buffered_len() <= QueryStripper::MAX_BUFFERED);
        }
        assert!(stripper.finish().is_empty());
    }

    #[test]
    fn stress_strips_queries_with_bounded_state() {
        let mut stripper = QueryStripper::new();
        let mut output_len = 0usize;
        for i in 0..(1024 * 1024 / 16) {
            let out = match i % 7 {
                0 => stripper.feed(b"abcdefgh\x1b[c"),
                1 => stripper.feed(b"abcdefgh\x1b[>c"),
                2 => stripper.feed(b"abcdefgh\x1b[6n"),
                3 => stripper.feed(b"abcdefgh\x1b[?u"),
                4 => stripper.feed(b"abcdefgh\x1b[>1u"),
                5 => stripper.feed(b"abcdefgh\x1b[=15u"),
                _ => stripper.feed(b"abcdefgh\x1b[<u"),
            };
            output_len += out.len();
            assert!(stripper.buffered_len() <= QueryStripper::MAX_BUFFERED);
        }
        assert!(stripper.finish().is_empty());
        assert_eq!(output_len, (1024 * 1024 / 16) * 8);
    }
}

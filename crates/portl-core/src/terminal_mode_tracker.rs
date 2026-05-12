const KITTY_POP: &[u8] = b"\x1b[<u";
const KITTY_FLAGS_CLEAR: &[u8] = b"\x1b[=0u";
const MODIFY_OTHER_KEYS_CLEAR: &[u8] = b"\x1b[>4;0m";
const ALT_SCREEN_1049_LEAVE: &[u8] = b"\x1b[?1049l";
const ALT_SCREEN_47_LEAVE: &[u8] = b"\x1b[?47l";
const BRACKETED_PASTE_DISABLE: &[u8] = b"\x1b[?2004l";
const DECAWM_ENABLE: &[u8] = b"\x1b[?7h";
const SCROLL_REGION_RESET: &[u8] = b"\x1b[r";
const MOUSE_MODES: [u16; 4] = [1000, 1002, 1003, 1006];
const CSI_BUFFER_CAPACITY: usize = 64;
const MAX_KITTY_DEPTH: u8 = 16;
const MOUSE_1000_INDEX: usize = 0;
const MOUSE_1002_INDEX: usize = 1;
const MOUSE_1003_INDEX: usize = 2;
const MOUSE_1006_INDEX: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AltScreenMode {
    Legacy47,
    Mode1049,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalModeState {
    pub kitty_keyboard_depth: u8,
    pub kitty_flags: u16,
    pub alt_screen: Option<AltScreenMode>,
    pub bracketed_paste: bool,
    pub mouse_modes: [bool; 4],
    pub modify_other_keys: u16,
    pub decawm: bool,
    pub scroll_region_non_default: bool,
}

impl Default for TerminalModeState {
    fn default() -> Self {
        Self {
            kitty_keyboard_depth: 0,
            kitty_flags: 0,
            alt_screen: None,
            bracketed_paste: false,
            mouse_modes: [false; 4],
            modify_other_keys: 0,
            decawm: true,
            scroll_region_non_default: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParserState {
    Ground,
    Escape,
    Csi,
    Osc,
    OscEscape,
}

pub struct TerminalModeTracker {
    modes: TerminalModeState,
    parser: ParserState,
    csi: [u8; CSI_BUFFER_CAPACITY],
    csi_len: usize,
    csi_overflowed: bool,
    pending_alt_screen_kitty_reset: bool,
}

impl Default for TerminalModeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalModeTracker {
    pub fn new() -> Self {
        Self {
            modes: TerminalModeState::default(),
            parser: ParserState::Ground,
            csi: [0; CSI_BUFFER_CAPACITY],
            csi_len: 0,
            csi_overflowed: false,
            pending_alt_screen_kitty_reset: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.feed_byte(byte);
        }
    }

    pub fn state(&self) -> TerminalModeState {
        self.modes
    }

    pub fn is_kitty_keyboard_enabled(&self) -> bool {
        self.modes.kitty_keyboard_depth > 0
    }

    pub fn is_kitty_active(&self) -> bool {
        self.modes.kitty_keyboard_depth > 0 || self.modes.kitty_flags != 0
    }

    pub fn kitty_keyboard_depth(&self) -> u8 {
        self.modes.kitty_keyboard_depth
    }

    pub fn kitty_flags(&self) -> u16 {
        self.modes.kitty_flags
    }

    pub fn alt_screen(&self) -> Option<AltScreenMode> {
        self.modes.alt_screen
    }

    pub fn is_alt_screen_active(&self) -> bool {
        self.modes.alt_screen.is_some()
    }

    pub fn is_bracketed_paste_enabled(&self) -> bool {
        self.modes.bracketed_paste
    }

    pub fn is_mouse_mode_enabled(&self, mode: u16) -> bool {
        mouse_mode_index(mode).is_some_and(|index| self.modes.mouse_modes[index])
    }

    pub fn modify_other_keys(&self) -> u16 {
        self.modes.modify_other_keys
    }

    pub fn decawm(&self) -> bool {
        self.modes.decawm
    }

    pub fn scroll_region_non_default(&self) -> bool {
        self.modes.scroll_region_non_default
    }

    pub fn buffered_len(&self) -> usize {
        self.csi_len
    }

    pub fn take_alt_screen_leave_kitty_reset(&mut self) -> Vec<u8> {
        if !self.pending_alt_screen_kitty_reset {
            return Vec::new();
        }
        self.pending_alt_screen_kitty_reset = false;
        let needs_kitty_pop = self.modes.kitty_keyboard_depth > 0;
        self.modes.kitty_keyboard_depth = 0;
        self.modes.kitty_flags = 0;
        self.modes.modify_other_keys = 0;

        let mut plan = Vec::with_capacity(
            KITTY_POP.len() + KITTY_FLAGS_CLEAR.len() + MODIFY_OTHER_KEYS_CLEAR.len(),
        );
        if needs_kitty_pop {
            plan.extend_from_slice(KITTY_POP);
        }
        plan.extend_from_slice(KITTY_FLAGS_CLEAR);
        plan.extend_from_slice(MODIFY_OTHER_KEYS_CLEAR);
        plan.extend_from_slice(&self.cleanup_plan());
        plan
    }

    pub fn has_pending_alt_screen_leave_kitty_reset(&self) -> bool {
        self.pending_alt_screen_kitty_reset
    }

    pub fn cleanup_plan(&mut self) -> Vec<u8> {
        let mut plan = Vec::new();

        for _ in 0..self.modes.kitty_keyboard_depth {
            plan.extend_from_slice(KITTY_POP);
        }
        self.modes.kitty_keyboard_depth = 0;
        self.pending_alt_screen_kitty_reset = false;

        if self.modes.kitty_flags != 0 {
            plan.extend_from_slice(KITTY_FLAGS_CLEAR);
            self.modes.kitty_flags = 0;
        }

        if self.modes.modify_other_keys != 0 {
            plan.extend_from_slice(MODIFY_OTHER_KEYS_CLEAR);
            self.modes.modify_other_keys = 0;
        }

        if let Some(mode) = self.modes.alt_screen.take() {
            match mode {
                AltScreenMode::Legacy47 => plan.extend_from_slice(ALT_SCREEN_47_LEAVE),
                AltScreenMode::Mode1049 => plan.extend_from_slice(ALT_SCREEN_1049_LEAVE),
            }
        }

        if self.modes.bracketed_paste {
            plan.extend_from_slice(BRACKETED_PASTE_DISABLE);
            self.modes.bracketed_paste = false;
        }

        for mode in MOUSE_MODES {
            if self.is_mouse_mode_enabled(mode) {
                extend_private_mode_reset(&mut plan, mode);
                self.set_mouse_mode(mode, false);
            }
        }

        if !self.modes.decawm {
            plan.extend_from_slice(DECAWM_ENABLE);
            self.modes.decawm = true;
        }

        if self.modes.scroll_region_non_default {
            plan.extend_from_slice(SCROLL_REGION_RESET);
            self.modes.scroll_region_non_default = false;
        }

        plan
    }

    fn feed_byte(&mut self, byte: u8) {
        match self.parser {
            ParserState::Ground => {
                if byte == 0x1b {
                    self.parser = ParserState::Escape;
                }
            }
            ParserState::Escape => match byte {
                b'[' => {
                    self.reset_csi();
                    self.parser = ParserState::Csi;
                }
                b']' => self.parser = ParserState::Osc,
                0x1b => self.parser = ParserState::Escape,
                _ => self.parser = ParserState::Ground,
            },
            ParserState::Csi => {
                if byte == 0x1b {
                    self.parser = ParserState::Escape;
                    self.reset_csi();
                } else if (0x40..=0x7e).contains(&byte) {
                    self.handle_csi(byte);
                    self.parser = ParserState::Ground;
                    self.reset_csi();
                } else if self.csi_len < self.csi.len() {
                    self.csi[self.csi_len] = byte;
                    self.csi_len += 1;
                } else {
                    self.csi_overflowed = true;
                }
            }
            ParserState::Osc => match byte {
                0x07 => self.parser = ParserState::Ground,
                0x1b => self.parser = ParserState::OscEscape,
                _ => {}
            },
            ParserState::OscEscape => match byte {
                b'\\' => self.parser = ParserState::Ground,
                0x1b => self.parser = ParserState::OscEscape,
                _ => self.parser = ParserState::Osc,
            },
        }
    }

    fn reset_csi(&mut self) {
        self.csi_len = 0;
        self.csi_overflowed = false;
    }

    fn handle_csi(&mut self, final_byte: u8) {
        if self.csi_overflowed {
            return;
        }
        let params = &self.csi[..self.csi_len];
        match (params.first().copied(), final_byte) {
            (Some(b'>'), b'u')
                if params.len() > 1
                    && parse_params(&params[1..]).first().copied().unwrap_or(0) > 0 =>
            {
                self.modes.kitty_keyboard_depth = self
                    .modes
                    .kitty_keyboard_depth
                    .saturating_add(1)
                    .min(MAX_KITTY_DEPTH);
            }
            (Some(b'<'), b'u') => {
                self.modes.kitty_keyboard_depth = self.modes.kitty_keyboard_depth.saturating_sub(1);
                if !self.is_kitty_active() {
                    self.pending_alt_screen_kitty_reset = false;
                }
            }
            (Some(b'='), b'u') => {
                self.modes.kitty_flags = parse_params(&params[1..]).first().copied().unwrap_or(0);
                if !self.is_kitty_active() {
                    self.pending_alt_screen_kitty_reset = false;
                }
            }
            (Some(b'>'), b'm') => {
                let parsed = parse_params(&params[1..]);
                if parsed.first().copied() == Some(4) {
                    self.modes.modify_other_keys = parsed.get(1).copied().unwrap_or(0);
                }
            }
            (Some(b'?'), b'h' | b'l') => {
                let enable = final_byte == b'h';
                for mode in parse_params(&params[1..]) {
                    self.apply_private_mode(mode, enable);
                }
            }
            (_, b'r') => self.modes.scroll_region_non_default = scroll_region_non_default(params),
            _ => {}
        }
    }

    fn apply_private_mode(&mut self, mode: u16, enable: bool) {
        match mode {
            47 => self.set_alt_screen(AltScreenMode::Legacy47, enable),
            1049 => self.set_alt_screen(AltScreenMode::Mode1049, enable),
            2004 => self.modes.bracketed_paste = enable,
            7 => self.modes.decawm = enable,
            1000 | 1002 | 1003 | 1006 => self.set_mouse_mode(mode, enable),
            _ => {}
        }
    }

    fn set_alt_screen(&mut self, mode: AltScreenMode, enable: bool) {
        if enable {
            self.modes.alt_screen = Some(mode);
        } else if self.modes.alt_screen == Some(mode) || self.modes.alt_screen.is_some() {
            let any_dirty = self.is_kitty_active()
                || self.modes.modify_other_keys != 0
                || self.modes.bracketed_paste
                || self.modes.mouse_modes.iter().any(|enabled| *enabled)
                || !self.modes.decawm
                || self.modes.scroll_region_non_default;
            self.modes.alt_screen = None;
            if any_dirty {
                self.pending_alt_screen_kitty_reset = true;
            }
        }
    }

    fn set_mouse_mode(&mut self, mode: u16, enable: bool) {
        if let Some(index) = mouse_mode_index(mode) {
            self.modes.mouse_modes[index] = enable;
        }
    }
}

fn mouse_mode_index(mode: u16) -> Option<usize> {
    match mode {
        1000 => Some(MOUSE_1000_INDEX),
        1002 => Some(MOUSE_1002_INDEX),
        1003 => Some(MOUSE_1003_INDEX),
        1006 => Some(MOUSE_1006_INDEX),
        _ => None,
    }
}

fn scroll_region_non_default(params: &[u8]) -> bool {
    if params.is_empty() {
        return false;
    }

    let parsed = parse_params(params);
    !matches!(parsed.as_slice(), [] | [0] | [1, 0])
}

fn parse_params(params: &[u8]) -> Vec<u16> {
    let mut parsed = Vec::new();
    let mut current: u16 = 0;
    let mut has_digit = false;

    for &byte in params {
        match byte {
            b'0'..=b'9' => {
                has_digit = true;
                current = current
                    .saturating_mul(10)
                    .saturating_add(u16::from(byte - b'0'));
            }
            b';' | b':' => {
                parsed.push(if has_digit { current } else { 0 });
                current = 0;
                has_digit = false;
            }
            _ => return Vec::new(),
        }
    }

    if has_digit || !params.is_empty() {
        parsed.push(if has_digit { current } else { 0 });
    }

    parsed
}

fn extend_private_mode_reset(plan: &mut Vec<u8>, mode: u16) {
    plan.extend_from_slice(b"\x1b[?");
    let digits = decimal_digits(mode);
    plan.extend_from_slice(&digits);
    plan.push(b'l');
}

fn decimal_digits(value: u16) -> Vec<u8> {
    value.to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &[u8] = b"";

    fn feed_split_everywhere(bytes: &[u8]) -> Vec<TerminalModeState> {
        let mut states = Vec::new();
        for split in 0..=bytes.len() {
            let mut tracker = TerminalModeTracker::new();
            tracker.feed(&bytes[..split]);
            tracker.feed(&bytes[split..]);
            states.push(tracker.state());
        }
        states
    }

    #[test]
    fn terminal_mode_tracker_kitty_push_and_pop_drive_cleanup() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u");
        assert!(tracker.is_kitty_keyboard_enabled());
        assert_eq!(tracker.cleanup_plan(), KITTY_POP);
        assert_eq!(tracker.cleanup_plan(), EMPTY);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u\x1b[<u");
        assert!(!tracker.is_kitty_keyboard_enabled());
        assert!(
            !tracker
                .cleanup_plan()
                .windows(KITTY_POP.len())
                .any(|w| w == KITTY_POP)
        );
    }

    #[test]
    fn terminal_mode_tracker_kitty_flags_set_clear_drive_cleanup() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[=15u");
        assert_eq!(tracker.kitty_flags(), 15);
        assert_eq!(tracker.cleanup_plan(), KITTY_FLAGS_CLEAR);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[=15u\x1b[=0u");
        assert_eq!(tracker.kitty_flags(), 0);
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_alt_screen_1049_and_47_toggle() {
        for (enter, leave, mode, cleanup) in [
            (
                b"\x1b[?1049h".as_slice(),
                b"\x1b[?1049l".as_slice(),
                AltScreenMode::Mode1049,
                ALT_SCREEN_1049_LEAVE,
            ),
            (
                b"\x1b[?47h".as_slice(),
                b"\x1b[?47l".as_slice(),
                AltScreenMode::Legacy47,
                ALT_SCREEN_47_LEAVE,
            ),
        ] {
            let mut tracker = TerminalModeTracker::new();
            tracker.feed(enter);
            assert_eq!(tracker.alt_screen(), Some(mode));
            assert_eq!(tracker.cleanup_plan(), cleanup);

            let mut tracker = TerminalModeTracker::new();
            tracker.feed(enter);
            tracker.feed(leave);
            assert!(!tracker.is_alt_screen_active());
            assert_eq!(tracker.cleanup_plan(), EMPTY);
        }
    }

    #[test]
    fn terminal_mode_tracker_bracketed_paste_toggle() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[?2004h");
        assert!(tracker.is_bracketed_paste_enabled());
        assert_eq!(tracker.cleanup_plan(), BRACKETED_PASTE_DISABLE);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[?2004h\x1b[?2004l");
        assert!(!tracker.is_bracketed_paste_enabled());
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_mouse_modes_are_independent() {
        for mode in MOUSE_MODES {
            let mut tracker = TerminalModeTracker::new();
            let enable = format!("\x1b[?{mode}h");
            let disable = format!("\x1b[?{mode}l");
            tracker.feed(enable.as_bytes());
            assert!(tracker.is_mouse_mode_enabled(mode));
            assert_eq!(tracker.cleanup_plan(), disable.as_bytes());

            let mut tracker = TerminalModeTracker::new();
            tracker.feed(enable.as_bytes());
            tracker.feed(disable.as_bytes());
            assert!(!tracker.is_mouse_mode_enabled(mode));
            assert_eq!(tracker.cleanup_plan(), EMPTY);
        }
    }

    #[test]
    fn terminal_mode_tracker_modify_other_keys_toggle() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>4;2m");
        assert_eq!(tracker.modify_other_keys(), 2);
        assert_eq!(tracker.cleanup_plan(), MODIFY_OTHER_KEYS_CLEAR);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>4;1m\x1b[>4;0m");
        assert_eq!(tracker.modify_other_keys(), 0);
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_decawm_defaults_on_and_restores_only_when_off() {
        let mut tracker = TerminalModeTracker::new();
        assert!(tracker.decawm());
        assert_eq!(tracker.cleanup_plan(), EMPTY);

        tracker.feed(b"\x1b[?7l");
        assert!(!tracker.decawm());
        assert_eq!(tracker.cleanup_plan(), DECAWM_ENABLE);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[?7l\x1b[?7h");
        assert!(tracker.decawm());
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_scroll_region_tracks_non_default() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[5;20r");
        assert!(tracker.scroll_region_non_default());
        assert_eq!(tracker.cleanup_plan(), SCROLL_REGION_RESET);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[5;20r\x1b[r");
        assert!(!tracker.scroll_region_non_default());
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_chunk_boundary_safe_for_tracked_sequences() {
        let sequences: &[&[u8]] = &[
            b"\x1b[>1u",
            b"\x1b[<u",
            b"\x1b[=15u",
            b"\x1b[?1049h",
            b"\x1b[?1049l",
            b"\x1b[?47h",
            b"\x1b[?2004h",
            b"\x1b[?1000h",
            b"\x1b[?1002h",
            b"\x1b[?1003h",
            b"\x1b[?1006h",
            b"\x1b[>4;2m",
            b"\x1b[?7l",
            b"\x1b[5;20r",
            b"\x1b[r",
        ];

        for sequence in sequences {
            let mut whole = TerminalModeTracker::new();
            whole.feed(sequence);
            for state in feed_split_everywhere(sequence) {
                assert_eq!(state, whole.state(), "sequence {sequence:?}");
            }
        }
    }

    #[test]
    fn terminal_mode_tracker_ignores_unrelated_bytes_and_bounds_buffer() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"text\x1b[31mred\x1b]0;title\x07\x1b[10;20H");
        assert_eq!(tracker.state(), TerminalModeState::default());

        let long = vec![b'1'; CSI_BUFFER_CAPACITY * 4];
        tracker.feed(b"\x1b[");
        tracker.feed(&long);
        assert!(tracker.buffered_len() <= CSI_BUFFER_CAPACITY);
        tracker.feed(b"m\x1b[?1006h");
        assert!(tracker.is_mouse_mode_enabled(1006));
    }

    #[test]
    fn terminal_mode_tracker_precise_teardown_only_emits_enabled_modes() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u\x1b[?1049h\x1b[?1006h");
        assert_eq!(tracker.cleanup_plan(), b"\x1b[<u\x1b[?1049l\x1b[?1006l");
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_symptom2_defensive_reset_fires_once() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u\x1b[=15u\x1b[>4;2m\x1b[?1049h\x1b[?1049l");
        assert_eq!(
            tracker.take_alt_screen_leave_kitty_reset(),
            b"\x1b[<u\x1b[=0u\x1b[>4;0m"
        );
        assert_eq!(tracker.take_alt_screen_leave_kitty_reset(), EMPTY);
        assert_eq!(tracker.cleanup_plan(), EMPTY);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u\x1b[?1049h\x1b[<u\x1b[?1049l");
        assert_eq!(tracker.take_alt_screen_leave_kitty_reset(), EMPTY);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u\x1b[?1049h\x1b[?1049l\x1b[<u");
        assert_eq!(tracker.take_alt_screen_leave_kitty_reset(), EMPTY);

        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u\x1b[?1049h\x1b[?1049l");
        assert_eq!(
            tracker.take_alt_screen_leave_kitty_reset(),
            b"\x1b[<u\x1b[=0u\x1b[>4;0m"
        );
    }

    #[test]
    fn terminal_mode_tracker_symptom2_treats_direct_kitty_flags_as_active() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[=15u");
        tracker.feed(b"\x1b[?1049h");
        tracker.feed(b"\x1b[?1049l");

        let reset = tracker.take_alt_screen_leave_kitty_reset();
        assert!(
            reset
                .windows(KITTY_FLAGS_CLEAR.len())
                .any(|window| window == KITTY_FLAGS_CLEAR),
            "direct Kitty flags must be cleared by defensive reset: {reset:?}"
        );
        assert!(
            !reset
                .windows(KITTY_POP.len())
                .any(|window| window == KITTY_POP),
            "push pop should not be emitted when only direct flags were active: {reset:?}"
        );
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_alt_screen_leave_reset_includes_targeted_non_kitty_cleanup() {
        let mut tracker = TerminalModeTracker::new();

        tracker.feed(
            b"\x1b[>1u\x1b[=15u\x1b[>4;2m\x1b[?1049h\x1b[?1000h\x1b[?1002h\
              \x1b[?1003h\x1b[?1006h\x1b[?2004h\x1b[?7l\x1b[5;20r\x1b[?1049l",
        );

        assert_eq!(
            tracker.take_alt_screen_leave_kitty_reset(),
            b"\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\
              \x1b[?1003l\x1b[?1006l\x1b[?7h\x1b[r"
        );
        assert!(!tracker.is_bracketed_paste_enabled());
        assert!(
            MOUSE_MODES
                .iter()
                .all(|mode| !tracker.is_mouse_mode_enabled(*mode))
        );
        assert!(tracker.decawm());
        assert!(!tracker.scroll_region_non_default());
    }

    #[test]
    fn terminal_mode_tracker_alt_screen_leave_reset_survives_stripped_kitty_push() {
        let mut tracker = TerminalModeTracker::new();

        tracker.feed(b"\x1b[?1049h\x1b[>4;2m\x1b[?1006h\x1b[?2004h\x1b[?7l\x1b[5;20r\x1b[?1049l");

        let reset = tracker.take_alt_screen_leave_kitty_reset();
        assert!(
            !reset
                .windows(KITTY_POP.len())
                .any(|window| window == KITTY_POP),
            "stripped Kitty push must not synthesize a Kitty pop: {reset:?}"
        );
        for cleanup in [
            MODIFY_OTHER_KEYS_CLEAR,
            BRACKETED_PASTE_DISABLE,
            b"\x1b[?1006l",
            DECAWM_ENABLE,
            SCROLL_REGION_RESET,
        ] {
            assert!(
                reset.windows(cleanup.len()).any(|window| window == cleanup),
                "missing cleanup {cleanup:?} from reset {reset:?}"
            );
        }
        assert!(!tracker.is_bracketed_paste_enabled());
        assert!(!tracker.is_mouse_mode_enabled(1006));
        assert!(tracker.decawm());
        assert!(!tracker.scroll_region_non_default());
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_spurious_disables_are_noops() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(
            b"\x1b[<u\x1b[<u\x1b[=0u\x1b[?1049l\x1b[?47l\x1b[?2004l\
              \x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[>4;0m",
        );
        assert_eq!(tracker.state(), TerminalModeState::default());
        assert_eq!(tracker.cleanup_plan(), EMPTY);

        tracker.feed(b"\x1b[>1u\x1b[<u\x1b[<u");
        assert_eq!(tracker.kitty_keyboard_depth(), 0);
        assert_eq!(tracker.cleanup_plan(), EMPTY);
    }

    #[test]
    fn terminal_mode_tracker_new_instance_resets_lifecycle_state() {
        let mut tracker = TerminalModeTracker::new();
        tracker.feed(b"\x1b[>1u\x1b[?1049h\x1b[?1006h");
        assert_ne!(tracker.state(), TerminalModeState::default());

        let tracker = TerminalModeTracker::new();
        assert_eq!(tracker.state(), TerminalModeState::default());
    }
}

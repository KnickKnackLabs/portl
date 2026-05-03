use std::time::Duration;

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
pub struct RenderBarOptions<'a> {
    pub canonical_ref: &'a str,
    pub supports_kick_others: bool,
    pub paste_cancellable: bool,
    pub remaining: Duration,
    pub unicode: bool,
    pub color: bool,
}

#[must_use]
pub fn render_bar(options: RenderBarOptions<'_>) -> String {
    let tenths = options.remaining.as_millis().div_ceil(100).min(99);
    let seconds = tenths / 10;
    let tenth = tenths % 10;
    let time = format!("{seconds}.{tenth}s");
    let (lead, arrow, sep, send_key) = if options.unicode {
        ("▌", "›", "·", "^\\")
    } else {
        ("|", ">", "|", "^\\")
    };
    let prefix = styled(
        &format!("{lead} Portl {arrow}"),
        "\x1b[1;36m",
        options.color,
    );
    let sep = styled(sep, "\x1b[2m", options.color);
    let key = |value: &str| styled(value, "\x1b[1;33m", options.color);
    let label = |value: &str| styled(value, "\x1b[2m", options.color);
    let timer = styled(&time, "\x1b[2m", options.color);

    let mut parts = vec![format!(
        "{} {}  {}  {} {}",
        prefix,
        options.canonical_ref,
        sep,
        key("d"),
        label("detach")
    )];
    if options.supports_kick_others {
        parts.push(format!("{} {} {}", sep, key("k"), label("kick")));
    }
    parts.push(format!("{} {} {}", sep, key(send_key), label("send")));
    if options.paste_cancellable {
        parts.push(format!("{} {} {}", sep, key("c"), label("cancel paste")));
    }
    parts.push(format!("{} {} {}", sep, key("Esc"), label("cancel")));
    parts.push(format!("{sep} {timer}"));
    parts.join(" ")
}

#[must_use]
pub fn fit_visible(text: &str, cols: u16) -> String {
    let max = usize::from(cols.max(1));
    let visible = visible_width(text);
    if visible <= max {
        return text.to_owned();
    }
    if max <= 1 {
        return "…".to_owned();
    }

    let mut out = String::new();
    let mut width = 0_usize;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            out.push(ch);
            for next in chars.by_ref() {
                out.push(next);
                if next == 'm' {
                    break;
                }
            }
            continue;
        }
        if width >= max - 1 {
            break;
        }
        out.push(ch);
        width += 1;
    }
    out.push('…');
    out.push_str("\x1b[0m");
    out
}

#[must_use]
pub fn visible_width(text: &str) -> usize {
    let mut width = 0_usize;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            width += 1;
        }
    }
    width
}

#[must_use]
pub fn is_ctrl_backslash_sequence(data: &[u8]) -> bool {
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

fn styled(text: &str, sgr: &str, color: bool) -> String {
    if color {
        format!("{sgr}{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_bar_renders_heavy_unicode_style() {
        let bar = render_bar(RenderBarOptions {
            canonical_ref: "max-b265/tmux/dotfiles",
            supports_kick_others: true,
            paste_cancellable: false,
            remaining: Duration::from_millis(1900),
            unicode: true,
            color: false,
        });

        assert_eq!(
            bar,
            "▌ Portl › max-b265/tmux/dotfiles  ·  d detach · k kick · ^\\ send · Esc cancel · 1.9s"
        );
    }

    #[test]
    fn compact_bar_omits_kick_for_zmx_and_falls_back_to_ascii() {
        let bar = render_bar(RenderBarOptions {
            canonical_ref: "max-b265/zmx/dev",
            supports_kick_others: false,
            paste_cancellable: false,
            remaining: Duration::from_secs(2),
            unicode: false,
            color: false,
        });

        assert_eq!(
            bar,
            "| Portl > max-b265/zmx/dev  |  d detach | ^\\ send | Esc cancel | 2.0s"
        );
    }

    #[test]
    fn compact_bar_shows_cancel_paste_when_paste_active() {
        let bar = render_bar(RenderBarOptions {
            canonical_ref: "max-b265/zmx/dev",
            supports_kick_others: false,
            paste_cancellable: true,
            remaining: Duration::from_secs(2),
            unicode: false,
            color: false,
        });

        assert_eq!(
            bar,
            "| Portl > max-b265/zmx/dev  |  d detach | ^\\ send | c cancel paste | Esc cancel | 2.0s"
        );
    }

    #[test]
    fn ansi_fitting_uses_visible_width() {
        let text = "\x1b[1;36mPortl ›\x1b[0m abcdef";

        assert_eq!(visible_width(text), "Portl › abcdef".chars().count());
        assert_eq!(fit_visible(text, 10), "\x1b[1;36mPortl ›\x1b[0m a…\x1b[0m");
    }

    #[test]
    fn detects_raw_and_kitty_ctrl_backslash() {
        assert!(is_ctrl_backslash_sequence(b"\x1c"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;5u"));
        assert!(is_ctrl_backslash_sequence(b"prefix\x1b[92;5:1usuffix"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;5:2u"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92;69u"));
        assert!(is_ctrl_backslash_sequence(b"\x1b[92:124;5u"));

        assert!(!is_ctrl_backslash_sequence(b"\\"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;5:3u"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;6u"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[92;7u"));
        assert!(!is_ctrl_backslash_sequence(b"\x1b[91;5u"));
        assert!(!is_ctrl_backslash_sequence(b"not-detach"));
    }
}

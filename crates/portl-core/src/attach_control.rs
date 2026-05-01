use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct RenderBarOptions<'a> {
    pub canonical_ref: &'a str,
    pub supports_kick_others: bool,
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
    fn ansi_fitting_uses_visible_width() {
        let text = "\x1b[1;36mPortl ›\x1b[0m abcdef";

        assert_eq!(visible_width(text), "Portl › abcdef".chars().count());
        assert_eq!(fit_visible(text, 10), "\x1b[1;36mPortl ›\x1b[0m a…\x1b[0m");
    }
}

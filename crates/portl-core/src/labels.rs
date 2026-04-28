/// Build the canonical human label for a machine identity:
/// `<sanitized-hostname>-<endpoint-last4>`.
#[must_use]
pub fn machine_label(hostname: Option<&str>, endpoint_id_hex: &str) -> String {
    let host = hostname.and_then(|h| h.split('.').next());
    machine_label_from_hint(host, endpoint_id_hex)
}

/// Build a machine label from an explicit human hint, appending the
/// endpoint suffix unless the hint already carries it.
#[must_use]
pub fn machine_label_from_hint(hint: Option<&str>, endpoint_id_hex: &str) -> String {
    let base = hint
        .and_then(sanitize_label_component)
        .unwrap_or_else(|| "host".to_owned());
    let suffix = endpoint_suffix(endpoint_id_hex, 4);
    if base.ends_with(&format!("-{suffix}")) {
        base
    } else {
        format!("{base}-{suffix}")
    }
}

/// Build the default ref for an imported session share:
/// `<machine-label>/<friendly-name>`.
#[must_use]
pub fn session_share_label(machine_label: &str, friendly_name: &str) -> String {
    let friendly = sanitize_label_component(friendly_name).unwrap_or_else(|| "session".to_owned());
    format!("{}/{friendly}", machine_label.trim_matches('-'))
}

/// Build the default label for a generic saved ticket:
/// `<machine-label>-ticket-<purpose>`.
#[must_use]
pub fn ticket_label(machine_label: &str, purpose: &str) -> String {
    let purpose = sanitize_label_component(purpose).unwrap_or_else(|| "access".to_owned());
    format!("{}-ticket-{purpose}", machine_label.trim_matches('-'))
}

#[must_use]
pub fn endpoint_suffix(endpoint_id_hex: &str, chars: usize) -> String {
    let hex = endpoint_id_hex.trim().to_ascii_lowercase();
    let start = hex.len().saturating_sub(chars);
    hex[start..].to_owned()
}

#[must_use]
pub fn sanitize_label_component(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in raw.trim().chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_label_uses_sanitized_host_and_endpoint_suffix() {
        assert_eq!(machine_label(Some("Max.local"), "bba96591b265"), "max-b265");
    }

    #[test]
    fn machine_label_falls_back_to_endpoint_when_host_is_empty() {
        assert_eq!(machine_label(Some("---"), "bba96591b265"), "host-b265");
    }

    #[test]
    fn machine_label_from_hint_does_not_double_append_suffix() {
        assert_eq!(
            machine_label_from_hint(Some("onyx-7310"), "d65f9e657310"),
            "onyx-7310"
        );
    }

    #[test]
    fn session_share_label_is_machine_slash_friendly_name() {
        assert_eq!(
            session_share_label("max-b265", "Dotfiles Main"),
            "max-b265/dotfiles-main"
        );
    }

    #[test]
    fn ticket_label_keeps_ticket_segment_explicit() {
        assert_eq!(ticket_label("max-b265", "shell"), "max-b265-ticket-shell");
    }
}

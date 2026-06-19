//! Canonical-form enforcement per `docs/design/030-tickets.md §2.2`.
//!
//! `canonical_check` is the verifier's first line of defence. It
//! runs before any signature work so malformed bodies are cheap to
//! reject, and it's also called by the minting path so portl never
//! emits a non-canonical ticket. Every rule here is reflected in
//! an integration test in `tests/ticket_canonical.rs`.
//!
//! Rules enforced (numbered as in the design doc):
//!   1. Issuer elision is **mandatory**, not optional.
//!      1b. `body.target` equals `addr.endpoint_id`.
//!   2. The presence bitmap on `Capabilities` equals the set of
//!      `Some` fields — no mismatch in either direction.
//!   3. All `Vec` fields are lexicographically sorted with unique
//!      elements.
//!   4. Timestamps: `not_after > not_before`, TTL ≤ 365 days,
//!      `nonce` is non-zero.
//!   5. Signature canonicalisation (low-S) lives in `sign.rs`
//!      because it needs the signature bytes, not just the body;
//!      checked at verify time.
//!   6. `postcard::to_stdvec(decoded) == received_bytes` — lives
//!      in `codec.rs` for the same reason (needs the on-wire
//!      bytes).

use crate::error::{PortlError, Result};
use crate::ticket::schema::{
    Capabilities, EnvPolicy, PortRule, PortlBody, PortlTicket, ShellCaps, TCP_LISTEN_CAP_BIT,
    UnixPathRule, validate_unix_path_rule,
};

/// One year in seconds (365 × 86 400).
const MAX_TTL_SECONDS: u64 = 365 * 86_400;

/// Verify a body is in canonical form.
///
/// Returns `Ok(())` iff every rule from `030-tickets.md §2.2`
/// items 1–4 holds. Returns `Err(PortlError::Canonical(reason))`
/// otherwise; the `reason` is a short human-readable tag that
/// matches the rule it violated.
pub fn canonical_check(body: &PortlBody) -> Result<()> {
    // Rule 1 (partial): issuer MUST be None when it would equal
    // addr.endpoint_id. We can't check against `addr` from the
    // body alone; that comparison happens where the ticket is
    // available (decoder, mint). What we *can* do here: if an
    // explicit issuer is present, it must not equal the body's
    // own implicit self-issuer fingerprint. The ticket-level
    // entry point below (`canonical_check_ticket`) enforces the
    // addr-equivalence form.
    //
    // The test matrix drives this via the ticket-aware entry
    // point. `canonical_check` on the body alone is still
    // responsible for every non-addr rule.

    // Rule 2: presence bitmap equals Some-set.
    check_presence_bitmap(&body.caps)?;

    // Rule 3: sorted + dedup for every Vec-typed field.
    if let Some(rules) = &body.caps.tcp {
        check_sorted_unique_port_rules(rules)?;
    }
    if let Some(rules) = &body.caps.udp {
        check_sorted_unique_port_rules(rules)?;
    }
    if let Some(fs) = &body.caps.fs {
        check_sorted_unique_strings(&fs.roots, "fs.roots")?;
    }
    if let Some(shell) = &body.caps.shell {
        check_shell_caps_sorted(shell)?;
    }
    if let Some(unix) = &body.caps.unix {
        check_sorted_unique_unix_path_rules(&unix.connect, "unix.connect")?;
        check_sorted_unique_unix_path_rules(&unix.listen, "unix.listen")?;
    }
    // alpns_extra: rule 3 (sort+dedup) and the v0.1 "MUST be empty"
    // invariant from §2.
    if !body.alpns_extra.is_empty() {
        return Err(PortlError::Canonical("alpns_extra must be empty in v0.1"));
    }

    // Rule 4: timestamps + nonce.
    if body.not_after <= body.not_before {
        return Err(PortlError::Canonical("not_after must be > not_before"));
    }
    if body.not_after.saturating_sub(body.not_before) > MAX_TTL_SECONDS {
        return Err(PortlError::Canonical("ttl exceeds 365 days"));
    }
    if body.nonce == [0u8; 8] {
        return Err(PortlError::Canonical("nonce must be non-zero"));
    }
    if matches!(body.bearer.as_deref(), Some([])) {
        return Err(PortlError::Canonical(
            "bearer must be Some(non-empty) or None",
        ));
    }

    // Rule 1 at the body level: if issuer is Some, disallow the
    // common typo of signalling "self-signed" with the wrong form.
    // The strict addr-equivalence form is enforced in
    // `canonical_check_ticket` below. Here we simply let any
    // non-None issuer through; it's resolved against `addr` by
    // callers with access to the ticket.

    Ok(())
}

/// Ticket-level canonical check.
///
/// Enforces rule 1 in its full form: `body.issuer ==
/// Some(addr.endpoint_id)` is rejected, so self-signed roots MUST
/// use issuer elision (`None`). Also enforces rule 1b:
/// `body.target == addr.endpoint_id`.
pub fn canonical_check_ticket(ticket: &PortlTicket) -> Result<()> {
    canonical_check(&ticket.body)?;
    if ticket.body.target != *ticket.addr.id.as_bytes() {
        return Err(PortlError::Canonical(
            "body.target does not match addr.endpoint_id",
        ));
    }
    if let Some(issuer) = ticket.body.issuer
        && &issuer == ticket.addr.id.as_bytes()
    {
        return Err(PortlError::Canonical(
            "issuer equals addr.endpoint_id; MUST use None (rule 1)",
        ));
    }
    Ok(())
}

/// Resolve a ticket's effective signing key per rule 1.
///
/// * If `body.issuer == None` → the `addr.endpoint_id`.
/// * If `body.issuer == Some(k)` → `k`.
///
/// Rule 1 forbids `body.issuer == Some(addr.endpoint_id)`; that
/// case is rejected by `canonical_check_ticket`, so we only reach
/// this function after passing that gate.
pub fn resolved_issuer(ticket: &PortlTicket) -> [u8; 32] {
    ticket
        .body
        .issuer
        .unwrap_or_else(|| *ticket.addr.id.as_bytes())
}

// ---------- internals ----------

/// Rule 2: the presence bitmap equals the set of `Some` fields.
#[allow(clippy::cognitive_complexity)]
fn check_presence_bitmap(caps: &Capabilities) -> Result<()> {
    let expected = u8::from(caps.shell.is_some())
        | (u8::from(caps.tcp.is_some()) << 1)
        | (u8::from(caps.udp.is_some()) << 2)
        | (u8::from(caps.fs.is_some()) << 3)
        | (u8::from(caps.vpn.is_some()) << 4)
        | (u8::from(caps.meta.is_some()) << 5)
        | (u8::from(caps.unix.is_some()) << 6)
        | (caps.presence & TCP_LISTEN_CAP_BIT);
    if caps.presence != expected {
        return Err(PortlError::Canonical(
            "presence bitmap does not match Some-set",
        ));
    }
    if caps.presence & TCP_LISTEN_CAP_BIT != 0 && caps.tcp.is_none() {
        return Err(PortlError::Canonical("tcp listen flag requires tcp caps"));
    }
    Ok(())
}

/// Rule 3 for `Vec<PortRule>`.
fn check_sorted_unique_port_rules(rules: &[PortRule]) -> Result<()> {
    for w in rules.windows(2) {
        let ord = portrule_ord(&w[0], &w[1]);
        match ord {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(PortlError::Canonical("duplicate port rule"));
            }
            std::cmp::Ordering::Greater => {
                return Err(PortlError::Canonical("port rules not sorted"));
            }
        }
    }
    Ok(())
}

fn portrule_ord(a: &PortRule, b: &PortRule) -> std::cmp::Ordering {
    a.host_glob
        .cmp(&b.host_glob)
        .then(a.port_min.cmp(&b.port_min))
        .then(a.port_max.cmp(&b.port_max))
}

fn check_sorted_unique_unix_path_rules(rules: &[UnixPathRule], tag: &'static str) -> Result<()> {
    for rule in rules {
        if validate_unix_path_rule(&rule.path, true).is_err() {
            return Err(PortlError::Canonical(match tag {
                "unix.connect" => "invalid unix.connect path rule",
                "unix.listen" => "invalid unix.listen path rule",
                _ => "invalid unix path rule",
            }));
        }
    }
    for w in rules.windows(2) {
        match w[0].path.cmp(&w[1].path) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(PortlError::Canonical(match tag {
                    "unix.connect" => "duplicate unix.connect path rule",
                    "unix.listen" => "duplicate unix.listen path rule",
                    _ => "duplicate unix path rule",
                }));
            }
            std::cmp::Ordering::Greater => {
                return Err(PortlError::Canonical(match tag {
                    "unix.connect" => "unix.connect path rules not sorted",
                    "unix.listen" => "unix.listen path rules not sorted",
                    _ => "unix path rules not sorted",
                }));
            }
        }
    }
    Ok(())
}

/// Rule 3 for `Vec<String>` with a tag so errors say which field.
fn check_sorted_unique_strings(v: &[String], tag: &'static str) -> Result<()> {
    for w in v.windows(2) {
        match w[0].cmp(&w[1]) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(PortlError::Canonical(match tag {
                    "fs.roots" => "duplicate fs.roots entry",
                    "shell.user_allowlist" => "duplicate shell.user_allowlist entry",
                    "shell.command_allowlist" => "duplicate shell.command_allowlist entry",
                    "env.allow" => "duplicate env.allow entry",
                    _ => "duplicate string entry",
                }));
            }
            std::cmp::Ordering::Greater => {
                return Err(PortlError::Canonical(match tag {
                    "fs.roots" => "fs.roots not sorted",
                    "shell.user_allowlist" => "shell.user_allowlist not sorted",
                    "shell.command_allowlist" => "shell.command_allowlist not sorted",
                    "env.allow" => "env.allow not sorted",
                    _ => "string vec not sorted",
                }));
            }
        }
    }
    Ok(())
}

/// Rule 3 applied to every `Vec` inside `ShellCaps`.
fn check_shell_caps_sorted(s: &ShellCaps) -> Result<()> {
    if let Some(v) = &s.user_allowlist {
        check_sorted_unique_strings(v, "shell.user_allowlist")?;
    }
    if let Some(v) = &s.command_allowlist {
        check_sorted_unique_strings(v, "shell.command_allowlist")?;
    }
    match &s.env_policy {
        EnvPolicy::Deny | EnvPolicy::Merge { allow: None } => {}
        EnvPolicy::Merge { allow: Some(v) } => {
            check_sorted_unique_strings(v, "env.allow")?;
        }
        EnvPolicy::Replace { base } => {
            // Sort by key, no duplicates.
            for w in base.windows(2) {
                match w[0].0.cmp(&w[1].0) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => {
                        return Err(PortlError::Canonical("duplicate env.replace key"));
                    }
                    std::cmp::Ordering::Greater => {
                        return Err(PortlError::Canonical("env.replace not sorted by key"));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::canonical_check;
    use crate::ticket::schema::{Capabilities, PortRule, PortlBody, TCP_LISTEN_CAP_BIT};

    #[test]
    fn tcp_listen_presence_bit_is_canonical_when_tcp_caps_exist() {
        let body = body_with_caps(Capabilities {
            presence: 0b0000_0010 | TCP_LISTEN_CAP_BIT,
            shell: None,
            tcp: Some(vec![PortRule {
                host_glob: "127.0.0.1".to_owned(),
                port_min: 1,
                port_max: 65535,
            }]),
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
            unix: None,
        });

        canonical_check(&body).expect("tcp listen bit with tcp caps should be canonical");
    }

    #[test]
    fn tcp_listen_presence_bit_requires_tcp_caps() {
        let body = body_with_caps(Capabilities {
            presence: TCP_LISTEN_CAP_BIT,
            shell: None,
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
            unix: None,
        });

        let err = canonical_check(&body).expect_err("tcp listen bit without tcp must be invalid");
        assert_eq!(
            err.to_string(),
            "canonical form violated: tcp listen flag requires tcp caps"
        );
    }

    fn body_with_caps(caps: Capabilities) -> PortlBody {
        PortlBody {
            caps,
            target: [1; 32],
            alpns_extra: Vec::new(),
            not_before: 10,
            not_after: 20,
            issuer: None,
            parent: None,
            nonce: [1; 8],
            bearer: None,
            to: None,
        }
    }
}

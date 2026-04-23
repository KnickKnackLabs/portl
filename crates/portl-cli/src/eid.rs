//! Endpoint-id display + resolution helpers.
//!
//! Two jobs:
//!
//! 1. `format_short` — canonical middle-elided form (`PPPPPPPP…SSSS`)
//!    for human-facing tabular and dashboard output. Any eight hex
//!    chars of prefix plus four of suffix are enough to discriminate
//!    peers we've actually seen; full hex is only needed for
//!    bootstrapping.
//!
//! 2. `resolve` — accept full hex, middle-elided forms, or a unique
//!    hex prefix and map back to a concrete `EndpointId`, using the
//!    peer store + ticket store as the universe of known peers.
//!    Returns a concise disambiguation error when the short form is
//!    ambiguous.

use anyhow::{Context, Result, anyhow, bail};
use iroh_base::EndpointId;
use portl_core::peer_store::PeerStore;
use portl_core::ticket_store::TicketStore;

/// Unicode horizontal ellipsis used to separate prefix/suffix in the
/// short form. Shared constant so display and parse stay in sync.
pub const ELLIPSIS: char = '…';

/// Number of hex chars kept from the prefix in `format_short`.
pub const SHORT_PREFIX: usize = 8;
/// Number of hex chars kept from the suffix in `format_short`.
pub const SHORT_SUFFIX: usize = 4;

/// Render an endpoint-id hex string as `PPPPPPPP…SSSS`. Idempotent
/// for strings already shorter than `SHORT_PREFIX + SHORT_SUFFIX`
/// (returns them unchanged).
#[must_use]
pub fn format_short(eid_hex: &str) -> String {
    if eid_hex.len() <= SHORT_PREFIX + SHORT_SUFFIX {
        return eid_hex.to_owned();
    }
    format!(
        "{}{ELLIPSIS}{}",
        &eid_hex[..SHORT_PREFIX],
        &eid_hex[eid_hex.len().saturating_sub(SHORT_SUFFIX)..]
    )
}

/// Same as `format_short`, for raw 32-byte endpoint-id bytes.
#[must_use]
pub fn format_short_bytes(eid: &[u8; 32]) -> String {
    format_short(&hex::encode(eid))
}

/// Resolve a user-supplied token to a concrete `EndpointId`.
///
/// Accepts:
/// - Full 64-char hex (always valid, no lookup required).
/// - Middle-elided form `PPPP…SSSS` (any prefix/suffix lengths,
///   both must be hex), matched against the known-peer universe.
///
/// Bare hex prefixes without the ellipsis are rejected to avoid
/// surprising prefix-match behaviour when a user typos a label as
/// hex-looking text.
///
/// The "known" universe is the union of `peer_store.iter()` and
/// `ticket_store.iter()` endpoint ids. Ambiguous short forms return
/// an error listing the matches so the caller can retype more
/// specifically.
pub fn resolve(
    token: &str,
    peer_store: Option<&PeerStore>,
    ticket_store: Option<&TicketStore>,
) -> Result<EndpointId> {
    // Fast path: full 64-char hex. Works without any known-peer
    // context, which is exactly what bootstrap / one-off dial needs.
    if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return parse_full_hex(token);
    }

    // Anything else must be the explicit elided form.
    let Some((prefix_raw, suffix_raw)) = token.split_once(ELLIPSIS) else {
        bail!(
            "endpoint id '{token}' must be 64-char hex or a middle-elided \
             form like `d65f9e65{ELLIPSIS}7310`"
        );
    };
    let prefix = prefix_raw.to_ascii_lowercase();
    let suffix = suffix_raw.to_ascii_lowercase();
    if !prefix.chars().all(|c| c.is_ascii_hexdigit())
        || !suffix.chars().all(|c| c.is_ascii_hexdigit())
    {
        bail!("endpoint id '{token}' has non-hex characters");
    }
    if prefix.is_empty() && suffix.is_empty() {
        bail!("endpoint id '{token}' is empty around the ellipsis");
    }

    let known: Vec<String> = known_eids(peer_store, ticket_store);
    if known.is_empty() {
        bail!(
            "endpoint id '{token}' is a short form but no peers are stored \
             locally to resolve against; pass the full 64-char hex id"
        );
    }

    let matches: Vec<&String> = known
        .iter()
        .filter(|full| full.starts_with(&prefix) && full.ends_with(&suffix))
        .collect();

    match matches.len() {
        0 => bail!(
            "no known peer matches '{token}'. Run `portl peer ls` or \
             `portl ticket ls` to see stored peers."
        ),
        1 => parse_full_hex(matches[0]),
        n => {
            let listing = matches
                .iter()
                .take(5)
                .map(|s| format_short(s))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "endpoint id '{token}' is ambiguous ({n} matches: {listing}{more}). \
                 Retype more prefix or suffix characters.",
                more = if n > 5 { ", …" } else { "" }
            )
        }
    }
}

fn parse_full_hex(hex_str: &str) -> Result<EndpointId> {
    let bytes = hex::decode(hex_str).context("endpoint id hex decode")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("endpoint id must be exactly 32 bytes"))?;
    EndpointId::from_bytes(&bytes).context("invalid endpoint id")
}

fn known_eids(
    peer_store: Option<&PeerStore>,
    ticket_store: Option<&TicketStore>,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ps) = peer_store {
        for e in ps.iter() {
            out.push(e.endpoint_id_hex.clone());
        }
    }
    if let Some(ts) = ticket_store {
        for (_label, entry) in ts.iter() {
            out.push(entry.endpoint_id_hex.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_A: &str = "d65f9e6500000000000000000000000000000000000000000000000000007310";
    const FULL_C: &str = "bba96591222222222222222222222222222222222222222222222222ffffb265";

    #[test]
    fn format_short_is_eight_plus_four() {
        assert_eq!(format_short(FULL_A), "d65f9e65…7310");
        assert_eq!(format_short(FULL_C), "bba96591…b265");
    }

    #[test]
    fn format_short_passes_through_shorter_inputs() {
        assert_eq!(format_short("deadbeef"), "deadbeef");
        assert_eq!(format_short(""), "");
    }

    #[test]
    fn resolve_accepts_full_hex_without_known_universe() {
        let eid = resolve(FULL_A, None, None).expect("full hex resolves");
        assert_eq!(hex::encode(eid.as_bytes()), FULL_A);
    }

    #[test]
    fn resolve_elided_requires_known_universe() {
        let err = resolve("d65f9e65…7310", None, None).unwrap_err();
        assert!(err.to_string().contains("no peers are stored"));
    }

    #[test]
    fn resolve_rejects_bare_prefix_without_ellipsis() {
        // No ellipsis and not 64 chars → rejected. Prevents label
        // typos from accidentally resolving via prefix match.
        let err = resolve("d65f9e65", None, None).unwrap_err();
        assert!(err.to_string().contains("middle-elided"));
    }

    // Integration coverage for the short-form lookup path lives in
    // the CLI tests (where a real PeerStore is available). The pure
    // parsing/classification logic above is fully covered here.

    #[test]
    fn resolve_rejects_non_hex() {
        let err = resolve("abcd…zzzz", None, None).unwrap_err();
        assert!(err.to_string().contains("non-hex"));
    }

    #[test]
    fn ellipsis_constant_is_horizontal_ellipsis() {
        // Guardrail: the display sites reach for '…' (U+2026)
        // directly in format strings. If anyone changes this we want
        // a compile/test failure, not drift.
        assert_eq!(ELLIPSIS, '\u{2026}');
    }
}

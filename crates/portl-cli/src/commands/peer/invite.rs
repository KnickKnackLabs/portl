//! `portl peer invite` — issue, list, revoke pair invite codes.
//!
//! Writes `pending_invites.json` in `$PORTL_HOME`. The running
//! agent picks up new invites within ~500ms via the existing
//! peer-store reload-task cadence (v0.3.4 adds a parallel task
//! for the invite store, but reads are already safe because each
//! `pair_handler::handle_pair` call loads the file fresh).

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use portl_core::id::store;
use portl_core::pair_code::InviteCode;
use portl_core::pair_store::{PairStore, PendingInvite};
use rand::RngCore;

const DEFAULT_TTL_SECS: u64 = 3600;

pub fn issue(ttl: Option<&str>, for_label: Option<&str>, json: bool) -> Result<ExitCode> {
    let ttl_secs = parse_ttl(ttl)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let not_after_unix = now.saturating_add(ttl_secs);

    // Generate a 128-bit nonce. OsRng is fine — not latency-sensitive.
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);

    // Inviter's endpoint_id is the local identity's verifying key.
    let identity = store::load(&store::default_path()).context("load local identity")?;
    let inviter_eid = identity.verifying_key();

    let invite = PendingInvite {
        nonce_hex: nonce_hex.clone(),
        issued_at_unix: now,
        not_after_unix,
        for_label_hint: for_label.map(ToOwned::to_owned),
    };

    let mut store_file = PairStore::load(PairStore::default_path()).context("load pair store")?;
    store_file.insert(invite);
    store_file.save().context("save pair store")?;

    let code = InviteCode::new(inviter_eid, nonce, not_after_unix, None)
        .encode()
        .context("encode invite code")?;

    if json {
        let envelope = serde_json::json!({
            "schema": 1,
            "kind": "peer.invite.issued",
            "code": code,
            "nonce_hex": nonce_hex,
            "expires_at_unix": not_after_unix,
            "expires_in_secs": ttl_secs,
            "for_label": for_label,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        println!("code:    {code}");
        println!(
            "expires: in {} (unix {not_after_unix})",
            fmt_duration(ttl_secs)
        );
        println!("share this code over a trusted channel (DM, signed email, etc.)");
        println!("  pair:   portl peer pair <code>     # mutual trust");
        println!("  accept: portl peer accept <code>   # one-way: they can reach you");
    }
    Ok(ExitCode::SUCCESS)
}

pub fn list(json: bool) -> Result<ExitCode> {
    let store = PairStore::load(PairStore::default_path())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if json {
        let invites: Vec<_> = store
            .iter()
            .map(|i| {
                serde_json::json!({
                    "nonce_hex": i.nonce_hex,
                    "issued_at_unix": i.issued_at_unix,
                    "expires_at_unix": i.not_after_unix,
                    "expired": i.not_after_unix <= now,
                    "expires_in_secs": i.not_after_unix.saturating_sub(now),
                    "for_label": i.for_label_hint,
                })
            })
            .collect();
        let envelope = serde_json::json!({
            "schema": 1,
            "kind": "peer.invite.list",
            "now_unix": now,
            "invites": invites,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(ExitCode::SUCCESS);
    }

    if store.is_empty() {
        println!("no pending invites. Issue one with:\n  portl peer invite");
        return Ok(ExitCode::SUCCESS);
    }
    println!("{:<16} {:<14} {:<14}", "NONCE", "FOR_LABEL", "EXPIRES");
    for invite in store.iter() {
        let nonce_short = &invite.nonce_hex[..12.min(invite.nonce_hex.len())];
        let for_label = invite.for_label_hint.as_deref().unwrap_or("—");
        let expires = if invite.not_after_unix <= now {
            "EXPIRED".to_owned()
        } else {
            format!("in {}", fmt_duration(invite.not_after_unix - now))
        };
        println!("{nonce_short:<16} {for_label:<14} {expires:<14}");
    }
    Ok(ExitCode::SUCCESS)
}

pub fn revoke(nonce_prefix: &str) -> Result<ExitCode> {
    let mut store = PairStore::load(PairStore::default_path())?;
    let Some(invite) = store.find_by_nonce_prefix(nonce_prefix)? else {
        eprintln!("no pending invite matches prefix {nonce_prefix:?}");
        return Ok(ExitCode::FAILURE);
    };
    let nonce_hex = invite.nonce_hex.clone();
    if !store.remove(&nonce_hex) {
        eprintln!("invite {nonce_prefix} vanished before it could be revoked");
        return Ok(ExitCode::FAILURE);
    }
    store.save()?;
    println!("revoked invite {nonce_hex}");
    Ok(ExitCode::SUCCESS)
}

fn parse_ttl(ttl: Option<&str>) -> Result<u64> {
    let Some(s) = ttl else {
        return Ok(DEFAULT_TTL_SECS);
    };
    // Accept bare seconds (`3600`) or duration shorthand (10m, 1h, 30d).
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(secs);
    }
    let (num_part, suffix) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num_part
        .parse()
        .with_context(|| format!("parse ttl value {s:?}"))?;
    let mul = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => bail!("unknown ttl suffix {suffix:?} (expected s/m/h/d)"),
    };
    Ok(n.saturating_mul(mul))
}

fn fmt_duration(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_accepts_bare_seconds() {
        assert_eq!(parse_ttl(Some("120")).unwrap(), 120);
    }

    #[test]
    fn parse_ttl_accepts_shorthand() {
        assert_eq!(parse_ttl(Some("10m")).unwrap(), 600);
        assert_eq!(parse_ttl(Some("1h")).unwrap(), 3600);
        assert_eq!(parse_ttl(Some("30d")).unwrap(), 30 * 86_400);
    }

    #[test]
    fn parse_ttl_defaults_when_absent() {
        assert_eq!(parse_ttl(None).unwrap(), DEFAULT_TTL_SECS);
    }

    #[test]
    fn parse_ttl_rejects_garbage() {
        assert!(parse_ttl(Some("xyz")).is_err());
    }
}

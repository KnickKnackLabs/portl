//! `portl peer add-unsafe-raw` — escape hatch for environments where
//! the pairing handshake (v0.3.1+) isn't usable yet. Writes a peer
//! entry directly to `peers.json` after a confirmation prompt that
//! requires the user to retype the `endpoint_id` to prove they've
//! read it. No network round-trip; no way to verify the endpoint
//! holds the matching private key — that's the "unsafe" in the
//! name.
//!
//! The standard flow for v0.3.0:
//!   - On max: `portl whoami` → copy `endpoint_id`
//!   - On onyx: `portl peer add-unsafe-raw <max_eid> --label max --mutual`
//!   - On onyx: `portl whoami` → copy `endpoint_id`
//!   - On max:  `portl peer add-unsafe-raw <onyx_eid> --label onyx --mutual`
//!   - On onyx: `portl shell max`

use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore, auto_label};
use portl_core::ticket_store::TicketStore;

#[allow(clippy::fn_params_excessive_bools)]
pub fn run(
    endpoint_hex: &str,
    label: Option<String>,
    mutual: bool,
    inbound: bool,
    outbound: bool,
    yes: bool,
) -> Result<ExitCode> {
    // Validate endpoint_id before the confirmation prompt — typos
    // should fail early, not after the user's retyped it correctly.
    let eid = parse_endpoint_hex(endpoint_hex)?;

    let (accepts_from_them, they_accept_from_me) = match (mutual, inbound, outbound) {
        (true, false, false) => (true, true),
        (false, true, false) => (true, false),
        (false, false, true) => (false, true),
        (false, false, false) => bail!(
            "must pick exactly one of: --mutual, --inbound, --outbound \
             (these set the relationship flags; see `portl peer ls --help`)"
        ),
        _ => bail!("--mutual, --inbound, --outbound are mutually exclusive; pick one"),
    };

    let label = label.unwrap_or_else(|| auto_label(&eid));

    // Global label-uniqueness guard: refuse collisions across both
    // peer and ticket stores so `shell <label>` never becomes
    // ambiguous.
    let peers_path = PeerStore::default_path();
    let mut peers = PeerStore::load(&peers_path)?;
    let tickets = TicketStore::load(&TicketStore::default_path())?;
    if let Some(store) = portl_core::store_index::label_in_use(&label, &peers, &tickets) {
        if store == "peer" {
            // Allow updating a same-endpoint, same-label row (idempotent).
            if let Some(existing) = peers.get_by_label(&label)
                && existing.endpoint_id_hex != hex::encode(eid)
            {
                bail!(
                    "label '{label}' already points at a different peer; \
                     pick another label or `portl peer unlink {label}` first"
                );
            }
        } else {
            bail!(
                "label '{label}' is already used by a saved ticket; pick another \
                 label or `portl ticket rm {label}` first"
            );
        }
    }

    if !yes {
        // Require the user to retype the endpoint_id. A --force /
        // --yes flag alone isn't enough; this command grants
        // root-equivalent authority when `accepts_from_them=true`.
        eprint!(
            "This grants peer '{label}' ({rel}) authority on this machine.\n\
             Retype the full endpoint_id to continue:\n> ",
            rel = match (accepts_from_them, they_accept_from_me) {
                (true, true) => "mutual",
                (true, false) => "inbound",
                (false, true) => "outbound",
                _ => unreachable!(),
            }
        );
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .context("read confirmation")?;
        if line.trim() != endpoint_hex {
            bail!("endpoint_id confirmation did not match; aborted");
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    peers.insert_or_update(PeerEntry {
        label: label.clone(),
        endpoint_id_hex: hex::encode(eid),
        accepts_from_them,
        they_accept_from_me,
        since: now,
        origin: PeerOrigin::Raw,
        last_hold_at: None,
        is_self: false,
        relay_hint: None,
        schema_version: 2,
    })?;
    peers.save(&peers_path)?;
    println!("added peer '{label}' (raw). Agent will pick up the change within ~500ms.");
    Ok(ExitCode::SUCCESS)
}

fn parse_endpoint_hex(spec: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(spec).with_context(|| format!("endpoint_id must be hex: {spec}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("endpoint_id must be exactly 32 bytes (64 hex chars)"))
}

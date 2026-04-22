//! `portl ticket ls` — show saved tickets with endpoint and
//! human-readable expiry. No caps column (would need re-parsing
//! each ticket; save `portl ticket show <label>` for that if we
//! want it later).

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_core::ticket_store::TicketStore;

pub fn run() -> Result<ExitCode> {
    let tickets = TicketStore::load(&TicketStore::default_path())?;
    if tickets.is_empty() {
        println!("no tickets saved. Save one with:\n  portl ticket save <label> <ticket-string>");
        return Ok(ExitCode::SUCCESS);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();

    let mut rows: Vec<_> = tickets.iter().collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));

    println!("{:<14} {:<22} {:<14}", "LABEL", "ENDPOINT", "EXPIRES");
    for (label, entry) in rows {
        let eid_hex = &entry.endpoint_id_hex;
        let eid_short = format!(
            "{}…{}",
            &eid_hex[..8.min(eid_hex.len())],
            &eid_hex[eid_hex.len().saturating_sub(4)..]
        );
        let expires = if entry.expires_at <= now {
            "EXPIRED".to_owned()
        } else {
            format_duration(entry.expires_at - now)
        };
        println!("{label:<14} {eid_short:<22} {expires:<14}");
    }
    Ok(ExitCode::SUCCESS)
}

fn format_duration(secs: u64) -> String {
    if secs >= 24 * 3600 {
        format!("in {}d", secs / (24 * 3600))
    } else if secs >= 3600 {
        format!("in {}h", secs / 3600)
    } else if secs >= 60 {
        format!("in {}m", secs / 60)
    } else {
        format!("in {secs}s")
    }
}

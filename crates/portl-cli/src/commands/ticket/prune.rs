//! `portl ticket prune` — bulk-remove expired tickets.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_core::ticket_store::TicketStore;

pub fn run() -> Result<ExitCode> {
    let path = TicketStore::default_path();
    let mut tickets = TicketStore::load(&path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let removed = tickets.prune_expired(now);
    if removed.is_empty() {
        println!("no expired tickets");
    } else {
        tickets.save(&path)?;
        println!(
            "pruned {} expired ticket(s): {}",
            removed.len(),
            removed.join(", ")
        );
    }
    Ok(ExitCode::SUCCESS)
}

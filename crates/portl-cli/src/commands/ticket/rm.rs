//! `portl ticket rm <label>` — drop a saved ticket by label.

use std::process::ExitCode;

use anyhow::{Result, bail};
use portl_core::ticket_store::TicketStore;

pub fn run(label: &str) -> Result<ExitCode> {
    let path = TicketStore::default_path();
    let mut tickets = TicketStore::load(&path)?;
    match tickets.remove(label) {
        Some(_) => {
            tickets.save(&path)?;
            println!("removed ticket '{label}'");
            Ok(ExitCode::SUCCESS)
        }
        None => {
            bail!("no ticket with label '{label}'. Try `portl ticket ls` for the current list.")
        }
    }
}

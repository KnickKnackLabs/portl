//! `portl peer ls` — tabulate `peers.json`.

use std::process::ExitCode;

use anyhow::Result;
use portl_core::peer_store::PeerStore;

pub fn run() -> Result<ExitCode> {
    let peers = PeerStore::load(&PeerStore::default_path())?;
    if peers.is_empty() {
        println!(
            "no peers yet. Add one with:\n  portl peer add-unsafe-raw <endpoint_hex> --label <name> --mutual"
        );
        return Ok(ExitCode::SUCCESS);
    }

    // Sort by label so output is stable (hash-map iteration order
    // otherwise varies run-to-run and breaks comparison / eyeballing).
    let mut rows: Vec<_> = peers.iter().collect();
    rows.sort_by(|a, b| a.label.cmp(&b.label));

    println!(
        "{:<14} {:<22} {:<10} {:<10}",
        "LABEL", "ENDPOINT", "REL", "ORIGIN"
    );
    for entry in rows {
        let eid_hex = &entry.endpoint_id_hex;
        let eid_short = format!(
            "{}…{}",
            &eid_hex[..8.min(eid_hex.len())],
            &eid_hex[eid_hex.len().saturating_sub(4)..]
        );
        println!(
            "{:<14} {:<22} {:<10} {:<10}",
            entry.label,
            eid_short,
            entry.relationship(),
            entry.origin.as_str(),
        );
    }
    Ok(ExitCode::SUCCESS)
}

//! `portl peer ls` — tabulate `peers.json`.
//!
//! `--active` overlays the agent's connection registry so operators
//! can see which peers are live right now. `--json` emits the
//! structured view for scripting.

use std::process::ExitCode;

use anyhow::Result;
use portl_core::peer_store::PeerStore;
use serde_json::json;

use std::collections::HashSet;

pub fn run(json_out: bool, active: bool) -> Result<ExitCode> {
    let peers = PeerStore::load(&PeerStore::default_path())?;
    let active_set = if active {
        fetch_active_eids()
    } else {
        HashSet::new()
    };

    if peers.is_empty() {
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema": 1,
                    "kind": "peer.ls",
                    "peers": [],
                }))?
            );
            return Ok(ExitCode::SUCCESS);
        }
        println!(
            "no peers yet. Add one with:\n  portl peer add-unsafe-raw <endpoint_hex> --label <name> --mutual"
        );
        return Ok(ExitCode::SUCCESS);
    }

    // Sort by label so output is stable (hash-map iteration order
    // otherwise varies run-to-run and breaks comparison / eyeballing).
    let mut rows: Vec<_> = peers.iter().collect();
    rows.sort_by(|a, b| a.label.cmp(&b.label));

    if json_out {
        let peers_json: Vec<_> = rows
            .iter()
            .map(|entry| {
                let live = active_set.contains(&entry.endpoint_id_hex);
                json!({
                    "label": entry.label,
                    "endpoint_id": entry.endpoint_id_hex,
                    "relationship": entry.relationship(),
                    "origin": entry.origin.as_str(),
                    "active": if active { Some(live) } else { None },
                })
            })
            .collect();
        let envelope = json!({
            "schema": 1,
            "kind": "peer.ls",
            "active_overlay": active,
            "peers": peers_json,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(ExitCode::SUCCESS);
    }

    let live_col = if active { " LIVE" } else { "" };
    println!(
        "{:<14} {:<22} {:<10} {:<10}{live_col}",
        "LABEL", "ENDPOINT", "REL", "ORIGIN"
    );
    for entry in rows {
        let eid_short = crate::eid::format_short(&entry.endpoint_id_hex);
        let live_cell = if active {
            if active_set.contains(&entry.endpoint_id_hex) {
                " ●"
            } else {
                " ·"
            }
        } else {
            ""
        };
        println!(
            "{:<14} {:<22} {:<10} {:<10}{live_cell}",
            entry.label,
            eid_short,
            entry.relationship(),
            entry.origin.as_str(),
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Best-effort fetch of the active-connections overlay. Returns an
/// empty set if the agent isn't running or the IPC call fails;
/// `peer ls --active` degrades to "no one is live" silently to
/// avoid turning a dashboard call into a hard error.
fn fetch_active_eids() -> HashSet<String> {
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return HashSet::new();
    };
    let socket = crate::agent_ipc::default_socket_path();
    runtime.block_on(async move {
        match crate::agent_ipc::fetch_connections(&socket).await {
            Ok(resp) => resp.connections.into_iter().map(|c| c.peer_eid).collect(),
            Err(_) => HashSet::new(),
        }
    })
}

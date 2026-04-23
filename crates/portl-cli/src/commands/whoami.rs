//! `portl whoami` — print the local identity's `endpoint_id` + its
//! label from the peer store, if any. With `--eid`, print just the
//! 64-char hex (script-friendly; saves an awk dance).

use std::process::ExitCode;

use anyhow::Result;
use portl_core::id::store;
use portl_core::peer_store::PeerStore;

pub fn run(eid_only: bool, json: bool) -> Result<ExitCode> {
    let identity = store::load(&store::default_path())?;
    let eid_hex = hex::encode(identity.verifying_key());
    if eid_only {
        // `--eid` predates `--json` and is explicitly the
        // single-hex-line escape hatch. Ignore `--json` here so
        // existing scripts that `portl whoami --eid` keep working
        // even if someone appends --json by habit.
        println!("{eid_hex}");
        return Ok(ExitCode::SUCCESS);
    }
    let peers = PeerStore::load(&PeerStore::default_path())?;
    let label = peers
        .get_by_endpoint(&identity.verifying_key())
        .map_or("self", |e| e.label.as_str());
    if json {
        let envelope = serde_json::json!({
            "schema": 1,
            "kind": "whoami",
            "label": label,
            "endpoint_id": eid_hex,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        println!("label: {label}");
        println!("endpoint_id: {eid_hex}");
    }
    Ok(ExitCode::SUCCESS)
}

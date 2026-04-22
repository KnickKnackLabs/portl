//! `portl whoami` — print the local identity's `endpoint_id` + its
//! label from the peer store, if any. Machine-readable output lives
//! in `portl doctor` (JSON-ish); `whoami` is the two-line
//! human-friendly verb for sharing your `endpoint_id` ad hoc.

use std::process::ExitCode;

use anyhow::Result;
use portl_core::id::store;
use portl_core::peer_store::PeerStore;

pub fn run() -> Result<ExitCode> {
    let identity = store::load(&store::default_path())?;
    let eid_hex = hex::encode(identity.verifying_key());
    let peers = PeerStore::load(&PeerStore::default_path())?;
    let label = peers
        .get_by_endpoint(&identity.verifying_key())
        .map_or("self", |e| e.label.as_str());
    println!("label: {label}");
    println!("endpoint_id: {eid_hex}");
    Ok(ExitCode::SUCCESS)
}

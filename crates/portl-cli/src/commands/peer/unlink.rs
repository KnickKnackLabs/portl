//! `portl peer unlink <label>` — drop a peer by label. Takes effect
//! within ~500ms on the running agent (peer-store reload task polls
//! the file). Errors if the label is unknown so typos are caught.

use std::process::ExitCode;

use anyhow::{Result, bail};
use portl_core::peer_store::PeerStore;

pub fn run(label: &str) -> Result<ExitCode> {
    let path = PeerStore::default_path();
    let mut peers = PeerStore::load(&path)?;
    match peers.remove_by_label(label) {
        Some(entry) if entry.is_self => {
            // Restore the row; refusing to break trust-root on self
            // preserves the self-host contract. If the user really
            // wants to unlink self, they can edit peers.json manually.
            peers
                .insert_or_update(entry)
                .expect("reinsert self row after refusing unlink");
            bail!(
                "refusing to unlink the self-row; `portl init --force` followed by \
                 `portl install --apply` regenerates the identity + seeds a new self-row"
            );
        }
        Some(entry) => {
            peers.save(&path)?;
            println!(
                "unlinked peer '{label}' ({short}…)",
                short = &entry.endpoint_id_hex[..16]
            );
            Ok(ExitCode::SUCCESS)
        }
        None => bail!("no peer with label '{label}'. Try `portl peer ls` for the current list."),
    }
}

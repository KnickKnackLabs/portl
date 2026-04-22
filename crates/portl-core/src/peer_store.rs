//! Filesystem-backed peer trust store.
//!
//! This is the source of truth for what endpoints the local agent will
//! accept tickets from (`accepts_from_them`) and which endpoints the
//! local client believes will honor tickets minted by us
//! (`they_accept_from_me`). Replaces the v0.2.x `PORTL_TRUST_ROOTS`
//! env var: that surface is gone, this file is the only way in.
//!
//! On-disk format is JSON at `<config_dir>/peers.json`. Writes are
//! atomic (tmp + fsync + rename) so concurrent readers never see a
//! half-written file. The agent's reload task re-reads this file
//! every 500ms so `portl peer` commands take effect without needing
//! a service restart.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

/// How the entry was created. Drives display colors in `peer ls` and
/// gates some warnings (`raw` entries are highlighted as untrusted
/// provenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerOrigin {
    /// Created by `portl install` for the local machine's own identity.
    #[serde(rename = "self")]
    Zelf,
    /// Created by a successful pairing handshake.
    Paired,
    /// Created by `portl peer accept <code>` — one-way grant.
    Accepted,
    /// Created via `portl peer add-unsafe-raw`. No handshake validated
    /// the endpoint — user pasted it in.
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub label: String,
    /// Hex-encoded 32-byte iroh endpoint public key.
    pub endpoint_id_hex: String,
    /// Our agent accepts tickets signed by this endpoint.
    pub accepts_from_them: bool,
    /// Their agent accepts tickets minted by us.
    pub they_accept_from_me: bool,
    /// Unix-seconds when the entry was created.
    pub since: u64,
    pub origin: PeerOrigin,
    /// Non-None means entry is suspended. `accepts_from_them` is
    /// ignored while held.
    pub last_hold_at: Option<u64>,
    /// True only for the `self` row. Convenience flag for doctor and
    /// install seeding.
    pub is_self: bool,
}

impl PeerEntry {
    /// 32-byte `endpoint_id` as raw bytes. Returns error if the
    /// on-disk hex is malformed (should not happen for stores we
    /// wrote ourselves, but guards against manual edits).
    pub fn endpoint_id_bytes(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.endpoint_id_hex)
            .with_context(|| format!("decode endpoint_id_hex for peer {}", self.label))?;
        bytes
            .try_into()
            .map_err(|_| anyhow!("peer {}: endpoint_id_hex is not 32 bytes", self.label))
    }

    /// Human-readable relationship label for `peer ls`.
    pub fn relationship(&self) -> &'static str {
        if self.last_hold_at.is_some() {
            return "held";
        }
        if self.is_self {
            return "self";
        }
        match (self.accepts_from_them, self.they_accept_from_me) {
            (true, true) => "mutual",
            (true, false) => "inbound",
            (false, true) => "outbound",
            (false, false) => "none",
        }
    }
}

impl PeerOrigin {
    /// Lowercase word matching the on-disk serialization; used by
    /// `peer ls` so display matches the JSON value users see when
    /// they `cat peers.json`. `Debug` prints `Zelf` (the Rust
    /// identifier) which would be confusing here.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zelf => "self",
            Self::Paired => "paired",
            Self::Accepted => "accepted",
            Self::Raw => "raw",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerStore {
    pub schema: u32,
    /// Keyed by `endpoint_id_hex` for O(1) lookup by endpoint. Labels
    /// are unique across the store but are a secondary index we
    /// recompute on demand.
    pub entries: HashMap<String, PeerEntry>,
}

const CURRENT_SCHEMA: u32 = 1;

impl PeerStore {
    pub fn new() -> Self {
        Self {
            schema: CURRENT_SCHEMA,
            entries: HashMap::new(),
        }
    }

    /// Default path: `<config_dir>/peers.json`. Overridden by
    /// `$PORTL_HOME/peers.json` when set (matches the identity-file
    /// resolution convention).
    pub fn default_path() -> PathBuf {
        home_dir().join("peers.json")
    }

    /// Load from disk. Missing file returns an empty store. Malformed
    /// file errors loudly rather than silently resetting — we'd
    /// rather fail closed than drop a user's trust policy.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read peer store at {}", path.display()))?;
        let store: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parse peer store at {}", path.display()))?;
        if store.schema != CURRENT_SCHEMA {
            bail!(
                "peer store at {} has schema v{} but v{} is required",
                path.display(),
                store.schema,
                CURRENT_SCHEMA
            );
        }
        Ok(store)
    }

    /// Atomic write: `path.tmp` → fsync → rename. Readers never see
    /// a half-written file; a crash mid-save leaves the old version
    /// intact.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let encoded = serde_json::to_vec_pretty(self).context("encode peer store")?;
        {
            let mut f =
                fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(&encoded)
                .with_context(|| format!("write {}", tmp.display()))?;
            f.sync_all()
                .with_context(|| format!("fsync {}", tmp.display()))?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    /// Insert or update by `endpoint_id`. Fails if the requested label
    /// is already used by a *different* endpoint (label collision).
    /// Updating the same endpoint's own entry is fine.
    pub fn insert_or_update(&mut self, entry: PeerEntry) -> Result<()> {
        for (key, existing) in &self.entries {
            if existing.label == entry.label && *key != entry.endpoint_id_hex {
                bail!(
                    "label '{}' is already in use by a different peer ({})",
                    entry.label,
                    &existing.endpoint_id_hex[..16.min(existing.endpoint_id_hex.len())]
                );
            }
        }
        self.entries.insert(entry.endpoint_id_hex.clone(), entry);
        Ok(())
    }

    pub fn remove_by_label(&mut self, label: &str) -> Option<PeerEntry> {
        let key = self
            .entries
            .iter()
            .find(|(_, v)| v.label == label)
            .map(|(k, _)| k.clone())?;
        self.entries.remove(&key)
    }

    pub fn remove_by_endpoint(&mut self, eid: &[u8; 32]) -> Option<PeerEntry> {
        let key = hex::encode(eid);
        self.entries.remove(&key)
    }

    pub fn get_by_label(&self, label: &str) -> Option<&PeerEntry> {
        self.entries.values().find(|e| e.label == label)
    }

    pub fn get_by_endpoint(&self, eid: &[u8; 32]) -> Option<&PeerEntry> {
        self.entries.get(&hex::encode(eid))
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerEntry> {
        self.entries.values()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the set of `endpoint_id`s the agent currently accepts
    /// tickets from. Held entries are excluded.
    pub fn trust_roots(&self) -> HashSet<[u8; 32]> {
        self.entries
            .values()
            .filter(|e| e.accepts_from_them && e.last_hold_at.is_none())
            .filter_map(|e| e.endpoint_id_bytes().ok())
            .collect()
    }
}

/// Auto-generate a label from an `endpoint_id`: first 8 hex chars.
pub fn auto_label(eid: &[u8; 32]) -> String {
    hex::encode(&eid[..4])
}

fn home_dir() -> PathBuf {
    home_dir_pub()
}

/// Exposed for other stores (ticket, pair) so they share exactly
/// one path-resolution policy.
#[doc(hidden)]
pub fn home_dir_pub() -> PathBuf {
    if let Some(home) = std::env::var_os("PORTL_HOME") {
        return PathBuf::from(home);
    }
    ProjectDirs::from("computer", "KnickKnackLabs", "portl").map_or_else(
        || PathBuf::from("./.portl"),
        |dirs| dirs.config_dir().to_path_buf(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn mk_entry(label: &str, eid: [u8; 32], accepts: bool, they_accept: bool) -> PeerEntry {
        PeerEntry {
            label: label.to_owned(),
            endpoint_id_hex: hex::encode(eid),
            accepts_from_them: accepts,
            they_accept_from_me: they_accept,
            since: 1_000_000,
            origin: PeerOrigin::Raw,
            last_hold_at: None,
            is_self: false,
        }
    }

    #[test]
    fn roundtrips_through_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::new();
        store
            .insert_or_update(mk_entry("alice", [1; 32], true, true))
            .unwrap();
        store
            .insert_or_update(mk_entry("bob", [2; 32], true, false))
            .unwrap();
        store.save(&path).unwrap();

        let loaded = PeerStore::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get_by_label("alice").unwrap().label, "alice");
        assert_eq!(
            loaded.get_by_endpoint(&[1; 32]).unwrap().relationship(),
            "mutual"
        );
        assert_eq!(
            loaded.get_by_endpoint(&[2; 32]).unwrap().relationship(),
            "inbound"
        );
    }

    #[test]
    fn label_collision_across_endpoints_fails() {
        let mut store = PeerStore::new();
        store
            .insert_or_update(mk_entry("alice", [1; 32], true, true))
            .unwrap();
        let err = store
            .insert_or_update(mk_entry("alice", [2; 32], true, true))
            .unwrap_err();
        assert!(err.to_string().contains("already in use"));
    }

    #[test]
    fn label_reuse_on_same_endpoint_ok() {
        // `portl peer invite` followed by a successful pair updates
        // the same endpoint row; this must not trip the collision
        // check.
        let mut store = PeerStore::new();
        store
            .insert_or_update(mk_entry("alice", [1; 32], true, false))
            .unwrap();
        store
            .insert_or_update(mk_entry("alice", [1; 32], true, true))
            .unwrap();
        assert!(store.get_by_endpoint(&[1; 32]).unwrap().they_accept_from_me);
    }

    #[test]
    fn trust_roots_excludes_held_and_outbound_only() {
        let mut store = PeerStore::new();
        store
            .insert_or_update(mk_entry("inbound", [1; 32], true, false))
            .unwrap();
        store
            .insert_or_update(mk_entry("outbound", [2; 32], false, true))
            .unwrap();
        store
            .insert_or_update(mk_entry("mutual", [3; 32], true, true))
            .unwrap();
        let mut held = mk_entry("held", [4; 32], true, true);
        held.last_hold_at = Some(1_000_500);
        store.insert_or_update(held).unwrap();

        let roots = store.trust_roots();
        assert!(roots.contains(&[1; 32]));
        assert!(!roots.contains(&[2; 32]), "outbound-only excluded");
        assert!(roots.contains(&[3; 32]));
        assert!(!roots.contains(&[4; 32]), "held excluded");
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let store = PeerStore::load(&path).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn malformed_file_errors_rather_than_resetting() {
        // Explicit failure mode: if the file is corrupt, we refuse
        // to boot rather than silently dropping trust state.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.json");
        fs::write(&path, "{not valid json").unwrap();
        let err = PeerStore::load(&path).unwrap_err();
        assert!(err.to_string().contains("parse peer store"));
    }

    #[test]
    fn auto_label_is_first_8_hex() {
        assert_eq!(auto_label(&[0xab; 32]), "abababab");
    }
}

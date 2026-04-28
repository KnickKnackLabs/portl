//! Filesystem-backed store for saved tickets (issued to *us* by
//! other identities). This is the outbound-credential half of the
//! peer/ticket split: peers store standing authority, tickets store
//! bounded credentials.
//!
//! On-disk format is JSON at `<config_dir>/tickets.json`. Writes are
//! atomic. No live-reload is needed because `portl ticket ls` and
//! the resolve cascade read from disk on demand — mutations are rare
//! and latency-insensitive.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::peer_store::home_dir_pub as home_dir;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionShareMetadata {
    pub friendly_name: String,
    pub provider_session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_label_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_label_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketEntry {
    /// Hex-encoded 32-byte endpoint id parsed from the ticket's
    /// terminal endpoint address. Bound at save time; `shell <label>`
    /// refuses to route through a ticket whose endpoint disagrees
    /// with a peer entry of the same label (anti-misroute guardrail).
    pub endpoint_id_hex: String,
    /// Original ticket string as pasted in.
    pub ticket_string: String,
    /// `not_after` field from the terminal certificate chain. Used
    /// for the `expires_in` column and `ticket prune`.
    pub expires_at: u64,
    /// When the entry was saved (unix seconds).
    pub saved_at: u64,
    /// Metadata captured when this ticket was imported from a
    /// `PORTL-S-*` session share. Lets `portl session attach <label>`
    /// infer the provider session without repeating it positionally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_share: Option<SessionShareMetadata>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TicketStore {
    pub schema: u32,
    pub entries: HashMap<String, TicketEntry>,
}

const CURRENT_SCHEMA: u32 = 1;

impl TicketStore {
    pub fn new() -> Self {
        Self {
            schema: CURRENT_SCHEMA,
            entries: HashMap::new(),
        }
    }

    pub fn default_path() -> PathBuf {
        home_dir().join("tickets.json")
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read ticket store at {}", path.display()))?;
        let store: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parse ticket store at {}", path.display()))?;
        if store.schema != CURRENT_SCHEMA {
            bail!(
                "ticket store at {} has schema v{} but v{} is required",
                path.display(),
                store.schema,
                CURRENT_SCHEMA
            );
        }
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let encoded = serde_json::to_vec_pretty(self).context("encode ticket store")?;
        {
            let mut f =
                fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(&encoded)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    /// Insert a ticket under a label. Fails if the label is already
    /// in use (no silent overwrite — forces caller to `rm` first).
    pub fn insert(&mut self, label: String, entry: TicketEntry) -> Result<()> {
        if self.entries.contains_key(&label) {
            bail!(
                "ticket label '{label}' already exists; remove it first with `portl ticket rm {label}`"
            );
        }
        self.entries.insert(label, entry);
        Ok(())
    }

    pub fn remove(&mut self, label: &str) -> Option<TicketEntry> {
        self.entries.remove(label)
    }

    pub fn get(&self, label: &str) -> Option<&TicketEntry> {
        self.entries.get(label)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &TicketEntry)> {
        self.entries.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Drop every entry with `expires_at <= now`. Returns labels
    /// that were removed.
    pub fn prune_expired(&mut self, now: u64) -> Vec<String> {
        let removed: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for label in &removed {
            self.entries.remove(label);
        }
        removed
    }

    /// Soonest-expiring unexpired ticket. Used by `doctor` for the
    /// `soonest expires in …` line.
    pub fn soonest_expiry(&self, now: u64) -> Option<u64> {
        self.entries
            .values()
            .filter(|e| e.expires_at > now)
            .map(|e| e.expires_at - now)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn mk(eid: u8, expires_at: u64) -> TicketEntry {
        TicketEntry {
            endpoint_id_hex: hex::encode([eid; 32]),
            ticket_string: format!("portl{eid:02x}"),
            expires_at,
            saved_at: 1_000_000,
            session_share: None,
        }
    }

    #[test]
    fn roundtrips_through_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tickets.json");
        let mut store = TicketStore::new();
        store.insert("a".into(), mk(1, 2_000_000)).unwrap();
        store.insert("b".into(), mk(2, 3_000_000)).unwrap();
        store.save(&path).unwrap();

        let loaded = TicketStore::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get("a").unwrap().expires_at, 2_000_000);
    }

    #[test]
    fn session_share_metadata_roundtrips_through_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tickets.json");
        let mut entry = mk(1, 2_000_000);
        entry.session_share = Some(SessionShareMetadata {
            friendly_name: "dotfiles".to_owned(),
            provider_session: "dotfiles".to_owned(),
            provider: Some("zmx".to_owned()),
            origin_label_hint: Some("max-b265".to_owned()),
            target_label_hint: Some("max-b265".to_owned()),
        });
        let mut store = TicketStore::new();
        store.insert("max-b265-dotfiles".into(), entry).unwrap();
        store.save(&path).unwrap();

        let loaded = TicketStore::load(&path).unwrap();
        let metadata = loaded
            .get("max-b265-dotfiles")
            .unwrap()
            .session_share
            .as_ref()
            .unwrap();
        assert_eq!(metadata.provider_session, "dotfiles");
        assert_eq!(metadata.origin_label_hint.as_deref(), Some("max-b265"));
    }

    #[test]
    fn insert_rejects_existing_label() {
        let mut store = TicketStore::new();
        store.insert("a".into(), mk(1, 2_000_000)).unwrap();
        let err = store.insert("a".into(), mk(2, 2_000_000)).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn prune_removes_only_expired() {
        let mut store = TicketStore::new();
        store.insert("dead".into(), mk(1, 500)).unwrap();
        store.insert("live".into(), mk(2, 5_000)).unwrap();
        let removed = store.prune_expired(1_000);
        assert_eq!(removed, vec!["dead".to_owned()]);
        assert!(store.get("live").is_some());
    }

    #[test]
    fn soonest_expiry_ignores_expired_entries() {
        let mut store = TicketStore::new();
        store.insert("past".into(), mk(1, 500)).unwrap();
        store.insert("soon".into(), mk(2, 2_000)).unwrap();
        store.insert("later".into(), mk(3, 5_000)).unwrap();
        assert_eq!(store.soonest_expiry(1_000), Some(1_000));
    }
}

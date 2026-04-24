//! `pending_invites.json` — open pair invites awaiting caller.
//!
//! Parallels `PeerStore` / `TicketStore` / `RevocationSet`: JSON
//! file, atomic write-tmp + rename, same "reload task polls
//! every 500ms" pattern so the running agent picks up new
//! invites + prunes revoked ones without restart.
//!
//! This store holds *server-side* state only. The caller side
//! doesn't persist invites; it consumes an invite code once and
//! writes its outcome into `peers.json` atomically.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::pair_code::InitiatorMode;

const DEFAULT_FILE_NAME: &str = "pending_invites.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    /// 32-char lowercase hex for readability. Matches the shape of
    /// other hex identifiers in the project (`endpoint_id`,
    /// `ticket_id`).
    pub nonce_hex: String,
    pub issued_at_unix: u64,
    pub not_after_unix: u64,
    /// Inviter-chosen relationship shape encoded into the invite code.
    #[serde(default)]
    pub initiator: InitiatorMode,
    /// Optional label hint the operator attached via
    /// `portl invite --for <label>`. Server uses this as the
    /// auto-label when the caller doesn't supply one.
    pub for_label_hint: Option<String>,
}

impl PendingInvite {
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.not_after_unix <= now_unix
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PairStoreFile {
    #[serde(default = "PairStoreFile::current_schema")]
    pub schema: u32,
    #[serde(default)]
    pub invites: Vec<PendingInvite>,
}

impl PairStoreFile {
    fn current_schema() -> u32 {
        1
    }
}

/// Wrapper around the on-disk file. Atomic writes via write-tmp +
/// rename, same pattern as `PeerStore`.
#[derive(Debug, Clone)]
pub struct PairStore {
    path: PathBuf,
    inner: PairStoreFile,
}

impl PairStore {
    /// Resolve the default store path: `<home>/pending_invites.json`
    /// using the same home-dir convention as the peer store.
    #[must_use]
    pub fn default_path() -> PathBuf {
        crate::peer_store::PeerStore::default_path()
            .parent()
            .map_or_else(
                || PathBuf::from(DEFAULT_FILE_NAME),
                |parent| parent.join(DEFAULT_FILE_NAME),
            )
    }

    /// Load the store from disk. Missing file → empty store; this
    /// is the steady-state for a fresh agent that's never issued
    /// an invite.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let inner = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("read pair store at {}", path.display()))?;
            serde_json::from_str::<PairStoreFile>(&raw)
                .with_context(|| format!("parse pair store at {}", path.display()))?
        } else {
            PairStoreFile::default()
        };
        Ok(Self { path, inner })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn iter(&self) -> impl Iterator<Item = &PendingInvite> {
        self.inner.invites.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.invites.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.invites.is_empty()
    }

    /// Look up an invite by its nonce (32-char hex).
    #[must_use]
    pub fn find_by_nonce(&self, nonce_hex: &str) -> Option<&PendingInvite> {
        self.inner
            .invites
            .iter()
            .find(|i| i.nonce_hex.eq_ignore_ascii_case(nonce_hex))
    }

    /// Find an invite by a prefix of its nonce (for `--revoke <prefix>`).
    /// Returns `Err` when the prefix is ambiguous (two+ matches);
    /// `Ok(None)` when no invite matches.
    pub fn find_by_nonce_prefix(&self, prefix: &str) -> Result<Option<&PendingInvite>> {
        let prefix = prefix.to_ascii_lowercase();
        let mut matches = self
            .inner
            .invites
            .iter()
            .filter(|i| i.nonce_hex.to_ascii_lowercase().starts_with(&prefix));
        let first = matches.next();
        if matches.next().is_some() {
            anyhow::bail!("nonce prefix {prefix:?} matches multiple invites; use more characters");
        }
        Ok(first)
    }

    /// Append a new invite. No-op if a nonce collision exists
    /// (extremely unlikely given 128-bit random nonces).
    pub fn insert(&mut self, invite: PendingInvite) {
        if self
            .inner
            .invites
            .iter()
            .any(|i| i.nonce_hex.eq_ignore_ascii_case(&invite.nonce_hex))
        {
            return;
        }
        self.inner.invites.push(invite);
    }

    /// Remove an invite by nonce. Returns `true` when the invite
    /// was present.
    pub fn remove(&mut self, nonce_hex: &str) -> bool {
        let before = self.inner.invites.len();
        self.inner
            .invites
            .retain(|i| !i.nonce_hex.eq_ignore_ascii_case(nonce_hex));
        before != self.inner.invites.len()
    }

    /// Drop expired invites. Returns the number removed.
    pub fn prune_expired(&mut self, now_unix: u64) -> usize {
        let before = self.inner.invites.len();
        self.inner.invites.retain(|i| !i.is_expired(now_unix));
        before - self.inner.invites.len()
    }

    /// Write to disk atomically.
    pub fn save(&self) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create dir for {}", self.path.display()))?;
        }
        let serialized =
            serde_json::to_string_pretty(&self.inner).context("serialize pair store")?;
        fs::write(&tmp, serialized).with_context(|| format!("write tmp {}", tmp.display()))?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn invite(nonce: &str, not_after: u64) -> PendingInvite {
        PendingInvite {
            nonce_hex: nonce.to_owned(),
            issued_at_unix: 1_000,
            not_after_unix: not_after,
            initiator: InitiatorMode::Mutual,
            for_label_hint: None,
        }
    }

    #[test]
    fn load_missing_returns_empty() {
        let tmp = tempdir().unwrap();
        let store = PairStore::load(tmp.path().join("pending_invites.json")).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn insert_and_save_roundtrip() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("pending_invites.json");
        let mut store = PairStore::load(&path).unwrap();
        store.insert(invite("aaaa", 2000));
        store.save().unwrap();
        let reloaded = PairStore::load(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.find_by_nonce("aaaa").is_some());
    }

    #[test]
    fn insert_is_idempotent_on_nonce_collision() {
        let tmp = tempdir().unwrap();
        let mut store = PairStore::load(tmp.path().join("pending_invites.json")).unwrap();
        store.insert(invite("aaaa", 2000));
        store.insert(invite("aaaa", 3000));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn remove_drops_specific_nonce() {
        let tmp = tempdir().unwrap();
        let mut store = PairStore::load(tmp.path().join("pending_invites.json")).unwrap();
        store.insert(invite("aaaa", 2000));
        store.insert(invite("bbbb", 2000));
        assert!(store.remove("aaaa"));
        assert_eq!(store.len(), 1);
        assert!(!store.remove("aaaa")); // already gone
    }

    #[test]
    fn prune_expired_drops_past_invites() {
        let tmp = tempdir().unwrap();
        let mut store = PairStore::load(tmp.path().join("pending_invites.json")).unwrap();
        store.insert(invite("aaaa", 1_000)); // expired at now
        store.insert(invite("bbbb", 5_000));
        let removed = store.prune_expired(2_000);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
        assert!(store.find_by_nonce("bbbb").is_some());
    }

    #[test]
    fn find_by_nonce_prefix_unique() {
        let tmp = tempdir().unwrap();
        let mut store = PairStore::load(tmp.path().join("pending_invites.json")).unwrap();
        store.insert(invite("aa11", 2000));
        store.insert(invite("bb22", 2000));
        let found = store.find_by_nonce_prefix("aa").unwrap();
        assert!(found.is_some());
    }

    #[test]
    fn find_by_nonce_prefix_ambiguous() {
        let tmp = tempdir().unwrap();
        let mut store = PairStore::load(tmp.path().join("pending_invites.json")).unwrap();
        store.insert(invite("aaaa1", 2000));
        store.insert(invite("aaaa2", 2000));
        assert!(store.find_by_nonce_prefix("aaaa").is_err());
    }

    #[test]
    fn find_by_nonce_prefix_unknown() {
        let tmp = tempdir().unwrap();
        let store = PairStore::load(tmp.path().join("pending_invites.json")).unwrap();
        assert!(store.find_by_nonce_prefix("ff").unwrap().is_none());
    }
}

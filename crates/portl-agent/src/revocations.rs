use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use tokio_util::sync::CancellationToken;
use tracing::info;

pub const REVOCATION_LINGER_SECS: u64 = 7 * 86_400;
pub const DEFAULT_REVOCATIONS_MAX_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevocationRecord {
    pub ticket_id: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after_of_ticket: Option<u64>,
}

impl RevocationRecord {
    #[must_use]
    pub fn new(
        ticket_id: [u8; 16],
        reason: impl Into<String>,
        revoked_at: u64,
        not_after_of_ticket: Option<u64>,
    ) -> Self {
        Self {
            ticket_id: hex::encode(ticket_id),
            reason: reason.into(),
            revoked_at: Some(revoked_at),
            not_after_of_ticket,
        }
    }

    fn legacy(ticket_id: [u8; 16], now: u64) -> Self {
        Self {
            ticket_id: hex::encode(ticket_id),
            reason: String::from("legacy_json_import"),
            revoked_at: Some(now),
            not_after_of_ticket: None,
        }
    }

    fn ticket_id_bytes(&self) -> Result<[u8; 16]> {
        decode_ticket_id(&self.ticket_id)
    }
}

#[derive(Debug)]
pub struct RevocationSet {
    file: PathBuf,
    ids: HashSet<[u8; 16]>,
    records: Vec<RevocationRecord>,
    live_sessions: HashMap<[u8; 16], HashMap<[u8; 16], CancellationToken>>,
    max_bytes: u64,
}

impl RevocationSet {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_max_bytes(path, DEFAULT_REVOCATIONS_MAX_BYTES)
    }

    pub fn load_with_max_bytes(path: impl AsRef<Path>, max_bytes: u64) -> Result<Self> {
        let requested = path.as_ref().to_path_buf();
        let now = unix_now_secs()?;
        let file = migrate_legacy_json_if_needed(&requested, now)?;
        let records = if file.exists() {
            let raw = fs::read_to_string(&file)
                .with_context(|| format!("read revocations from {}", file.display()))?;
            parse_revocation_records(&raw, &file, now)?
        } else {
            Vec::new()
        };

        let ids = records
            .iter()
            .map(RevocationRecord::ticket_id_bytes)
            .collect::<Result<HashSet<_>>>()?;
        let mut set = Self {
            file,
            ids,
            records,
            live_sessions: HashMap::new(),
            max_bytes,
        };
        if set.gc(now) > 0 {
            set.persist()?;
        }
        Ok(set)
    }

    #[must_use]
    pub fn contains(&self, id: &[u8; 16]) -> bool {
        self.ids.contains(id)
    }

    pub fn insert(&mut self, id: [u8; 16]) -> bool {
        if !self.ids.insert(id) {
            return false;
        }
        self.records.push(RevocationRecord {
            ticket_id: hex::encode(id),
            reason: String::from("manual"),
            revoked_at: None,
            not_after_of_ticket: None,
        });
        self.cancel_live_sessions(id);
        true
    }

    /// Append a fully-formed `RevocationRecord` to disk if its `ticket_id`
    /// is not already present. Returns `true` when a new entry was recorded.
    pub fn append(&mut self, record: RevocationRecord) -> std::result::Result<bool, AppendError> {
        let id = record
            .ticket_id_bytes()
            .map_err(|err| AppendError::InvalidRecord {
                message: err.to_string(),
            })?;
        if self.ids.contains(&id) {
            return Ok(false);
        }
        append_record_limited(&self.file, &record, self.max_bytes)?;
        self.ids.insert(id);
        self.records.push(record);
        self.cancel_live_sessions(id);
        Ok(true)
    }

    /// Insert a fully-formed `RevocationRecord` into memory only.
    /// Used when rebuilding state from disk or restoring snapshots in tests.
    pub fn insert_record(&mut self, record: RevocationRecord) -> bool {
        let Ok(id) = record.ticket_id_bytes() else {
            return false;
        };
        if !self.ids.insert(id) {
            return false;
        }
        self.records.push(record);
        self.cancel_live_sessions(id);
        true
    }

    pub fn register_live_session(
        &mut self,
        session_id: [u8; 16],
        ticket_chain_ids: &[[u8; 16]],
        token: &CancellationToken,
    ) {
        for ticket_id in ticket_chain_ids.iter().copied().collect::<HashSet<_>>() {
            self.live_sessions
                .entry(ticket_id)
                .or_default()
                .insert(session_id, token.clone());
        }
    }

    pub fn deregister_live_session(&mut self, session_id: [u8; 16], ticket_chain_ids: &[[u8; 16]]) {
        for ticket_id in ticket_chain_ids.iter().copied().collect::<HashSet<_>>() {
            let remove_entry = if let Some(sessions) = self.live_sessions.get_mut(&ticket_id) {
                sessions.remove(&session_id);
                sessions.is_empty()
            } else {
                false
            };
            if remove_entry {
                self.live_sessions.remove(&ticket_id);
            }
        }
    }

    pub fn persist(&self) -> Result<()> {
        write_jsonl(&self.file, &self.records)
    }

    /// Borrow the underlying on-disk path (used by async persist).
    pub fn file_path(&self) -> &Path {
        &self.file
    }

    /// Clone the in-memory record vector for off-lock persistence.
    pub fn snapshot(&self) -> Vec<RevocationRecord> {
        self.records.clone()
    }

    pub fn gc(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|record| {
            // Per docs/design/070-security.md §4.12, a record may be
            // GC'd once both:
            //   - revoked_at + LINGER has elapsed, AND
            //   - the underlying ticket has itself expired OR its
            //     expiry is unknown.
            // If we lack both timestamps, fall back to the minimal
            // linger-from-now semantics by pretending revoked_at is
            // "now" so the record is kept until next hour's GC pass.
            let linger_ok = match record.revoked_at {
                None => true,
                Some(revoked_at) => now < revoked_at + REVOCATION_LINGER_SECS,
            };
            let ticket_still_valid = matches!(
                record.not_after_of_ticket,
                Some(not_after) if now < not_after
            );
            linger_ok || ticket_still_valid
        });
        self.ids = self
            .records
            .iter()
            .filter_map(|record| record.ticket_id_bytes().ok())
            .collect();
        before - self.records.len()
    }

    fn cancel_live_sessions(&self, ticket_id: [u8; 16]) {
        if let Some(sessions) = self.live_sessions.get(&ticket_id) {
            for token in sessions.values() {
                token.cancel();
            }
        }
    }
}

/// Low-level JSONL writer shared by [`RevocationSet::persist`] and the
/// off-task async publish path.
pub fn write_jsonl(path: &Path, records: &[RevocationRecord]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut encoded = String::new();
    for record in records {
        encoded.push_str(
            &serde_json::to_string(record)
                .with_context(|| format!("encode revocation {}", record.ticket_id))?,
        );
        encoded.push('\n');
    }
    fs::write(path, encoded).with_context(|| format!("write revocations to {}", path.display()))
}

pub fn append_record(path: impl AsRef<Path>, record: &RevocationRecord) -> Result<()> {
    append_record_limited(path, record, DEFAULT_REVOCATIONS_MAX_BYTES).map_err(anyhow::Error::from)
}

#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    #[error(
        "revocations.jsonl would exceed ceiling: current={current_bytes} append={append_bytes} max={max_bytes}"
    )]
    SizeCeilingExceeded {
        current_bytes: u64,
        append_bytes: u64,
        max_bytes: u64,
    },
    #[error("invalid revocation record: {message}")]
    InvalidRecord { message: String },
    #[error(transparent)]
    Io(#[from] anyhow::Error),
}

pub fn append_record_limited(
    path: impl AsRef<Path>,
    record: &RevocationRecord,
    max_bytes: u64,
) -> std::result::Result<(), AppendError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))
            .map_err(AppendError::Io)?;
    }
    let encoded = format!(
        "{}\n",
        serde_json::to_string(record)
            .with_context(|| format!("encode revocation {}", record.ticket_id))
            .map_err(AppendError::Io)?
    );
    let current_bytes = fs::metadata(path).map_or(0, |metadata| metadata.len());
    let append_bytes = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
    if current_bytes.saturating_add(append_bytes) > max_bytes {
        return Err(AppendError::SizeCeilingExceeded {
            current_bytes,
            append_bytes,
            max_bytes,
        });
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open revocations file {}", path.display()))
        .map_err(AppendError::Io)?;
    file.write_all(encoded.as_bytes())
        .with_context(|| format!("append revocation record to {}", path.display()))
        .map_err(AppendError::Io)
}

fn migrate_legacy_json_if_needed(path: &Path, now: u64) -> Result<PathBuf> {
    if path.exists() || path.extension().is_some_and(|ext| ext == "json") {
        return Ok(path.to_path_buf());
    }

    let Some(file_name) = path.file_name() else {
        return Ok(path.to_path_buf());
    };
    if file_name != "revocations.jsonl" {
        return Ok(path.to_path_buf());
    }

    let legacy = path.with_file_name("revocations.json");
    if !legacy.exists() {
        return Ok(path.to_path_buf());
    }

    let raw = fs::read_to_string(&legacy)
        .with_context(|| format!("read legacy revocations from {}", legacy.display()))?;
    let records = parse_revocation_records(&raw, &legacy, now)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut encoded = String::new();
    for record in &records {
        encoded.push_str(
            &serde_json::to_string(record)
                .with_context(|| format!("encode migrated revocation {}", record.ticket_id))?,
        );
        encoded.push('\n');
    }
    fs::write(path, encoded)
        .with_context(|| format!("write migrated revocations to {}", path.display()))?;
    let migrated = legacy.with_file_name("revocations.json.migrated");
    fs::rename(&legacy, &migrated).with_context(|| {
        format!(
            "rename legacy revocations {} to {}",
            legacy.display(),
            migrated.display()
        )
    })?;
    info!(from = %legacy.display(), to = %path.display(), archived = %migrated.display(), "converted legacy revocations.json to jsonl");
    Ok(path.to_path_buf())
}

fn parse_revocation_records(raw: &str, file: &Path, now: u64) -> Result<Vec<RevocationRecord>> {
    if let Ok(hex_ids) = serde_json::from_str::<Vec<String>>(raw) {
        return hex_ids
            .into_iter()
            .map(|hex_id| Ok(RevocationRecord::legacy(decode_ticket_id(&hex_id)?, now)))
            .collect();
    }

    let mut records = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: RevocationRecord = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "parse revocation JSONL line {} from {}",
                index + 1,
                file.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

fn decode_ticket_id(hex_id: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_id).with_context(|| format!("decode ticket id {hex_id}"))?;
    let id = bytes
        .try_into()
        .map_err(|_| anyhow!("ticket id must be exactly 16 bytes: {hex_id}"))?;
    Ok(id)
}

fn unix_now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before unix epoch"))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{
        AppendError, REVOCATION_LINGER_SECS, RevocationRecord, RevocationSet, append_record,
        migrate_legacy_json_if_needed, unix_now_secs,
    };

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");

        let mut set = RevocationSet::load(&path).expect("load empty set");
        assert!(set.insert([0x11; 16]));
        assert!(set.insert([0x22; 16]));
        set.persist().expect("persist set");

        let reloaded = RevocationSet::load(&path).expect("reload set");
        assert!(reloaded.contains(&[0x11; 16]));
        assert!(reloaded.contains(&[0x22; 16]));
        let persisted = std::fs::read_to_string(path).expect("read persisted jsonl");
        assert!(!persisted.trim_start().starts_with('['));
    }

    #[test]
    fn load_accepts_jsonl_records() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        let now = unix_now_secs().expect("unix now");
        append_record(
            &path,
            &RevocationRecord::new([0x11; 16], "docker_rm", now, Some(now + 60)),
        )
        .expect("write jsonl revocations");

        let reloaded = RevocationSet::load(&path).expect("reload jsonl set");
        assert!(reloaded.contains(&[0x11; 16]));
    }

    #[test]
    fn append_at_ceiling_returns_size_exceeded_error() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        let mut set = RevocationSet::load_with_max_bytes(&path, 1).expect("load revocations set");

        let err = set
            .append(RevocationRecord::new([0x11; 16], "manual", 7, None))
            .expect_err("append should hit size ceiling");
        assert!(matches!(err, AppendError::SizeCeilingExceeded { .. }));
    }

    #[test]
    fn gc_removes_expired_revocations() {
        // Matches 070-security §4.12: drop when BOTH the linger window
        // past revocation has expired AND the ticket itself is no
        // longer valid. Here both are true so the record is collected.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        let now = unix_now_secs().expect("unix now");
        let revoked_at = now - REVOCATION_LINGER_SECS - 1;
        let mut set = RevocationSet {
            file: path,
            ids: std::collections::HashSet::from([[0x11; 16]]),
            records: vec![RevocationRecord::new(
                [0x11; 16],
                "docker_rm",
                revoked_at,
                Some(revoked_at),
            )],
            live_sessions: std::collections::HashMap::new(),
            max_bytes: super::DEFAULT_REVOCATIONS_MAX_BYTES,
        };

        let removed = set.gc(now);
        assert_eq!(removed, 1);
        assert!(!set.contains(&[0x11; 16]));
    }

    #[test]
    fn gc_keeps_revocation_within_linger_even_if_ticket_expired() {
        // Revocation is fresh (now) but the ticket itself was already
        // expired when revoked. Linger window still protects it.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        let now = unix_now_secs().expect("unix now");
        let mut set = RevocationSet {
            file: path,
            ids: std::collections::HashSet::from([[0x11; 16]]),
            records: vec![RevocationRecord::new(
                [0x11; 16],
                "docker_rm",
                now,
                Some(now - 1),
            )],
            live_sessions: std::collections::HashMap::new(),
            max_bytes: super::DEFAULT_REVOCATIONS_MAX_BYTES,
        };

        let removed = set.gc(now);
        assert_eq!(removed, 0);
        assert!(set.contains(&[0x11; 16]));
    }

    #[test]
    fn gc_removes_old_manual_revocation_without_ticket_expiry() {
        // `portl revoke` records leave `not_after_of_ticket = None`.
        // After the linger window on revoked_at, GC still collects
        // them so the set stops growing unboundedly.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        let now = unix_now_secs().expect("unix now");
        let mut set = RevocationSet {
            file: path,
            ids: std::collections::HashSet::from([[0x22; 16]]),
            records: vec![RevocationRecord::new(
                [0x22; 16],
                "manual",
                now - REVOCATION_LINGER_SECS - 1,
                None,
            )],
            live_sessions: std::collections::HashMap::new(),
            max_bytes: super::DEFAULT_REVOCATIONS_MAX_BYTES,
        };

        let removed = set.gc(now);
        assert_eq!(removed, 1);
        assert!(!set.contains(&[0x22; 16]));
    }

    #[test]
    fn gc_keeps_recent_revocations() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        let now = unix_now_secs().expect("unix now");
        append_record(
            &path,
            &RevocationRecord::new([0x11; 16], "docker_rm", now, Some(now)),
        )
        .expect("write jsonl revocations");

        let mut set = RevocationSet::load(&path).expect("load jsonl set");
        let removed = set.gc(now + REVOCATION_LINGER_SECS - 1);
        assert_eq!(removed, 0);
        assert!(set.contains(&[0x11; 16]));
    }

    #[test]
    fn load_migrates_legacy_json_array() {
        let dir = tempdir().expect("tempdir");
        let json_path = dir.path().join("revocations.json");
        std::fs::write(
            &json_path,
            serde_json::to_string(&vec![hex::encode([0x11; 16])]).expect("encode legacy json"),
        )
        .expect("write legacy revocations");

        let jsonl_path = dir.path().join("revocations.jsonl");
        // Migrate with a revoked_at timestamp close to the current
        // wall clock so RevocationSet::load's GC pass (which uses
        // real now) keeps the migrated record.
        let now = unix_now_secs().expect("unix now");
        let migrated =
            migrate_legacy_json_if_needed(&jsonl_path, now).expect("migrate legacy json");
        assert_eq!(migrated, jsonl_path);
        assert!(jsonl_path.exists());
        assert!(dir.path().join("revocations.json.migrated").exists());
        let reloaded = RevocationSet::load(&jsonl_path).expect("load migrated jsonl");
        assert!(reloaded.contains(&[0x11; 16]));
    }
}

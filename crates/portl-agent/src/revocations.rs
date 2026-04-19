use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use tracing::info;

pub const REVOCATION_LINGER_SECS: u64 = 7 * 86_400;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationSet {
    file: PathBuf,
    ids: HashSet<[u8; 16]>,
    records: Vec<RevocationRecord>,
}

impl RevocationSet {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
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
        let mut set = Self { file, ids, records };
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
        true
    }

    pub fn persist(&self) -> Result<()> {
        if let Some(parent) = self.file.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }

        let mut encoded = String::new();
        for record in &self.records {
            encoded.push_str(
                &serde_json::to_string(record)
                    .with_context(|| format!("encode revocation {}", record.ticket_id))?,
            );
            encoded.push('\n');
        }
        fs::write(&self.file, encoded)
            .with_context(|| format!("write revocations to {}", self.file.display()))
    }

    pub fn gc(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records
            .retain(|record| match record.not_after_of_ticket {
                Some(not_after) => now < not_after + REVOCATION_LINGER_SECS,
                None => true,
            });
        self.ids = self
            .records
            .iter()
            .filter_map(|record| record.ticket_id_bytes().ok())
            .collect();
        before - self.records.len()
    }
}

pub fn append_record(path: impl AsRef<Path>, record: &RevocationRecord) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open revocations file {}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(record)
            .with_context(|| format!("encode revocation {}", record.ticket_id))?
    )
    .with_context(|| format!("append revocation record to {}", path.display()))
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
        REVOCATION_LINGER_SECS, RevocationRecord, RevocationSet, append_record,
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
    fn gc_removes_expired_revocations() {
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
                Some(now - REVOCATION_LINGER_SECS - 1),
            )],
        };

        let removed = set.gc(now);
        assert_eq!(removed, 1);
        assert!(!set.contains(&[0x11; 16]));
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
        let migrated = migrate_legacy_json_if_needed(&jsonl_path, 42).expect("migrate legacy json");
        assert_eq!(migrated, jsonl_path);
        assert!(jsonl_path.exists());
        assert!(dir.path().join("revocations.json.migrated").exists());
        let reloaded = RevocationSet::load(&jsonl_path).expect("load migrated jsonl");
        assert!(reloaded.contains(&[0x11; 16]));
    }
}

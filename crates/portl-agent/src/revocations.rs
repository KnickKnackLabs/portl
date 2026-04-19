use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationSet {
    file: PathBuf,
    ids: HashSet<[u8; 16]>,
}

impl RevocationSet {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let file = path.as_ref().to_path_buf();
        let ids = if file.exists() {
            let raw = fs::read_to_string(&file)
                .with_context(|| format!("read revocations from {}", file.display()))?;
            let hex_ids: Vec<String> = serde_json::from_str(&raw)
                .with_context(|| format!("parse revocations from {}", file.display()))?;
            hex_ids
                .into_iter()
                .map(|hex_id| decode_ticket_id(&hex_id))
                .collect::<Result<HashSet<_>>>()?
        } else {
            HashSet::new()
        };

        Ok(Self { file, ids })
    }

    #[must_use]
    pub fn contains(&self, id: &[u8; 16]) -> bool {
        self.ids.contains(id)
    }

    pub fn insert(&mut self, id: [u8; 16]) -> bool {
        self.ids.insert(id)
    }

    pub fn persist(&self) -> Result<()> {
        if let Some(parent) = self.file.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }

        let mut hex_ids: Vec<_> = self.ids.iter().map(hex::encode).collect();
        hex_ids.sort_unstable();
        let encoded = serde_json::to_string_pretty(&hex_ids).context("encode revocations")?;
        fs::write(&self.file, encoded)
            .with_context(|| format!("write revocations to {}", self.file.display()))
    }
}

fn decode_ticket_id(hex_id: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_id).with_context(|| format!("decode ticket id {hex_id}"))?;
    let id = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ticket id must be exactly 16 bytes: {hex_id}"))?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::RevocationSet;

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.json");

        let mut set = RevocationSet::load(&path).expect("load empty set");
        assert!(set.insert([0x11; 16]));
        assert!(set.insert([0x22; 16]));
        set.persist().expect("persist set");

        let reloaded = RevocationSet::load(&path).expect("reload set");
        assert!(reloaded.contains(&[0x11; 16]));
        assert!(reloaded.contains(&[0x22; 16]));
    }
}

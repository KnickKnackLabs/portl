use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fd_lock::RwLock;
use portl_core::id::store;
use portl_core::ticket::schema::Capabilities;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const DB_FILE: &str = "aliases.json";
const LOCK_FILE: &str = "aliases.json.lock";
const CURRENT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasRecord {
    pub name: String,
    pub adapter: String,
    pub container_id: String,
    pub endpoint_id: String,
    pub image: String,
    pub network: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSpec {
    pub caps: Capabilities,
    pub ttl_secs: u64,
    #[serde(with = "hex_opt_32", default)]
    pub to: Option<[u8; 32]>,
    pub labels: Vec<(String, String)>,
    #[serde(with = "hex_opt_16", default)]
    pub root_ticket_id: Option<[u8; 16]>,
    pub ticket_file_path: Option<PathBuf>,
    pub group_name: Option<String>,
    pub base_url: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Root {
    version: u32,
    aliases: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    record: AliasRecord,
    spec: StoredSpec,
}

pub struct AliasStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl Default for AliasStore {
    fn default() -> Self {
        Self::new(default_db_path())
    }
}

impl AliasStore {
    pub fn new(db_path: PathBuf) -> Self {
        let lock_path = db_path.with_file_name(LOCK_FILE);
        Self {
            path: db_path,
            lock_path,
        }
    }

    pub fn save(&self, alias: &AliasRecord, spec: &StoredSpec) -> Result<()> {
        self.with_write_lock(|root| {
            root.version = CURRENT_VERSION;
            root.aliases.insert(
                alias.name.clone(),
                Entry {
                    record: alias.clone(),
                    spec: spec.clone(),
                },
            );
            Ok(())
        })
    }

    pub fn get(&self, name: &str) -> Result<Option<AliasRecord>> {
        let mut root = self.read()?;
        Ok(root.aliases.remove(name).map(|entry| entry.record))
    }

    pub fn get_spec(&self, name: &str) -> Result<Option<StoredSpec>> {
        let mut root = self.read()?;
        Ok(root.aliases.remove(name).map(|entry| entry.spec))
    }

    pub fn list(&self) -> Result<Vec<AliasRecord>> {
        Ok(self
            .read()?
            .aliases
            .into_values()
            .map(|entry| entry.record)
            .collect())
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        self.with_write_lock(|root| {
            root.version = CURRENT_VERSION;
            root.aliases.remove(name);
            Ok(())
        })
    }

    fn read(&self) -> Result<Root> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Root::default());
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("open alias store {}", self.path.display()));
            }
        };
        let lock = RwLock::new(file);
        let guard = lock.read().context("acquire alias store read lock")?;
        let mut file = &*guard;
        let mut json = String::new();
        file.read_to_string(&mut json).context("read alias store")?;
        if json.trim().is_empty() {
            return Ok(Root::default());
        }
        serde_json::from_str(&json).context("parse alias store JSON")
    }

    fn with_write_lock<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Root) -> Result<()>,
    {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create alias store directory {}", parent.display()))?;
        }

        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)
            .with_context(|| format!("open alias store lock {}", self.lock_path.display()))?;
        let mut lock = RwLock::new(lock_file);
        let _guard = lock.write().context("acquire alias store write lock")?;

        let mut root = self.read()?;
        root.version = CURRENT_VERSION;
        f(&mut root)?;
        self.write_root(&root)
    }

    fn write_root(&self, root: &Root) -> Result<()> {
        let tmp_path = self.path.with_extension("json.tmp");
        let mut file = File::create(&tmp_path)
            .with_context(|| format!("create alias store tmp {}", tmp_path.display()))?;
        serde_json::to_writer_pretty(&mut file, root).context("encode alias store JSON")?;
        file.write_all(b"\n")
            .context("write alias store trailing newline")?;
        file.sync_all().context("fsync alias store tmp")?;
        fs::rename(&tmp_path, &self.path).with_context(|| {
            format!(
                "rename alias store tmp {} into place {}",
                tmp_path.display(),
                self.path.display()
            )
        })?;
        Ok(())
    }
}

pub fn default_db_path() -> PathBuf {
    store::default_path()
        .parent()
        .map_or_else(|| PathBuf::from(DB_FILE), |parent| parent.join(DB_FILE))
}

pub fn now_unix_secs() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs(),
    )?)
}

#[allow(clippy::ref_option)]
fn serialize_hex_opt<const N: usize, S>(
    value: &Option<[u8; N]>,
    serializer: S,
) -> StdResult<S::Ok, S::Error>
where
    S: Serializer,
{
    Option::<String>::serialize(&value.as_ref().map(hex::encode), serializer)
}

fn deserialize_hex_opt<'de, const N: usize, D>(
    deserializer: D,
) -> StdResult<Option<[u8; N]>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => {
            let bytes = hex::decode(&value).map_err(serde::de::Error::custom)?;
            let bytes: [u8; N] = bytes.try_into().map_err(|_| {
                serde::de::Error::custom(format!("expected exactly {N} bytes of hex"))
            })?;
            Ok(Some(bytes))
        }
    }
}

mod hex_opt_32 {
    use super::{Deserializer, Serializer, StdResult, deserialize_hex_opt, serialize_hex_opt};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_hex_opt(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> StdResult<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_hex_opt(deserializer)
    }
}

mod hex_opt_16 {
    use super::{Deserializer, Serializer, StdResult, deserialize_hex_opt, serialize_hex_opt};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(value: &Option<[u8; 16]>, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_hex_opt(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> StdResult<Option<[u8; 16]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_hex_opt(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};

    use tempfile::tempdir;

    use super::{AliasRecord, AliasStore, StoredSpec};
    use portl_core::ticket::schema::Capabilities;

    fn empty_caps() -> Capabilities {
        Capabilities {
            presence: 0,
            shell: None,
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
        }
    }

    fn alias(
        name: impl Into<String>,
        endpoint_id: impl Into<String>,
        created_at: i64,
    ) -> AliasRecord {
        let name = name.into();
        AliasRecord {
            container_id: format!("cid-{name}"),
            endpoint_id: endpoint_id.into(),
            name,
            adapter: "docker-portl".to_owned(),
            image: "img".to_owned(),
            network: "bridge".to_owned(),
            created_at,
        }
    }

    fn spec(ticket_file_path: Option<PathBuf>) -> StoredSpec {
        StoredSpec {
            caps: empty_caps(),
            ttl_secs: 60,
            to: Some([9; 32]),
            labels: vec![("a".to_owned(), "b".to_owned())],
            root_ticket_id: Some([4; 16]),
            ticket_file_path,
            group_name: Some("sbox".to_owned()),
            base_url: Some("http://127.0.0.1:8080".to_owned()),
        }
    }

    fn minimal_spec() -> StoredSpec {
        StoredSpec {
            caps: empty_caps(),
            ttl_secs: 60,
            to: None,
            labels: vec![],
            root_ticket_id: None,
            ticket_file_path: None,
            group_name: None,
            base_url: None,
        }
    }

    #[test]
    fn alias_store_round_trips_alias_and_spec() {
        let dir = tempdir().expect("tempdir");
        let store = AliasStore::new(dir.path().join("aliases.json"));
        let alias = alias("demo", "eid", 7);
        let spec = spec(Some(dir.path().join("demo.ticket")));

        store.save(&alias, &spec).expect("save alias");
        assert_eq!(store.get("demo").expect("get alias"), Some(alias));
        assert_eq!(store.get_spec("demo").expect("get spec"), Some(spec));
    }

    #[test]
    fn concurrent_saves_serialize_without_corruption() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("aliases.json");
        let barrier = Arc::new(Barrier::new(3));

        let worker = |name: &'static str, endpoint_id: &'static str| {
            let db_path = db_path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = AliasStore::new(db_path);
                let alias = alias(name, endpoint_id, 1);
                let spec = minimal_spec();
                barrier.wait();
                store.save(&alias, &spec).expect("concurrent save");
            })
        };

        let t1 = worker("demo-1", "endpoint-1");
        let t2 = worker("demo-2", "endpoint-2");
        barrier.wait();
        t1.join().expect("thread 1");
        t2.join().expect("thread 2");

        let store = AliasStore::new(db_path);
        let aliases = store.list().expect("list aliases");
        assert_eq!(aliases.len(), 2);
        assert!(store.get_spec("demo-1").expect("spec 1").is_some());
        assert!(store.get_spec("demo-2").expect("spec 2").is_some());
    }

    #[test]
    fn stale_sqlite_file_is_ignored() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("aliases.sqlite"), b"SQLite format 3\0junk")
            .expect("write stale file");
        let store = AliasStore::new(dir.path().join("aliases.json"));

        assert!(store.list().expect("list").is_empty());

        let alias = alias("demo", "endpoint-1", 1);
        let spec = minimal_spec();
        store.save(&alias, &spec).expect("save");

        assert!(dir.path().join("aliases.sqlite").exists());
        assert!(dir.path().join("aliases.json").exists());
    }

    #[test]
    fn many_writers_converge_to_full_set() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let store = AliasStore::new(path);
                    for j in 0..250_u32 {
                        let alias = alias(
                            format!("t{i}-{j}"),
                            format!("endpoint-{i}-{j}"),
                            i64::from(j),
                        );
                        store.save(&alias, &minimal_spec()).expect("save");
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread");
        }

        let store = AliasStore::new(path);
        assert_eq!(store.list().expect("list").len(), 1_000);
    }
}

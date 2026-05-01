use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use fd_lock::RwLock;
use portl_core::ticket::schema::Capabilities;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
    #[serde(default)]
    pub session_provider: Option<String>,
    #[serde(default)]
    pub session_provider_install: Option<SessionProviderInstall>,
    #[serde(default)]
    pub docker_exec_id: Option<String>,
    #[serde(default)]
    pub docker_injected_binary_path: Option<PathBuf>,
    #[serde(default)]
    pub docker_injected_binary_preexisted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProviderInstall {
    pub provider: String,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
    pub installed_by_portl: bool,
}

#[derive(Serialize, Deserialize)]
struct Root {
    version: u32,
    aliases: BTreeMap<String, Entry>,
}

impl Default for Root {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            aliases: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Entry {
    record: AliasRecord,
    spec: StoredSpec,
    #[serde(flatten, default)]
    pub(crate) extra: BTreeMap<String, serde_json::Value>,
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
            if let Some(other_name) = root.aliases.values().find_map(|entry| {
                (entry.record.name != alias.name && entry.record.endpoint_id == alias.endpoint_id)
                    .then_some(entry.record.name.as_str())
            }) {
                bail!(
                    "endpoint_id {} is already registered as alias {}",
                    alias.endpoint_id,
                    other_name
                );
            }
            let extra = root
                .aliases
                .get(&alias.name)
                .map(|entry| entry.extra.clone())
                .unwrap_or_default();
            root.aliases.insert(
                alias.name.clone(),
                Entry {
                    record: alias.clone(),
                    spec: spec.clone(),
                    extra,
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
            root.aliases.remove(name);
            Ok(())
        })
    }

    fn read(&self) -> Result<Root> {
        if let Some(parent) = parent_dir(&self.lock_path) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create alias store directory {}", parent.display()))?;
        }

        let lock_file = self.open_lock_file()?;
        let lock = RwLock::new(lock_file);
        let _guard = lock.read().context("acquire alias store read lock")?;
        self.read_unlocked()
    }

    fn read_unlocked(&self) -> Result<Root> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Root::default());
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("open alias store {}", self.path.display()));
            }
        };
        let mut json = String::new();
        file.read_to_string(&mut json).context("read alias store")?;
        if json.trim().is_empty() {
            return Ok(Root::default());
        }
        let root: Root = serde_json::from_str(&json).context("parse alias store JSON")?;
        if root.version > CURRENT_VERSION {
            bail!(
                "alias store at {} was written by a newer portl (version={}); refusing to open",
                self.path.display(),
                root.version
            );
        }
        Ok(root)
    }

    fn with_write_lock<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Root) -> Result<()>,
    {
        if let Some(parent) = parent_dir(&self.path) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create alias store directory {}", parent.display()))?;
        }

        let lock_file = self.open_lock_file()?;
        let mut lock = RwLock::new(lock_file);
        let _guard = lock.write().context("acquire alias store write lock")?;

        let mut root = self.read_unlocked()?;
        root.version = CURRENT_VERSION;
        f(&mut root)?;
        self.write_root(&root)
    }

    fn write_root(&self, root: &Root) -> Result<()> {
        let tmp_path = self.path.with_extension("json.tmp");
        let mut file = Self::create_tmp_file(&tmp_path)?;
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

        let parent = parent_dir(&self.path).unwrap_or_else(|| Path::new("."));
        let parent_dir = File::open(parent)
            .with_context(|| format!("open alias store parent directory {}", parent.display()))?;
        parent_dir
            .sync_all()
            .with_context(|| format!("fsync alias store parent directory {}", parent.display()))?;
        Ok(())
    }

    fn open_lock_file(&self) -> Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        options
            .open(&self.lock_path)
            .with_context(|| format!("open alias store lock {}", self.lock_path.display()))
    }

    fn create_tmp_file(path: &Path) -> Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        options
            .open(path)
            .with_context(|| format!("create alias store tmp {}", path.display()))
    }
}

fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

pub fn default_db_path() -> PathBuf {
    portl_core::paths::aliases_path()
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
        Some(value) if value.is_empty() => Err(serde::de::Error::custom(format!(
            "expected exactly {N} bytes of hex, got empty string"
        ))),
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
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    use anyhow::Result;
    use serde_json::json;
    use tempfile::tempdir;

    use super::{AliasRecord, AliasStore, CURRENT_VERSION, StoredSpec};
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
            session_provider: None,
            session_provider_install: None,
            docker_exec_id: None,
            docker_injected_binary_path: None,
            docker_injected_binary_preexisted: false,
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
            session_provider: None,
            session_provider_install: None,
            docker_exec_id: None,
            docker_injected_binary_path: None,
            docker_injected_binary_preexisted: false,
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
        // Keep the four-writer contention shape (the semantic
        // contract) but cut SAVES_PER_WRITER from 250 -> 20
        // (1_000 -> 80 total saves). Each save fsyncs + atomic-
        // renames an aliases.json shard, and 80 fsyncs is still >>
        // any plausible fd-lock queue depth, so concurrent-writer
        // convergence is still exercised. Drops standalone test
        // wall-clock from ~210s -> ~5s on this host.
        const WRITERS: u32 = 4;
        const SAVES_PER_WRITER: u32 = 20;
        const EXPECTED_TOTAL: usize = (WRITERS * SAVES_PER_WRITER) as usize;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        let handles: Vec<_> = (0..WRITERS)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let store = AliasStore::new(path);
                    for j in 0..SAVES_PER_WRITER {
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
        assert_eq!(store.list().expect("list").len(), EXPECTED_TOTAL);
    }

    #[test]
    fn save_rejects_duplicate_endpoint_id_for_other_alias() {
        let dir = tempdir().expect("tempdir");
        let store = AliasStore::new(dir.path().join("aliases.json"));
        let spec = minimal_spec();

        store
            .save(&alias("demo-1", "endpoint-1", 1), &spec)
            .expect("save first alias");

        let err = store
            .save(&alias("demo-2", "endpoint-1", 2), &spec)
            .expect_err("duplicate endpoint_id should fail");
        assert_eq!(
            err.to_string(),
            "endpoint_id endpoint-1 is already registered as alias demo-1"
        );
    }

    #[test]
    fn read_rejects_alias_store_from_newer_version() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        fs::write(
            &path,
            format!(
                "{{\n  \"version\": {},\n  \"aliases\": {{}}\n}}\n",
                CURRENT_VERSION + 1
            ),
        )
        .expect("write future alias store");
        let store = AliasStore::new(path.clone());

        let err = store
            .list()
            .expect_err("future alias store should fail closed");
        assert_eq!(
            err.to_string(),
            format!(
                "alias store at {} was written by a newer portl (version={}); refusing to open",
                path.display(),
                CURRENT_VERSION + 1
            )
        );
    }

    #[test]
    fn empty_hex_strings_are_rejected() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        fs::write(
            &path,
            json!({
                "version": CURRENT_VERSION,
                "aliases": {
                    "demo": {
                        "record": {
                            "name": "demo",
                            "adapter": "docker-portl",
                            "container_id": "cid-demo",
                            "endpoint_id": "endpoint-demo",
                            "image": "img",
                            "network": "bridge",
                            "created_at": 7
                        },
                        "spec": {
                            "caps": empty_caps(),
                            "ttl_secs": 60,
                            "to": "",
                            "labels": [],
                            "root_ticket_id": null,
                            "ticket_file_path": null,
                            "group_name": null,
                            "base_url": null
                        }
                    }
                }
            })
            .to_string(),
        )
        .expect("write alias store with empty hex string");
        let store = AliasStore::new(path);

        let err = store
            .list()
            .expect_err("empty hex string should fail closed");
        assert!(
            format!("{err:#}").contains("expected exactly 32 bytes of hex, got empty string"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn save_preserves_unknown_entry_fields_for_existing_alias() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "version": CURRENT_VERSION,
                "aliases": {
                    "demo": {
                        "record": {
                            "name": "demo",
                            "adapter": "docker-portl",
                            "container_id": "cid-demo",
                            "endpoint_id": "endpoint-demo",
                            "image": "img",
                            "network": "bridge",
                            "created_at": 7
                        },
                        "spec": {
                            "caps": empty_caps(),
                            "ttl_secs": 60,
                            "to": null,
                            "labels": [],
                            "root_ticket_id": null,
                            "ticket_file_path": null,
                            "group_name": null,
                            "base_url": null
                        },
                        "future_field": "preserve-me"
                    }
                }
            }))
            .expect("encode alias store")
                + "\n",
        )
        .expect("write alias store with future entry field");
        let store = AliasStore::new(path.clone());

        store
            .save(&alias("demo", "endpoint-rebuilt", 8), &minimal_spec())
            .expect("update alias");

        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path).expect("read alias store"))
                .expect("parse alias store");
        assert_eq!(
            value["aliases"]["demo"]["future_field"],
            serde_json::Value::String("preserve-me".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn alias_store_files_are_created_owner_only() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        let store = AliasStore::new(path.clone());

        store
            .save(&alias("demo", "endpoint-demo", 1), &minimal_spec())
            .expect("save alias");

        let data_mode = fs::metadata(&path).expect("data metadata").mode() & 0o777;
        let lock_mode = fs::metadata(dir.path().join("aliases.json.lock"))
            .expect("lock metadata")
            .mode()
            & 0o777;
        assert_eq!(data_mode, 0o600);
        assert_eq!(lock_mode, 0o600);
    }

    #[test]
    fn readers_observe_monotonic_snapshots_while_writer_updates() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("aliases.json");
        let barrier = Arc::new(Barrier::new(4));
        let writer_done = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..3)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                let writer_done = Arc::clone(&writer_done);
                std::thread::spawn(move || -> Result<Vec<usize>> {
                    let store = AliasStore::new(path);
                    // Per TEST_BUILD_TUNING.md fsync-throughput guidance: readers
                    // cap at 400 snapshots and break early once writer is done + they
                    // have at least 80 samples. Pairs with writer loop reduced to 80.
                    let mut counts = Vec::with_capacity(400);
                    barrier.wait();
                    for _ in 0..400 {
                        counts.push(store.list()?.len());
                        if writer_done.load(Ordering::Acquire) && counts.len() >= 80 {
                            break;
                        }
                    }
                    Ok(counts)
                })
            })
            .collect();

        let writer = {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let writer_done = Arc::clone(&writer_done);
            std::thread::spawn(move || -> Result<()> {
                let store = AliasStore::new(path);
                let spec = minimal_spec();
                barrier.wait();
                // 80 writes is plenty to observe monotonic growth from 3 readers;
                // each save fsyncs + renames, so cost scales linearly with count.
                for i in 0..80_u32 {
                    let alias = alias(format!("writer-{i}"), format!("endpoint-{i}"), i64::from(i));
                    store.save(&alias, &spec)?;
                }
                writer_done.store(true, Ordering::Release);
                Ok(())
            })
        };

        writer
            .join()
            .expect("writer thread")
            .expect("writer result");

        for reader in readers {
            let counts = reader
                .join()
                .expect("reader thread")
                .expect("reader result");
            assert!(
                !counts.is_empty(),
                "reader should observe at least one snapshot"
            );
            assert!(
                counts.windows(2).all(|window| window[0] <= window[1]),
                "reader counts should be monotonic: {counts:?}"
            );
        }

        let store = AliasStore::new(path);
        assert_eq!(store.list().expect("final list").len(), 80);
    }
}

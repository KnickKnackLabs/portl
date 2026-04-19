use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_core::id::store;
use portl_core::ticket::schema::Capabilities;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

const DB_FILE: &str = "aliases.sqlite";
const BUSY_TIMEOUT_MS: u64 = 5_000;
static DB_INIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
    pub to: Option<[u8; 32]>,
    pub labels: Vec<(String, String)>,
    pub root_ticket_id: Option<[u8; 16]>,
}

pub struct AliasStore {
    db_path: PathBuf,
}

impl Default for AliasStore {
    fn default() -> Self {
        Self::new(default_db_path())
    }
}

impl AliasStore {
    pub fn new(db_path: PathBuf) -> Self {
        Self { db_path }
    }

    pub fn save(&self, alias: &AliasRecord, spec: &StoredSpec) -> Result<()> {
        let mut conn = self.open()?;
        let tx = conn.transaction().context("begin alias save transaction")?;
        tx.execute(
            "INSERT OR REPLACE INTO aliases (
                name, adapter, container_id, endpoint_id, image, network, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                alias.name,
                alias.adapter,
                alias.container_id,
                alias.endpoint_id,
                alias.image,
                alias.network,
                alias.created_at,
            ],
        )
        .context("upsert alias row")?;
        tx.execute(
            "INSERT OR REPLACE INTO alias_specs (
                name, caps_json, ttl_secs, to_hex, labels_json, root_ticket_id_hex
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                alias.name,
                serde_json::to_string(&spec.caps).context("encode caps json")?,
                i64::try_from(spec.ttl_secs).context("ttl exceeds sqlite integer range")?,
                spec.to.map(hex::encode),
                serde_json::to_string(&spec.labels).context("encode labels json")?,
                spec.root_ticket_id.map(hex::encode),
            ],
        )
        .context("upsert alias spec row")?;
        tx.commit().context("commit alias save transaction")?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<Option<AliasRecord>> {
        let conn = self.open()?;
        conn.query_row(
            "SELECT name, adapter, container_id, endpoint_id, image, network, created_at
             FROM aliases WHERE name = ?1",
            params![name],
            |row| {
                Ok(AliasRecord {
                    name: row.get(0)?,
                    adapter: row.get(1)?,
                    container_id: row.get(2)?,
                    endpoint_id: row.get(3)?,
                    image: row.get(4)?,
                    network: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )
        .optional()
        .context("query alias by name")
    }

    pub fn get_spec(&self, name: &str) -> Result<Option<StoredSpec>> {
        let conn = self.open()?;
        conn.query_row(
            "SELECT caps_json, ttl_secs, to_hex, labels_json, root_ticket_id_hex
             FROM alias_specs WHERE name = ?1",
            params![name],
            |row| {
                let caps_json: String = row.get(0)?;
                let ttl_secs: i64 = row.get(1)?;
                let to_hex: Option<String> = row.get(2)?;
                let labels_json: String = row.get(3)?;
                let root_ticket_id_hex: Option<String> = row.get(4)?;
                Ok(StoredSpec {
                    caps: serde_json::from_str(&caps_json).map_err(json_error_to_sqlite)?,
                    ttl_secs: u64::try_from(ttl_secs).map_err(int_error_to_sqlite)?,
                    to: to_hex
                        .map(|value| parse_optional_hex32(&value))
                        .transpose()
                        .map_err(json_error_to_sqlite)?,
                    labels: serde_json::from_str(&labels_json).map_err(json_error_to_sqlite)?,
                    root_ticket_id: root_ticket_id_hex
                        .map(|value| parse_optional_hex16(&value))
                        .transpose()
                        .map_err(json_error_to_sqlite)?,
                })
            },
        )
        .optional()
        .context("query alias spec by name")
    }

    pub fn list(&self) -> Result<Vec<AliasRecord>> {
        let conn = self.open()?;
        let mut stmt = conn
            .prepare(
                "SELECT name, adapter, container_id, endpoint_id, image, network, created_at
                 FROM aliases ORDER BY name ASC",
            )
            .context("prepare alias list query")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AliasRecord {
                    name: row.get(0)?,
                    adapter: row.get(1)?,
                    container_id: row.get(2)?,
                    endpoint_id: row.get(3)?,
                    image: row.get(4)?,
                    network: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .context("query alias list")?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("collect alias rows")
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let conn = self.open()?;
        conn.execute("DELETE FROM alias_specs WHERE name = ?1", params![name])
            .context("delete alias spec row")?;
        conn.execute("DELETE FROM aliases WHERE name = ?1", params![name])
            .context("delete alias row")?;
        Ok(())
    }

    fn open(&self) -> Result<Connection> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create alias db directory {}", parent.display()))?;
        }
        let conn = Connection::open(&self.db_path)
            .with_context(|| format!("open alias db {}", self.db_path.display()))?;
        let _guard = DB_INIT_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| anyhow::anyhow!("alias db init lock poisoned"))?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        migrate_schema(&conn)?;
        Ok(conn)
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

fn configure_connection(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))
        .context("set alias db busy timeout")?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;\
         PRAGMA journal_mode = WAL;",
    )
    .context("configure alias db pragmas")
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "BEGIN;
         CREATE TABLE IF NOT EXISTS aliases (
             name TEXT PRIMARY KEY,
             adapter TEXT NOT NULL,
             container_id TEXT NOT NULL,
             endpoint_id TEXT NOT NULL,
             image TEXT NOT NULL,
             network TEXT NOT NULL,
             created_at INTEGER NOT NULL
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_aliases_endpoint_id
             ON aliases(endpoint_id);
         CREATE TABLE IF NOT EXISTS alias_specs (
             name TEXT PRIMARY KEY,
             caps_json TEXT NOT NULL,
             ttl_secs INTEGER NOT NULL,
             to_hex TEXT,
             labels_json TEXT NOT NULL,
             root_ticket_id_hex TEXT,
             FOREIGN KEY(name) REFERENCES aliases(name) ON DELETE CASCADE
         );
         COMMIT;",
    )
    .context("initialize alias db schema")
}

fn migrate_schema(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "alias_specs", "root_ticket_id_hex")? {
        conn.execute(
            "ALTER TABLE alias_specs ADD COLUMN root_ticket_id_hex TEXT",
            [],
        )
        .context("add root_ticket_id_hex column to alias_specs")?;
    }
    Ok(())
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .with_context(|| format!("prepare table_info for {table}"))?;
    let mut rows = stmt
        .query([])
        .with_context(|| format!("query table_info for {table}"))?;
    while let Some(row) = rows.next().context("step table_info rows")? {
        let name: String = row.get(1).context("read table_info column name")?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_optional_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid 32-byte hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected exactly 32 bytes of hex: {value}"))
}

fn parse_optional_hex16(value: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid 16-byte hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected exactly 16 bytes of hex: {value}"))
}

fn json_error_to_sqlite(err: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            err.to_string(),
        )),
    )
}

fn int_error_to_sqlite(err: impl std::fmt::Display) -> rusqlite::Error {
    json_error_to_sqlite(err)
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn alias_store_round_trips_alias_and_spec() {
        let dir = tempdir().expect("tempdir");
        let store = AliasStore::new(dir.path().join("aliases.sqlite"));
        let alias = AliasRecord {
            name: "demo".to_owned(),
            adapter: "docker-portl".to_owned(),
            container_id: "cid".to_owned(),
            endpoint_id: "eid".to_owned(),
            image: "img".to_owned(),
            network: "bridge".to_owned(),
            created_at: 7,
        };
        let spec = StoredSpec {
            caps: empty_caps(),
            ttl_secs: 60,
            to: Some([9; 32]),
            labels: vec![("a".to_owned(), "b".to_owned())],
            root_ticket_id: Some([4; 16]),
        };

        store.save(&alias, &spec).expect("save alias");
        assert_eq!(store.get("demo").expect("get alias"), Some(alias));
        assert_eq!(store.get_spec("demo").expect("get spec"), Some(spec));
    }

    #[test]
    fn concurrent_saves_serialize_without_corruption() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("aliases.sqlite");
        let barrier = Arc::new(Barrier::new(3));

        let worker = |name: &'static str, endpoint_id: &'static str| {
            let db_path = db_path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = AliasStore::new(db_path);
                let alias = AliasRecord {
                    name: name.to_owned(),
                    adapter: "docker-portl".to_owned(),
                    container_id: format!("cid-{name}"),
                    endpoint_id: endpoint_id.to_owned(),
                    image: "img".to_owned(),
                    network: "bridge".to_owned(),
                    created_at: 1,
                };
                let spec = StoredSpec {
                    caps: empty_caps(),
                    ttl_secs: 60,
                    to: None,
                    labels: vec![],
                    root_ticket_id: None,
                };
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
}

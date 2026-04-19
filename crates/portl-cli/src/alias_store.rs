use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_core::id::store;
use portl_core::ticket::schema::Capabilities;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

const DB_FILE: &str = "aliases.sqlite";

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
        let conn = self.open()?;
        conn.execute(
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
        conn.execute(
            "INSERT OR REPLACE INTO alias_specs (
                name, caps_json, ttl_secs, to_hex, labels_json
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                alias.name,
                serde_json::to_string(&spec.caps).context("encode caps json")?,
                i64::try_from(spec.ttl_secs).context("ttl exceeds sqlite integer range")?,
                spec.to.map(hex::encode),
                serde_json::to_string(&spec.labels).context("encode labels json")?,
            ],
        )
        .context("upsert alias spec row")?;
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
            "SELECT caps_json, ttl_secs, to_hex, labels_json FROM alias_specs WHERE name = ?1",
            params![name],
            |row| {
                let caps_json: String = row.get(0)?;
                let ttl_secs: i64 = row.get(1)?;
                let to_hex: Option<String> = row.get(2)?;
                let labels_json: String = row.get(3)?;
                Ok(StoredSpec {
                    caps: serde_json::from_str(&caps_json).map_err(json_error_to_sqlite)?,
                    ttl_secs: u64::try_from(ttl_secs).map_err(int_error_to_sqlite)?,
                    to: to_hex
                        .map(|value| parse_optional_hex32(&value))
                        .transpose()
                        .map_err(json_error_to_sqlite)?,
                    labels: serde_json::from_str(&labels_json).map_err(json_error_to_sqlite)?,
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
        init_schema(&conn)?;
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
         CREATE TABLE IF NOT EXISTS alias_specs (
             name TEXT PRIMARY KEY,
             caps_json TEXT NOT NULL,
             ttl_secs INTEGER NOT NULL,
             to_hex TEXT,
             labels_json TEXT NOT NULL,
             FOREIGN KEY(name) REFERENCES aliases(name) ON DELETE CASCADE
         );
         COMMIT;",
    )
    .context("initialize alias db schema")
}

fn parse_optional_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid 32-byte hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected exactly 32 bytes of hex: {value}"))
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
        };

        store.save(&alias, &spec).expect("save alias");
        assert_eq!(store.get("demo").expect("get alias"), Some(alias));
        assert_eq!(store.get_spec("demo").expect("get spec"), Some(spec));
    }
}

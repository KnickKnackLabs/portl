//! Live connection registry.
//!
//! One row per live QUIC connection, keyed by `(peer_eid, stable_id)`
//! so multiple concurrent connections from the same peer coexist
//! without stomping on each other's rows. Inserted at ticket-accept
//! time (see `ticket_handler`), removed by a per-connection Drop
//! guard when the authenticated stream loop exits.
//!
//! RTT, bytes, and path classification are derived **on snapshot**
//! from the live `iroh::endpoint::Connection`, not sampled into the
//! registry out-of-band. This keeps the hot send/recv paths free of
//! extra bookkeeping and guarantees that `/status/connections`
//! reflects iroh's actual state at the moment of the query.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use iroh::endpoint::Connection;
use serde::{Deserialize, Serialize};

/// Composite key for the registry: `(peer_eid, stable_id)`. Two
/// concurrent QUIC connections from the same peer have the same
/// `peer_eid` but different `stable_id`, so they hash to distinct
/// rows.
pub type ConnKey = ([u8; 32], usize);

/// Connection path: direct-UDP, relayed, or mixed (iroh reports more
/// than one live path, e.g. during a holepunch-over-relay transition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    DirectUdp,
    Relay,
    Mixed,
    Unknown,
}

impl PathKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DirectUdp => "direct-udp",
            Self::Relay => "relay",
            Self::Mixed => "mixed",
            Self::Unknown => "unknown",
        }
    }
}

/// Snapshot of a single connection for IPC responses. Point-in-time
/// values derived from the live iroh connection; nothing outside the
/// agent process can mutate these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    /// 64-char hex of the remote transport `endpoint_id`.
    pub peer_eid: String,
    /// 64-char hex of the root ticket issuer that authorized this connection.
    #[serde(default)]
    pub ticket_issuer_id: Option<String>,
    /// 64-char hex of the proof-of-possession holder, when the ticket was `to`-bound.
    #[serde(default)]
    pub ticket_holder_id: Option<String>,
    /// iroh `Connection::stable_id()` — unique per QUIC connection,
    /// so two concurrent connections from the same peer are
    /// distinguishable in output.
    pub connection_id: u64,
    pub path: PathKind,
    /// Round-trip estimate in microseconds. `None` when iroh has
    /// not yet produced an RTT sample for the selected path.
    pub rtt_micros: Option<u64>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    /// Unix seconds since epoch when the connection opened.
    pub up_since_unix: u64,
}

/// Internal per-connection handle. The `Connection` is kept so
/// `snapshot()` can pull rtt / stats / paths on demand.
#[derive(Debug, Clone)]
struct Entry {
    connection: Connection,
    ticket_issuer_id: [u8; 32],
    ticket_holder_id: Option<[u8; 32]>,
    up_since_unix: u64,
}

/// Shared registry of live connections.
///
/// Cheap to clone (`Arc`-backed). Safe to mutate concurrently.
#[derive(Debug, Default, Clone)]
pub struct ConnectionRegistry {
    inner: Arc<DashMap<ConnKey, Entry>>,
}

impl ConnectionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a QUIC connection has opened. The key is
    /// `(peer_eid, connection.stable_id())`, so concurrent
    /// connections from the same peer get distinct rows. Inserting
    /// the same key twice (shouldn't happen — `stable_id` is unique
    /// per-connection) overwrites the prior row.
    pub fn insert(
        &self,
        peer_eid: [u8; 32],
        connection: Connection,
        ticket_issuer_id: [u8; 32],
        ticket_holder_id: Option<[u8; 32]>,
    ) -> ConnKey {
        let key = (peer_eid, connection.stable_id());
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.inner.insert(
            key,
            Entry {
                connection,
                ticket_issuer_id,
                ticket_holder_id,
                up_since_unix: now_unix,
            },
        );
        key
    }

    /// Remove a connection record. No-op if unknown.
    pub fn remove(&self, key: &ConnKey) {
        self.inner.remove(key);
    }

    /// Take a snapshot of every live connection. Order is unspecified
    /// (`DashMap` iteration order); callers that need stable output
    /// should sort. Path/rtt/bytes are pulled from the live iroh
    /// connection at snapshot time.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        self.inner
            .iter()
            .map(|entry| {
                let (key, value) = (entry.key(), entry.value());
                let (path, rtt_micros) = classify_path_and_rtt(&value.connection);
                let stats = value.connection.stats();
                ConnectionSnapshot {
                    peer_eid: hex::encode(key.0),
                    ticket_issuer_id: Some(hex::encode(value.ticket_issuer_id)),
                    ticket_holder_id: value.ticket_holder_id.map(hex::encode),
                    connection_id: key.1 as u64,
                    path,
                    rtt_micros,
                    bytes_rx: stats.udp_rx.bytes,
                    bytes_tx: stats.udp_tx.bytes,
                    up_since_unix: value.up_since_unix,
                }
            })
            .collect()
    }

    /// Number of currently-tracked connections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Classify an iroh connection's live paths into a `PathKind` and
/// pull the best available RTT sample. Returns `(Unknown, None)` if
/// the connection has no non-closed paths (shouldn't happen while
/// the Drop guard is alive, but handled defensively).
fn classify_path_and_rtt(conn: &Connection) -> (PathKind, Option<u64>) {
    let paths = conn.paths();
    if paths.is_empty() {
        return (PathKind::Unknown, None);
    }
    let has_ip = paths.iter().any(|p| p.is_ip());
    let has_relay = paths.iter().any(|p| p.is_relay());
    let kind = match (has_ip, has_relay) {
        (true, true) => PathKind::Mixed,
        (true, false) => PathKind::DirectUdp,
        (false, true) => PathKind::Relay,
        (false, false) => PathKind::Unknown,
    };
    let rtt = paths
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .or_else(|| paths.iter().next())
        .and_then(|p| rtt_micros_if_sampled(p.rtt()));
    (kind, rtt)
}

fn rtt_micros_if_sampled(rtt: Duration) -> Option<u64> {
    (!rtt.is_zero()).then(|| u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_kind_as_str_is_stable() {
        // Observability consumers depend on this string shape for
        // OpenMetrics labels + JSON output.
        assert_eq!(PathKind::DirectUdp.as_str(), "direct-udp");
        assert_eq!(PathKind::Relay.as_str(), "relay");
        assert_eq!(PathKind::Mixed.as_str(), "mixed");
        assert_eq!(PathKind::Unknown.as_str(), "unknown");
    }

    #[test]
    fn zero_rtt_is_treated_as_missing_sample() {
        assert_eq!(rtt_micros_if_sampled(Duration::ZERO), None);
        assert_eq!(rtt_micros_if_sampled(Duration::from_micros(42)), Some(42));
    }

    #[test]
    fn empty_registry_snapshot_is_empty() {
        let reg = ConnectionRegistry::new();
        assert!(reg.is_empty());
        assert!(reg.snapshot().is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn connection_snapshot_deserializes_legacy_json_without_auth_fields() {
        let snapshot: ConnectionSnapshot = serde_json::from_str(
            r#"{
                "peer_eid":"1111111111111111111111111111111111111111111111111111111111111111",
                "connection_id":7,
                "path":"relay",
                "rtt_micros":1000,
                "bytes_rx":10,
                "bytes_tx":20,
                "up_since_unix":1704067199
            }"#,
        )
        .expect("deserialize legacy snapshot");

        assert_eq!(snapshot.ticket_issuer_id, None);
        assert_eq!(snapshot.ticket_holder_id, None);
    }

    // Behavioural coverage for insert / remove / snapshot requires a
    // live `iroh::endpoint::Connection`, which is exercised by the
    // integration tests under `crates/portl-agent/tests/`. The key
    // invariant — that concurrent connections from the same peer
    // coexist under distinct `(eid, stable_id)` rows — is structural
    // (see `ConnKey` + `insert`) and guaranteed by `DashMap`'s
    // hashing.
}

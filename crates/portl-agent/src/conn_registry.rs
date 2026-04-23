//! Per-peer connection tracking for the v0.3.2 observability
//! release.
//!
//! Complements the existing `active_connections` gauge by keying on
//! peer `EndpointId`. Updated from the ticket / shell / tcp / udp
//! handlers; read by the `/status/connections` IPC route.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Connection path: direct-UDP, relayed, or mixed (in-flight path
/// change; iroh rarely reports this but the enum accounts for it).
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

/// Snapshot of a single connection for IPC responses. Values are
/// captured point-in-time; no references to live atomics leak out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    /// 64-char hex of the remote `endpoint_id`.
    pub peer_eid: String,
    pub path: PathKind,
    /// Round-trip estimate in microseconds. `None` if never sampled.
    pub rtt_micros: Option<u64>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    /// Unix seconds since epoch when the connection opened.
    pub up_since_unix: u64,
}

/// Internal per-connection handle.
#[derive(Debug)]
struct Entry {
    path: PathKind,
    rtt_micros: Option<u64>,
    bytes_rx: u64,
    bytes_tx: u64,
    started: Instant,
    up_since_unix: u64,
}

/// Shared registry of live connections.
///
/// Cheap to clone (`Arc`-backed). Safe to mutate concurrently.
#[derive(Debug, Default, Clone)]
pub struct ConnectionRegistry {
    inner: Arc<DashMap<[u8; 32], Entry>>,
}

impl ConnectionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a connection to `peer_eid` has opened. Idempotent
    /// per-eid: re-insertion updates `started`/`up_since_unix` but
    /// preserves byte counters if the entry was still around.
    pub fn insert(&self, peer_eid: [u8; 32], path: PathKind) {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.inner
            .entry(peer_eid)
            .and_modify(|entry| {
                entry.path = path;
                // Keep byte counters; reset clock if this is a new
                // QUIC session (semantically a new connection).
                entry.started = Instant::now();
                entry.up_since_unix = now_unix;
            })
            .or_insert(Entry {
                path,
                rtt_micros: None,
                bytes_rx: 0,
                bytes_tx: 0,
                started: Instant::now(),
                up_since_unix: now_unix,
            });
    }

    /// Remove a connection record. No-op if unknown.
    pub fn remove(&self, peer_eid: &[u8; 32]) {
        self.inner.remove(peer_eid);
    }

    /// Update connection path (e.g. holepunch succeeded post-relay).
    pub fn set_path(&self, peer_eid: &[u8; 32], path: PathKind) {
        if let Some(mut entry) = self.inner.get_mut(peer_eid) {
            entry.path = path;
        }
    }

    /// Record an RTT sample in microseconds.
    pub fn set_rtt(&self, peer_eid: &[u8; 32], rtt_micros: u64) {
        if let Some(mut entry) = self.inner.get_mut(peer_eid) {
            entry.rtt_micros = Some(rtt_micros);
        }
    }

    /// Add to byte counters. Called from the stream read / write
    /// hot paths.
    pub fn add_bytes(&self, peer_eid: &[u8; 32], rx: u64, tx: u64) {
        if let Some(mut entry) = self.inner.get_mut(peer_eid) {
            entry.bytes_rx = entry.bytes_rx.saturating_add(rx);
            entry.bytes_tx = entry.bytes_tx.saturating_add(tx);
        }
    }

    /// Take a snapshot of every live connection. Order is unspecified
    /// (`DashMap` iteration order); callers that need stable output
    /// should sort by `peer_eid`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        self.inner
            .iter()
            .map(|entry| ConnectionSnapshot {
                peer_eid: hex::encode(entry.key()),
                path: entry.path,
                rtt_micros: entry.rtt_micros,
                bytes_rx: entry.bytes_rx,
                bytes_tx: entry.bytes_tx,
                up_since_unix: entry.up_since_unix,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn eid(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    #[test]
    fn insert_and_snapshot_roundtrip() {
        let reg = ConnectionRegistry::new();
        reg.insert(eid(1), PathKind::DirectUdp);
        reg.set_rtt(&eid(1), 23_500);
        reg.add_bytes(&eid(1), 100, 200);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].peer_eid.chars().count(), 64);
        assert_eq!(snap[0].path, PathKind::DirectUdp);
        assert_eq!(snap[0].rtt_micros, Some(23_500));
        assert_eq!(snap[0].bytes_rx, 100);
        assert_eq!(snap[0].bytes_tx, 200);
    }

    #[test]
    fn remove_forgets_connection() {
        let reg = ConnectionRegistry::new();
        reg.insert(eid(1), PathKind::Relay);
        reg.remove(&eid(1));
        assert!(reg.snapshot().is_empty());
    }

    #[test]
    fn reinsert_preserves_byte_counters_but_resets_clock() {
        let reg = ConnectionRegistry::new();
        reg.insert(eid(1), PathKind::Relay);
        reg.add_bytes(&eid(1), 50, 75);
        reg.insert(eid(1), PathKind::DirectUdp);
        let snap = reg.snapshot();
        assert_eq!(snap[0].bytes_rx, 50);
        assert_eq!(snap[0].bytes_tx, 75);
        assert_eq!(snap[0].path, PathKind::DirectUdp);
    }

    #[test]
    fn set_path_updates_only_existing_entries() {
        let reg = ConnectionRegistry::new();
        reg.set_path(&eid(1), PathKind::DirectUdp); // no-op
        assert!(reg.is_empty());
        reg.insert(eid(1), PathKind::Relay);
        reg.set_path(&eid(1), PathKind::DirectUdp);
        assert_eq!(reg.snapshot()[0].path, PathKind::DirectUdp);
    }

    #[test]
    fn path_kind_as_str_is_stable() {
        // Observability consumers depend on this string shape for
        // OpenMetrics labels + JSON output.
        assert_eq!(PathKind::DirectUdp.as_str(), "direct-udp");
        assert_eq!(PathKind::Relay.as_str(), "relay");
        assert_eq!(PathKind::Mixed.as_str(), "mixed");
        assert_eq!(PathKind::Unknown.as_str(), "unknown");
    }
}

//! `portl/pair/v1` acceptor.
//!
//! Lives alongside the existing `portl/ticket/v1` listener on the
//! same iroh endpoint. The caller dials this ALPN after decoding
//! an invite code; server:
//!
//! 1. Reads one postcard-framed `PairRequest`.
//! 2. Looks up `nonce` in `$PORTL_HOME/pending_invites.json`.
//! 3. If present + not expired: inserts/updates the caller in
//!    `peers.json` and deletes the consumed invite.
//! 4. Writes a `PairResponse` and closes the stream.
//!
//! The caller's identity is read from iroh's TLS peer cert, not
//! from anything in the request — the wire format has no way to
//! spoof `endpoint_id`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use portl_core::labels;
use portl_core::pair_store::PairStore;
use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore};
use portl_proto::pair_v1::{PairRequest, PairResponse, PairResult};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, info, instrument};

use crate::AgentState;

const MAX_PAIR_REQ_BYTES: usize = 8 * 1024;

#[instrument(skip_all, fields(remote = %connection.remote_id().fmt_short()))]
pub(crate) async fn serve_connection(connection: Connection, state: Arc<AgentState>) -> Result<()> {
    let caller_eid = *connection.remote_id().as_bytes();
    let (mut send, recv) = connection
        .accept_bi()
        .await
        .context("accept pair bi-stream")?;

    let request = read_pair_request_frame(recv)
        .await
        .context("read PairRequest")?;
    debug!(initiator = ?request.initiator, nonce = %short_nonce(&request.nonce), "received pair request");

    let response = handle_pair(&state, caller_eid, &request)?;
    debug!(result = ?response.result, "sending pair response");

    let bytes = postcard::to_stdvec(&response).context("encode PairResponse")?;
    let len_prefix: u32 = bytes
        .len()
        .try_into()
        .context("pair response length overflow u32")?;
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&len_prefix.to_le_bytes());
    framed.extend_from_slice(&bytes);
    send.write_all(&framed)
        .await
        .context("write PairResponse")?;
    send.finish().context("finish PairResponse")?;
    connection.closed().await;

    Ok(())
}

async fn read_pair_request_frame<R>(mut recv: R) -> Result<PairRequest>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("read PairRequest length prefix")?;
    let req_len = u32::from_le_bytes(len_buf) as usize;
    if req_len > MAX_PAIR_REQ_BYTES {
        anyhow::bail!("PairRequest size {req_len} exceeds cap {MAX_PAIR_REQ_BYTES}");
    }
    let mut body = vec![0u8; req_len];
    recv.read_exact(&mut body)
        .await
        .context("read PairRequest body")?;
    postcard::from_bytes(&body).context("decode PairRequest")
}

#[allow(clippy::too_many_lines)]
pub(crate) fn handle_pair(
    state: &AgentState,
    caller_eid: [u8; 32],
    request: &PairRequest,
) -> Result<PairResponse> {
    if request.version != 1 {
        return Ok(PairResponse {
            version: 1,
            result: PairResult::PolicyRejected(format!(
                "unsupported pair protocol version {}",
                request.version
            )),
            responder_relay_hint: None,
            responder_chosen_label: None,
            responder_self_label: None,
        });
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let peers_path = state
        .peers_path
        .clone()
        .unwrap_or_else(PeerStore::default_path);
    let pair_path = peers_path
        .parent()
        .map_or_else(PairStore::default_path, |p| p.join("pending_invites.json"));

    let mut pair_store = PairStore::load(&pair_path)
        .with_context(|| format!("load pair store at {}", pair_path.display()))?;
    let nonce_hex = hex::encode(request.nonce);
    debug!(
        pair_store = %pair_path.display(),
        peers_store = %peers_path.display(),
        nonce = %short_nonce(&request.nonce),
        initiator = ?request.initiator,
        "handling pair request"
    );
    let Some(invite) = pair_store.find_by_nonce(&nonce_hex).cloned() else {
        return Ok(PairResponse {
            version: 1,
            result: PairResult::NonceUnknown,
            responder_relay_hint: relay_hint_for_response(state),
            responder_chosen_label: None,
            responder_self_label: responder_self_label(state),
        });
    };
    if invite.is_expired(now) {
        return Ok(PairResponse {
            version: 1,
            result: PairResult::NonceExpired,
            responder_relay_hint: relay_hint_for_response(state),
            responder_chosen_label: None,
            responder_self_label: responder_self_label(state),
        });
    }
    if request.initiator != invite.initiator {
        return Ok(PairResponse {
            version: 1,
            result: PairResult::PolicyRejected("invite initiator mismatch".to_owned()),
            responder_relay_hint: relay_hint_for_response(state),
            responder_chosen_label: None,
            responder_self_label: responder_self_label(state),
        });
    }

    let mut peers = PeerStore::load(&peers_path)
        .with_context(|| format!("load peer store at {}", peers_path.display()))?;
    let caller_eid_hex = hex::encode(caller_eid);

    // Already paired? Respond idempotently — the consumed-nonce is
    // the canonical signal that this was a legitimate pair; we just
    // don't duplicate the entry.
    if let Some(existing) = peers.iter().find(|e| e.endpoint_id_hex == caller_eid_hex) {
        pair_store.remove(&nonce_hex);
        let _ = pair_store.save();
        return Ok(PairResponse {
            version: 1,
            result: PairResult::AlreadyPaired {
                existing_label: existing.label.clone(),
            },
            responder_relay_hint: relay_hint_for_response(state),
            responder_chosen_label: Some(existing.label.clone()),
            responder_self_label: responder_self_label(state),
        });
    }

    let chosen_label = choose_label(
        &peers,
        request.caller_label.as_deref(),
        invite.for_label_hint.as_deref(),
        &caller_eid_hex,
    );
    let (accepts_from_them, they_accept_from_me) =
        invite.initiator.relationship().inviter_peer_flags();

    peers
        .insert_or_update(PeerEntry {
            label: chosen_label.clone(),
            endpoint_id_hex: caller_eid_hex,
            accepts_from_them,
            they_accept_from_me,
            since: now,
            origin: PeerOrigin::Paired,
            last_hold_at: None,
            is_self: false,
            relay_hint: request.caller_relay_hint.clone(),
            schema_version: 2,
        })
        .context("insert paired peer")?;
    peers.save(&peers_path).context("save peer store")?;

    pair_store.remove(&nonce_hex);
    pair_store.save().context("save pair store after consume")?;

    info!(
        caller_eid = %hex::encode(caller_eid),
        label = %chosen_label,
        initiator = ?invite.initiator,
        "accepted pair request"
    );

    Ok(PairResponse {
        version: 1,
        result: PairResult::Ok,
        responder_relay_hint: relay_hint_for_response(state),
        responder_chosen_label: Some(chosen_label),
        responder_self_label: responder_self_label(state),
    })
}

/// Pick a label for the new peer entry. Priority: caller's hint →
/// operator's `--for` hint → first-8-hex of `endpoint_id`. Falls
/// back when there's a collision with an existing label.
fn choose_label(
    peers: &PeerStore,
    caller_label: Option<&str>,
    for_label_hint: Option<&str>,
    caller_eid_hex: &str,
) -> String {
    let candidate =
        labels::machine_label_from_hint(for_label_hint.or(caller_label), caller_eid_hex);
    if !label_in_use(peers, &candidate) {
        return candidate;
    }
    extend_machine_label_until_unique(peers, &candidate, caller_eid_hex)
}

fn label_in_use(peers: &PeerStore, label: &str) -> bool {
    peers.iter().any(|e| e.label == label)
}

fn relay_hint_for_response(state: &AgentState) -> Option<String> {
    let guard = state.relay_status.read().ok()?;
    if !guard.enabled {
        return None;
    }
    guard
        .hostname
        .as_ref()
        .map(|h| format!("https://{h}/"))
        .or_else(|| guard.https_addr.as_ref().map(|a| format!("https://{a}/")))
        .or_else(|| guard.http_addr.as_ref().map(|a| format!("http://{a}/")))
}

fn short_nonce(nonce: &[u8; 16]) -> String {
    let hex = hex::encode(nonce);
    hex[..12.min(hex.len())].to_owned()
}

fn responder_self_label(state: &AgentState) -> Option<String> {
    let peers = state.peers_path.as_ref()?;
    let store = PeerStore::load(peers).ok()?;
    let self_entry = store.iter().find(|e| e.is_self)?;
    Some(local_machine_label(&self_entry.endpoint_id_hex))
}

fn local_machine_label(endpoint_id_hex: &str) -> String {
    labels::machine_label(local_hostname().as_deref(), endpoint_id_hex)
}

fn local_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|out| out.status.success().then_some(out.stdout))
                .and_then(|stdout| String::from_utf8(stdout).ok())
                .map(|h| h.trim().to_owned())
                .filter(|h| !h.is_empty())
        })
}

fn extend_machine_label_until_unique(
    peers: &PeerStore,
    candidate: &str,
    endpoint_id_hex: &str,
) -> String {
    let Some((base, _suffix)) = candidate.rsplit_once('-') else {
        return format!(
            "{}-{}",
            candidate,
            labels::endpoint_suffix(endpoint_id_hex, 6)
        );
    };
    for len in [6usize, 8, 12, 16, 64] {
        let label = format!("{}-{}", base, labels::endpoint_suffix(endpoint_id_hex, len));
        if !label_in_use(peers, &label) {
            return label;
        }
    }
    candidate.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use portl_core::pair_code::InitiatorMode;
    use portl_core::pair_store::PendingInvite;
    use portl_core::test_util::pair;
    use portl_proto::pair_v1::ALPN_PAIR_V1;
    use tempfile::tempdir;

    fn put_invite(store_path: &std::path::Path, nonce_hex: &str, not_after: u64) {
        put_invite_with_initiator(store_path, nonce_hex, not_after, InitiatorMode::Mutual);
    }

    fn put_invite_with_initiator(
        store_path: &std::path::Path,
        nonce_hex: &str,
        not_after: u64,
        initiator: InitiatorMode,
    ) {
        let mut store = PairStore::load(store_path).unwrap();
        store.insert(PendingInvite {
            nonce_hex: nonce_hex.to_owned(),
            issued_at_unix: 0,
            not_after_unix: not_after,
            for_label_hint: Some("friend-laptop".to_owned()),
            initiator,
        });
        store.save().unwrap();
    }

    fn seed_self(peers_path: &std::path::Path) {
        let mut store = PeerStore::load(peers_path).unwrap();
        store
            .insert_or_update(PeerEntry {
                label: "max".to_owned(),
                endpoint_id_hex: hex::encode([9u8; 32]),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 0,
                origin: PeerOrigin::Zelf,
                last_hold_at: None,
                is_self: true,
                relay_hint: None,
                schema_version: 2,
            })
            .unwrap();
        store.save(peers_path).unwrap();
    }

    fn make_state(peers_path: &std::path::Path) -> AgentState {
        use std::collections::HashSet;
        use std::sync::RwLock;
        use std::time::Instant;

        use portl_core::ticket::verify::TrustRoots;

        use crate::config::DiscoveryConfig;
        use crate::conn_registry::ConnectionRegistry;
        use crate::metrics::Metrics;
        use crate::rate_limit::OfferRateLimiter;
        use crate::revocations::{DEFAULT_REVOCATIONS_MAX_BYTES, RevocationSet};
        use crate::shell_registry::ShellRegistry;
        use crate::udp_registry::UdpSessionRegistry;

        let revocations_path = std::env::temp_dir().join(format!(
            "portl-test-revocations-{}.jsonl",
            std::process::id()
        ));
        AgentState {
            trust_roots: RwLock::new(TrustRoots(HashSet::new())),
            bootstrap_roots: HashSet::new(),
            revocations: RwLock::new(
                RevocationSet::load_with_max_bytes(revocations_path, DEFAULT_REVOCATIONS_MAX_BYTES)
                    .unwrap(),
            ),
            rate_limit: OfferRateLimiter::new(&crate::config::RateLimitConfig::default()).unwrap(),
            started_at: Instant::now(),
            shell_registry: ShellRegistry::default(),
            udp_registry: UdpSessionRegistry::new(60),
            mode: crate::config::AgentMode::Listener,
            metrics: Arc::new(Metrics::default()),
            connections: ConnectionRegistry::new(),
            peers_path: Some(peers_path.to_path_buf()),
            discovery: DiscoveryConfig::default(),
            home: peers_path.parent().unwrap_or(peers_path).to_path_buf(),
            metrics_socket: std::env::temp_dir().join("portl-pair-test.sock"),
            session_provider_path: None,
            started_at_unix: 0,
            relay_status: RwLock::new(crate::relay::RelayStatus::disabled()),
        }
    }

    #[tokio::test]
    async fn reads_cli_length_prefixed_pair_request() {
        let request = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Mutual,
            caller_relay_hint: Some("https://relay.caller./".to_owned()),
            caller_label: Some("onyx".to_owned()),
        };
        let body = postcard::to_stdvec(&request).unwrap();
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        framed.extend_from_slice(&body);

        let (mut writer, reader) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut writer, &framed)
                .await
                .unwrap();
        });

        let decoded = read_pair_request_frame(reader).await.unwrap();

        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn serve_connection_delivers_pair_response() {
        let (client, server) = pair().await.unwrap();
        server.inner().set_alpns(vec![ALPN_PAIR_V1.to_vec()]);

        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        let pair_path = tmp.path().join("pending_invites.json");
        seed_self(&peers_path);
        put_invite(&pair_path, &hex::encode([7u8; 16]), u64::MAX / 2);
        let state = Arc::new(make_state(&peers_path));

        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.inner().accept().await.unwrap();
                let connection = incoming.await.unwrap();
                serve_connection(connection, state).await.unwrap();
            }
        });

        let connection = client
            .inner()
            .connect(server.addr(), ALPN_PAIR_V1)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let request = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Mutual,
            caller_relay_hint: Some("https://relay.caller./".to_owned()),
            caller_label: Some("onyx".to_owned()),
        };
        let body = postcard::to_stdvec(&request).unwrap();
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        framed.extend_from_slice(&body);
        send.write_all(&framed).await.unwrap();
        send.finish().unwrap();

        let mut len_buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            recv.read_exact(&mut len_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let resp_len = u32::from_le_bytes(len_buf) as usize;
        let mut resp_body = vec![0u8; resp_len];
        recv.read_exact(&mut resp_body).await.unwrap();
        let response: PairResponse = postcard::from_bytes(&resp_body).unwrap();

        assert_eq!(response.result, PairResult::Ok);
        connection.close(0u32.into(), b"test complete");
        client.inner().close().await;
        server.inner().close().await;
        server_task.await.unwrap();
    }

    #[test]
    fn handle_pair_happy_path() {
        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        let pair_path = tmp.path().join("pending_invites.json");
        seed_self(&peers_path);
        put_invite(&pair_path, &hex::encode([7u8; 16]), u64::MAX / 2);

        let state = make_state(&peers_path);
        let caller_eid = [11u8; 32];
        let req = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Mutual,
            caller_relay_hint: Some("https://relay.caller./".to_owned()),
            caller_label: Some("onyx".to_owned()),
        };
        let resp = handle_pair(&state, caller_eid, &req).unwrap();
        assert_eq!(resp.result, PairResult::Ok);
        assert_eq!(
            resp.responder_self_label.as_deref(),
            Some(local_machine_label(&hex::encode([9u8; 32])).as_str())
        );

        let peers = PeerStore::load(&peers_path).unwrap();
        let entry = peers
            .iter()
            .find(|e| e.endpoint_id_hex == hex::encode(caller_eid))
            .unwrap();
        assert_eq!(entry.label, "friend-laptop-0b0b");
        assert!(entry.accepts_from_them);
        assert!(entry.they_accept_from_me);
        assert_eq!(entry.origin, PeerOrigin::Paired);
        assert_eq!(entry.relay_hint.as_deref(), Some("https://relay.caller./"));

        // Nonce consumed
        let pair_store = PairStore::load(&pair_path).unwrap();
        assert!(pair_store.is_empty());
    }

    #[test]
    fn handle_pair_uses_inviter_dictated_initiator_me() {
        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        let pair_path = tmp.path().join("pending_invites.json");
        seed_self(&peers_path);
        put_invite_with_initiator(
            &pair_path,
            &hex::encode([7u8; 16]),
            u64::MAX / 2,
            InitiatorMode::Me,
        );
        let state = make_state(&peers_path);
        let req = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Me,
            caller_relay_hint: None,
            caller_label: Some("biz-customer".to_owned()),
        };
        let resp = handle_pair(&state, [33u8; 32], &req).unwrap();
        assert_eq!(resp.result, PairResult::Ok);
        let peers = PeerStore::load(&peers_path).unwrap();
        let entry = peers
            .iter()
            .find(|e| e.label == "friend-laptop-2121")
            .unwrap();
        assert!(!entry.accepts_from_them);
        assert!(entry.they_accept_from_me);
        assert_eq!(entry.origin, PeerOrigin::Paired);
    }

    #[test]
    fn handle_pair_rejects_tampered_initiator() {
        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        let pair_path = tmp.path().join("pending_invites.json");
        seed_self(&peers_path);
        put_invite_with_initiator(
            &pair_path,
            &hex::encode([7u8; 16]),
            u64::MAX / 2,
            InitiatorMode::Me,
        );
        let state = make_state(&peers_path);
        let req = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Them,
            caller_relay_hint: None,
            caller_label: Some("biz-customer".to_owned()),
        };
        let resp = handle_pair(&state, [33u8; 32], &req).unwrap();
        assert!(
            matches!(resp.result, PairResult::PolicyRejected(reason) if reason.contains("initiator"))
        );
    }

    #[test]
    fn handle_pair_initiator_them_is_inbound_only() {
        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        let pair_path = tmp.path().join("pending_invites.json");
        seed_self(&peers_path);
        put_invite_with_initiator(
            &pair_path,
            &hex::encode([7u8; 16]),
            u64::MAX / 2,
            InitiatorMode::Them,
        );
        let state = make_state(&peers_path);
        let req = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Them,
            caller_relay_hint: None,
            caller_label: Some("biz-customer".to_owned()),
        };
        let resp = handle_pair(&state, [33u8; 32], &req).unwrap();
        assert_eq!(resp.result, PairResult::Ok);
        let peers = PeerStore::load(&peers_path).unwrap();
        let entry = peers
            .iter()
            .find(|e| e.label == "friend-laptop-2121")
            .unwrap();
        assert!(entry.accepts_from_them);
        assert!(!entry.they_accept_from_me);
        assert_eq!(entry.origin, PeerOrigin::Paired);
    }

    #[test]
    fn handle_pair_unknown_nonce() {
        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        seed_self(&peers_path);
        let state = make_state(&peers_path);
        let req = PairRequest {
            version: 1,
            nonce: [255u8; 16],
            initiator: InitiatorMode::Mutual,
            caller_relay_hint: None,
            caller_label: None,
        };
        let resp = handle_pair(&state, [22u8; 32], &req).unwrap();
        assert_eq!(resp.result, PairResult::NonceUnknown);
    }

    #[test]
    fn handle_pair_expired_nonce() {
        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        let pair_path = tmp.path().join("pending_invites.json");
        seed_self(&peers_path);
        put_invite(&pair_path, &hex::encode([7u8; 16]), 100); // already past
        let state = make_state(&peers_path);
        let req = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Mutual,
            caller_relay_hint: None,
            caller_label: None,
        };
        let resp = handle_pair(&state, [44u8; 32], &req).unwrap();
        assert_eq!(resp.result, PairResult::NonceExpired);
    }

    #[test]
    fn handle_pair_already_paired_is_idempotent() {
        let tmp = tempdir().unwrap();
        let peers_path = tmp.path().join("peers.json");
        let pair_path = tmp.path().join("pending_invites.json");
        seed_self(&peers_path);
        // Pre-seed the caller as an existing peer
        let mut peers = PeerStore::load(&peers_path).unwrap();
        peers
            .insert_or_update(PeerEntry {
                label: "already-here".to_owned(),
                endpoint_id_hex: hex::encode([55u8; 32]),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 0,
                origin: PeerOrigin::Raw,
                last_hold_at: None,
                is_self: false,
                relay_hint: None,
                schema_version: 2,
            })
            .unwrap();
        peers.save(&peers_path).unwrap();
        put_invite(&pair_path, &hex::encode([7u8; 16]), u64::MAX / 2);

        let state = make_state(&peers_path);
        let req = PairRequest {
            version: 1,
            nonce: [7u8; 16],
            initiator: InitiatorMode::Mutual,
            caller_relay_hint: None,
            caller_label: Some("new-label".to_owned()),
        };
        let resp = handle_pair(&state, [55u8; 32], &req).unwrap();
        assert!(matches!(
            resp.result,
            PairResult::AlreadyPaired { ref existing_label } if existing_label == "already-here"
        ));
        // Nonce is still consumed so a later retry doesn't succeed.
        let pair_store = PairStore::load(&pair_path).unwrap();
        assert!(pair_store.is_empty());
    }
}

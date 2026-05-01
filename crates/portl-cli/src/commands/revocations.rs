//! `portl revocations publish` — best-effort distribution of the local
//! JSONL revocation log to peer agents via the `meta/v1
//! PublishRevocations` request.

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use portl_core::id::store;
use portl_proto::meta_v1::{MetaReq, MetaResp};
use tokio::time::timeout;

/// Matches the agent-side `MAX_PUBLISH_ITEMS` guardrail in
/// `crates/portl-agent/src/meta_handler.rs`.
const MAX_PUBLISH_BATCH: usize = 1000;
/// Wall-clock budget per per-peer publish request.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

use portl_core::ticket::schema::{Capabilities, MetaCaps};

use crate::alias_store::AliasStore;
use crate::commands::peer_resolve::{
    bind_client_endpoint, close_client_endpoint, connect_peer_with_endpoint,
};
use crate::commands::revoke::local_revocations_path;

/// Dispatch for the `publish` subcommand.
pub fn publish(peer: Option<&str>, all_peers: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let peers = resolve_targets(peer, all_peers)?;
        if peers.is_empty() {
            println!("no peers selected; pass --peer <alias> or --all-peers");
            return Ok(ExitCode::SUCCESS);
        }
        let items = load_revocations(&local_revocations_path())?;
        if items.is_empty() {
            println!("no local revocations to publish");
            return Ok(ExitCode::SUCCESS);
        }

        let identity_path = crate::commands::peer_resolve::resolve_identity_path(None);
        let identity = store::load(&identity_path).context("load local identity")?;
        let endpoint = bind_client_endpoint(&identity).await?;

        let mut any_success = false;
        for target in peers {
            match push_to_peer(&target, &identity, &endpoint, &items).await {
                Ok((accepted, rejected)) => {
                    any_success = true;
                    println!("{target}: accepted={accepted} rejected={}", rejected.len());
                    for (ticket, reason) in rejected {
                        println!("  rejected {}: {reason}", hex::encode(&ticket));
                    }
                }
                Err(err) => {
                    tracing::warn!(%err, %target, "publish failed");
                    println!("{target}: failed ({err})");
                }
            }
        }

        close_client_endpoint(endpoint, "revocations publish").await;
        Ok(if any_success {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    })
}

fn resolve_targets(peer: Option<&str>, all_peers: bool) -> Result<Vec<String>> {
    if let Some(peer) = peer {
        return Ok(vec![peer.to_owned()]);
    }
    if !all_peers {
        bail!("exactly one of --peer <name_or_ticket_uri> or --all-peers is required");
    }
    alias_names(&AliasStore::default())
}

pub(crate) fn load_revocations(path: &Path) -> Result<Vec<Vec<u8>>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read revocations from {}", path.display()))?;
    let mut items: Vec<Vec<u8>> = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: portl_agent::revocations::RevocationRecord =
            serde_json::from_str(trimmed).context("parse revocation record")?;
        let bytes = hex::decode(&record.ticket_id).context("decode revocation ticket_id")?;
        items.push(bytes);
    }
    Ok(items)
}

async fn push_to_peer(
    peer: &str,
    identity: &portl_core::id::Identity,
    endpoint: &iroh::Endpoint,
    items: &[Vec<u8>],
) -> Result<(u32, Vec<(Vec<u8>, String)>)> {
    let quiet = false;
    let connected = timeout(
        PUBLISH_TIMEOUT,
        connect_peer_with_endpoint(peer, publish_meta_caps(), identity, endpoint, quiet),
    )
    .await
    .with_context(|| format!("ticket handshake to {peer} timed out"))??;
    let connection = connected.connection.clone();
    let peer_token = connected.session.peer_token;
    let _guard = ConnectionClose {
        connection: connection.clone(),
        reason: b"publish done",
    };

    // Agents cap each PublishRevocations batch at 1000 records. Chunk
    // so operators with thousands of stored revocations can still
    // ship the whole set without exceeding the 64 KiB meta frame.
    let mut accepted_total: u32 = 0;
    let mut rejected_total: Vec<(Vec<u8>, String)> = Vec::new();
    for chunk in items.chunks(MAX_PUBLISH_BATCH) {
        match timeout(
            PUBLISH_TIMEOUT,
            publish_chunk(&connection, peer_token, chunk),
        )
        .await
        {
            Ok(Ok((accepted, rejected))) => {
                accepted_total = accepted_total.saturating_add(accepted);
                rejected_total.extend(rejected);
            }
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(anyhow!("publish request to {peer} timed out")),
        }
    }
    Ok((accepted_total, rejected_total))
}

async fn publish_chunk(
    connection: &iroh::endpoint::Connection,
    peer_token: [u8; 16],
    items: &[Vec<u8>],
) -> Result<(u32, Vec<(Vec<u8>, String)>)> {
    let (mut send, mut recv) = connection.open_bi().await.context("open meta/v1 stream")?;

    let preamble = portl_core::wire::StreamPreamble {
        peer_token,
        alpn: String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1).into_owned(),
    };
    let pre_bytes = postcard::to_stdvec(&preamble).context("encode preamble")?;
    send.write_all(&pre_bytes).await.context("write preamble")?;

    let req = MetaReq::PublishRevocations {
        items: items.to_vec(),
    };
    let req_bytes = postcard::to_stdvec(&req).context("encode publish request")?;
    send.write_all(&req_bytes)
        .await
        .context("write publish request")?;
    send.finish().context("finish publish request")?;

    let raw = recv
        .read_to_end(64 * 1024)
        .await
        .context("read publish response")?;
    let resp: MetaResp = postcard::from_bytes(&raw).context("decode publish response")?;
    match resp {
        MetaResp::PublishedRevocations { accepted, rejected } => Ok((accepted, rejected)),
        MetaResp::Error(err) => Err(anyhow!("peer returned error: {}", err.message)),
        other => Err(anyhow!("unexpected response: {other:?}")),
    }
}

struct ConnectionClose {
    connection: iroh::endpoint::Connection,
    reason: &'static [u8],
}

impl Drop for ConnectionClose {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), self.reason);
    }
}

fn publish_meta_caps() -> Capabilities {
    // We need meta/v1 Info/Ping-style access plus the PublishRevocations
    // permission. Agents currently gate PublishRevocations on session
    // existence alone, but requesting the meta cap lets the CLI dial
    // agents that scope meta narrowly via their delegation.
    Capabilities {
        presence: 0b0010_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: Some(MetaCaps {
            ping: true,
            info: true,
        }),
    }
}

fn alias_names(store: &AliasStore) -> Result<Vec<String>> {
    Ok(store.list()?.into_iter().map(|alias| alias.name).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use portl_agent::revocations::{RevocationRecord, append_record};
    use tempfile::tempdir;

    #[test]
    fn load_revocations_returns_items() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("revocations.jsonl");
        append_record(
            &path,
            &RevocationRecord::new([1u8; 16], "test", 42, Some(100)),
        )
        .unwrap();
        let items = load_revocations(&path).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].len(), 16);
        assert_eq!(items[0][0], 1);
    }

    #[test]
    fn load_revocations_on_missing_file_is_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.jsonl");
        let items = load_revocations(&path).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn resolve_targets_requires_flag() {
        let err = resolve_targets(None, false).unwrap_err();
        assert!(err.to_string().contains("--peer"));
    }

    #[test]
    fn resolve_targets_with_peer() {
        let v = resolve_targets(Some("foo"), false).unwrap();
        assert_eq!(v, vec!["foo"]);
    }
}

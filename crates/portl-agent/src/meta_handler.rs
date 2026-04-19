use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use tracing::instrument;

use crate::AgentState;
use crate::session::Session;
use crate::stream_io::BufferedRecv;

const MAX_META_BYTES: usize = 64 * 1024;

#[instrument(skip_all)]
pub(crate) async fn serve_stream(
    connection: Connection,
    session: Session,
    state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    if preamble.peer_token != session.peer_token
        || preamble.alpn != String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1)
    {
        connection.close(0x1001u32.into(), b"policy denied");
        bail!("policy denied");
    }

    let req = recv
        .read_frame::<portl_proto::meta_v1::MetaReq>(MAX_META_BYTES)
        .await?
        .context("missing meta request")?;

    let response = match req {
        portl_proto::meta_v1::MetaReq::Ping { .. } => {
            if meta_caps(&session).is_some_and(|caps| caps.ping) {
                portl_proto::meta_v1::MetaResp::Pong {
                    t_server_us: unix_now_micros()?,
                }
            } else {
                cap_denied("meta ping not allowed")
            }
        }
        portl_proto::meta_v1::MetaReq::Info => {
            if meta_caps(&session).is_some_and(|caps| caps.info) {
                portl_proto::meta_v1::MetaResp::Info {
                    agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                    supported_alpns: vec![
                        String::from_utf8_lossy(portl_proto::ticket_v1::ALPN_TICKET_V1).into(),
                        String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1).into(),
                        String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1).into(),
                        String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1).into(),
                        String::from_utf8_lossy(portl_proto::udp_v1::ALPN_UDP_V1).into(),
                    ],
                    uptime_s: state.started_at.elapsed().as_secs(),
                    hostname: hostname(),
                    os: std::env::consts::OS.to_owned(),
                    tags: Vec::new(),
                }
            } else {
                cap_denied("meta info not allowed")
            }
        }
        portl_proto::meta_v1::MetaReq::PublishRevocations { items } => {
            publish_revocations(&state, &session, items).await
        }
    };

    let encoded = postcard::to_stdvec(&response).context("encode meta response")?;
    send.write_all(&encoded)
        .await
        .context("write meta response")?;
    send.finish().context("finish meta response")?;
    Ok(())
}

fn meta_caps(session: &Session) -> Option<&portl_core::ticket::schema::MetaCaps> {
    session.caps.meta.as_ref()
}

/// Per-design (`070-security.md §10.9`) max records a single
/// `PublishRevocations` request may carry.
const MAX_PUBLISH_ITEMS: usize = 1000;

async fn publish_revocations(
    state: &Arc<AgentState>,
    session: &Session,
    items: Vec<Vec<u8>>,
) -> portl_proto::meta_v1::MetaResp {
    // Authorization: requires that the caller's ticket granted the
    // `meta.info` capability. `meta.info` is the closest v0.1 cap
    // that exposes operator-level meta functionality; narrower
    // delegates (e.g. shell-only) must NOT be able to mutate the
    // revocation set. A future ticket schema bump will add a
    // dedicated `meta.publish_revocations` bit.
    if !meta_caps(session).is_some_and(|caps| caps.info) {
        return cap_denied("publish revocations requires meta.info capability");
    }

    if items.len() > MAX_PUBLISH_ITEMS {
        return portl_proto::meta_v1::MetaResp::Error(portl_proto::error::Error {
            kind: portl_proto::error::ErrorKind::RateLimited,
            message: format!(
                "batch exceeds {MAX_PUBLISH_ITEMS} records; split into smaller requests"
            ),
            retry_after_ms: Some(1_000),
        });
    }

    let now = match unix_now_secs() {
        Ok(value) => value,
        Err(err) => {
            return portl_proto::meta_v1::MetaResp::Error(portl_proto::error::Error {
                kind: portl_proto::error::ErrorKind::InternalError,
                message: format!("unix time unavailable: {err}"),
                retry_after_ms: None,
            });
        }
    };

    let mut accepted: u32 = 0;
    let mut rejected: Vec<(Vec<u8>, String)> = Vec::new();
    let caller_hex = hex::encode(session.caller_endpoint_id);

    // Build the new records under the write lock, release the lock,
    // then fsync off the runtime.
    let (to_persist, persist_path) = {
        let mut revocations = state
            .revocations
            .write()
            .expect("revocations lock poisoned");
        for raw in items {
            let Ok(id) = <[u8; 16]>::try_from(raw.as_slice()) else {
                rejected.push((raw, "ticket_id must be 16 bytes".to_owned()));
                continue;
            };
            if revocations.contains(&id) {
                accepted += 1;
                continue;
            }
            revocations.insert_record(crate::revocations::RevocationRecord::new(
                id,
                format!("meta_publish_from_{caller_hex}"),
                now,
                None,
            ));
            accepted += 1;
        }
        (
            revocations.snapshot(),
            revocations.file_path().to_path_buf(),
        )
    };

    // Persist off the async task so a slow fsync doesn't stall the
    // ticket acceptance pipeline (which reads the same RwLock).
    let persist_result = tokio::task::spawn_blocking(move || {
        crate::revocations::write_jsonl(&persist_path, &to_persist)
    })
    .await;
    match persist_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(?err, "persist revocations after publish");
            return portl_proto::meta_v1::MetaResp::Error(portl_proto::error::Error {
                kind: portl_proto::error::ErrorKind::InternalError,
                message: format!("persist revocations: {err}"),
                retry_after_ms: None,
            });
        }
        Err(join_err) => {
            tracing::warn!(?join_err, "persist revocations task panicked");
            return portl_proto::meta_v1::MetaResp::Error(portl_proto::error::Error {
                kind: portl_proto::error::ErrorKind::InternalError,
                message: "persist revocations task panicked".to_owned(),
                retry_after_ms: None,
            });
        }
    }

    portl_proto::meta_v1::MetaResp::PublishedRevocations { accepted, rejected }
}

fn unix_now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

fn cap_denied(message: &str) -> portl_proto::meta_v1::MetaResp {
    portl_proto::meta_v1::MetaResp::Error(portl_proto::error::Error {
        kind: portl_proto::error::ErrorKind::CapDenied,
        message: message.to_owned(),
        retry_after_ms: None,
    })
}

fn unix_now_micros() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_micros()
        .try_into()
        .context("micros overflow u64")
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

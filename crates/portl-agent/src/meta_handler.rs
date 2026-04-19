use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::AgentState;
use crate::session::Session;

const MAX_META_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MetaEnvelope {
    preamble: portl_proto::wire::StreamPreamble,
    req: portl_proto::meta_v1::MetaReq,
}

#[instrument(skip_all)]
pub(crate) async fn serve_stream(
    connection: &Connection,
    session: &Session,
    state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let bytes = recv
        .read_to_end(MAX_META_BYTES)
        .await
        .context("read meta request")?;
    let envelope: MetaEnvelope = postcard::from_bytes(&bytes).context("decode meta envelope")?;

    if envelope.preamble.peer_token != session.peer_token
        || envelope.preamble.alpn != String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1)
    {
        connection.close(0x1001u32.into(), b"policy denied");
        return Ok(());
    }

    let response = match envelope.req {
        portl_proto::meta_v1::MetaReq::Ping { .. } => {
            if !meta_caps(session).is_some_and(|caps| caps.ping) {
                cap_denied("meta ping not allowed")
            } else {
                portl_proto::meta_v1::MetaResp::Pong {
                    t_server_us: unix_now_micros()?,
                }
            }
        }
        portl_proto::meta_v1::MetaReq::Info => {
            if !meta_caps(session).is_some_and(|caps| caps.info) {
                cap_denied("meta info not allowed")
            } else {
                portl_proto::meta_v1::MetaResp::Info {
                    agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                    supported_alpns: vec![
                        String::from_utf8_lossy(portl_proto::ticket_v1::ALPN_TICKET_V1).into(),
                        String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1).into(),
                    ],
                    uptime_s: state.started_at.elapsed().as_secs(),
                    hostname: hostname(),
                    os: std::env::consts::OS.to_owned(),
                    tags: Vec::new(),
                }
            }
        }
        portl_proto::meta_v1::MetaReq::PublishRevocations { .. } => {
            portl_proto::meta_v1::MetaResp::Error(portl_proto::error::Error {
                kind: portl_proto::error::ErrorKind::InternalError,
                message: "not yet implemented".to_owned(),
                retry_after_ms: None,
            })
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

fn cap_denied(message: &str) -> portl_proto::meta_v1::MetaResp {
    portl_proto::meta_v1::MetaResp::Error(portl_proto::error::Error {
        kind: portl_proto::error::ErrorKind::CapDenied,
        message: message.to_owned(),
        retry_after_ms: None,
    })
}

fn unix_now_micros() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_micros()
        .try_into()
        .context("micros overflow u64")?)
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

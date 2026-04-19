use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};

use crate::caps_enforce::udp_permits;
use crate::session::Session;
use crate::stream_io::BufferedRecv;
use crate::udp_registry::UdpSessionRegistry;

const MAX_UDP_CTL_REQ_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct UdpConnectionContext {
    registry: UdpSessionRegistry,
    datagram_pump_started: AtomicBool,
}

impl UdpConnectionContext {
    pub(crate) fn new(registry: UdpSessionRegistry) -> Self {
        Self {
            registry,
            datagram_pump_started: AtomicBool::new(false),
        }
    }

    fn ensure_datagram_pump(self: &Arc<Self>, connection: Connection) {
        if self.datagram_pump_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let context = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(err) = context.datagram_pump(connection).await {
                tracing::debug!(%err, "udp datagram pump stopped");
            }
        });
    }

    async fn datagram_pump(self: Arc<Self>, connection: Connection) -> Result<()> {
        loop {
            let bytes = connection
                .read_datagram()
                .await
                .context("read udp datagram")?;
            let datagram: portl_proto::udp_v1::UdpDatagram =
                match postcard::from_bytes(&bytes).context("decode udp datagram") {
                    Ok(datagram) => datagram,
                    Err(err) => {
                        tracing::debug!(%err, "dropping invalid udp datagram");
                        continue;
                    }
                };
            let Some(session) = self.registry.get_live(datagram.session_id).await? else {
                continue;
            };
            if bytes.len() > portl_proto::udp_v1::MAX_UDP_DATAGRAM_BYTES {
                session
                    .send_error(datagram.target_port, datagram.src_tag, "payload too large")
                    .await?;
                continue;
            }
            if let Err(err) = session.route_to_target(&datagram).await {
                session
                    .send_error(datagram.target_port, datagram.src_tag, &err.to_string())
                    .await?;
            }
        }
    }
}

pub(crate) async fn serve_stream(
    connection: Connection,
    session: Session,
    _state: Arc<crate::AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
    connection_ctx: Arc<UdpConnectionContext>,
) -> Result<()> {
    let body = recv
        .read_frame::<portl_proto::udp_v1::UdpCtlReqTail>(MAX_UDP_CTL_REQ_BYTES)
        .await?
        .context("missing udp control request")?;
    let req = portl_proto::udp_v1::UdpCtlReq::new(preamble, body);

    if req.preamble.peer_token != session.peer_token
        || req.preamble.alpn != String::from_utf8_lossy(portl_proto::udp_v1::ALPN_UDP_V1)
    {
        bail!("invalid udp preamble");
    }
    if req.binds.is_empty() {
        reject(
            &mut send,
            req.session_id,
            "at least one udp bind is required",
        )
        .await?;
        return Ok(());
    }
    for bind in &req.binds {
        if let Err(error) = udp_permits(&session.caps, bind) {
            reject(&mut send, req.session_id, error).await?;
            return Ok(());
        }
    }

    let udp_session = connection_ctx
        .registry
        .attach_or_create(req.session_id, req.binds.clone(), connection.clone())
        .await?;
    send.write_all(&postcard::to_stdvec(&portl_proto::udp_v1::UdpCtlResp {
        ok: true,
        error: None,
        session_id: udp_session.session_id(),
    })?)
    .await
    .context("write udp control response")?;
    send.finish().context("finish udp control response")?;

    connection_ctx.ensure_datagram_pump(connection.clone());

    let connection_id = connection.stable_id();
    let _control_lifecycle = tokio::io::copy(&mut recv, &mut tokio::io::sink()).await;
    connection_ctx
        .registry
        .mark_linger_if_current(udp_session.session_id(), connection_id)
        .await?;
    Ok(())
}

async fn reject(send: &mut SendStream, session_id: [u8; 8], error: &str) -> Result<()> {
    send.write_all(&postcard::to_stdvec(&portl_proto::udp_v1::UdpCtlResp {
        ok: false,
        error: Some(error.to_owned()),
        session_id,
    })?)
    .await
    .context("write rejected udp control response")?;
    send.finish()
        .context("finish rejected udp control response")?;
    Ok(())
}

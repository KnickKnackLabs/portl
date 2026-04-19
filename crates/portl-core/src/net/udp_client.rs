use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use iroh::endpoint::{Connection, SendStream};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::wire::StreamPreamble;
use crate::wire::udp::{
    ALPN_UDP_V1, MAX_UDP_DATAGRAM_BYTES, UdpBind, UdpCtlReq, UdpCtlReqTail, UdpCtlResp,
    UdpDatagram, encode_datagram, udp_error_payload,
};

use super::PeerSession;

const MAX_UDP_CTL_RESP_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct UdpControl {
    pub session_id: [u8; 8],
    send: SendStream,
}

impl UdpControl {
    pub fn close(mut self) -> Result<()> {
        self.send.finish().context("finish udp control stream")
    }
}

#[derive(Debug)]
pub struct LocalUdpForwardHandle {
    local_socket: Arc<UdpSocket>,
    src_tags: Arc<Mutex<HashMap<SocketAddr, u32>>>,
    reverse_index: Arc<Mutex<HashMap<u32, SocketAddr>>>,
    next_src_tag: Arc<Mutex<u32>>,
    session_id: Arc<Mutex<Option<[u8; 8]>>>,
}

impl LocalUdpForwardHandle {
    pub async fn bind(local_addr: &str) -> Result<Self> {
        Ok(Self {
            local_socket: Arc::new(
                UdpSocket::bind(local_addr)
                    .await
                    .with_context(|| format!("bind local udp socket on {local_addr}"))?,
            ),
            src_tags: Arc::new(Mutex::new(HashMap::new())),
            reverse_index: Arc::new(Mutex::new(HashMap::new())),
            next_src_tag: Arc::new(Mutex::new(1)),
            session_id: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn session_id(&self) -> Option<[u8; 8]> {
        *self.session_id.lock().await
    }

    pub async fn run_with_control(
        &self,
        connection: Connection,
        control: UdpControl,
        target_port: u16,
    ) -> Result<()> {
        let session_id = control.session_id;
        *self.session_id.lock().await = Some(session_id);

        let upstream = upstream_loop(
            connection.clone(),
            Arc::clone(&self.local_socket),
            Arc::clone(&self.src_tags),
            Arc::clone(&self.reverse_index),
            Arc::clone(&self.next_src_tag),
            session_id,
            target_port,
        );
        let reverse = reverse_loop(
            connection,
            Arc::clone(&self.local_socket),
            Arc::clone(&self.reverse_index),
            session_id,
        );

        tokio::select! {
            result = upstream => {
                drop(control);
                result
            }
            result = reverse => {
                drop(control);
                result
            }
        }
    }
}

pub async fn open_udp(
    connection: &Connection,
    session: &PeerSession,
    requested_session_id: Option<[u8; 8]>,
    binds: Vec<UdpBind>,
) -> Result<UdpControl> {
    let req = UdpCtlReq::new(
        StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(ALPN_UDP_V1).into_owned(),
        },
        UdpCtlReqTail {
            session_id: requested_session_id.unwrap_or_default(),
            binds,
        },
    );
    let (mut send, mut recv) = connection.open_bi().await.context("open udp stream")?;
    send.write_all(&postcard::to_stdvec(&req).context("encode udp control request")?)
        .await
        .context("write udp control request")?;

    let ack_bytes = recv
        .read_to_end(MAX_UDP_CTL_RESP_BYTES)
        .await
        .context("read udp control response")?;
    let ack: UdpCtlResp =
        postcard::from_bytes(&ack_bytes).context("decode udp control response")?;
    if !ack.ok {
        bail!(
            "udp request rejected: {}",
            ack.error.unwrap_or_else(|| "unknown error".to_owned())
        );
    }

    Ok(UdpControl {
        session_id: ack.session_id,
        send,
    })
}

pub async fn run_local_forward(
    connection: Connection,
    control: UdpControl,
    local_addr: &str,
    target_port: u16,
) -> Result<()> {
    let handle = LocalUdpForwardHandle::bind(local_addr).await?;
    handle
        .run_with_control(connection, control, target_port)
        .await
}

async fn upstream_loop(
    connection: Connection,
    local_socket: Arc<UdpSocket>,
    src_tags: Arc<Mutex<HashMap<SocketAddr, u32>>>,
    reverse_index: Arc<Mutex<HashMap<u32, SocketAddr>>>,
    next_src_tag: Arc<Mutex<u32>>,
    session_id: [u8; 8],
    target_port: u16,
) -> Result<()> {
    let mut buf = vec![0_u8; 64 * 1024];

    loop {
        let (read, from) = local_socket
            .recv_from(&mut buf)
            .await
            .context("receive local udp datagram")?;

        let src_tag = {
            let mut src_tags = src_tags.lock().await;
            if let Some(src_tag) = src_tags.get(&from).copied() {
                src_tag
            } else {
                let allocated = allocate_src_tag(&next_src_tag, &reverse_index).await;
                src_tags.insert(from, allocated);
                reverse_index.lock().await.insert(allocated, from);
                allocated
            }
        };

        let datagram = UdpDatagram {
            session_id,
            target_port,
            src_tag,
            payload: buf[..read].to_vec(),
        };
        let encoded = match encode_datagram(&datagram) {
            Ok(encoded) if encoded.len() <= MAX_UDP_DATAGRAM_BYTES => encoded,
            Ok(_) => {
                local_socket
                    .send_to(&udp_error_payload("payload too large"), from)
                    .await
                    .context("send local udp oversize error")?;
                continue;
            }
            Err(err) => {
                local_socket
                    .send_to(&udp_error_payload(&format!("encode failed: {err}")), from)
                    .await
                    .context("send local udp encode error")?;
                continue;
            }
        };

        connection
            .send_datagram_wait(Bytes::from(encoded))
            .await
            .context("send udp datagram")?;
    }
}

async fn reverse_loop(
    connection: Connection,
    local_socket: Arc<UdpSocket>,
    reverse_index: Arc<Mutex<HashMap<u32, SocketAddr>>>,
    session_id: [u8; 8],
) -> Result<()> {
    loop {
        let bytes = connection
            .read_datagram()
            .await
            .context("read udp datagram")?;
        let datagram: UdpDatagram = match postcard::from_bytes::<UdpDatagram>(&bytes) {
            Ok(datagram) if datagram.session_id == session_id => datagram,
            Ok(_) | Err(_) => continue,
        };
        let Some(to) = reverse_index.lock().await.get(&datagram.src_tag).copied() else {
            continue;
        };
        local_socket
            .send_to(&datagram.payload, to)
            .await
            .context("send udp payload to local app")?;
    }
}

async fn allocate_src_tag(
    next_src_tag: &Arc<Mutex<u32>>,
    reverse_index: &Arc<Mutex<HashMap<u32, SocketAddr>>>,
) -> u32 {
    loop {
        let candidate = {
            let mut next_src_tag_guard = next_src_tag.lock().await;
            let candidate = (*next_src_tag_guard).max(1);
            let next = candidate.wrapping_add(1);
            *next_src_tag_guard = if next == 0 { 1 } else { next };
            candidate
        };
        if !reverse_index.lock().await.contains_key(&candidate) {
            return candidate;
        }
    }
}

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

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
pub const CLIENT_MAX_SRC_TAGS: usize = 4096;

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
    src_tags: Arc<Mutex<SrcTagTable>>,
    session_id: Arc<Mutex<Option<[u8; 8]>>>,
}

#[derive(Debug)]
struct SrcTagTable {
    by_addr: HashMap<SocketAddr, SrcTagEntry>,
    by_tag: HashMap<u32, SocketAddr>,
    next_src_tag: u32,
}

#[derive(Debug, Clone, Copy)]
struct SrcTagEntry {
    src_tag: u32,
    last_used: Instant,
}

impl LocalUdpForwardHandle {
    pub async fn bind(local_addr: &str) -> Result<Self> {
        Ok(Self {
            local_socket: Arc::new(
                UdpSocket::bind(local_addr)
                    .await
                    .with_context(|| format!("bind local udp socket on {local_addr}"))?,
            ),
            src_tags: Arc::new(Mutex::new(SrcTagTable::default())),
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
            session_id,
            target_port,
        );
        let reverse = reverse_loop(
            connection,
            Arc::clone(&self.local_socket),
            Arc::clone(&self.src_tags),
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
    src_tags: Arc<Mutex<SrcTagTable>>,
    session_id: [u8; 8],
    target_port: u16,
) -> Result<()> {
    let mut buf = vec![0_u8; 64 * 1024];

    loop {
        let (read, from) = local_socket
            .recv_from(&mut buf)
            .await
            .context("receive local udp datagram")?;
        let src_tag = src_tags.lock().await.touch_or_insert(from);

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
    src_tags: Arc<Mutex<SrcTagTable>>,
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
        let Some(to) = src_tags.lock().await.touch_by_tag(datagram.src_tag) else {
            continue;
        };
        local_socket
            .send_to(&datagram.payload, to)
            .await
            .context("send udp payload to local app")?;
    }
}

impl Default for SrcTagTable {
    fn default() -> Self {
        Self {
            by_addr: HashMap::new(),
            by_tag: HashMap::new(),
            next_src_tag: 1,
        }
    }
}

impl SrcTagTable {
    fn touch_or_insert(&mut self, addr: SocketAddr) -> u32 {
        if let Some(entry) = self.by_addr.get_mut(&addr) {
            entry.last_used = Instant::now();
            return entry.src_tag;
        }

        if self.by_addr.len() >= CLIENT_MAX_SRC_TAGS
            && let Some(oldest_addr) = self
                .by_addr
                .iter()
                .min_by_key(|entry| entry.1.last_used)
                .map(|entry| *entry.0)
            && let Some(evicted) = self.by_addr.remove(&oldest_addr)
        {
            self.by_tag.remove(&evicted.src_tag);
        }

        let src_tag = self.allocate_src_tag();
        self.by_addr.insert(
            addr,
            SrcTagEntry {
                src_tag,
                last_used: Instant::now(),
            },
        );
        self.by_tag.insert(src_tag, addr);
        src_tag
    }

    fn touch_by_tag(&mut self, src_tag: u32) -> Option<SocketAddr> {
        let addr = self.by_tag.get(&src_tag).copied()?;
        if let Some(entry) = self.by_addr.get_mut(&addr) {
            entry.last_used = Instant::now();
        }
        Some(addr)
    }

    fn allocate_src_tag(&mut self) -> u32 {
        loop {
            let candidate = self.next_src_tag.max(1);
            let next = candidate.wrapping_add(1);
            self.next_src_tag = if next == 0 { 1 } else { next };
            if !self.by_tag.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{CLIENT_MAX_SRC_TAGS, SrcTagTable};

    #[test]
    fn client_src_tag_lru_evicts_oldest_entry() {
        let mut table = SrcTagTable::default();
        let first = std::net::SocketAddr::from(([127, 0, 0, 1], 1000));
        let second = std::net::SocketAddr::from(([127, 0, 0, 1], 1001));

        let first_tag = table.touch_or_insert(first);
        std::thread::sleep(Duration::from_millis(1));
        let second_tag = table.touch_or_insert(second);
        table
            .by_addr
            .get_mut(&first)
            .expect("first entry")
            .last_used = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .expect("backdate");
        table
            .by_addr
            .get_mut(&second)
            .expect("second entry")
            .last_used = Instant::now();

        table.by_addr.reserve(CLIENT_MAX_SRC_TAGS);
        for offset in 2..=CLIENT_MAX_SRC_TAGS {
            let port =
                u16::try_from(1000 + offset).expect("synthetic port fits in u16 for test range");
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            table.touch_or_insert(addr);
        }

        assert!(table.touch_by_tag(first_tag).is_none());
        assert_eq!(table.touch_by_tag(second_tag), Some(second));
    }
}

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use dashmap::DashMap;
use iroh::endpoint::Connection;
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use portl_proto::udp_v1::{
    MAX_UDP_DATAGRAM_BYTES, UdpBind, UdpDatagram, encode_datagram, udp_error_payload,
};

pub(crate) const DEFAULT_UDP_SESSION_LINGER_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub(crate) struct UdpSessionRegistry {
    inner: Arc<UdpSessionRegistryInner>,
}

#[derive(Debug)]
struct UdpSessionRegistryInner {
    linger_secs: u64,
    sessions: DashMap<[u8; 8], Arc<UdpSession>>,
}

#[derive(Debug)]
pub(crate) struct UdpSession {
    session_id: [u8; 8],
    socket: Arc<UdpSocket>,
    cancel: CancellationToken,
    inner: Mutex<UdpSessionInner>,
}

#[derive(Debug)]
struct UdpSessionInner {
    binds: Vec<ResolvedUdpBind>,
    connection: Option<Connection>,
    connection_id: Option<usize>,
    linger_until: Option<u64>,
    src_to_peer: HashMap<u32, SocketAddr>,
    peer_to_src: HashMap<SocketAddr, u32>,
}

#[derive(Debug, Clone)]
struct ResolvedUdpBind {
    bind: UdpBind,
    target_ip: IpAddr,
}

impl UdpSessionRegistry {
    pub(crate) fn new(linger_secs: u64) -> Self {
        Self {
            inner: Arc::new(UdpSessionRegistryInner {
                linger_secs,
                sessions: DashMap::new(),
            }),
        }
    }

    pub(crate) async fn attach_or_create(
        &self,
        requested_session_id: [u8; 8],
        binds: Vec<UdpBind>,
        connection: Connection,
    ) -> Result<Arc<UdpSession>> {
        if requested_session_id != [0; 8]
            && let Some(session) = self.get_live(requested_session_id).await?
        {
            session.reattach(connection, binds).await?;
            return Ok(session);
        }

        let session_id = self.allocate_session_id();
        let session = Arc::new(UdpSession::new(session_id, binds, connection).await?);
        self.inner.sessions.insert(session_id, Arc::clone(&session));
        session.spawn_reply_loop();
        Ok(session)
    }

    pub(crate) async fn get_live(&self, session_id: [u8; 8]) -> Result<Option<Arc<UdpSession>>> {
        let Some(session) = self
            .inner
            .sessions
            .get(&session_id)
            .map(|entry| Arc::clone(entry.value()))
        else {
            return Ok(None);
        };

        if session.is_expired(unix_now_secs()?).await {
            self.remove_session(session_id);
            return Ok(None);
        }

        Ok(Some(session))
    }

    pub(crate) async fn mark_linger_if_current(
        &self,
        session_id: [u8; 8],
        connection_id: usize,
    ) -> Result<()> {
        if let Some(session) = self.get_live(session_id).await? {
            session
                .mark_linger_if_current(connection_id, unix_now_secs()? + self.inner.linger_secs)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn gc_expired(&self) -> Result<()> {
        let now = unix_now_secs()?;
        let sessions = self
            .inner
            .sessions
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect::<Vec<_>>();
        for (session_id, session) in sessions {
            if session.is_expired(now).await {
                self.remove_session(session_id);
            }
        }
        Ok(())
    }

    fn allocate_session_id(&self) -> [u8; 8] {
        loop {
            let session_id = rand::random::<[u8; 8]>();
            if session_id != [0; 8] && !self.inner.sessions.contains_key(&session_id) {
                return session_id;
            }
        }
    }

    fn remove_session(&self, session_id: [u8; 8]) {
        if let Some((_, session)) = self.inner.sessions.remove(&session_id) {
            session.cancel();
        }
    }
}

impl UdpSession {
    async fn new(session_id: [u8; 8], binds: Vec<UdpBind>, connection: Connection) -> Result<Self> {
        Ok(Self {
            session_id,
            socket: Arc::new(
                UdpSocket::bind(("0.0.0.0", 0))
                    .await
                    .context("bind udp session socket")?,
            ),
            cancel: CancellationToken::new(),
            inner: Mutex::new(UdpSessionInner {
                binds: resolve_binds(&binds).await?,
                connection: Some(connection.clone()),
                connection_id: Some(connection.stable_id()),
                linger_until: None,
                src_to_peer: HashMap::new(),
                peer_to_src: HashMap::new(),
            }),
        })
    }

    pub(crate) fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    pub(crate) async fn reattach(&self, connection: Connection, binds: Vec<UdpBind>) -> Result<()> {
        let resolved = resolve_binds(&binds).await?;
        let mut inner = self.inner.lock().await;
        inner.binds = resolved;
        inner.connection = Some(connection.clone());
        inner.connection_id = Some(connection.stable_id());
        inner.linger_until = None;
        Ok(())
    }

    pub(crate) async fn route_to_target(&self, datagram: &UdpDatagram) -> Result<()> {
        let target = {
            let mut inner = self.inner.lock().await;
            let target = inner
                .binds
                .iter()
                .find(|bind| {
                    bind.bind.target_port_range.0 <= datagram.target_port
                        && datagram.target_port <= bind.bind.target_port_range.1
                })
                .map(|bind| SocketAddr::from((bind.target_ip, datagram.target_port)))
                .ok_or_else(|| anyhow!("target port {} is not bound", datagram.target_port))?;
            inner.src_to_peer.insert(datagram.src_tag, target);
            inner.peer_to_src.insert(target, datagram.src_tag);
            target
        };

        self.socket
            .send_to(&datagram.payload, target)
            .await
            .with_context(|| format!("send udp payload to {target}"))?;
        Ok(())
    }

    pub(crate) async fn send_reply(&self, peer: SocketAddr, payload: Vec<u8>) -> Result<()> {
        let (src_tag, connection) = {
            let inner = self.inner.lock().await;
            let Some(src_tag) = inner.peer_to_src.get(&peer).copied() else {
                return Ok(());
            };
            let Some(connection) = inner.connection.clone() else {
                return Ok(());
            };
            (src_tag, connection)
        };

        let datagram = UdpDatagram {
            session_id: self.session_id,
            target_port: peer.port(),
            src_tag,
            payload,
        };
        self.send_to_client(connection, datagram).await
    }

    pub(crate) async fn send_error(
        &self,
        target_port: u16,
        src_tag: u32,
        message: &str,
    ) -> Result<()> {
        let connection = {
            let inner = self.inner.lock().await;
            inner.connection.clone()
        };
        let Some(connection) = connection else {
            return Ok(());
        };
        let datagram = UdpDatagram {
            session_id: self.session_id,
            target_port,
            src_tag,
            payload: udp_error_payload(message),
        };
        self.send_to_client(connection, datagram).await
    }

    pub(crate) async fn mark_linger_if_current(&self, connection_id: usize, linger_until: u64) {
        let mut inner = self.inner.lock().await;
        if inner.connection_id == Some(connection_id) {
            inner.connection = None;
            inner.connection_id = None;
            inner.linger_until = Some(linger_until);
        }
    }

    pub(crate) async fn is_expired(&self, now: u64) -> bool {
        self.inner
            .lock()
            .await
            .linger_until
            .is_some_and(|deadline| deadline <= now)
    }

    pub(crate) fn spawn_reply_loop(self: &Arc<Self>) {
        let session = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 64 * 1024];
            loop {
                tokio::select! {
                    biased;
                    () = session.cancel.cancelled() => break,
                    result = session.socket.recv_from(&mut buf) => {
                        let (read, peer) = match result {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::debug!(%err, session_id = %hex::encode(session.session_id), "udp session recv loop stopped");
                                break;
                            }
                        };
                        if let Err(err) = session.send_reply(peer, buf[..read].to_vec()).await {
                            tracing::debug!(%err, session_id = %hex::encode(session.session_id), "udp session reply failed");
                        }
                    }
                }
            }
        });
    }

    pub(crate) fn cancel(&self) {
        self.cancel.cancel();
    }

    async fn send_to_client(&self, connection: Connection, datagram: UdpDatagram) -> Result<()> {
        let encoded = match encode_datagram(&datagram) {
            Ok(encoded) if encoded.len() <= MAX_UDP_DATAGRAM_BYTES => encoded,
            Ok(_) => encode_datagram(&UdpDatagram {
                payload: udp_error_payload("payload too large"),
                ..datagram
            })
            .context("encode udp oversize error")?,
            Err(err) => encode_datagram(&UdpDatagram {
                payload: udp_error_payload(&format!("encode failed: {err}")),
                ..datagram
            })
            .context("encode udp encode-error reply")?,
        };
        connection
            .send_datagram_wait(Bytes::from(encoded))
            .await
            .context("send udp reply datagram")?;
        Ok(())
    }
}

async fn resolve_binds(binds: &[UdpBind]) -> Result<Vec<ResolvedUdpBind>> {
    let mut resolved = Vec::with_capacity(binds.len());
    for bind in binds {
        let target_ip = lookup_host((bind.target_host.as_str(), bind.target_port_range.0))
            .await
            .with_context(|| format!("resolve udp target {}", bind.target_host))?
            .map(|addr| match addr {
                SocketAddr::V4(addr) => IpAddr::V4(*addr.ip()),
                SocketAddr::V6(addr) => IpAddr::V6(*addr.ip()),
            })
            .next()
            .with_context(|| format!("no socket addresses resolved for {}", bind.target_host))?;
        resolved.push(ResolvedUdpBind {
            bind: bind.clone(),
            target_ip,
        });
    }
    Ok(resolved)
}

fn unix_now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

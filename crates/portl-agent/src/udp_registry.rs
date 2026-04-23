use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use dashmap::DashMap;
use iroh::endpoint::Connection;
use sha2::{Digest, Sha256};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use portl_proto::udp_v1::{
    MAX_UDP_DATAGRAM_BYTES, UdpBind, UdpDatagram, encode_datagram, udp_error_payload,
};

pub(crate) const DEFAULT_UDP_SESSION_LINGER_SECS: u64 = 60;
pub(crate) const MAX_SESSIONS_PER_CONNECTION: usize = 16;
pub(crate) const MAX_SRC_TAGS_PER_SESSION: usize = 1024;

const OWNER_FINGERPRINT_DOMAIN: &[u8] = b"portl/udp-session/v1";

#[derive(Clone, Debug)]
pub(crate) struct UdpSessionRegistry {
    inner: Arc<UdpSessionRegistryInner>,
}

#[derive(Debug)]
struct UdpSessionRegistryInner {
    linger_secs: u64,
    sessions: DashMap<[u8; 8], Arc<UdpSession>>,
    connection_sessions: DashMap<usize, usize>,
    attach_lock: Mutex<()>,
}

#[derive(Debug)]
pub(crate) struct UdpSession {
    session_id: [u8; 8],
    owner_fingerprint: [u8; 32],
    cancel: CancellationToken,
    inner: Mutex<UdpSessionInner>,
}

#[derive(Debug)]
struct UdpSessionInner {
    binds: Vec<ResolvedUdpBind>,
    connection: Option<Connection>,
    connection_id: Option<usize>,
    active_controls: usize,
    linger_until: Option<u64>,
    src_tags: HashMap<u32, SrcTagEntry>,
}

#[derive(Debug)]
struct SrcTagEntry {
    target: SocketAddr,
    socket: Arc<UdpSocket>,
    reply_task: JoinHandle<()>,
    last_used: Instant,
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
                connection_sessions: DashMap::new(),
                attach_lock: Mutex::new(()),
            }),
        }
    }

    pub(crate) async fn attach_or_create(
        &self,
        requested_session_id: [u8; 8],
        binds: Vec<UdpBind>,
        connection: Connection,
        peer_token: [u8; 16],
        ticket_id_hex: &str,
    ) -> Result<Arc<UdpSession>> {
        let _attach_guard = self.inner.attach_lock.lock().await;
        let resolved_binds = resolve_binds(&binds).await?;
        let now = unix_now_secs()?;
        let owner_fingerprint = owner_fingerprint(peer_token, ticket_id_hex);
        let connection_id = connection.stable_id();

        if requested_session_id != [0; 8]
            && let Some(existing) = self
                .inner
                .sessions
                .get(&requested_session_id)
                .map(|entry| Arc::clone(entry.value()))
        {
            if existing.is_expired(now).await {
                self.remove_session_locked(requested_session_id).await;
            } else {
                let attach = existing
                    .attach(
                        resolved_binds.clone(),
                        connection.clone(),
                        owner_fingerprint,
                    )
                    .await?;
                match attach {
                    AttachResult::Attached { counts_as_session } => {
                        if counts_as_session {
                            self.ensure_connection_quota(connection_id)?;
                            self.increment_connection_sessions(connection_id);
                        }
                        return Ok(existing);
                    }
                    AttachResult::CreateFresh => {}
                }
            }
        }

        self.ensure_connection_quota(connection_id)?;
        let session_id = self.allocate_session_id_locked();
        let session = Arc::new(UdpSession::new(
            session_id,
            owner_fingerprint,
            resolved_binds,
            &connection,
        ));
        self.inner.sessions.insert(session_id, Arc::clone(&session));
        self.increment_connection_sessions(connection_id);
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
            self.remove_session(session_id).await;
            return Ok(None);
        }

        Ok(Some(session))
    }

    pub(crate) async fn mark_linger_if_current(
        &self,
        session_id: [u8; 8],
        connection_id: usize,
    ) -> Result<()> {
        if let Some(session) = self.get_live(session_id).await?
            && session
                .mark_linger_if_current(connection_id, unix_now_secs()? + self.inner.linger_secs)
                .await
        {
            self.decrement_connection_sessions(connection_id);
        }
        Ok(())
    }

    pub(crate) async fn gc_expired(&self) -> Result<()> {
        let _attach_guard = self.inner.attach_lock.lock().await;
        let now = unix_now_secs()?;
        let sessions = self
            .inner
            .sessions
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect::<Vec<_>>();
        for (session_id, session) in sessions {
            if session.is_expired(now).await {
                self.remove_session_locked(session_id).await;
            }
        }
        Ok(())
    }

    /// Number of UDP sessions currently in the registry (live or
    /// lingering). Used to derive `portl_active_udp_sessions` at
    /// scrape time.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.inner.sessions.len()
    }

    pub async fn shutdown(&self) {
        let _attach_guard = self.inner.attach_lock.lock().await;
        let session_ids = self
            .inner
            .sessions
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for session_id in session_ids {
            self.remove_session_locked(session_id).await;
        }
        self.inner.connection_sessions.clear();
    }

    fn allocate_session_id_locked(&self) -> [u8; 8] {
        loop {
            let session_id = rand::random::<[u8; 8]>();
            if session_id != [0; 8] && !self.inner.sessions.contains_key(&session_id) {
                return session_id;
            }
        }
    }

    async fn remove_session(&self, session_id: [u8; 8]) {
        let _attach_guard = self.inner.attach_lock.lock().await;
        self.remove_session_locked(session_id).await;
    }

    async fn remove_session_locked(&self, session_id: [u8; 8]) {
        if let Some((_, session)) = self.inner.sessions.remove(&session_id) {
            if let Some(connection_id) = session.connection_id().await {
                self.decrement_connection_sessions(connection_id);
            }
            session.shutdown().await;
        }
    }

    fn ensure_connection_quota(&self, connection_id: usize) -> Result<()> {
        if self.connection_session_count(connection_id) >= MAX_SESSIONS_PER_CONNECTION {
            return Err(anyhow!("session quota exceeded"));
        }
        Ok(())
    }

    fn connection_session_count(&self, connection_id: usize) -> usize {
        self.inner
            .connection_sessions
            .get(&connection_id)
            .map_or(0, |entry| *entry)
    }

    fn increment_connection_sessions(&self, connection_id: usize) {
        self.inner
            .connection_sessions
            .entry(connection_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    fn decrement_connection_sessions(&self, connection_id: usize) {
        if let Some(mut count) = self.inner.connection_sessions.get_mut(&connection_id) {
            if *count <= 1 {
                drop(count);
                self.inner.connection_sessions.remove(&connection_id);
            } else {
                *count -= 1;
            }
        }
    }
}

impl UdpSession {
    fn new(
        session_id: [u8; 8],
        owner_fingerprint: [u8; 32],
        binds: Vec<ResolvedUdpBind>,
        connection: &Connection,
    ) -> Self {
        Self {
            session_id,
            owner_fingerprint,
            cancel: CancellationToken::new(),
            inner: Mutex::new(UdpSessionInner {
                binds,
                connection: Some(connection.clone()),
                connection_id: Some(connection.stable_id()),
                active_controls: 1,
                linger_until: None,
                src_tags: HashMap::new(),
            }),
        }
    }

    pub(crate) fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    pub(crate) async fn route_to_target(self: &Arc<Self>, datagram: &UdpDatagram) -> Result<()> {
        let (target, socket) = {
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

            let socket = if let Some(entry) = inner.src_tags.get_mut(&datagram.src_tag) {
                entry.target = target;
                entry.last_used = Instant::now();
                Arc::clone(&entry.socket)
            } else {
                if inner.src_tags.len() >= MAX_SRC_TAGS_PER_SESSION
                    && let Some(evicted_src_tag) = inner.oldest_src_tag()
                    && let Some(evicted) = inner.src_tags.remove(&evicted_src_tag)
                {
                    evicted.reply_task.abort();
                }

                let socket = Arc::new(
                    UdpSocket::bind(("0.0.0.0", 0))
                        .await
                        .context("bind udp src-tag socket")?,
                );
                let reply_task = self.spawn_reply_loop(datagram.src_tag, Arc::clone(&socket));
                inner.src_tags.insert(
                    datagram.src_tag,
                    SrcTagEntry {
                        target,
                        socket: Arc::clone(&socket),
                        reply_task,
                        last_used: Instant::now(),
                    },
                );
                socket
            };
            (target, socket)
        };

        socket
            .send_to(&datagram.payload, target)
            .await
            .with_context(|| format!("send udp payload to {target}"))?;
        Ok(())
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

    pub(crate) async fn mark_linger_if_current(
        &self,
        connection_id: usize,
        linger_until: u64,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        if inner.connection_id != Some(connection_id) {
            return false;
        }
        if inner.active_controls > 1 {
            inner.active_controls -= 1;
            return false;
        }
        inner.active_controls = 0;
        inner.connection = None;
        inner.connection_id = None;
        inner.linger_until = Some(linger_until);
        true
    }

    pub(crate) async fn is_expired(&self, now: u64) -> bool {
        self.inner
            .lock()
            .await
            .linger_until
            .is_some_and(|deadline| deadline <= now)
    }

    pub(crate) async fn shutdown(&self) {
        self.cancel.cancel();
        let mut inner = self.inner.lock().await;
        inner.connection = None;
        inner.connection_id = None;
        inner.active_controls = 0;
        inner.linger_until = Some(0);
        for (_, entry) in inner.src_tags.drain() {
            entry.reply_task.abort();
        }
    }

    async fn attach(
        &self,
        binds: Vec<ResolvedUdpBind>,
        connection: Connection,
        owner_fingerprint: [u8; 32],
    ) -> Result<AttachResult> {
        if self.owner_fingerprint != owner_fingerprint {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "udp session owner mismatch",
            )
            .into());
        }

        let mut inner = self.inner.lock().await;
        let new_connection_id = connection.stable_id();

        let counts_as_session = match inner.connection_id {
            Some(current_connection_id) if current_connection_id == new_connection_id => false,
            Some(_) if inner.linger_until.is_none() => return Ok(AttachResult::CreateFresh),
            Some(_) | None => true,
        };

        inner.binds = binds;
        inner.connection = Some(connection.clone());
        inner.connection_id = Some(new_connection_id);
        inner.linger_until = None;
        if counts_as_session {
            inner.active_controls = 1;
        } else {
            inner.active_controls += 1;
        }
        Ok(AttachResult::Attached { counts_as_session })
    }

    async fn connection_id(&self) -> Option<usize> {
        self.inner.lock().await.connection_id
    }

    fn spawn_reply_loop(self: &Arc<Self>, src_tag: u32, socket: Arc<UdpSocket>) -> JoinHandle<()> {
        let session = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 64 * 1024];
            loop {
                tokio::select! {
                    biased;
                    () = session.cancel.cancelled() => break,
                    result = socket.recv_from(&mut buf) => {
                        let (read, peer) = match result {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::debug!(%err, session_id = %hex::encode(session.session_id), src_tag, "udp src-tag reply loop stopped");
                                break;
                            }
                        };
                        if let Err(err) = session.send_reply(src_tag, peer, buf[..read].to_vec()).await {
                            tracing::debug!(%err, session_id = %hex::encode(session.session_id), src_tag, "udp src-tag reply failed");
                        }
                    }
                }
            }
        })
    }

    async fn send_reply(&self, src_tag: u32, peer: SocketAddr, payload: Vec<u8>) -> Result<()> {
        let connection = {
            let mut inner = self.inner.lock().await;
            let Some(entry) = inner.src_tags.get_mut(&src_tag) else {
                return Ok(());
            };
            entry.last_used = Instant::now();
            inner.connection.clone()
        };

        let Some(connection) = connection else {
            return Ok(());
        };

        let datagram = UdpDatagram {
            session_id: self.session_id,
            target_port: peer.port(),
            src_tag,
            payload,
        };
        self.send_to_client(connection, datagram).await
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

impl UdpSessionInner {
    fn oldest_src_tag(&self) -> Option<u32> {
        self.src_tags
            .iter()
            .min_by_key(|entry| entry.1.last_used)
            .map(|entry| *entry.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachResult {
    Attached { counts_as_session: bool },
    CreateFresh,
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

fn owner_fingerprint(peer_token: [u8; 16], ticket_id_hex: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(peer_token);
    hasher.update(ticket_id_hex.as_bytes());
    hasher.update(OWNER_FINGERPRINT_DOMAIN);
    hasher.finalize().into()
}

fn unix_now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

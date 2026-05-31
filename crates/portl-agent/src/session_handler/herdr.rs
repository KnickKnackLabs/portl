use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use iroh::endpoint::SendStream;
use portl_core::herdr_wire::{
    ClientLane, ClientMessage, FrameDirection, HerdrFrameError, MAX_FRAME_SIZE, RawHerdrFrame,
    ServerLane, ServerMessage,
};
use portl_core::wire::session::{SessionAck, SessionStreamKind, SessionSubTail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, watch};
use tokio::task::JoinHandle;

use crate::AgentState;
use crate::stream_io::BufferedRecv;
use crate::target_context::TargetProcessContext;

const HERDR_LANE_BUFFER: usize = 64;
const HERDR_RESIZE_BUFFER: usize = 1;
const HERDR_RENDER_PENDING_LIMIT: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HerdrRenderFrameMeta {
    SemanticFrame { has_graphics: bool },
    Terminal { full: bool },
}

impl HerdrRenderFrameMeta {
    fn from_frame(frame: &RawHerdrFrame) -> Result<Self> {
        Ok(match frame.decode_server()? {
            ServerMessage::Frame(frame) => Self::SemanticFrame {
                has_graphics: !frame.graphics.is_empty(),
            },
            ServerMessage::Terminal(frame) => Self::Terminal { full: frame.full },
            _ => anyhow::bail!("non-render Herdr frame sent through render coalescer"),
        })
    }
}

#[derive(Debug)]
struct HerdrRenderPendingFrame {
    meta: HerdrRenderFrameMeta,
    frame: RawHerdrFrame,
}

#[derive(Debug)]
struct HerdrRenderPendingFrames {
    max: usize,
    frames: VecDeque<HerdrRenderPendingFrame>,
}

impl HerdrRenderPendingFrames {
    fn new(max: usize) -> Self {
        Self {
            max,
            frames: VecDeque::new(),
        }
    }

    fn push_or_return(&mut self, frame: RawHerdrFrame) -> Result<Option<RawHerdrFrame>> {
        let meta = HerdrRenderFrameMeta::from_frame(&frame)?;
        match meta {
            HerdrRenderFrameMeta::SemanticFrame {
                has_graphics: false,
            } => self.frames.retain(|pending| {
                !matches!(
                    pending.meta,
                    HerdrRenderFrameMeta::SemanticFrame {
                        has_graphics: false
                    }
                )
            }),
            HerdrRenderFrameMeta::Terminal { full: true } => self
                .frames
                .retain(|pending| !matches!(pending.meta, HerdrRenderFrameMeta::Terminal { .. })),
            HerdrRenderFrameMeta::SemanticFrame { has_graphics: true }
            | HerdrRenderFrameMeta::Terminal { full: false } => {}
        }
        if self.frames.len() >= self.max {
            return Ok(Some(frame));
        }
        self.frames
            .push_back(HerdrRenderPendingFrame { meta, frame });
        Ok(None)
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    fn pop_front(&mut self) -> Option<RawHerdrFrame> {
        self.frames.pop_front().map(|pending| pending.frame)
    }
}

#[derive(Clone)]
struct HerdrRenderSender {
    tx: mpsc::Sender<RawHerdrFrame>,
    pending: Arc<AsyncMutex<HerdrRenderPendingFrames>>,
    scheduled: Arc<std::sync::atomic::AtomicBool>,
    notify_space: Arc<Notify>,
}

impl HerdrRenderSender {
    fn new(tx: mpsc::Sender<RawHerdrFrame>) -> Self {
        Self {
            tx,
            pending: Arc::new(AsyncMutex::new(HerdrRenderPendingFrames::new(
                HERDR_RENDER_PENDING_LIMIT,
            ))),
            scheduled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify_space: Arc::new(Notify::new()),
        }
    }

    async fn send(&self, mut frame: RawHerdrFrame) -> Result<()> {
        loop {
            if self.tx.is_closed() {
                anyhow::bail!("send herdr render frame");
            }
            let returned = self.pending.lock().await.push_or_return(frame)?;
            self.ensure_drain_task();
            match returned {
                Some(returned_frame) => {
                    frame = returned_frame;
                    self.notify_space.notified().await;
                }
                None => return Ok(()),
            }
        }
    }

    fn ensure_drain_task(&self) {
        if !self
            .scheduled
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            tokio::spawn(drain_herdr_render_pending(
                self.tx.clone(),
                Arc::clone(&self.pending),
                Arc::clone(&self.scheduled),
                Arc::clone(&self.notify_space),
            ));
        }
    }
}

async fn drain_herdr_render_pending(
    tx: mpsc::Sender<RawHerdrFrame>,
    pending: Arc<AsyncMutex<HerdrRenderPendingFrames>>,
    scheduled: Arc<std::sync::atomic::AtomicBool>,
    notify_space: Arc<Notify>,
) {
    loop {
        let frame = {
            let mut pending = pending.lock().await;
            let frame = pending.pop_front();
            if frame.is_some() {
                notify_space.notify_one();
            }
            frame
        };
        if let Some(frame) = frame {
            if tx.send(frame).await.is_err() {
                scheduled.store(false, std::sync::atomic::Ordering::Release);
                notify_space.notify_one();
                return;
            }
        } else {
            scheduled.store(false, std::sync::atomic::Ordering::Release);
            notify_space.notify_one();
            if pending.lock().await.is_empty() {
                return;
            }
            if scheduled.swap(true, std::sync::atomic::Ordering::AcqRel) {
                return;
            }
        }
    }
}

pub(crate) struct HerdrAttach {
    pid: u32,
    exit_rx: watch::Receiver<Option<i32>>,
    client_control_tx: mpsc::Sender<RawHerdrFrame>,
    client_input_tx: mpsc::Sender<RawHerdrFrame>,
    client_resize: ResizeCoalescer,
    client_bulk_tx: mpsc::Sender<RawHerdrFrame>,
    server_control_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    server_render_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    server_bulk_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    _tasks: Vec<JoinHandle<()>>,
}

pub(crate) fn is_herdr_stream_kind(kind: SessionStreamKind) -> bool {
    matches!(
        kind,
        SessionStreamKind::HerdrClientControl
            | SessionStreamKind::HerdrClientInput
            | SessionStreamKind::HerdrClientResize
            | SessionStreamKind::HerdrClientBulk
            | SessionStreamKind::HerdrServerControl
            | SessionStreamKind::HerdrServerRender
            | SessionStreamKind::HerdrServerBulk
    )
}

pub(crate) async fn serve_herdr_attach(
    state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    name: &str,
    context: &TargetProcessContext,
    provider: super::provider::HerdrProvider,
) -> Result<()> {
    let session_id = rand::random::<[u8; 16]>();
    let audit_session_id = hex::encode(session_id);
    let attach = match spawn_herdr_attach(name, context, &audit_session_id, &provider) {
        Ok(attach) => attach,
        Err(err) => {
            let reason = portl_proto::session_v1::SessionReason::SpawnFailed(err.to_string());
            super::record_session_attach_rejection("herdr", &reason);
            super::write_ack(&mut send, super::reject(reason)).await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    state
        .herdr_attach_registry
        .insert(session_id, Arc::clone(&attach));
    let _guard = HerdrAttachRegistryGuard {
        state: Arc::clone(&state),
        session_id,
    };
    let _termination_guard = HerdrAttachTerminationGuard {
        attach: Arc::clone(&attach),
    };
    super::write_ack(
        &mut send,
        SessionAck {
            ok: true,
            reason: None,
            session_id: Some(session_id),
            provider: Some("herdr".to_owned()),
            providers: None,
            sessions: None,
            session_entries: None,
            session_groups: None,
            run: None,
            output: None,
        },
    )
    .await?;

    let mut control_buffer = [0_u8; 1024];
    loop {
        let read = recv
            .read(&mut control_buffer)
            .await
            .context("read herdr session control")?;
        if read == 0 {
            let _ = send.finish();
            return Ok(());
        }
    }
}

pub(crate) async fn serve_substream(
    state: Arc<AgentState>,
    send: SendStream,
    recv: BufferedRecv,
    tail: SessionSubTail,
) -> Result<()> {
    let attach = state
        .herdr_attach_registry
        .get(&tail.session_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| anyhow!("herdr attach session not found"))?;
    match tail.kind {
        SessionStreamKind::HerdrClientControl => {
            pump_herdr_client_frames(recv, attach.client_control_tx.clone()).await
        }
        SessionStreamKind::HerdrClientInput => {
            pump_herdr_client_frames(recv, attach.client_input_tx.clone()).await
        }
        SessionStreamKind::HerdrClientResize => {
            pump_herdr_resize_frames(recv, attach.client_resize.clone()).await
        }
        SessionStreamKind::HerdrClientBulk => {
            pump_herdr_client_frames(recv, attach.client_bulk_tx.clone()).await
        }
        SessionStreamKind::HerdrServerControl => {
            let rx = take_receiver(
                &attach.server_control_rx,
                "herdr control stream already attached",
            )
            .await?;
            pump_herdr_server_frames(send, rx).await
        }
        SessionStreamKind::HerdrServerRender => {
            let rx = take_receiver(
                &attach.server_render_rx,
                "herdr render stream already attached",
            )
            .await?;
            pump_herdr_server_frames(send, rx).await
        }
        SessionStreamKind::HerdrServerBulk => {
            let rx =
                take_receiver(&attach.server_bulk_rx, "herdr bulk stream already attached").await?;
            pump_herdr_server_frames(send, rx).await
        }
        _ => anyhow::bail!("not a herdr stream kind"),
    }
}

fn spawn_herdr_attach(
    name: &str,
    context: &TargetProcessContext,
    audit_session_id: &str,
    provider: &super::provider::HerdrProvider,
) -> Result<Arc<HerdrAttach>> {
    let mut command = provider.bridge_command(name, context.cwd.as_deref(), &context.env)?;
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .context("spawn herdr remote-client-bridge")?;
    let pid = child.id().context("missing herdr child pid")?;
    let stdin = child.stdin.take().context("missing herdr child stdin")?;
    let stdout = child.stdout.take().context("missing herdr child stdout")?;
    let stderr = child.stderr.take().context("missing herdr child stderr")?;

    let (client_control_tx, client_control_rx) = mpsc::channel(HERDR_LANE_BUFFER);
    let (client_input_tx, client_input_rx) = mpsc::channel(HERDR_LANE_BUFFER);
    let (client_resize_tx, client_resize_rx) = mpsc::channel(HERDR_RESIZE_BUFFER);
    let (client_bulk_tx, client_bulk_rx) = mpsc::channel(HERDR_LANE_BUFFER);
    let (server_control_tx, server_control_rx) = mpsc::channel(HERDR_LANE_BUFFER);
    let (server_render_tx, server_render_rx) = mpsc::channel(HERDR_LANE_BUFFER);
    let (server_bulk_tx, server_bulk_rx) = mpsc::channel(HERDR_LANE_BUFFER);
    let (exit_tx, exit_rx) = watch::channel(None);

    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(async move {
        if let Err(err) = pump_client_lanes_to_bridge(
            stdin,
            client_control_rx,
            client_input_rx,
            client_resize_rx,
            client_bulk_rx,
        )
        .await
        {
            tracing::debug!(%err, "herdr bridge stdin pump ended");
        }
    }));
    tasks.push(tokio::spawn(async move {
        if let Err(err) = pump_bridge_stdout_to_server_lanes(
            stdout,
            server_control_tx,
            server_render_tx,
            server_bulk_tx,
        )
        .await
        {
            tracing::debug!(%err, "herdr bridge stdout pump ended");
        }
    }));
    tasks.push(tokio::spawn(async move {
        let mut stderr = stderr;
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes).await;
        if !bytes.is_empty() {
            tracing::debug!(stderr = %String::from_utf8_lossy(&bytes), "herdr bridge stderr");
        }
    }));
    let audit_session_id = audit_session_id.to_owned();
    tasks.push(tokio::spawn(async move {
        let code = child
            .wait()
            .await
            .ok()
            .and_then(|status| status.code())
            .unwrap_or(1);
        tracing::debug!(pid, code, audit_session_id, "herdr bridge exited");
        let _ = exit_tx.send(Some(code));
    }));

    Ok(Arc::new(HerdrAttach {
        pid,
        exit_rx,
        client_control_tx,
        client_input_tx,
        client_resize: ResizeCoalescer::new(client_resize_tx),
        client_bulk_tx,
        server_control_rx: AsyncMutex::new(Some(server_control_rx)),
        server_render_rx: AsyncMutex::new(Some(server_render_rx)),
        server_bulk_rx: AsyncMutex::new(Some(server_bulk_rx)),
        _tasks: tasks,
    }))
}

impl HerdrAttach {
    fn terminate_bridge(&self) {
        if self.exit_rx.borrow().is_some() {
            return;
        }
        #[cfg(unix)]
        {
            let Ok(pid) = i32::try_from(self.pid) else {
                return;
            };
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }
}

impl Drop for HerdrAttach {
    fn drop(&mut self) {
        self.terminate_bridge();
    }
}

struct HerdrAttachTerminationGuard {
    attach: Arc<HerdrAttach>,
}

impl Drop for HerdrAttachTerminationGuard {
    fn drop(&mut self) {
        self.attach.terminate_bridge();
    }
}

async fn take_receiver(
    slot: &AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    error: &'static str,
) -> Result<mpsc::Receiver<RawHerdrFrame>> {
    slot.lock().await.take().ok_or_else(|| anyhow!(error))
}

async fn pump_herdr_client_frames(
    mut recv: BufferedRecv,
    tx: mpsc::Sender<RawHerdrFrame>,
) -> Result<()> {
    while let Some(frame) = read_next_raw_frame(&mut recv, FrameDirection::ClientToServer).await? {
        match frame.client_lane()? {
            ClientLane::Control | ClientLane::Input | ClientLane::Bulk | ClientLane::Resize => {
                tx.send(frame).await.context("send herdr client frame")?;
            }
        }
    }
    Ok(())
}

async fn pump_herdr_resize_frames(
    mut recv: BufferedRecv,
    coalescer: ResizeCoalescer,
) -> Result<()> {
    while let Some(frame) = read_next_raw_frame(&mut recv, FrameDirection::ClientToServer).await? {
        coalescer.send(frame).await?;
    }
    Ok(())
}

async fn pump_herdr_server_frames(
    mut send: SendStream,
    mut rx: mpsc::Receiver<RawHerdrFrame>,
) -> Result<()> {
    while let Some(frame) = rx.recv().await {
        send.write_all(frame.framed_bytes())
            .await
            .context("write herdr server frame")?;
    }
    let _ = send.finish();
    Ok(())
}

async fn pump_client_lanes_to_bridge<W>(
    mut stdin: W,
    mut control_rx: mpsc::Receiver<RawHerdrFrame>,
    mut input_rx: mpsc::Receiver<RawHerdrFrame>,
    mut resize_rx: mpsc::Receiver<RawHerdrFrame>,
    mut bulk_rx: mpsc::Receiver<RawHerdrFrame>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let hello = control_rx
        .recv()
        .await
        .context("herdr client control stream closed before Hello")?;
    if !matches!(hello.decode_client()?, ClientMessage::Hello { .. }) {
        anyhow::bail!("first Herdr client control frame must be Hello");
    }
    stdin
        .write_all(hello.framed_bytes())
        .await
        .context("write herdr Hello to bridge")?;
    stdin.flush().await.context("flush herdr bridge stdin")?;

    let mut control_open = true;
    let mut input_open = true;
    let mut resize_open = true;
    let mut bulk_open = true;
    while control_open || input_open || resize_open || bulk_open {
        let frame = tokio::select! {
            biased;
            frame = control_rx.recv(), if control_open => {
                if let Some(frame) = frame {
                    Some(frame)
                } else {
                    control_open = false;
                    None
                }
            }
            frame = input_rx.recv(), if input_open => {
                if let Some(frame) = frame {
                    Some(frame)
                } else {
                    input_open = false;
                    None
                }
            }
            frame = resize_rx.recv(), if resize_open => {
                if let Some(frame) = frame {
                    Some(frame)
                } else {
                    resize_open = false;
                    None
                }
            }
            frame = bulk_rx.recv(), if bulk_open => {
                if let Some(frame) = frame {
                    Some(frame)
                } else {
                    bulk_open = false;
                    None
                }
            }
        };
        let Some(frame) = frame else {
            continue;
        };
        stdin
            .write_all(frame.framed_bytes())
            .await
            .context("write herdr frame to bridge")?;
        stdin.flush().await.context("flush herdr bridge stdin")?;
    }
    let _ = stdin.shutdown().await;
    Ok(())
}

async fn pump_bridge_stdout_to_server_lanes<R>(
    mut stdout: R,
    control_tx: mpsc::Sender<RawHerdrFrame>,
    render_tx: mpsc::Sender<RawHerdrFrame>,
    bulk_tx: mpsc::Sender<RawHerdrFrame>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let render_sender = HerdrRenderSender::new(render_tx);
    while let Some(frame) = read_next_raw_frame(&mut stdout, FrameDirection::ServerToClient).await?
    {
        match frame.server_lane()? {
            ServerLane::Control => control_tx
                .send(frame)
                .await
                .context("send herdr control frame")?,
            ServerLane::Render => render_sender.send(frame).await?,
            ServerLane::Bulk => bulk_tx.send(frame).await.context("send herdr bulk frame")?,
        }
    }
    Ok(())
}

async fn read_next_raw_frame<R>(
    reader: &mut R,
    direction: FrameDirection,
) -> Result<Option<RawHerdrFrame>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0_u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("read herdr frame length"),
    }
    let claimed = u32::from_le_bytes(len_buf) as usize;
    if claimed > MAX_FRAME_SIZE {
        return Err(HerdrFrameError::Oversized {
            claimed,
            max: MAX_FRAME_SIZE,
        })
        .context("decode herdr frame");
    }
    let mut framed = Vec::with_capacity(4 + claimed);
    framed.extend_from_slice(&len_buf);
    let mut payload = vec![0_u8; claimed];
    reader
        .read_exact(&mut payload)
        .await
        .context("read herdr frame payload")?;
    framed.extend_from_slice(&payload);
    match direction {
        FrameDirection::ClientToServer => RawHerdrFrame::decode_client_from_bytes(&framed),
        FrameDirection::ServerToClient => RawHerdrFrame::decode_server_from_bytes(&framed),
    }
    .map(Some)
    .context("decode herdr frame")
}

#[derive(Clone)]
struct ResizeCoalescer {
    tx: mpsc::Sender<RawHerdrFrame>,
    latest: Arc<AsyncMutex<Option<RawHerdrFrame>>>,
    scheduled: Arc<std::sync::atomic::AtomicBool>,
}

impl ResizeCoalescer {
    fn new(tx: mpsc::Sender<RawHerdrFrame>) -> Self {
        Self {
            tx,
            latest: Arc::new(AsyncMutex::new(None)),
            scheduled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    async fn send(&self, frame: RawHerdrFrame) -> Result<()> {
        *self.latest.lock().await = Some(frame);
        if !self
            .scheduled
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            tokio::spawn(drain_resize_coalescer(
                self.tx.clone(),
                Arc::clone(&self.latest),
                Arc::clone(&self.scheduled),
            ));
        }
        Ok(())
    }
}

async fn drain_resize_coalescer(
    tx: mpsc::Sender<RawHerdrFrame>,
    latest: Arc<AsyncMutex<Option<RawHerdrFrame>>>,
    scheduled: Arc<std::sync::atomic::AtomicBool>,
) {
    loop {
        tokio::task::yield_now().await;
        let Ok(permit) = tx.reserve().await else {
            scheduled.store(false, std::sync::atomic::Ordering::Release);
            return;
        };
        let Some(frame) = latest.lock().await.take() else {
            drop(permit);
            scheduled.store(false, std::sync::atomic::Ordering::Release);
            if latest.lock().await.is_none()
                || scheduled.swap(true, std::sync::atomic::Ordering::AcqRel)
            {
                return;
            }
            continue;
        };
        permit.send(frame);
        if latest.lock().await.is_some() {
            continue;
        }
        scheduled.store(false, std::sync::atomic::Ordering::Release);
        if latest.lock().await.is_none()
            || scheduled.swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
    }
}

struct HerdrAttachRegistryGuard {
    state: Arc<AgentState>,
    session_id: [u8; 16],
}

impl Drop for HerdrAttachRegistryGuard {
    fn drop(&mut self) {
        self.state.herdr_attach_registry.remove(&self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portl_core::herdr_wire::{
        CellData, ClientKeybindings, ClientMessage, FrameData, HERDR_PROTOCOL_VERSION, NotifyKind,
        RawHerdrFrame, RenderEncoding, ServerMessage, TerminalFrame,
    };

    fn hello_frame() -> RawHerdrFrame {
        RawHerdrFrame::encode_client(&ClientMessage::Hello {
            version: HERDR_PROTOCOL_VERSION,
            cols: 80,
            rows: 24,
            cell_width_px: 0,
            cell_height_px: 0,
            requested_encoding: RenderEncoding::SemanticFrame,
            keybindings: ClientKeybindings::Server,
        })
        .unwrap()
    }

    fn semantic_server_frame(symbol: &str) -> RawHerdrFrame {
        RawHerdrFrame::encode_server(&ServerMessage::Frame(FrameData {
            cells: vec![CellData {
                symbol: symbol.to_owned(),
                fg: 0,
                bg: 0,
                modifier: 0,
                skip: false,
                hyperlink: None,
            }],
            width: 1,
            height: 1,
            cursor: None,
            hyperlinks: Vec::new(),
            graphics: Vec::new(),
        }))
        .unwrap()
    }

    fn terminal_server_frame(seq: u64, full: bool, bytes: &[u8]) -> RawHerdrFrame {
        RawHerdrFrame::encode_server(&ServerMessage::Terminal(TerminalFrame {
            seq,
            width: 80,
            height: 24,
            full,
            bytes: bytes.to_vec(),
        }))
        .unwrap()
    }

    fn notify_server_frame(message: &str) -> RawHerdrFrame {
        RawHerdrFrame::encode_server(&ServerMessage::Notify {
            kind: NotifyKind::Toast,
            message: message.to_owned(),
        })
        .unwrap()
    }

    async fn write_server_frames<W>(writer: &mut W, frames: &[RawHerdrFrame])
    where
        W: AsyncWrite + Unpin,
    {
        for frame in frames {
            writer.write_all(frame.framed_bytes()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn herdr_bridge_sender_coalesces_semantic_render_backlog() {
        let (mut stdout_writer, stdout_reader) = tokio::io::duplex(8192);
        let (control_tx, _control_rx) = mpsc::channel(4);
        let (render_tx, mut render_rx) = mpsc::channel(1);
        let (bulk_tx, _bulk_rx) = mpsc::channel(4);
        let frames: Vec<_> = (0..8)
            .map(|idx| semantic_server_frame(&format!("frame-{idx}")))
            .collect();

        let pump = tokio::spawn(pump_bridge_stdout_to_server_lanes(
            stdout_reader,
            control_tx,
            render_tx,
            bulk_tx,
        ));
        write_server_frames(&mut stdout_writer, &frames).await;
        drop(stdout_writer);

        tokio::time::timeout(std::time::Duration::from_secs(1), pump)
            .await
            .expect("stdout pump should not block on stale render backlog")
            .unwrap()
            .unwrap();

        let mut delivered = Vec::new();
        while let Ok(Some(frame)) =
            tokio::time::timeout(std::time::Duration::from_millis(100), render_rx.recv()).await
        {
            delivered.push(frame);
        }
        assert!(
            delivered.len() < frames.len(),
            "expected stale semantic frames to be coalesced; delivered {} of {}",
            delivered.len(),
            frames.len()
        );
        assert_eq!(delivered.last(), frames.last());
    }

    #[tokio::test]
    async fn herdr_bridge_sender_backpressures_uncoalescible_render_backlog() {
        let (mut stdout_writer, stdout_reader) = tokio::io::duplex(65_536);
        let (control_tx, _control_rx) = mpsc::channel(4);
        let (render_tx, mut render_rx) = mpsc::channel(1);
        let (bulk_tx, _bulk_rx) = mpsc::channel(4);
        let frames: Vec<_> = (0..80)
            .map(|seq| terminal_server_frame(seq, false, format!("diff-{seq}").as_bytes()))
            .collect();

        let mut pump = tokio::spawn(pump_bridge_stdout_to_server_lanes(
            stdout_reader,
            control_tx,
            render_tx,
            bulk_tx,
        ));
        write_server_frames(&mut stdout_writer, &frames).await;
        drop(stdout_writer);

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut pump)
                .await
                .is_err(),
            "stdout pump should backpressure rather than buffer unbounded terminal diffs"
        );

        let mut delivered = Vec::new();
        while delivered.len() < frames.len() {
            let Some(frame) =
                tokio::time::timeout(std::time::Duration::from_secs(1), render_rx.recv())
                    .await
                    .expect("render diffs should drain once receiver catches up")
            else {
                break;
            };
            delivered.push(frame);
        }
        pump.await.unwrap().unwrap();
        assert_eq!(delivered, frames);
    }

    #[tokio::test]
    async fn herdr_bridge_sender_preserves_terminal_diffs() {
        let (mut stdout_writer, stdout_reader) = tokio::io::duplex(8192);
        let (control_tx, _control_rx) = mpsc::channel(4);
        let (render_tx, mut render_rx) = mpsc::channel(8);
        let (bulk_tx, _bulk_rx) = mpsc::channel(4);
        let frames = vec![
            terminal_server_frame(1, false, b"diff-1"),
            terminal_server_frame(2, false, b"diff-2"),
            terminal_server_frame(3, false, b"diff-3"),
        ];

        let pump = tokio::spawn(pump_bridge_stdout_to_server_lanes(
            stdout_reader,
            control_tx,
            render_tx,
            bulk_tx,
        ));
        write_server_frames(&mut stdout_writer, &frames).await;
        drop(stdout_writer);
        pump.await.unwrap().unwrap();

        let mut delivered = Vec::new();
        while let Some(frame) = render_rx.recv().await {
            delivered.push(frame);
        }
        assert_eq!(delivered, frames);
    }

    #[tokio::test]
    async fn herdr_bridge_sender_control_not_blocked_by_render_backlog() {
        let (mut stdout_writer, stdout_reader) = tokio::io::duplex(8192);
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let (render_tx, _render_rx) = mpsc::channel(1);
        let (bulk_tx, _bulk_rx) = mpsc::channel(4);
        let notify = notify_server_frame("control-ready");
        let mut frames: Vec<_> = (0..8)
            .map(|idx| semantic_server_frame(&format!("frame-{idx}")))
            .collect();
        frames.push(notify.clone());

        let pump = tokio::spawn(pump_bridge_stdout_to_server_lanes(
            stdout_reader,
            control_tx,
            render_tx,
            bulk_tx,
        ));
        write_server_frames(&mut stdout_writer, &frames).await;

        let delivered =
            tokio::time::timeout(std::time::Duration::from_millis(200), control_rx.recv())
                .await
                .expect("control frame should not wait behind render backlog")
                .expect("control channel should remain open");
        assert_eq!(delivered, notify);
        drop(stdout_writer);
        pump.abort();
    }

    #[tokio::test]
    async fn client_bridge_waits_for_hello_before_input_frames() {
        let (control_tx, control_rx) = mpsc::channel(4);
        let (input_tx, input_rx) = mpsc::channel(4);
        let (resize_tx, resize_rx) = mpsc::channel(4);
        let (bulk_tx, bulk_rx) = mpsc::channel(4);
        let (writer, mut reader) = tokio::io::duplex(4096);
        let input = RawHerdrFrame::encode_client(&ClientMessage::Input {
            data: b"typed-before-hello".to_vec(),
        })
        .unwrap();
        input_tx.send(input.clone()).await.unwrap();

        let pump = tokio::spawn(pump_client_lanes_to_bridge(
            writer, control_rx, input_rx, resize_rx, bulk_rx,
        ));
        tokio::task::yield_now().await;
        control_tx.send(hello_frame()).await.unwrap();
        drop(control_tx);
        drop(input_tx);
        drop(resize_tx);
        drop(bulk_tx);

        let first = read_next_raw_frame(&mut reader, FrameDirection::ClientToServer)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            first.decode_client().unwrap(),
            ClientMessage::Hello { .. }
        ));
        let second = read_next_raw_frame(&mut reader, FrameDirection::ClientToServer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second, input);
        pump.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn client_bridge_rejects_non_hello_first_control_frame() {
        let (control_tx, control_rx) = mpsc::channel(4);
        let (_input_tx, input_rx) = mpsc::channel(4);
        let (_resize_tx, resize_rx) = mpsc::channel(4);
        let (_bulk_tx, bulk_rx) = mpsc::channel(4);
        control_tx
            .send(RawHerdrFrame::encode_client(&ClientMessage::Detach).unwrap())
            .await
            .unwrap();
        drop(control_tx);

        let err = pump_client_lanes_to_bridge(
            tokio::io::sink(),
            control_rx,
            input_rx,
            resize_rx,
            bulk_rx,
        )
        .await
        .expect_err("non-Hello first frame should fail");
        assert!(err.to_string().contains("first Herdr client control frame"));
    }

    #[tokio::test]
    async fn resize_coalescer_emits_latest_resize_under_backpressure() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(
            RawHerdrFrame::encode_client(&ClientMessage::Resize {
                cols: 80,
                rows: 24,
                cell_width_px: 0,
                cell_height_px: 0,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let coalescer = ResizeCoalescer::new(tx);

        coalescer
            .send(
                RawHerdrFrame::encode_client(&ClientMessage::Resize {
                    cols: 100,
                    rows: 30,
                    cell_width_px: 0,
                    cell_height_px: 0,
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), async {
            loop {
                if coalescer.latest.lock().await.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        coalescer
            .send(
                RawHerdrFrame::encode_client(&ClientMessage::Resize {
                    cols: 120,
                    rows: 40,
                    cell_width_px: 0,
                    cell_height_px: 0,
                })
                .unwrap(),
            )
            .await
            .unwrap();

        let first = rx.recv().await.unwrap();
        assert!(matches!(
            first.decode_client().unwrap(),
            ClientMessage::Resize { cols: 80, .. }
        ));
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("latest resize should be delivered after backpressure clears")
            .expect("resize channel should remain open");
        assert!(matches!(
            second.decode_client().unwrap(),
            ClientMessage::Resize {
                cols: 120,
                rows: 40,
                ..
            }
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "stale intermediate resize should remain coalesced"
        );
    }

    #[tokio::test]
    async fn resize_coalescer_emits_latest_resize() {
        let (tx, mut rx) = mpsc::channel(1);
        let coalescer = ResizeCoalescer::new(tx);

        coalescer
            .send(
                RawHerdrFrame::encode_client(&ClientMessage::Resize {
                    cols: 80,
                    rows: 24,
                    cell_width_px: 0,
                    cell_height_px: 0,
                })
                .unwrap(),
            )
            .await
            .unwrap();
        coalescer
            .send(
                RawHerdrFrame::encode_client(&ClientMessage::Resize {
                    cols: 120,
                    rows: 40,
                    cell_width_px: 0,
                    cell_height_px: 0,
                })
                .unwrap(),
            )
            .await
            .unwrap();

        let latest = rx.recv().await.unwrap();
        let decoded = latest.decode_client().unwrap();
        assert!(matches!(
            decoded,
            ClientMessage::Resize {
                cols: 120,
                rows: 40,
                ..
            }
        ));
    }
}

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use iroh::endpoint::SendStream;
use portl_core::herdr_wire::{
    ClientLane, FrameDirection, HerdrFrameBudget, HerdrReadLimits, RawHerdrFrame, ServerLane,
    read_herdr_frame,
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
const HERDR_CLIENT_LANE_WEIGHTS: [u8; 4] = [4, 8, 1, 1];

#[derive(Debug)]
struct HerdrRenderPendingFrames {
    max: usize,
    frames: VecDeque<RawHerdrFrame>,
}

impl HerdrRenderPendingFrames {
    fn new(max: usize) -> Self {
        Self {
            max,
            frames: VecDeque::new(),
        }
    }

    fn push_or_return(&mut self, frame: RawHerdrFrame) -> Result<Option<RawHerdrFrame>> {
        if !matches!(frame.server_lane()?, ServerLane::Render) {
            anyhow::bail!("non-render Herdr frame sent through render queue");
        }
        if self.frames.len() >= self.max {
            return Ok(Some(frame));
        }
        // Portl only models protocol 12, so decoding a protocol-19 Frame just
        // to coalesce it can allocate attacker-controlled nested collections.
        // Preserve opaque render frames FIFO instead.
        self.frames.push_back(frame);
        Ok(None)
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    fn pop_front(&mut self) -> Option<RawHerdrFrame> {
        self.frames.pop_front()
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
    client_budget: HerdrFrameBudget,
    server_control_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    server_render_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    server_bulk_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    tasks: Vec<JoinHandle<()>>,
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
            pump_herdr_client_frames(
                recv,
                attach.client_control_tx.clone(),
                attach.client_budget.clone(),
                ClientLane::Control,
            )
            .await
        }
        SessionStreamKind::HerdrClientInput => {
            pump_herdr_client_frames(
                recv,
                attach.client_input_tx.clone(),
                attach.client_budget.clone(),
                ClientLane::Input,
            )
            .await
        }
        SessionStreamKind::HerdrClientResize => {
            pump_herdr_resize_frames(
                recv,
                attach.client_resize.clone(),
                attach.client_budget.clone(),
            )
            .await
        }
        SessionStreamKind::HerdrClientBulk => {
            pump_herdr_client_frames(
                recv,
                attach.client_bulk_tx.clone(),
                attach.client_budget.clone(),
                ClientLane::Bulk,
            )
            .await
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
    let client_budget = HerdrFrameBudget::default();
    let server_budget = HerdrFrameBudget::default();

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
            server_budget,
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
        client_budget,
        server_control_rx: AsyncMutex::new(Some(server_control_rx)),
        server_render_rx: AsyncMutex::new(Some(server_render_rx)),
        server_bulk_rx: AsyncMutex::new(Some(server_bulk_rx)),
        tasks,
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
        for task in &self.tasks {
            task.abort();
        }
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
    budget: HerdrFrameBudget,
    expected_lane: ClientLane,
) -> Result<()> {
    while let Some(frame) = read_herdr_frame(
        &mut recv,
        FrameDirection::ClientToServer,
        &budget,
        &HerdrReadLimits::default(),
    )
    .await?
    {
        let actual_lane = frame.client_lane()?;
        if actual_lane != expected_lane {
            anyhow::bail!(
                "Herdr {actual_lane:?} frame received on {expected_lane:?} client stream"
            );
        }
        tx.send(frame).await.context("send herdr client frame")?;
    }
    Ok(())
}

async fn pump_herdr_resize_frames(
    mut recv: BufferedRecv,
    coalescer: ResizeCoalescer,
    budget: HerdrFrameBudget,
) -> Result<()> {
    while let Some(frame) = read_herdr_frame(
        &mut recv,
        FrameDirection::ClientToServer,
        &budget,
        &HerdrReadLimits::default(),
    )
    .await?
    {
        if frame.client_lane()? != ClientLane::Resize {
            anyhow::bail!("non-resize Herdr frame received on resize client stream");
        }
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
    if !hello.is_client_hello()? {
        anyhow::bail!("first Herdr client control frame must be Hello");
    }
    write_herdr_bridge_frame(&mut stdin, &hello).await?;

    // Weighted round robin is work-conserving but bounds starvation: control
    // and input receive larger bursts while resize and bulk each get a turn.
    let mut open = [true; 4];
    let mut cursor = 0_usize;
    let mut remaining = HERDR_CLIENT_LANE_WEIGHTS[cursor];
    while open.iter().any(|is_open| *is_open) {
        let mut selected = None;
        for _ in 0..4 {
            if remaining == 0 || !open[cursor] {
                cursor = (cursor + 1) % 4;
                remaining = HERDR_CLIENT_LANE_WEIGHTS[cursor];
            }
            let result = match cursor {
                0 => control_rx.try_recv(),
                1 => input_rx.try_recv(),
                2 => resize_rx.try_recv(),
                3 => bulk_rx.try_recv(),
                _ => unreachable!(),
            };
            match result {
                Ok(frame) => {
                    selected = Some((frame, cursor));
                    break;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => open[cursor] = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            cursor = (cursor + 1) % 4;
            remaining = HERDR_CLIENT_LANE_WEIGHTS[cursor];
        }
        if selected.is_none() && !open.iter().any(|is_open| *is_open) {
            break;
        }

        let (frame, lane) = if let Some(selected) = selected {
            selected
        } else {
            let selected = tokio::select! {
            biased;
            frame = control_rx.recv(), if open[0] => {
                if let Some(frame) = frame {
                    Some((frame, 0))
                } else {
                    open[0] = false;
                    None
                }
            }
            frame = input_rx.recv(), if open[1] => {
                if let Some(frame) = frame {
                    Some((frame, 1))
                } else {
                    open[1] = false;
                    None
                }
            }
            frame = resize_rx.recv(), if open[2] => {
                if let Some(frame) = frame {
                    Some((frame, 2))
                } else {
                    open[2] = false;
                    None
                }
            }
            frame = bulk_rx.recv(), if open[3] => {
                if let Some(frame) = frame {
                    Some((frame, 3))
                } else {
                    open[3] = false;
                    None
                }
            }
            };
            let Some(selected) = selected else {
                continue;
            };
            selected
        };
        if lane != cursor {
            cursor = lane;
            remaining = HERDR_CLIENT_LANE_WEIGHTS[cursor];
        }
        remaining = remaining.saturating_sub(1);
        if remaining == 0 {
            cursor = (cursor + 1) % 4;
            remaining = HERDR_CLIENT_LANE_WEIGHTS[cursor];
        }
        write_herdr_bridge_frame(&mut stdin, &frame).await?;
    }
    let _ = stdin.shutdown().await;
    Ok(())
}

async fn write_herdr_bridge_frame<W>(writer: &mut W, frame: &RawHerdrFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(frame.framed_bytes())
        .await
        .context("write herdr frame to bridge")?;
    writer.flush().await.context("flush herdr bridge stdin")
}

async fn pump_bridge_stdout_to_server_lanes<R>(
    mut stdout: R,
    control_tx: mpsc::Sender<RawHerdrFrame>,
    render_tx: mpsc::Sender<RawHerdrFrame>,
    bulk_tx: mpsc::Sender<RawHerdrFrame>,
    budget: HerdrFrameBudget,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let render_sender = HerdrRenderSender::new(render_tx);
    while let Some(frame) = read_herdr_frame(
        &mut stdout,
        FrameDirection::ServerToClient,
        &budget,
        &HerdrReadLimits::default(),
    )
    .await?
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
        CellData, ClientKeybindings, ClientLaunchMode, ClientMessage, FrameData,
        HERDR_PROTOCOL_VERSION, NotifyKind, RawHerdrFrame, RenderEncoding, ServerMessage,
        TerminalFrame,
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
            launch_mode: ClientLaunchMode::App,
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
    async fn herdr_bridge_sender_preserves_semantic_render_fifo() {
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
            HerdrFrameBudget::default(),
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
        assert_eq!(delivered, frames);
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
            HerdrFrameBudget::default(),
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
            HerdrFrameBudget::default(),
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
    async fn client_lane_scheduler_prioritizes_without_starving_any_lane() {
        let (writer, mut reader) = tokio::io::duplex(65_536);
        let (control_tx, control_rx) = mpsc::channel(32);
        let (input_tx, input_rx) = mpsc::channel(32);
        let (resize_tx, resize_rx) = mpsc::channel(32);
        let (bulk_tx, bulk_rx) = mpsc::channel(32);
        control_tx.send(hello_frame()).await.unwrap();
        for _ in 0..16 {
            control_tx
                .send(RawHerdrFrame::encode_client(&ClientMessage::Detach).unwrap())
                .await
                .unwrap();
        }
        let input =
            RawHerdrFrame::encode_client(&ClientMessage::Input { data: vec![b'x'] }).unwrap();
        for _ in 0..8 {
            input_tx.send(input.clone()).await.unwrap();
        }
        let resize = RawHerdrFrame::encode_client(&ClientMessage::Resize {
            cols: 100,
            rows: 40,
            cell_width_px: 0,
            cell_height_px: 0,
        })
        .unwrap();
        for _ in 0..2 {
            resize_tx.send(resize.clone()).await.unwrap();
        }
        let bulk = RawHerdrFrame::encode_client(&ClientMessage::ClipboardImage {
            extension: "png".to_owned(),
            data: vec![1, 2, 3],
        })
        .unwrap();
        for _ in 0..2 {
            bulk_tx.send(bulk.clone()).await.unwrap();
        }
        drop(control_tx);
        drop(input_tx);
        drop(resize_tx);
        drop(bulk_tx);

        let pump = tokio::spawn(pump_client_lanes_to_bridge(
            writer, control_rx, input_rx, resize_rx, bulk_rx,
        ));
        let budget = HerdrFrameBudget::default();
        let mut seen_input_at = None;
        let mut seen_resize_at = None;
        let mut seen_bulk_at = None;
        for index in 0..29 {
            let frame = read_herdr_frame(
                &mut reader,
                FrameDirection::ClientToServer,
                &budget,
                &HerdrReadLimits::default(),
            )
            .await
            .unwrap()
            .unwrap();
            if frame == input && seen_input_at.is_none() {
                seen_input_at = Some(index);
            } else if frame == resize && seen_resize_at.is_none() {
                seen_resize_at = Some(index);
            } else if frame == bulk && seen_bulk_at.is_none() {
                seen_bulk_at = Some(index);
            }
        }
        pump.await.unwrap().unwrap();
        assert!(
            seen_input_at.is_some_and(|index| index <= 5),
            "input frame starved behind control traffic: {seen_input_at:?}"
        );
        assert!(
            seen_resize_at.is_some_and(|index| index <= 13),
            "resize frame starved behind high-priority traffic: {seen_resize_at:?}"
        );
        assert!(
            seen_bulk_at.is_some_and(|index| index <= 14),
            "bulk frame starved behind other lanes: {seen_bulk_at:?}"
        );
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
            HerdrFrameBudget::default(),
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

        let budget = HerdrFrameBudget::default();
        let first = read_herdr_frame(
            &mut reader,
            FrameDirection::ClientToServer,
            &budget,
            &HerdrReadLimits::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            first.decode_client().unwrap(),
            ClientMessage::Hello { .. }
        ));
        let second = read_herdr_frame(
            &mut reader,
            FrameDirection::ClientToServer,
            &budget,
            &HerdrReadLimits::default(),
        )
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

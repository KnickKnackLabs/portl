use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use iroh::endpoint::SendStream;
use portl_core::herdr_wire::{
    ClientLane, ClientMessage, FrameDirection, HerdrFrameError, MAX_FRAME_SIZE, RawHerdrFrame,
    ServerLane,
};
use portl_core::wire::session::{SessionAck, SessionStreamKind, SessionSubTail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tokio::task::JoinHandle;

use crate::AgentState;
use crate::stream_io::BufferedRecv;
use crate::target_context::TargetProcessContext;

const HERDR_LANE_BUFFER: usize = 64;
const HERDR_RESIZE_BUFFER: usize = 1;

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
    let attach = match spawn_herdr_attach(name, context, &audit_session_id, &provider).await {
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

async fn spawn_herdr_attach(
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

impl Drop for HerdrAttach {
    fn drop(&mut self) {
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
                match frame {
                    Some(frame) => Some(frame),
                    None => {
                        control_open = false;
                        None
                    }
                }
            }
            frame = input_rx.recv(), if input_open => {
                match frame {
                    Some(frame) => Some(frame),
                    None => {
                        input_open = false;
                        None
                    }
                }
            }
            frame = resize_rx.recv(), if resize_open => {
                match frame {
                    Some(frame) => Some(frame),
                    None => {
                        resize_open = false;
                        None
                    }
                }
            }
            frame = bulk_rx.recv(), if bulk_open => {
                match frame {
                    Some(frame) => Some(frame),
                    None => {
                        bulk_open = false;
                        None
                    }
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
    while let Some(frame) = read_next_raw_frame(&mut stdout, FrameDirection::ServerToClient).await?
    {
        match frame.server_lane()? {
            ServerLane::Control => control_tx
                .send(frame)
                .await
                .context("send herdr control frame")?,
            ServerLane::Render => render_tx
                .send(frame)
                .await
                .context("send herdr render frame")?,
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
            let tx = self.tx.clone();
            let latest = Arc::clone(&self.latest);
            let scheduled = Arc::clone(&self.scheduled);
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                let frame = latest.lock().await.take();
                scheduled.store(false, std::sync::atomic::Ordering::Release);
                if let Some(frame) = frame {
                    let _ = tx.send(frame).await;
                }
            });
        }
        Ok(())
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
        ClientKeybindings, ClientMessage, HERDR_PROTOCOL_VERSION, RawHerdrFrame, RenderEncoding,
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

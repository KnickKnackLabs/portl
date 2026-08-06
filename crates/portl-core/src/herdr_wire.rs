use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Latest Herdr protocol whose selected message layouts are modeled below.
///
/// This is not a negotiation pin: Portl forwards the real Herdr client/server
/// handshake unchanged. Routing compatibility is verified separately through
/// `HERDR_LATEST_VERIFIED_PROTOCOL_VERSION`.
pub const HERDR_PROTOCOL_VERSION: u32 = 12;
/// Latest protocol whose top-level tags and lane semantics were verified
/// against the authoritative Herdr source.
///
/// Source: <https://github.com/herdrdev/herdr/blob/346411fa21afd297f5ed3b3fa56f9e3fbf7654b7/src/protocol/wire.rs>
pub const HERDR_LATEST_VERIFIED_PROTOCOL_VERSION: u32 = 19;
pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GRAPHICS_FRAME_SIZE: usize = 32 * 1024 * 1024;
pub const MAX_CLIPBOARD_IMAGE_PAYLOAD: usize = 16 * 1024 * 1024;
const LENGTH_PREFIX_BYTES: usize = 4;
pub const HERDR_NORMAL_QUEUED_BYTES: usize = 8 * 1024 * 1024;
pub const HERDR_LARGE_QUEUED_BYTES: usize = 64 * 1024 * 1024;
pub const HERDR_BUDGET_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct HerdrReadLimits {
    pub normal_payload: usize,
    pub large_payload: usize,
    pub clipboard_image_data: usize,
}

impl Default for HerdrReadLimits {
    fn default() -> Self {
        Self {
            normal_payload: MAX_FRAME_SIZE,
            large_payload: MAX_GRAPHICS_FRAME_SIZE,
            clipboard_image_data: MAX_CLIPBOARD_IMAGE_PAYLOAD,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HerdrFrameBudget {
    normal: Arc<Semaphore>,
    large: Arc<Semaphore>,
    timeout: Duration,
}

impl Default for HerdrFrameBudget {
    fn default() -> Self {
        Self::new(
            HERDR_NORMAL_QUEUED_BYTES,
            HERDR_LARGE_QUEUED_BYTES,
            HERDR_BUDGET_TIMEOUT,
        )
    }
}

impl HerdrFrameBudget {
    #[must_use]
    pub fn new(normal_bytes: usize, large_bytes: usize, timeout: Duration) -> Self {
        Self {
            normal: Arc::new(Semaphore::new(normal_bytes)),
            large: Arc::new(Semaphore::new(large_bytes)),
            timeout,
        }
    }

    #[must_use]
    pub fn available_normal_bytes(&self) -> usize {
        self.normal.available_permits()
    }

    #[must_use]
    pub fn available_large_bytes(&self) -> usize {
        self.large.available_permits()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientLane {
    Control,
    Input,
    Resize,
    Bulk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerLane {
    Control,
    Render,
    Bulk,
}

#[derive(Debug, thiserror::Error)]
pub enum HerdrFrameError {
    #[error("Herdr frame length {claimed} exceeds maximum {max}")]
    Oversized { claimed: usize, max: usize },
    #[error("Herdr frame ended before {needed} bytes were available; got {actual}")]
    UnexpectedEof { needed: usize, actual: usize },
    #[error("Herdr bincode error: {0}")]
    Bincode(String),
    #[error("Herdr frame payload length {len} exceeds u32::MAX")]
    TooLargeToEncode { len: usize },
    #[error("Herdr frame I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Herdr enum tag encoding: {0}")]
    InvalidTag(&'static str),
    #[error("Herdr frame payload length must not be zero")]
    ZeroLength,
    #[error("Herdr frame allocation failed for {bytes} bytes")]
    Allocation { bytes: usize },
    #[error("Herdr queued-byte budget was unavailable for {bytes} bytes")]
    SlowConsumer { bytes: usize },
    #[error("Herdr ClipboardImage data length {claimed} exceeds maximum {max}")]
    ClipboardImageOversized { claimed: usize, max: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenderEncoding {
    SemanticFrame,
    TerminalAnsi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientKeybindings {
    Server,
    Local { keys_toml: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientLaunchMode {
    App,
    TerminalAttach,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello {
        version: u32,
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
        requested_encoding: RenderEncoding,
        keybindings: ClientKeybindings,
        launch_mode: ClientLaunchMode,
    },
    Input {
        data: Vec<u8>,
    },
    ClipboardImage {
        extension: String,
        data: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    },
    Detach,
    AttachTerminal {
        terminal_id: String,
        takeover: bool,
    },
    AttachScroll {
        source: AttachScrollSource,
        direction: AttachScrollDirection,
        lines: u16,
        column: Option<u16>,
        row: Option<u16>,
        modifiers: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ClientMessageV11 {
    Hello {
        version: u32,
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
        requested_encoding: RenderEncoding,
        keybindings: ClientKeybindings,
    },
    Input {
        data: Vec<u8>,
    },
    ClipboardImage {
        extension: String,
        data: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    },
    Detach,
    AttachTerminal {
        terminal_id: String,
        takeover: bool,
    },
    AttachScroll {
        source: AttachScrollSource,
        direction: AttachScrollDirection,
        lines: u16,
        column: Option<u16>,
        row: Option<u16>,
        modifiers: u8,
    },
}

impl From<ClientMessageV11> for ClientMessage {
    fn from(message: ClientMessageV11) -> Self {
        match message {
            ClientMessageV11::Hello {
                version,
                cols,
                rows,
                cell_width_px,
                cell_height_px,
                requested_encoding,
                keybindings,
            } => ClientMessage::Hello {
                version,
                cols,
                rows,
                cell_width_px,
                cell_height_px,
                requested_encoding,
                keybindings,
                launch_mode: ClientLaunchMode::App,
            },
            ClientMessageV11::Input { data } => ClientMessage::Input { data },
            ClientMessageV11::ClipboardImage { extension, data } => {
                ClientMessage::ClipboardImage { extension, data }
            }
            ClientMessageV11::Resize {
                cols,
                rows,
                cell_width_px,
                cell_height_px,
            } => ClientMessage::Resize {
                cols,
                rows,
                cell_width_px,
                cell_height_px,
            },
            ClientMessageV11::Detach => ClientMessage::Detach,
            ClientMessageV11::AttachTerminal {
                terminal_id,
                takeover,
            } => ClientMessage::AttachTerminal {
                terminal_id,
                takeover,
            },
            ClientMessageV11::AttachScroll {
                source,
                direction,
                lines,
                column,
                row,
                modifiers,
            } => ClientMessage::AttachScroll {
                source,
                direction,
                lines,
                column,
                row,
                modifiers,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachScrollDirection {
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachScrollSource {
    Wheel,
    PageKey { input: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellData {
    pub symbol: String,
    pub fg: u32,
    pub bg: u32,
    pub modifier: u16,
    pub skip: bool,
    pub hyperlink: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorState {
    pub x: u16,
    pub y: u16,
    pub visible: bool,
    #[serde(default)]
    pub shape: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameData {
    pub cells: Vec<CellData>,
    pub width: u16,
    pub height: u16,
    pub cursor: Option<CursorState>,
    pub hyperlinks: Vec<String>,
    pub graphics: Vec<u8>,
}

impl FrameData {
    #[cfg(test)]
    fn empty_for_test(width: u16, height: u16) -> Self {
        let cell = CellData {
            symbol: " ".to_owned(),
            fg: 0,
            bg: 0,
            modifier: 0,
            skip: false,
            hyperlink: None,
        };
        Self {
            cells: vec![cell; usize::from(width) * usize::from(height)],
            width,
            height,
            cursor: None,
            hyperlinks: Vec::new(),
            graphics: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalFrame {
    pub seq: u64,
    pub width: u16,
    pub height: u16,
    pub full: bool,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotifyKind {
    Sound,
    Toast,
    SystemToast,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    Welcome {
        version: u32,
        encoding: RenderEncoding,
        error: Option<String>,
    },
    Frame(FrameData),
    Terminal(TerminalFrame),
    Graphics {
        bytes: Vec<u8>,
    },
    ServerShutdown {
        reason: Option<String>,
    },
    Notify {
        kind: NotifyKind,
        message: String,
    },
    Clipboard {
        data: String,
    },
    ReloadSoundConfig,
    MouseCapture {
        enabled: bool,
    },
}

#[must_use]
pub const fn client_lane(message: &ClientMessage) -> ClientLane {
    match message {
        ClientMessage::Hello { .. }
        | ClientMessage::Detach
        | ClientMessage::AttachTerminal { .. } => ClientLane::Control,
        ClientMessage::Input { .. } | ClientMessage::AttachScroll { .. } => ClientLane::Input,
        ClientMessage::Resize { .. } => ClientLane::Resize,
        ClientMessage::ClipboardImage { .. } => ClientLane::Bulk,
    }
}

#[must_use]
pub const fn client_lane_from_variant_tag(tag: u32) -> ClientLane {
    match tag {
        // Protocol 13 added structured InputEvents at tag 7. Protocols 18 and
        // 19 changed its payload but retained the top-level input semantics.
        1 | 6 | 7 => ClientLane::Input,
        2 => ClientLane::Bulk,
        3 => ClientLane::Resize,
        _ => ClientLane::Control,
    }
}

#[must_use]
pub const fn server_lane(message: &ServerMessage) -> ServerLane {
    match message {
        ServerMessage::Welcome { .. }
        | ServerMessage::ServerShutdown { .. }
        | ServerMessage::Notify { .. }
        | ServerMessage::ReloadSoundConfig
        | ServerMessage::MouseCapture { .. } => ServerLane::Control,
        ServerMessage::Frame(_) | ServerMessage::Terminal(_) => ServerLane::Render,
        ServerMessage::Graphics { .. } | ServerMessage::Clipboard { .. } => ServerLane::Bulk,
    }
}

#[must_use]
pub const fn server_lane_from_variant_tag(tag: u32) -> ServerLane {
    match tag {
        1 | 2 => ServerLane::Render,
        3 | 6 => ServerLane::Bulk,
        _ => ServerLane::Control,
    }
}

#[derive(Debug)]
struct HerdrFrameStorage {
    framed: Vec<u8>,
    // The permit and bytes have exactly the same shared lifetime.
    _budget: Option<OwnedSemaphorePermit>,
}

#[derive(Debug, Clone)]
pub struct RawHerdrFrame {
    direction: FrameDirection,
    storage: Arc<HerdrFrameStorage>,
}

impl PartialEq for RawHerdrFrame {
    fn eq(&self, other: &Self) -> bool {
        self.direction == other.direction && self.storage.framed == other.storage.framed
    }
}

impl Eq for RawHerdrFrame {}

impl RawHerdrFrame {
    pub fn encode_client(message: &ClientMessage) -> Result<Self, HerdrFrameError> {
        encode_frame(FrameDirection::ClientToServer, message)
    }

    pub fn encode_server(message: &ServerMessage) -> Result<Self, HerdrFrameError> {
        encode_frame(FrameDirection::ServerToClient, message)
    }

    pub fn decode_client_from_bytes(bytes: &[u8]) -> Result<Self, HerdrFrameError> {
        validate_raw_frame(bytes, FrameDirection::ClientToServer)?;
        Ok(Self {
            direction: FrameDirection::ClientToServer,
            storage: Arc::new(HerdrFrameStorage {
                framed: bytes.to_vec(),
                _budget: None,
            }),
        })
    }

    pub fn decode_server_from_bytes(bytes: &[u8]) -> Result<Self, HerdrFrameError> {
        validate_raw_frame(bytes, FrameDirection::ServerToClient)?;
        Ok(Self {
            direction: FrameDirection::ServerToClient,
            storage: Arc::new(HerdrFrameStorage {
                framed: bytes.to_vec(),
                _budget: None,
            }),
        })
    }

    #[must_use]
    pub const fn direction(&self) -> FrameDirection {
        self.direction
    }

    #[must_use]
    pub fn framed_bytes(&self) -> &[u8] {
        &self.storage.framed
    }

    pub fn decode_client(&self) -> Result<ClientMessage, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ClientToServer)?;
        decode_client_payload(&self.storage.framed)
    }

    pub fn decode_server(&self) -> Result<ServerMessage, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ServerToClient)?;
        decode_payload(&self.storage.framed)
    }

    pub fn client_variant_tag(&self) -> Result<u32, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ClientToServer)?;
        frame_variant_tag(&self.storage.framed)
    }

    pub fn server_variant_tag(&self) -> Result<u32, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ServerToClient)?;
        frame_variant_tag(&self.storage.framed)
    }

    pub fn is_client_hello(&self) -> Result<bool, HerdrFrameError> {
        self.client_variant_tag().map(|tag| tag == 0)
    }

    pub fn is_server_welcome(&self) -> Result<bool, HerdrFrameError> {
        self.server_variant_tag().map(|tag| tag == 0)
    }

    pub fn client_lane(&self) -> Result<ClientLane, HerdrFrameError> {
        self.client_variant_tag().map(client_lane_from_variant_tag)
    }

    pub fn server_lane(&self) -> Result<ServerLane, HerdrFrameError> {
        self.server_variant_tag().map(server_lane_from_variant_tag)
    }
}

fn encode_frame<T: Serialize>(
    direction: FrameDirection,
    message: &T,
) -> Result<RawHerdrFrame, HerdrFrameError> {
    let payload = bincode::serde::encode_to_vec(message, bincode::config::standard())
        .map_err(|err| HerdrFrameError::Bincode(err.to_string()))?;
    let len = payload.len();
    let len_u32 = u32::try_from(len).map_err(|_| HerdrFrameError::TooLargeToEncode { len })?;
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + len);
    framed.extend_from_slice(&len_u32.to_le_bytes());
    framed.extend_from_slice(&payload);
    Ok(RawHerdrFrame {
        direction,
        storage: Arc::new(HerdrFrameStorage {
            framed,
            _budget: None,
        }),
    })
}

fn validate_raw_frame(bytes: &[u8], direction: FrameDirection) -> Result<(), HerdrFrameError> {
    if bytes.len() < LENGTH_PREFIX_BYTES {
        return Err(HerdrFrameError::UnexpectedEof {
            needed: LENGTH_PREFIX_BYTES,
            actual: bytes.len(),
        });
    }
    let claimed =
        u32::from_le_bytes(bytes[..LENGTH_PREFIX_BYTES].try_into().expect("slice len")) as usize;
    if claimed == 0 {
        return Err(HerdrFrameError::ZeroLength);
    }
    let tag_bytes = bytes
        .get(LENGTH_PREFIX_BYTES..)
        .ok_or(HerdrFrameError::UnexpectedEof {
            needed: LENGTH_PREFIX_BYTES + 1,
            actual: bytes.len(),
        })?;
    let (tag, _) = decode_tag_prefix(tag_bytes)?;
    let max = frame_payload_limit(direction, tag, &HerdrReadLimits::default());
    if claimed > max {
        return Err(HerdrFrameError::Oversized { claimed, max });
    }
    let _ = frame_variant_tag(bytes)?;
    Ok(())
}

fn decode_client_payload(bytes: &[u8]) -> Result<ClientMessage, HerdrFrameError> {
    match decode_payload::<ClientMessage>(bytes) {
        Ok(message) => Ok(message),
        Err(latest_err) => decode_payload::<ClientMessageV11>(bytes)
            .map(ClientMessage::from)
            .or(Err(latest_err)),
    }
}

fn frame_variant_tag(bytes: &[u8]) -> Result<u32, HerdrFrameError> {
    let payload = frame_payload(bytes)?;
    let (tag, consumed): (u32, usize) =
        bincode::serde::decode_from_slice(payload, bincode::config::standard())
            .map_err(|err| HerdrFrameError::Bincode(err.to_string()))?;
    if consumed == 0 {
        return Err(HerdrFrameError::Bincode(
            "decoded empty Herdr variant tag".to_owned(),
        ));
    }
    Ok(tag)
}

fn frame_payload(bytes: &[u8]) -> Result<&[u8], HerdrFrameError> {
    if bytes.len() < LENGTH_PREFIX_BYTES {
        return Err(HerdrFrameError::UnexpectedEof {
            needed: LENGTH_PREFIX_BYTES,
            actual: bytes.len(),
        });
    }
    let claimed =
        u32::from_le_bytes(bytes[..LENGTH_PREFIX_BYTES].try_into().expect("slice len")) as usize;
    if claimed > MAX_GRAPHICS_FRAME_SIZE {
        return Err(HerdrFrameError::Oversized {
            claimed,
            max: MAX_GRAPHICS_FRAME_SIZE,
        });
    }
    let needed = LENGTH_PREFIX_BYTES + claimed;
    if bytes.len() < needed {
        return Err(HerdrFrameError::UnexpectedEof {
            needed,
            actual: bytes.len(),
        });
    }
    if bytes.len() > needed {
        return Err(HerdrFrameError::Bincode(format!(
            "frame contains {} trailing bytes",
            bytes.len() - needed
        )));
    }
    Ok(&bytes[LENGTH_PREFIX_BYTES..needed])
}

fn decode_payload<T>(bytes: &[u8]) -> Result<T, HerdrFrameError>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = frame_payload(bytes)?;
    let (message, consumed) =
        bincode::serde::decode_from_slice(payload, bincode::config::standard())
            .map_err(|err| HerdrFrameError::Bincode(err.to_string()))?;
    if consumed != payload.len() {
        return Err(HerdrFrameError::Bincode(format!(
            "decoded {consumed} bytes but payload length was {}",
            payload.len()
        )));
    }
    Ok(message)
}

fn ensure_direction(
    actual: FrameDirection,
    expected: FrameDirection,
) -> Result<(), HerdrFrameError> {
    if actual == expected {
        Ok(())
    } else {
        Err(HerdrFrameError::Bincode(format!(
            "wrong Herdr frame direction: expected {expected:?}, got {actual:?}"
        )))
    }
}

/// Reads one Herdr frame while applying direction/tag-aware limits and a shared
/// queued-byte budget before allocating the complete payload.
pub async fn read_herdr_frame<R>(
    reader: &mut R,
    direction: FrameDirection,
    budget: &HerdrFrameBudget,
    limits: &HerdrReadLimits,
) -> Result<Option<RawHerdrFrame>, HerdrFrameError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0_u8; LENGTH_PREFIX_BYTES];
    let read = reader.read(&mut len_buf[..1]).await?;
    if read == 0 {
        return Ok(None);
    }
    read_exact_counted(reader, &mut len_buf[1..], LENGTH_PREFIX_BYTES, 1).await?;
    let claimed = u32::from_le_bytes(len_buf) as usize;
    if claimed == 0 {
        return Err(HerdrFrameError::ZeroLength);
    }

    let mut tag_bytes = [0_u8; 5];
    read_exact_counted(reader, &mut tag_bytes[..1], 1, 0).await?;
    let tag_len = match tag_bytes[0] {
        0..=250 => 1,
        251 => 3,
        252 => 5,
        253..=255 => {
            return Err(HerdrFrameError::InvalidTag(
                "reserved or overflowing marker",
            ));
        }
    };
    if tag_len > claimed {
        return Err(HerdrFrameError::UnexpectedEof {
            needed: tag_len,
            actual: claimed,
        });
    }
    if tag_len > 1 {
        read_exact_counted(reader, &mut tag_bytes[1..tag_len], tag_len, 1).await?;
    }
    let tag = decode_compact_u32(&tag_bytes[..tag_len])?;
    let large = is_large_frame(direction, tag);
    let max = frame_payload_limit(direction, tag, limits);
    if claimed > max {
        return Err(HerdrFrameError::Oversized { claimed, max });
    }
    let total = LENGTH_PREFIX_BYTES
        .checked_add(claimed)
        .ok_or(HerdrFrameError::Allocation { bytes: claimed })?;
    let permits = u32::try_from(total).map_err(|_| HerdrFrameError::Allocation { bytes: total })?;
    let semaphore = if large { &budget.large } else { &budget.normal };
    let permit = tokio::time::timeout(
        budget.timeout,
        Arc::clone(semaphore).acquire_many_owned(permits),
    )
    .await
    .map_err(|_| HerdrFrameError::SlowConsumer { bytes: total })?
    .map_err(|_| HerdrFrameError::SlowConsumer { bytes: total })?;
    let mut framed = Vec::new();
    framed
        .try_reserve_exact(total)
        .map_err(|_| HerdrFrameError::Allocation { bytes: total })?;
    framed.extend_from_slice(&len_buf);
    framed.extend_from_slice(&tag_bytes[..tag_len]);
    framed.resize(total, 0);
    read_exact_counted(
        reader,
        &mut framed[LENGTH_PREFIX_BYTES + tag_len..],
        claimed,
        tag_len,
    )
    .await?;

    if direction == FrameDirection::ClientToServer && tag == 2 {
        validate_clipboard_image(&framed[LENGTH_PREFIX_BYTES..], limits.clipboard_image_data)?;
    }
    Ok(Some(RawHerdrFrame {
        direction,
        storage: Arc::new(HerdrFrameStorage {
            framed,
            _budget: Some(permit),
        }),
    }))
}

async fn read_exact_counted<R: AsyncRead + Unpin>(
    reader: &mut R,
    dst: &mut [u8],
    needed: usize,
    already: usize,
) -> Result<(), HerdrFrameError> {
    let mut actual = already;
    while actual - already < dst.len() {
        match reader.read(&mut dst[actual - already..]).await {
            Ok(0) => return Err(HerdrFrameError::UnexpectedEof { needed, actual }),
            Ok(n) => actual += n,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(HerdrFrameError::UnexpectedEof { needed, actual });
            }
            Err(err) => return Err(HerdrFrameError::Io(err)),
        }
    }
    Ok(())
}

fn decode_tag_prefix(bytes: &[u8]) -> Result<(u32, usize), HerdrFrameError> {
    let marker = *bytes.first().ok_or(HerdrFrameError::UnexpectedEof {
        needed: 1,
        actual: 0,
    })?;
    let width = match marker {
        0..=250 => 1,
        251 => 3,
        252 => 5,
        253..=255 => {
            return Err(HerdrFrameError::InvalidTag(
                "reserved or overflowing marker",
            ));
        }
    };
    let encoded = bytes.get(..width).ok_or(HerdrFrameError::UnexpectedEof {
        needed: width,
        actual: bytes.len(),
    })?;
    Ok((decode_compact_u32(encoded)?, width))
}

const fn is_large_frame(direction: FrameDirection, tag: u32) -> bool {
    matches!(direction, FrameDirection::ClientToServer) && tag == 2
        || matches!(direction, FrameDirection::ServerToClient) && matches!(tag, 1 | 3)
}

const fn frame_payload_limit(
    direction: FrameDirection,
    tag: u32,
    limits: &HerdrReadLimits,
) -> usize {
    if is_large_frame(direction, tag) {
        limits.large_payload
    } else {
        limits.normal_payload
    }
}

fn decode_compact_u32(bytes: &[u8]) -> Result<u32, HerdrFrameError> {
    match bytes {
        [value @ 0..=250] => Ok(u32::from(*value)),
        [251, lo, hi] => {
            let value = u16::from_le_bytes([*lo, *hi]);
            (value > 250)
                .then_some(u32::from(value))
                .ok_or(HerdrFrameError::InvalidTag("non-canonical u16"))
        }
        [252, a, b, c, d] => {
            let value = u32::from_le_bytes([*a, *b, *c, *d]);
            (value > u32::from(u16::MAX))
                .then_some(value)
                .ok_or(HerdrFrameError::InvalidTag("non-canonical u32"))
        }
        _ => Err(HerdrFrameError::InvalidTag("invalid length")),
    }
}

fn parse_varint_usize(bytes: &[u8], offset: &mut usize) -> Result<usize, HerdrFrameError> {
    let marker = *bytes.get(*offset).ok_or(HerdrFrameError::UnexpectedEof {
        needed: *offset + 1,
        actual: bytes.len(),
    })?;
    let width = match marker {
        0..=250 => 1,
        251 => 3,
        252 => 5,
        253 => 9,
        _ => return Err(HerdrFrameError::InvalidTag("invalid length varint")),
    };
    let end = offset
        .checked_add(width)
        .ok_or(HerdrFrameError::Allocation { bytes: usize::MAX })?;
    let raw = bytes
        .get(*offset..end)
        .ok_or(HerdrFrameError::UnexpectedEof {
            needed: end,
            actual: bytes.len(),
        })?;
    *offset = end;
    let value = match raw {
        [v] => u64::from(*v),
        [251, a, b] => u64::from(u16::from_le_bytes([*a, *b])),
        [252, a, b, c, d] => u64::from(u32::from_le_bytes([*a, *b, *c, *d])),
        [253, octets @ ..] => u64::from_le_bytes(octets.try_into().expect("matched eight bytes")),
        _ => unreachable!(),
    };
    let canonical = match width {
        1 => true,
        3 => value > 250,
        5 => value > u64::from(u16::MAX),
        9 => value > u64::from(u32::MAX),
        _ => unreachable!(),
    };
    if !canonical {
        return Err(HerdrFrameError::InvalidTag(
            "non-canonical collection length",
        ));
    }
    usize::try_from(value).map_err(|_| HerdrFrameError::Allocation { bytes: usize::MAX })
}

fn validate_clipboard_image(payload: &[u8], max: usize) -> Result<(), HerdrFrameError> {
    let (tag, tag_len) = decode_tag_prefix(payload)?;
    if tag != 2 {
        return Err(HerdrFrameError::InvalidTag("expected ClipboardImage"));
    }
    let mut offset = tag_len;
    let extension_len = parse_varint_usize(payload, &mut offset)?;
    let extension_end = offset
        .checked_add(extension_len)
        .ok_or(HerdrFrameError::Allocation { bytes: usize::MAX })?;
    let extension = payload
        .get(offset..extension_end)
        .ok_or(HerdrFrameError::UnexpectedEof {
            needed: extension_end,
            actual: payload.len(),
        })?;
    if std::str::from_utf8(extension).is_err() {
        return Err(HerdrFrameError::Bincode(
            "ClipboardImage extension is not UTF-8".to_owned(),
        ));
    }
    offset = extension_end;
    if offset > payload.len() {
        return Err(HerdrFrameError::UnexpectedEof {
            needed: offset,
            actual: payload.len(),
        });
    }
    let data_len = parse_varint_usize(payload, &mut offset)?;
    if data_len > max {
        return Err(HerdrFrameError::ClipboardImageOversized {
            claimed: data_len,
            max,
        });
    }
    let end = offset
        .checked_add(data_len)
        .ok_or(HerdrFrameError::Allocation { bytes: usize::MAX })?;
    if end != payload.len() {
        return Err(HerdrFrameError::Bincode(
            "malformed ClipboardImage payload".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn classifies_client_messages_into_priority_lanes() {
        assert_eq!(
            client_lane(&ClientMessage::Hello {
                version: HERDR_PROTOCOL_VERSION,
                cols: 80,
                rows: 24,
                cell_width_px: 0,
                cell_height_px: 0,
                requested_encoding: RenderEncoding::SemanticFrame,
                keybindings: ClientKeybindings::Server,
                launch_mode: ClientLaunchMode::App,
            }),
            ClientLane::Control
        );
        assert_eq!(
            client_lane(&ClientMessage::Input {
                data: b"x".to_vec(),
            }),
            ClientLane::Input
        );
        assert_eq!(
            client_lane(&ClientMessage::Resize {
                cols: 100,
                rows: 40,
                cell_width_px: 0,
                cell_height_px: 0,
            }),
            ClientLane::Resize
        );
        assert_eq!(
            client_lane(&ClientMessage::ClipboardImage {
                extension: "png".to_owned(),
                data: vec![1, 2, 3],
            }),
            ClientLane::Bulk
        );
        assert_eq!(client_lane(&ClientMessage::Detach), ClientLane::Control);
    }

    #[test]
    fn classifies_server_messages_into_priority_lanes() {
        assert_eq!(
            server_lane(&ServerMessage::Welcome {
                version: HERDR_PROTOCOL_VERSION,
                encoding: RenderEncoding::SemanticFrame,
                error: None,
            }),
            ServerLane::Control
        );
        assert_eq!(
            server_lane(&ServerMessage::Frame(FrameData::empty_for_test(80, 24))),
            ServerLane::Render
        );
        assert_eq!(
            server_lane(&ServerMessage::Terminal(TerminalFrame {
                seq: 1,
                width: 80,
                height: 24,
                full: true,
                bytes: b"redraw".to_vec(),
            })),
            ServerLane::Render
        );
        assert_eq!(
            server_lane(&ServerMessage::Graphics { bytes: vec![1, 2] }),
            ServerLane::Bulk
        );
        assert_eq!(
            server_lane(&ServerMessage::Clipboard {
                data: "abc".to_owned(),
            }),
            ServerLane::Bulk
        );
        assert_eq!(
            server_lane(&ServerMessage::MouseCapture { enabled: true }),
            ServerLane::Control
        );
    }

    fn raw_frame_with_variant(tag: u32, extra_payload: &[u8]) -> Vec<u8> {
        let mut payload = bincode::serde::encode_to_vec(tag, bincode::config::standard())
            .expect("encode variant tag");
        payload.extend_from_slice(extra_payload);
        let frame_len =
            u32::try_from(payload.len()).expect("test payload fits in u32 frame length");
        let mut framed = Vec::new();
        framed.extend_from_slice(&frame_len.to_le_bytes());
        framed.extend_from_slice(&payload);
        framed
    }

    #[test]
    fn raw_frames_classify_unknown_variants_as_control_without_full_decode() {
        let client = RawHerdrFrame::decode_client_from_bytes(&raw_frame_with_variant(
            99,
            b"future-client-payload",
        ))
        .expect("accept unknown client variant");
        let server = RawHerdrFrame::decode_server_from_bytes(&raw_frame_with_variant(
            99,
            b"future-server-payload",
        ))
        .expect("accept unknown server variant");

        assert_eq!(client.client_variant_tag().expect("client tag"), 99);
        assert_eq!(server.server_variant_tag().expect("server tag"), 99);
        assert_eq!(
            client.client_lane().expect("client lane"),
            ClientLane::Control
        );
        assert_eq!(
            server.server_lane().expect("server lane"),
            ServerLane::Control
        );
        assert!(client.decode_client().is_err());
        assert!(server.decode_server().is_err());
    }

    #[test]
    fn protocol_19_structured_input_fixture_uses_input_lane_and_is_preserved() {
        // ClientMessage::InputEvents fixture frozen by Herdr protocol 19 at
        // v0.8.0 (346411fa21afd297f5ed3b3fa56f9e3fbf7654b7).
        let payload = vec![
            7, 5, 0, 15, 78, 1, 0, 1, 0, 0, 0, 0, 0, 0, 3, 0, 1, 8, 27, 91, 49, 50, 55, 59, 49,
            117, 0, 14, 0, 2, 1, 0, 2, 0, 1, 27, 1, 27, 0, 1, 7, 228, 189, 160, 240, 159, 153, 130,
            2, 0, 0, 3, 4, 0,
        ];
        let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
        framed.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("fixture length fits u32")
                .to_le_bytes(),
        );
        framed.extend_from_slice(&payload);

        let raw = RawHerdrFrame::decode_client_from_bytes(&framed)
            .expect("accept protocol 19 structured input");

        assert_eq!(raw.client_variant_tag().expect("tag"), 7);
        assert_eq!(raw.client_lane().expect("lane"), ClientLane::Input);
        assert_eq!(raw.framed_bytes(), framed);
        assert!(raw.decode_client().is_err());
    }

    #[test]
    fn protocol_19_top_level_tags_map_to_safe_lanes() {
        for tag in 0..=9 {
            let expected = match tag {
                1 | 6 | 7 => ClientLane::Input,
                2 => ClientLane::Bulk,
                3 => ClientLane::Resize,
                _ => ClientLane::Control,
            };
            assert_eq!(
                client_lane_from_variant_tag(tag),
                expected,
                "client tag {tag}"
            );
        }
        for tag in 0..=11 {
            let expected = match tag {
                1 | 2 => ServerLane::Render,
                3 | 6 => ServerLane::Bulk,
                _ => ServerLane::Control,
            };
            assert_eq!(
                server_lane_from_variant_tag(tag),
                expected,
                "server tag {tag}"
            );
        }
    }

    #[test]
    fn raw_frames_expose_future_hello_and_welcome_tags_without_full_decode() {
        let client = RawHerdrFrame::decode_client_from_bytes(&raw_frame_with_variant(
            0,
            b"future-hello-field",
        ))
        .expect("accept future hello");
        let server = RawHerdrFrame::decode_server_from_bytes(&raw_frame_with_variant(
            0,
            b"future-welcome-field",
        ))
        .expect("accept future welcome");

        assert!(client.is_client_hello().expect("client hello tag"));
        assert!(server.is_server_welcome().expect("server welcome tag"));
        assert_eq!(
            client.client_lane().expect("client lane"),
            ClientLane::Control
        );
        assert_eq!(
            server.server_lane().expect("server lane"),
            ServerLane::Control
        );
    }

    #[test]
    fn raw_frame_accepts_protocol_12_hello_for_lane_classification() {
        let raw = RawHerdrFrame::encode_client(&ClientMessage::Hello {
            version: HERDR_PROTOCOL_VERSION,
            cols: 80,
            rows: 24,
            cell_width_px: 0,
            cell_height_px: 0,
            requested_encoding: RenderEncoding::SemanticFrame,
            keybindings: ClientKeybindings::Server,
            launch_mode: ClientLaunchMode::TerminalAttach,
        })
        .expect("encode protocol 12 hello");

        assert_eq!(raw.client_lane().expect("lane"), ClientLane::Control);
        assert_eq!(
            raw.decode_client().expect("decode"),
            ClientMessage::Hello {
                version: HERDR_PROTOCOL_VERSION,
                cols: 80,
                rows: 24,
                cell_width_px: 0,
                cell_height_px: 0,
                requested_encoding: RenderEncoding::SemanticFrame,
                keybindings: ClientKeybindings::Server,
                launch_mode: ClientLaunchMode::TerminalAttach,
            }
        );
    }

    #[test]
    fn raw_frame_accepts_protocol_11_hello_as_app_launch_mode() {
        let raw = encode_frame(
            FrameDirection::ClientToServer,
            &ClientMessageV11::Hello {
                version: 11,
                cols: 80,
                rows: 24,
                cell_width_px: 0,
                cell_height_px: 0,
                requested_encoding: RenderEncoding::SemanticFrame,
                keybindings: ClientKeybindings::Server,
            },
        )
        .expect("encode protocol 11 hello");

        assert_eq!(raw.client_lane().expect("lane"), ClientLane::Control);
        assert_eq!(
            raw.decode_client().expect("decode"),
            ClientMessage::Hello {
                version: 11,
                cols: 80,
                rows: 24,
                cell_width_px: 0,
                cell_height_px: 0,
                requested_encoding: RenderEncoding::SemanticFrame,
                keybindings: ClientKeybindings::Server,
                launch_mode: ClientLaunchMode::App,
            }
        );
    }

    #[test]
    fn raw_frame_roundtrips_with_bincode_v2_length_prefix() {
        let msg = ClientMessage::Input {
            data: b"hello".to_vec(),
        };

        let raw = RawHerdrFrame::encode_client(&msg).expect("encode");

        assert_eq!(raw.direction(), FrameDirection::ClientToServer);
        assert_eq!(raw.client_lane().expect("lane"), ClientLane::Input);
        assert_eq!(raw.decode_client().expect("decode"), msg);
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let claimed = u32::try_from(MAX_FRAME_SIZE).expect("max frame size fits u32") + 1;
        let bytes = [claimed.to_le_bytes().as_slice(), &[99]].concat();

        let err = RawHerdrFrame::decode_client_from_bytes(&bytes).unwrap_err();

        assert!(matches!(err, HerdrFrameError::Oversized { .. }));
    }

    fn test_budget(bytes: usize) -> HerdrFrameBudget {
        HerdrFrameBudget::new(bytes, bytes, Duration::from_millis(20))
    }

    #[tokio::test]
    async fn async_reader_distinguishes_clean_eof_and_partial_prefixes() {
        let limits = HerdrReadLimits::default();
        for len in 0..4 {
            let bytes = vec![1_u8; len];
            let mut input = bytes.as_slice();
            let result = read_herdr_frame(
                &mut input,
                FrameDirection::ClientToServer,
                &test_budget(64),
                &limits,
            )
            .await;
            if len == 0 {
                assert!(matches!(result, Ok(None)));
            } else {
                assert!(
                    matches!(result, Err(HerdrFrameError::UnexpectedEof { .. })),
                    "prefix {len}"
                );
            }
        }
    }

    #[tokio::test]
    async fn async_reader_rejects_zero_invalid_and_unknown_oversized_frames() {
        let limits = HerdrReadLimits {
            normal_payload: 4,
            large_payload: 16,
            clipboard_image_data: 8,
        };
        for bytes in [
            0_u32.to_le_bytes().to_vec(),
            [1_u32.to_le_bytes().as_slice(), &[253]].concat(),
        ] {
            let mut input = bytes.as_slice();
            assert!(
                read_herdr_frame(
                    &mut input,
                    FrameDirection::ClientToServer,
                    &test_budget(64),
                    &limits
                )
                .await
                .is_err()
            );
        }
        let bytes = [5_u32.to_le_bytes().as_slice(), &[99, 0, 0, 0, 0]].concat();
        let mut input = bytes.as_slice();
        assert!(matches!(
            read_herdr_frame(
                &mut input,
                FrameDirection::ClientToServer,
                &test_budget(64),
                &limits
            )
            .await,
            Err(HerdrFrameError::Oversized { .. })
        ));
    }

    #[tokio::test]
    async fn budget_counts_shared_frame_once_and_releases_after_last_clone() {
        let raw = raw_frame_with_variant(1, b"x");
        let total = raw.len();
        let budget = test_budget(total);
        let mut input = raw.as_slice();
        let frame = read_herdr_frame(
            &mut input,
            FrameDirection::ClientToServer,
            &budget,
            &HerdrReadLimits::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(budget.available_normal_bytes(), 0);
        let clone = frame.clone();
        drop(frame);
        assert_eq!(budget.available_normal_bytes(), 0);
        drop(clone);
        assert_eq!(budget.available_normal_bytes(), total);
    }

    #[tokio::test]
    async fn budget_timeout_is_typed_and_cancellation_releases_waiter() {
        let raw = raw_frame_with_variant(1, b"x");
        let budget = test_budget(raw.len() - 1);
        let mut input = raw.as_slice();
        assert!(matches!(
            read_herdr_frame(
                &mut input,
                FrameDirection::ClientToServer,
                &budget,
                &HerdrReadLimits::default()
            )
            .await,
            Err(HerdrFrameError::SlowConsumer { .. })
        ));
        assert_eq!(budget.available_normal_bytes(), raw.len() - 1);
    }

    #[tokio::test]
    async fn async_reader_enforces_exact_normal_and_graphics_boundaries() {
        for (direction, tag, max) in [
            (FrameDirection::ClientToServer, 99_u8, MAX_FRAME_SIZE),
            (
                FrameDirection::ServerToClient,
                1_u8,
                MAX_GRAPHICS_FRAME_SIZE,
            ),
            (
                FrameDirection::ServerToClient,
                3_u8,
                MAX_GRAPHICS_FRAME_SIZE,
            ),
        ] {
            let mut exact = Vec::new();
            exact.extend_from_slice(&u32::try_from(max).unwrap().to_le_bytes());
            exact.push(tag);
            exact.resize(LENGTH_PREFIX_BYTES + max, 0);
            let budget = HerdrFrameBudget::new(
                MAX_FRAME_SIZE + LENGTH_PREFIX_BYTES,
                MAX_GRAPHICS_FRAME_SIZE + LENGTH_PREFIX_BYTES,
                Duration::from_secs(1),
            );
            let mut input = exact.as_slice();
            let frame =
                read_herdr_frame(&mut input, direction, &budget, &HerdrReadLimits::default())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(frame.framed_bytes().len(), LENGTH_PREFIX_BYTES + max);
            drop(frame);

            let over = u32::try_from(max + 1).unwrap();
            let oversized = [over.to_le_bytes().as_slice(), &[tag]].concat();
            let mut input = oversized.as_slice();
            assert!(matches!(
                read_herdr_frame(
                    &mut input,
                    direction,
                    &budget,
                    &HerdrReadLimits::default()
                )
                .await,
                Err(HerdrFrameError::Oversized { claimed, max: limit })
                    if claimed == max + 1 && limit == max
            ));
        }
    }

    #[tokio::test]
    async fn async_reader_enforces_clipboard_image_data_boundary() {
        for (data_len, accepted) in [
            (MAX_CLIPBOARD_IMAGE_PAYLOAD, true),
            (MAX_CLIPBOARD_IMAGE_PAYLOAD + 1, false),
        ] {
            let raw = RawHerdrFrame::encode_client(&ClientMessage::ClipboardImage {
                extension: "png".to_owned(),
                data: vec![0; data_len],
            })
            .unwrap();
            let mut input = raw.framed_bytes();
            let result = read_herdr_frame(
                &mut input,
                FrameDirection::ClientToServer,
                &HerdrFrameBudget::default(),
                &HerdrReadLimits::default(),
            )
            .await;
            if accepted {
                assert!(result.unwrap().is_some());
            } else {
                assert!(matches!(
                    result,
                    Err(HerdrFrameError::ClipboardImageOversized { claimed, max })
                        if claimed == data_len && max == MAX_CLIPBOARD_IMAGE_PAYLOAD
                ));
            }
        }
    }

    #[tokio::test]
    async fn async_reader_rejects_truncated_body_and_noncanonical_tags() {
        let limits = HerdrReadLimits::default();
        let budget = test_budget(64);
        for bytes in [
            [4_u32.to_le_bytes().as_slice(), &[1, 2]].concat(),
            [3_u32.to_le_bytes().as_slice(), &[251, 1, 0]].concat(),
            [5_u32.to_le_bytes().as_slice(), &[252, 251, 0, 0, 0]].concat(),
            [3_u32.to_le_bytes().as_slice(), &[251, 1]].concat(),
        ] {
            let mut input = bytes.as_slice();
            assert!(
                read_herdr_frame(&mut input, FrameDirection::ClientToServer, &budget, &limits,)
                    .await
                    .is_err(),
                "accepted malformed frame {bytes:?}"
            );
        }
    }

    #[tokio::test]
    async fn cancellation_during_body_read_releases_byte_budget() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let budget = test_budget(20);
        let task_budget = budget.clone();
        let task = tokio::spawn(async move {
            read_herdr_frame(
                &mut reader,
                FrameDirection::ClientToServer,
                &task_budget,
                &HerdrReadLimits::default(),
            )
            .await
        });
        writer.write_all(&16_u32.to_le_bytes()).await.unwrap();
        writer.write_all(&[1]).await.unwrap();
        for _ in 0..100 {
            if budget.available_normal_bytes() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.available_normal_bytes(), 0);
        task.abort();
        let _ = task.await;
        assert_eq!(budget.available_normal_bytes(), 20);
    }

    #[test]
    fn tag_and_size_classification_is_total_for_arbitrary_prefix_bytes() {
        for marker in 0_u8..=u8::MAX {
            for len in 0..=5 {
                let bytes = vec![marker; len];
                let _ = decode_tag_prefix(&bytes);
            }
        }
        for direction in [
            FrameDirection::ClientToServer,
            FrameDirection::ServerToClient,
        ] {
            for tag in 0..=512 {
                let limit = frame_payload_limit(direction, tag, &HerdrReadLimits::default());
                assert!(matches!(limit, MAX_FRAME_SIZE | MAX_GRAPHICS_FRAME_SIZE));
            }
        }
    }
}

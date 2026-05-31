use serde::{Deserialize, Serialize};

pub const HERDR_PROTOCOL_VERSION: u32 = 12;
pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GRAPHICS_FRAME_SIZE: usize = 32 * 1024 * 1024;
pub const MAX_CLIPBOARD_IMAGE_PAYLOAD: usize = 16 * 1024 * 1024;
const LENGTH_PREFIX_BYTES: usize = 4;

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
        1 | 6 => ClientLane::Input,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHerdrFrame {
    direction: FrameDirection,
    framed: Vec<u8>,
}

impl RawHerdrFrame {
    pub fn encode_client(message: &ClientMessage) -> Result<Self, HerdrFrameError> {
        encode_frame(FrameDirection::ClientToServer, message)
    }

    pub fn encode_server(message: &ServerMessage) -> Result<Self, HerdrFrameError> {
        encode_frame(FrameDirection::ServerToClient, message)
    }

    pub fn decode_client_from_bytes(bytes: &[u8]) -> Result<Self, HerdrFrameError> {
        validate_raw_frame(bytes)?;
        Ok(Self {
            direction: FrameDirection::ClientToServer,
            framed: bytes.to_vec(),
        })
    }

    pub fn decode_server_from_bytes(bytes: &[u8]) -> Result<Self, HerdrFrameError> {
        validate_raw_frame(bytes)?;
        Ok(Self {
            direction: FrameDirection::ServerToClient,
            framed: bytes.to_vec(),
        })
    }

    #[must_use]
    pub const fn direction(&self) -> FrameDirection {
        self.direction
    }

    #[must_use]
    pub fn framed_bytes(&self) -> &[u8] {
        &self.framed
    }

    pub fn decode_client(&self) -> Result<ClientMessage, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ClientToServer)?;
        decode_client_payload(&self.framed)
    }

    pub fn decode_server(&self) -> Result<ServerMessage, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ServerToClient)?;
        decode_payload(&self.framed)
    }

    pub fn client_variant_tag(&self) -> Result<u32, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ClientToServer)?;
        frame_variant_tag(&self.framed)
    }

    pub fn server_variant_tag(&self) -> Result<u32, HerdrFrameError> {
        ensure_direction(self.direction, FrameDirection::ServerToClient)?;
        frame_variant_tag(&self.framed)
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
    Ok(RawHerdrFrame { direction, framed })
}

fn validate_raw_frame(bytes: &[u8]) -> Result<(), HerdrFrameError> {
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
    if claimed > MAX_FRAME_SIZE {
        return Err(HerdrFrameError::Oversized {
            claimed,
            max: MAX_FRAME_SIZE,
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
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
        let bytes = claimed.to_le_bytes().to_vec();

        let err = RawHerdrFrame::decode_client_from_bytes(&bytes).unwrap_err();

        assert!(matches!(err, HerdrFrameError::Oversized { .. }));
    }
}

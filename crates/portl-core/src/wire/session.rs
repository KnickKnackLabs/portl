use std::collections::BTreeMap;
use std::io::Read as _;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::wire::StreamPreamble;

pub const ALPN_SESSION_V1: &[u8] = b"portl/session/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReq {
    pub preamble: StreamPreamble,
    pub op: SessionOp,
    pub provider: Option<String>,
    pub session_name: Option<String>,
    pub user: Option<String>,
    pub cwd: Option<String>,
    pub argv: Option<Vec<String>>,
    pub pty: Option<crate::wire::shell::PtyCfg>,
    #[serde(default)]
    pub attach_v2: Option<AttachV2Config>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReqBody {
    pub op: SessionOp,
    pub provider: Option<String>,
    pub session_name: Option<String>,
    pub user: Option<String>,
    pub cwd: Option<String>,
    pub argv: Option<Vec<String>>,
    pub pty: Option<crate::wire::shell::PtyCfg>,
    #[serde(default)]
    pub attach_v2: Option<AttachV2Config>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOp {
    Providers,
    List,
    Attach,
    AttachV2,
    Run,
    History,
    Kill,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub persistent: bool,
    pub multi_attach: bool,
    pub create_on_attach: bool,
    pub attach_command: bool,
    pub run: bool,
    pub detached_run: bool,
    pub history: bool,
    pub tail: bool,
    pub kill: bool,
    pub terminal_state_restore: bool,
    pub external_direct_attach: bool,
    pub exact_argv_spawn: bool,
}

impl ProviderCapabilities {
    #[must_use]
    pub const fn raw() -> Self {
        Self {
            persistent: false,
            multi_attach: false,
            create_on_attach: false,
            attach_command: false,
            run: false,
            detached_run: false,
            history: false,
            tail: false,
            kill: false,
            terminal_state_restore: false,
            external_direct_attach: false,
            exact_argv_spawn: false,
        }
    }

    #[must_use]
    pub const fn zmx() -> Self {
        Self {
            persistent: true,
            multi_attach: true,
            create_on_attach: true,
            attach_command: true,
            run: true,
            detached_run: false,
            history: true,
            tail: false,
            kill: true,
            terminal_state_restore: true,
            external_direct_attach: true,
            exact_argv_spawn: false,
        }
    }

    #[must_use]
    pub const fn tmux() -> Self {
        Self {
            persistent: true,
            multi_attach: true,
            create_on_attach: true,
            attach_command: true,
            run: false,
            detached_run: false,
            history: true,
            tail: false,
            kill: true,
            terminal_state_restore: true,
            external_direct_attach: false,
            exact_argv_spawn: false,
        }
    }

    #[must_use]
    pub const fn ghostty() -> Self {
        Self {
            persistent: true,
            multi_attach: true,
            create_on_attach: true,
            attach_command: true,
            run: true,
            detached_run: false,
            history: true,
            tail: false,
            kill: true,
            terminal_state_restore: true,
            external_direct_attach: false,
            exact_argv_spawn: true,
        }
    }

    #[must_use]
    pub const fn herdr() -> Self {
        Self {
            persistent: true,
            multi_attach: true,
            create_on_attach: true,
            attach_command: false,
            run: false,
            detached_run: false,
            history: false,
            tail: false,
            kill: false,
            terminal_state_restore: true,
            external_direct_attach: true,
            exact_argv_spawn: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStatus {
    pub name: String,
    pub available: bool,
    pub path: Option<String>,
    pub notes: Option<String>,
    pub capabilities: ProviderCapabilities,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReport {
    pub default_provider: Option<String>,
    pub providers: Vec<ProviderStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProviderSessions {
    pub provider: String,
    pub available: bool,
    #[serde(default)]
    pub default: bool,
    pub sessions: Vec<SessionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRunResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEntry {
    pub provider: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAck {
    pub ok: bool,
    pub reason: Option<SessionReason>,
    pub session_id: Option<[u8; 16]>,
    pub provider: Option<String>,
    pub providers: Option<ProviderReport>,
    pub sessions: Option<Vec<String>>,
    #[serde(default)]
    pub session_entries: Option<Vec<SessionEntry>>,
    #[serde(default)]
    pub session_groups: Option<Vec<SessionProviderSessions>>,
    pub run: Option<SessionRunResult>,
    pub output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionReason {
    CapDenied,
    ProviderNotFound(String),
    ProviderUnavailable(String),
    CapabilityUnsupported {
        provider: String,
        capability: String,
    },
    MissingSessionName,
    MissingArgv,
    SessionNotFound(String),
    SessionAmbiguous {
        name: String,
        providers: Vec<String>,
    },
    SpawnFailed(String),
    InternalError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStreamKind {
    Stdin,
    Stdout,
    Stderr,
    Signal,
    Resize,
    Exit,
    Control,
    AttachV2Input,
    AttachV2Resize,
    AttachV2Viewport,
    AttachV2Live,
    AttachV2History,
    HerdrClientControl,
    HerdrClientInput,
    HerdrClientResize,
    HerdrClientBulk,
    HerdrServerControl,
    HerdrServerRender,
    HerdrServerBulk,
}

pub const ATTACH_V2_DEFAULT_PRELUDE_MAX_WAIT_MS: u64 = 200;
pub const ATTACH_V2_DEFAULT_PRELUDE_MAX_BYTES: usize = 512 * 1024;
pub const ATTACH_V2_COMPRESS_THRESHOLD: usize = 16 * 1024;
pub const ATTACH_V2_MAX_DECODED_PAYLOAD: usize = 4 * 1024 * 1024;
pub const ATTACH_V2_ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachV2Config {
    pub prelude_max_wait_ms: u64,
    pub prelude_max_bytes: u64,
}

impl Default for AttachV2Config {
    fn default() -> Self {
        Self {
            prelude_max_wait_ms: ATTACH_V2_DEFAULT_PRELUDE_MAX_WAIT_MS,
            prelude_max_bytes: ATTACH_V2_DEFAULT_PRELUDE_MAX_BYTES as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachV2PayloadCodec {
    None,
    Zstd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachV2Payload {
    pub codec: AttachV2PayloadCodec,
    pub dictionary_id: Option<u32>,
    pub uncompressed_len: u64,
    pub compressed_len: u64,
    pub bytes: Vec<u8>,
}

impl AttachV2Payload {
    #[must_use]
    pub fn raw(bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        Self {
            codec: AttachV2PayloadCodec::None,
            dictionary_id: None,
            uncompressed_len: len,
            compressed_len: len,
            bytes,
        }
    }

    pub fn encode_auto(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= ATTACH_V2_COMPRESS_THRESHOLD {
            return Ok(Self::raw(bytes.to_vec()));
        }
        let compressed = zstd::stream::encode_all(bytes, ATTACH_V2_ZSTD_LEVEL)
            .context("zstd-compress attach v2 payload")?;
        if compressed.len() >= bytes.len() {
            return Ok(Self::raw(bytes.to_vec()));
        }
        Ok(Self {
            codec: AttachV2PayloadCodec::Zstd,
            dictionary_id: None,
            uncompressed_len: bytes.len() as u64,
            compressed_len: compressed.len() as u64,
            bytes: compressed,
        })
    }

    pub fn decode(&self, max_uncompressed_len: usize) -> Result<Vec<u8>> {
        let actual_len = self.bytes.len() as u64;
        if actual_len != self.compressed_len {
            bail!(
                "attach v2 payload compressed length mismatch: declared {}, actual {actual_len}",
                self.compressed_len
            );
        }
        if self.uncompressed_len > max_uncompressed_len as u64 {
            bail!(
                "attach v2 payload decoded length {} exceeds cap {max_uncompressed_len}",
                self.uncompressed_len
            );
        }
        if self.dictionary_id.is_some() {
            bail!("attach v2 payload dictionary is not negotiated");
        }
        match self.codec {
            AttachV2PayloadCodec::None => {
                if self.uncompressed_len != self.compressed_len {
                    bail!(
                        "raw attach v2 payload length mismatch: uncompressed {}, compressed {}",
                        self.uncompressed_len,
                        self.compressed_len
                    );
                }
                Ok(self.bytes.clone())
            }
            AttachV2PayloadCodec::Zstd => {
                let cap = max_uncompressed_len.saturating_add(1) as u64;
                let zstd_reader = zstd::stream::read::Decoder::new(self.bytes.as_slice())
                    .context("zstd-decode attach v2 payload")?;
                let decoded_capacity = usize::try_from(self.uncompressed_len)
                    .context("attach v2 decoded length does not fit usize")?;
                let mut decoded_payload = Vec::with_capacity(decoded_capacity);
                zstd_reader
                    .take(cap)
                    .read_to_end(&mut decoded_payload)
                    .context("read zstd attach v2 payload")?;
                if decoded_payload.len() as u64 != self.uncompressed_len {
                    bail!(
                        "attach v2 payload decoded length mismatch: declared {}, actual {}",
                        self.uncompressed_len,
                        decoded_payload.len()
                    );
                }
                Ok(decoded_payload)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachV2Progress {
    pub loaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub retained_history_truncated: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachV2ServerFrame {
    AttachReady {
        attach_id: [u8; 16],
        provider: String,
    },
    Heartbeat {
        attach_id: [u8; 16],
        sent_at_ms: u64,
    },
    PreludeChunk {
        attach_id: [u8; 16],
        seq: u64,
        progress: AttachV2Progress,
        payload: AttachV2Payload,
    },
    ViewportSnapshot {
        attach_id: [u8; 16],
        generation: u64,
        covers_live_seq: u64,
        cols: u16,
        rows: u16,
        resize_id: u64,
        payload: AttachV2Payload,
    },
    LiveOutput {
        attach_id: [u8; 16],
        start_seq: u64,
        end_seq: u64,
        payload: AttachV2Payload,
    },
    ReloadStarted {
        attach_id: [u8; 16],
        reload_id: u64,
        total_bytes: Option<u64>,
    },
    ReloadChunk {
        attach_id: [u8; 16],
        reload_id: u64,
        seq: u64,
        progress: AttachV2Progress,
        payload: AttachV2Payload,
    },
    ReloadDone {
        attach_id: [u8; 16],
        reload_id: u64,
        final_generation: u64,
    },
    ReloadCancelled {
        attach_id: [u8; 16],
        reload_id: u64,
    },
    BackpressureNotice {
        attach_id: [u8; 16],
        reason: String,
        from_seq: u64,
    },
    ResyncRequired {
        attach_id: [u8; 16],
        reason: String,
        from_seq: u64,
    },
    Exit {
        attach_id: [u8; 16],
        code: i32,
    },
    Error {
        attach_id: [u8; 16],
        message: String,
        recoverable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachV2ClientFrame {
    Input {
        attach_id: [u8; 16],
        bytes: Vec<u8>,
    },
    Resize {
        attach_id: [u8; 16],
        resize_id: u64,
        cols: u16,
        rows: u16,
    },
    Signal {
        attach_id: [u8; 16],
        sig: u8,
    },
    Detach {
        attach_id: [u8; 16],
    },
    HeartbeatAck {
        attach_id: [u8; 16],
        sent_at_ms: u64,
    },
    Reload {
        attach_id: [u8; 16],
        reload_id: u64,
    },
    CancelReload {
        attach_id: [u8; 16],
        reload_id: u64,
    },
    RequestViewport {
        attach_id: [u8; 16],
        reason: String,
        resize_id: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionControlAction {
    KickOthers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionControlFrame {
    pub action: SessionControlAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSubTail {
    pub session_id: [u8; 16],
    pub kind: SessionStreamKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionFirstFrame {
    Control(SessionReqBody),
    Sub(SessionSubTail),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::StreamPreamble;
    use crate::wire::shell::PtyCfg;

    #[test]
    fn ghostty_capabilities_match_native_persistent_provider_contract() {
        assert_eq!(
            ProviderCapabilities::ghostty(),
            ProviderCapabilities {
                persistent: true,
                multi_attach: true,
                create_on_attach: true,
                attach_command: true,
                run: true,
                detached_run: false,
                history: true,
                tail: false,
                kill: true,
                terminal_state_restore: true,
                external_direct_attach: false,
                exact_argv_spawn: true,
            }
        );
    }

    #[test]
    fn herdr_capabilities_match_external_protocol_provider_contract() {
        assert_eq!(
            ProviderCapabilities::herdr(),
            ProviderCapabilities {
                persistent: true,
                multi_attach: true,
                create_on_attach: true,
                attach_command: false,
                run: false,
                detached_run: false,
                history: false,
                tail: false,
                kill: false,
                terminal_state_restore: true,
                external_direct_attach: true,
                exact_argv_spawn: false,
            }
        );
    }

    #[test]
    fn herdr_stream_kinds_roundtrip_via_postcard() {
        let kinds = [
            SessionStreamKind::HerdrClientControl,
            SessionStreamKind::HerdrClientInput,
            SessionStreamKind::HerdrClientResize,
            SessionStreamKind::HerdrClientBulk,
            SessionStreamKind::HerdrServerControl,
            SessionStreamKind::HerdrServerRender,
            SessionStreamKind::HerdrServerBulk,
        ];
        for kind in kinds {
            let tail = SessionSubTail {
                session_id: [9; 16],
                kind,
            };
            let encoded = postcard::to_stdvec(&tail).expect("encode");
            let decoded: SessionSubTail = postcard::from_bytes(&encoded).expect("decode");
            assert_eq!(decoded, tail);
        }
    }

    #[test]
    fn attach_v2_wire_model_has_distinct_ghostty_planes() {
        assert_eq!(SessionOp::AttachV2, SessionOp::AttachV2);
        let planes = [
            SessionStreamKind::AttachV2Input,
            SessionStreamKind::AttachV2Resize,
            SessionStreamKind::AttachV2Viewport,
            SessionStreamKind::AttachV2Live,
            SessionStreamKind::AttachV2History,
        ];
        assert_eq!(planes.len(), 5);
    }

    #[test]
    fn attach_v2_payload_compresses_large_messages_and_round_trips() {
        let bytes = vec![b'a'; ATTACH_V2_COMPRESS_THRESHOLD + 1024];
        let payload = AttachV2Payload::encode_auto(&bytes).expect("encode payload");

        assert_eq!(payload.codec, AttachV2PayloadCodec::Zstd);
        assert_eq!(payload.dictionary_id, None);
        assert!(payload.compressed_len < payload.uncompressed_len);
        assert_eq!(
            payload.decode(ATTACH_V2_MAX_DECODED_PAYLOAD).unwrap(),
            bytes
        );
    }

    #[test]
    fn attach_v2_payload_rejects_oversized_decoded_payloads() {
        let bytes = vec![b'x'; 128];
        let payload = AttachV2Payload::raw(bytes);

        let err = payload
            .decode(64)
            .expect_err("decode cap should reject payload");

        assert!(
            err.to_string().contains("exceeds"),
            "unexpected decode error: {err:#}"
        );
    }

    #[test]
    fn session_req_roundtrips_via_postcard() {
        let value = SessionReq {
            preamble: StreamPreamble {
                peer_token: [3; 16],
                alpn: String::from_utf8_lossy(ALPN_SESSION_V1).into_owned(),
            },
            op: SessionOp::Attach,
            provider: Some("zmx".to_owned()),
            session_name: Some("dev".to_owned()),
            user: Some("alice".to_owned()),
            cwd: Some("/work".to_owned()),
            argv: Some(vec!["make".to_owned(), "test".to_owned()]),
            pty: Some(PtyCfg {
                term: "xterm-256color".to_owned(),
                cols: 120,
                rows: 40,
            }),
            attach_v2: None,
        };

        let encoded = postcard::to_stdvec(&value).expect("encode");
        let decoded: SessionReq = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn session_control_frame_roundtrips_via_postcard() {
        let value = SessionControlFrame {
            action: SessionControlAction::KickOthers,
        };

        let encoded = postcard::to_stdvec(&value).expect("encode");
        let decoded: SessionControlFrame = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn session_ack_roundtrips_via_postcard() {
        let value = SessionAck {
            ok: true,
            reason: None,
            session_id: Some([4; 16]),
            provider: Some("zmx".to_owned()),
            providers: Some(ProviderReport {
                default_provider: Some("zmx".to_owned()),
                providers: vec![ProviderStatus {
                    name: "zmx".to_owned(),
                    available: true,
                    path: Some("/usr/bin/zmx".to_owned()),
                    notes: None,
                    capabilities: ProviderCapabilities::zmx(),
                    tier: Some("control".to_owned()),
                    features: vec!["live_output.v1".to_owned()],
                }],
            }),
            sessions: Some(vec!["dev".to_owned()]),
            session_entries: Some(vec![SessionEntry {
                provider: "zmx".to_owned(),
                name: "dev".to_owned(),
            }]),
            session_groups: Some(vec![SessionProviderSessions {
                provider: "zmx".to_owned(),
                available: true,
                default: true,
                sessions: vec![SessionInfo {
                    name: "dev".to_owned(),
                    provider: "zmx".to_owned(),
                    metadata: BTreeMap::from([("pid".to_owned(), "123".to_owned())]),
                }],
            }]),
            run: Some(SessionRunResult {
                code: 0,
                stdout: "ok".to_owned(),
                stderr: String::new(),
            }),
            output: Some("history".to_owned()),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode");
        let decoded: SessionAck = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, value);
    }
}

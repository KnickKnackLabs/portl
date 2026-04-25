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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOp {
    Providers,
    List,
    Attach,
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
pub struct SessionRunResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAck {
    pub ok: bool,
    pub reason: Option<SessionReason>,
    pub session_id: Option<[u8; 16]>,
    pub provider: Option<String>,
    pub providers: Option<ProviderReport>,
    pub sessions: Option<Vec<String>>,
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
        };

        let encoded = postcard::to_stdvec(&value).expect("encode");
        let decoded: SessionReq = postcard::from_bytes(&encoded).expect("decode");
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

use serde::{Deserialize, Serialize};

use crate::wire::StreamPreamble;

pub const ALPN_SHELL_V1: &[u8] = b"portl/shell/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellReq {
    pub preamble: StreamPreamble,
    pub mode: ShellMode,
    pub argv: Option<Vec<String>>,
    pub env_patch: Vec<(String, EnvValue)>,
    pub cwd: Option<String>,
    pub pty: Option<PtyCfg>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellReqBody {
    pub mode: ShellMode,
    pub argv: Option<Vec<String>>,
    pub env_patch: Vec<(String, EnvValue)>,
    pub cwd: Option<String>,
    pub pty: Option<PtyCfg>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellMode {
    Shell,
    Exec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyCfg {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvValue {
    Set(String),
    Unset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellAck {
    pub ok: bool,
    pub reason: Option<ShellReason>,
    pub pid: Option<u32>,
    pub session_id: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellReason {
    CapDenied,
    BadUser(String),
    SpawnFailed(String),
    InvalidPty,
    NotFound,
    InternalError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellStreamKind {
    Stdin,
    Stdout,
    Stderr,
    Signal,
    Resize,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSubPreamble {
    pub peer_token: [u8; 16],
    pub alpn: String,
    pub session_id: [u8; 16],
    pub kind: ShellStreamKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSubTail {
    pub session_id: [u8; 16],
    pub kind: ShellStreamKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellFirstFrame {
    Control(ShellReqBody),
    Sub(ShellSubTail),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResizeFrame {
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalFrame {
    pub sig: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitFrame {
    pub code: i32,
}

#[cfg(test)]
mod tests {
    use super::{
        ALPN_SHELL_V1, EnvValue, ExitFrame, PtyCfg, ResizeFrame, ShellAck, ShellFirstFrame,
        ShellMode, ShellReason, ShellReq, ShellReqBody, ShellStreamKind, ShellSubPreamble,
        ShellSubTail, SignalFrame,
    };
    use crate::wire::StreamPreamble;

    #[test]
    fn shell_req_roundtrips_via_postcard() {
        let value = ShellReq {
            preamble: StreamPreamble {
                peer_token: [7; 16],
                alpn: String::from_utf8_lossy(ALPN_SHELL_V1).into_owned(),
            },
            mode: ShellMode::Exec,
            argv: Some(vec!["echo".to_owned(), "hello".to_owned()]),
            env_patch: vec![
                (
                    "TERM".to_owned(),
                    EnvValue::Set("xterm-256color".to_owned()),
                ),
                ("SECRET".to_owned(), EnvValue::Unset),
            ],
            cwd: Some("/tmp".to_owned()),
            pty: Some(PtyCfg {
                term: "xterm-256color".to_owned(),
                cols: 120,
                rows: 40,
            }),
            user: Some("alice".to_owned()),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode shell req");
        let decoded: ShellReq = postcard::from_bytes(&encoded).expect("decode shell req");
        assert_eq!(decoded, value);
    }

    #[test]
    fn shell_ack_roundtrips_via_postcard() {
        let value = ShellAck {
            ok: false,
            reason: Some(ShellReason::BadUser("unknown".to_owned())),
            pid: Some(42),
            session_id: Some([9; 16]),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode shell ack");
        let decoded: ShellAck = postcard::from_bytes(&encoded).expect("decode shell ack");
        assert_eq!(decoded, value);
    }

    #[test]
    fn shell_sub_preamble_roundtrips_via_postcard() {
        let value = ShellSubPreamble {
            peer_token: [1; 16],
            alpn: String::from_utf8_lossy(ALPN_SHELL_V1).into_owned(),
            session_id: [2; 16],
            kind: ShellStreamKind::Resize,
        };

        let encoded = postcard::to_stdvec(&value).expect("encode sub preamble");
        let decoded: ShellSubPreamble =
            postcard::from_bytes(&encoded).expect("decode sub preamble");
        assert_eq!(decoded, value);
    }

    #[test]
    fn shell_first_frame_roundtrips_via_postcard() {
        let control = ShellFirstFrame::Control(ShellReqBody {
            mode: ShellMode::Shell,
            argv: None,
            env_patch: vec![("TERM".to_owned(), EnvValue::Set("xterm".to_owned()))],
            cwd: Some("/tmp".to_owned()),
            pty: Some(PtyCfg {
                term: "xterm-256color".to_owned(),
                cols: 100,
                rows: 40,
            }),
            user: Some("alice".to_owned()),
        });
        let sub = ShellFirstFrame::Sub(ShellSubTail {
            session_id: [3; 16],
            kind: ShellStreamKind::Stdout,
        });

        assert_eq!(
            postcard::from_bytes::<ShellFirstFrame>(&postcard::to_stdvec(&control).unwrap())
                .unwrap(),
            control
        );
        assert_eq!(
            postcard::from_bytes::<ShellFirstFrame>(&postcard::to_stdvec(&sub).unwrap()).unwrap(),
            sub
        );
    }

    #[test]
    fn shell_frames_roundtrip_via_postcard() {
        let resize = ResizeFrame { cols: 80, rows: 24 };
        let signal = SignalFrame { sig: 2 };
        let exit = ExitFrame { code: 130 };

        assert_eq!(
            postcard::from_bytes::<ResizeFrame>(&postcard::to_stdvec(&resize).unwrap()).unwrap(),
            resize
        );
        assert_eq!(
            postcard::from_bytes::<SignalFrame>(&postcard::to_stdvec(&signal).unwrap()).unwrap(),
            signal
        );
        assert_eq!(
            postcard::from_bytes::<ExitFrame>(&postcard::to_stdvec(&exit).unwrap()).unwrap(),
            exit
        );
    }
}

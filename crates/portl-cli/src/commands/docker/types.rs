use std::path::PathBuf;

use portl_core::id::Identity;
use portl_core::ticket::schema::PortlTicket;

#[derive(Clone)]
pub(super) struct InjectionPlan {
    pub(super) identity: Identity,
    pub(super) ticket: PortlTicket,
    pub(super) caps: portl_core::ticket::schema::Capabilities,
    pub(super) ttl_secs: u64,
    pub(super) endpoint_id_hex: String,
    pub(super) holder: [u8; 32],
    pub(super) root_ticket_id: [u8; 16],
}

#[derive(Clone)]
pub(super) struct InjectionOutcome {
    pub(super) container: ContainerSnapshot,
    pub(super) binary_path: PathBuf,
    pub(super) binary_path_preexisted: bool,
    pub(super) exec_id: String,
    pub(super) plan: InjectionPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContainerSnapshot {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) image: String,
    pub(super) network: String,
    pub(super) running: bool,
    pub(super) pid: Option<i64>,
    pub(super) target_os: Option<String>,
    pub(super) target_arch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecSnapshot {
    pub(super) running: bool,
    pub(super) pid: Option<i64>,
    pub(super) exit_code: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BinarySource {
    CurrentExecutable,
    ExplicitPath(PathBuf),
    ReleaseTag(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RunRuntimeSpec {
    pub(super) env: Vec<String>,
    pub(super) volume: Vec<String>,
    pub(super) network: Option<String>,
    pub(super) user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContainerEvent {
    pub(super) action: String,
}

/// Enumerated reject reasons from spec docs/specs/150-v0.1.1-safety-net.md §3.2.
///
/// The wire-visible `ShellReason` is a free-form enum for client-facing
/// error messages; the audit reject reasons are a closed set. This
/// local enum carries the spec reason alongside every pre-spawn
/// failure so audit dispatch can match on the variant rather than
/// inferring from the request shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectKind {
    ArgvEmpty,
    PathProbeFailed,
    PtyAllocationFailed,
    UidLookupFailed,
    UserSwitchRefused,
}

impl RejectKind {
    pub(crate) fn reason_str(self) -> &'static str {
        match self {
            Self::ArgvEmpty => "argv_empty",
            Self::PathProbeFailed => "path_probe_failed",
            Self::PtyAllocationFailed => "pty_allocation_failed",
            Self::UidLookupFailed => "uid_lookup_failed",
            Self::UserSwitchRefused => "user_switch_refused",
        }
    }
}

/// Paired audit kind + wire reason returned from `spawn_process`
/// and `resolve_requested_user` so the control-stream handler can
/// emit both the spec-enumerated audit string and the client-visible
/// `ShellAck.reason` without re-deriving one from the other.
#[derive(Debug)]
pub(crate) struct SpawnReject {
    pub(crate) kind: RejectKind,
    pub(crate) wire: portl_proto::shell_v1::ShellReason,
}

impl SpawnReject {
    pub(crate) fn new(kind: RejectKind, wire: portl_proto::shell_v1::ShellReason) -> Self {
        Self { kind, wire }
    }

    pub(crate) fn argv_empty() -> Self {
        Self::new(
            RejectKind::ArgvEmpty,
            portl_proto::shell_v1::ShellReason::SpawnFailed("missing argv".to_owned()),
        )
    }

    pub(crate) fn path_probe_failed(msg: impl Into<String>) -> Self {
        Self::new(
            RejectKind::PathProbeFailed,
            portl_proto::shell_v1::ShellReason::SpawnFailed(msg.into()),
        )
    }

    pub(crate) fn pty_allocation_failed(wire: portl_proto::shell_v1::ShellReason) -> Self {
        Self::new(RejectKind::PtyAllocationFailed, wire)
    }

    pub(crate) fn uid_lookup_failed(msg: impl Into<String>) -> Self {
        Self::new(
            RejectKind::UidLookupFailed,
            portl_proto::shell_v1::ShellReason::BadUser(msg.into()),
        )
    }

    pub(crate) fn user_switch_refused(msg: impl Into<String>) -> Self {
        Self::new(
            RejectKind::UserSwitchRefused,
            portl_proto::shell_v1::ShellReason::BadUser(msg.into()),
        )
    }
}

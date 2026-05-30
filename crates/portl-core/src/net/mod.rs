pub mod client;
pub mod session_client;
pub mod shell_client;
pub mod tcp_client;
pub mod udp_client;
pub mod unix_client;

pub use crate::wire::AckReason;
pub use client::{PeerSession, TicketHandshakeError, open_ticket_v1};
pub use session_client::{
    HerdrSessionClient, SessionClient, SessionClientV2, SessionOpenError, open_session_attach,
    open_session_attach_checked, open_session_attach_herdr_checked, open_session_attach_v2,
    open_session_attach_v2_checked, open_session_entries, open_session_history, open_session_kill,
    open_session_list, open_session_list_detailed, open_session_list_detailed_checked,
    open_session_providers, open_session_run,
};
pub use shell_client::{ShellClient, open_exec, open_shell};
pub use tcp_client::{open_tcp, run_local_forward};
pub use udp_client::{
    LocalUdpForwardHandle, UdpControl, open_udp, run_local_forward as run_local_udp_forward,
};
pub use unix_client::{
    UnixListenControl, accept_unix_reverse_once, open_unix, open_unix_listen,
    run_local_unix_forward, run_unix_reverse_forward,
};

pub mod client;
pub mod session_client;
pub mod shell_client;
pub mod stream_priority;
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
pub use shell_client::{
    ShellClient, open_exec, open_exec_with_env, open_exec_with_env_and_controls,
    open_pty_exec_with_env_and_controls, open_raw_shell_with_env_and_controls, open_shell,
    open_shell_with_env,
};
pub use tcp_client::{
    bind_local_forward_listener, open_tcp, run_local_forward, run_local_forward_with_listener,
    run_local_forward_with_listener_quiet,
};
pub use udp_client::{
    LocalUdpForwardHandle, UdpControl, UdpForwardStatsSnapshot, open_udp,
    run_local_forward as run_local_udp_forward,
};
pub use unix_client::{
    LocalUnixForwardListener, UnixListenControl, UnixListenOptions, accept_unix_reverse_once,
    bind_local_unix_listener, open_unix, open_unix_listen, open_unix_listen_with_options,
    run_local_unix_forward, run_local_unix_forward_with_listener,
    run_local_unix_forward_with_listener_quiet, run_unix_reverse_forward,
    run_unix_reverse_forwards, run_unix_reverse_forwards_quiet,
};

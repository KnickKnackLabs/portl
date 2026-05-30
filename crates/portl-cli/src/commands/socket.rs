use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use portl_core::net::{open_unix_listen, run_local_unix_forward, run_unix_reverse_forward};
use portl_core::ticket::schema::{Capabilities, UnixCaps, UnixPathRule, validate_unix_path_rule};

use crate::commands::peer_resolve::{close_connected, connect_peer};

pub fn run(
    peer: &str,
    local: &str,
    connect: Option<&str>,
    listen: Option<&str>,
    cleanup: bool,
) -> Result<ExitCode> {
    let mode = SocketMode::from_args(connect, listen)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let connected = connect_peer(peer, socket_caps(&mode)).await?;
        match mode {
            SocketMode::Connect { remote } => {
                let mut task = tokio::spawn(run_local_unix_forward(
                    connected.connection.clone(),
                    connected.session.clone(),
                    local.to_owned(),
                    remote,
                    cleanup,
                ));
                tokio::select! {
                    signal = tokio::signal::ctrl_c() => {
                        signal.context("wait for ctrl-c")?;
                        task.abort();
                    }
                    result = &mut task => {
                        result.context("join local unix forward task")??;
                    }
                }
            }
            SocketMode::Listen { remote } => {
                let control =
                    open_unix_listen(&connected.connection, &connected.session, &remote, cleanup)
                        .await?;
                let mut task = tokio::spawn(run_unix_reverse_forward(
                    connected.connection.clone(),
                    connected.session.clone(),
                    remote,
                    local.to_owned(),
                ));
                tokio::select! {
                    signal = tokio::signal::ctrl_c() => {
                        signal.context("wait for ctrl-c")?;
                        control.close()?;
                        task.abort();
                    }
                    result = &mut task => {
                        control.close()?;
                        result.context("join reverse unix forward task")??;
                    }
                }
            }
        }
        close_connected(connected, b"socket complete").await;
        Ok(ExitCode::SUCCESS)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SocketMode {
    Connect { remote: String },
    Listen { remote: String },
}

impl SocketMode {
    fn from_args(connect: Option<&str>, listen: Option<&str>) -> Result<Self> {
        match (connect, listen) {
            (Some(remote), None) => {
                validate_socket_remote_path(remote)?;
                Ok(Self::Connect {
                    remote: remote.to_owned(),
                })
            }
            (None, Some(remote)) => {
                validate_socket_remote_path(remote)?;
                Ok(Self::Listen {
                    remote: remote.to_owned(),
                })
            }
            (None, None) => bail!("one of --connect or --listen is required"),
            (Some(_), Some(_)) => bail!("--connect and --listen are mutually exclusive"),
        }
    }
}

fn validate_socket_remote_path(path: &str) -> Result<()> {
    validate_unix_path_rule(path, false).map_err(anyhow::Error::msg)
}

fn socket_caps(mode: &SocketMode) -> Capabilities {
    let (connect, listen) = match mode {
        SocketMode::Connect { remote } => (vec![path_rule(remote)], vec![]),
        SocketMode::Listen { remote } => (vec![], vec![path_rule(remote)]),
    };
    Capabilities {
        presence: 0b0100_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix: Some(UnixCaps { connect, listen }),
    }
}

fn path_rule(path: &str) -> UnixPathRule {
    UnixPathRule {
        path: path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{SocketMode, socket_caps};

    #[test]
    fn socket_caps_grant_exact_connect_path() {
        let caps = socket_caps(&SocketMode::Connect {
            remote: "/run/agent.sock".to_owned(),
        });
        assert_eq!(caps.presence, 0b0100_0000);
        let unix = caps.unix.expect("unix caps");
        assert_eq!(unix.connect[0].path, "/run/agent.sock");
        assert!(unix.listen.is_empty());
    }

    #[test]
    fn socket_mode_rejects_unsafe_remote_path() {
        let err = SocketMode::from_args(Some("/tmp/portl-a/../b.sock"), None)
            .expect_err("unsafe remote path should fail");
        assert!(err.to_string().contains("unix path"));
    }

    #[test]
    fn socket_caps_grant_exact_listen_path() {
        let caps = socket_caps(&SocketMode::Listen {
            remote: "/tmp/portl-agent.sock".to_owned(),
        });
        let unix = caps.unix.expect("unix caps");
        assert!(unix.connect.is_empty());
        assert_eq!(unix.listen[0].path, "/tmp/portl-agent.sock");
    }
}

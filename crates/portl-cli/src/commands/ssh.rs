use std::ffi::OsString;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use portl_core::net::{UnixListenOptions, open_unix_listen_with_options, run_unix_reverse_forward};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps, UnixCaps, UnixPathRule};
use portl_core::wire::shell::EnvValue;

use crate::commands::peer_resolve::{ConnectedPeer, close_connected, connect_peer_quiet};
use crate::commands::{exec, shell};

fn validate_native_options(tty: Option<bool>, remote_command: &[String]) -> Result<()> {
    if tty == Some(true) && !remote_command.is_empty() {
        bail!("portl ssh: -t with a remote command is not supported yet");
    }
    Ok(())
}

fn validate_stdio_options(stdin_null: bool, remote_command: &[String]) -> Result<()> {
    if stdin_null {
        bail!(
            "portl ssh --stdio cannot combine with -n because stdin/stdout carry SSH protocol bytes"
        );
    }
    if !remote_command.is_empty() {
        bail!(
            "portl ssh --stdio does not accept a remote command; the OpenSSH client sends requests over the protocol stream"
        );
    }
    Ok(())
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
pub fn run(
    peer: &str,
    user: Option<&str>,
    tty: Option<bool>,
    forward_agent: bool,
    stdin_null: bool,
    stdio: bool,
    _quiet: bool,
    _verbose: u8,
    remote_command: &[String],
) -> Result<ExitCode> {
    if stdio {
        validate_stdio_options(stdin_null, remote_command)?;
        return crate::commands::ssh_stdio::run(peer, user, forward_agent);
    }

    validate_native_options(tty, remote_command)?;

    if forward_agent {
        return run_with_agent_forwarding(peer, user, stdin_null, remote_command);
    }

    run_without_agent_forwarding(peer, user, stdin_null, remote_command)
}

fn run_without_agent_forwarding(
    peer: &str,
    user: Option<&str>,
    stdin_null: bool,
    remote_command: &[String],
) -> Result<ExitCode> {
    if remote_command.is_empty() {
        return shell::run_with_options(
            peer,
            None,
            user,
            shell::ShellRunOptions {
                quiet_resolve: true,
                close_stdin: stdin_null,
                ..Default::default()
            },
        );
    }

    let argv = ssh_remote_command_argv(remote_command);
    exec::run_with_options(
        peer,
        None,
        user,
        &argv,
        exec::ExecRunOptions {
            quiet_resolve: true,
            close_stdin: stdin_null,
            ..Default::default()
        },
    )
}

fn run_with_agent_forwarding(
    peer: &str,
    user: Option<&str>,
    stdin_null: bool,
    remote_command: &[String],
) -> Result<ExitCode> {
    let local_agent_path = ssh_auth_sock_from_env(std::env::var_os("SSH_AUTH_SOCK"))?;
    let remote_agent_path = remote_agent_socket_path(rand::random());
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer_quiet(peer, ssh_caps(Some(&remote_agent_path))).await?;
        ensure_agent_env_allowed(&connected.session.effective_caps)?;
        let result = run_agent_forwarded_session(
            &connected,
            user,
            stdin_null,
            remote_command,
            local_agent_path,
            remote_agent_path,
        )
        .await;
        close_connected(connected, b"ssh complete").await;
        result
    });
    runtime.shutdown_background();
    result
}

async fn run_agent_forwarded_session(
    connected: &ConnectedPeer,
    user: Option<&str>,
    stdin_null: bool,
    remote_command: &[String],
    local_agent_path: String,
    remote_agent_path: String,
) -> Result<ExitCode> {
    let control = open_unix_listen_with_options(
        &connected.connection,
        &connected.session,
        &remote_agent_path,
        UnixListenOptions {
            cleanup: true,
            ssh_agent: true,
        },
    )
    .await?;
    let mut forward_task = tokio::spawn(run_unix_reverse_forward(
        connected.connection.clone(),
        connected.session.clone(),
        remote_agent_path.clone(),
        local_agent_path,
    ));
    let env_patch = vec![("SSH_AUTH_SOCK".to_owned(), EnvValue::Set(remote_agent_path))];
    let session = run_remote_session(connected, user, stdin_null, remote_command, env_patch);
    tokio::pin!(session);

    let session_result = tokio::select! {
        result = &mut session => result,
        result = &mut forward_task => {
            result.context("join ssh-agent forwarding task")??;
            bail!("ssh-agent forwarding stopped before the remote session finished");
        }
    };

    let close_result = control.close();
    forward_task.abort();
    let _ = forward_task.await;
    close_result?;
    session_result
}

async fn run_remote_session(
    connected: &ConnectedPeer,
    user: Option<&str>,
    stdin_null: bool,
    remote_command: &[String],
    env_patch: Vec<(String, EnvValue)>,
) -> Result<ExitCode> {
    if remote_command.is_empty() {
        return shell::run_on_connected(
            connected,
            None,
            user,
            shell::ShellRunOptions {
                close_stdin: stdin_null,
                env_patch,
                ..Default::default()
            },
        )
        .await;
    }

    let argv = ssh_remote_command_argv(remote_command);
    exec::run_on_connected(
        connected,
        None,
        user,
        &argv,
        exec::ExecRunOptions {
            close_stdin: stdin_null,
            env_patch,
            ..Default::default()
        },
    )
    .await
}

fn ssh_remote_command_argv(remote_command: &[String]) -> Vec<String> {
    let command = remote_command.join(" ");
    vec!["/bin/sh".to_owned(), "-lc".to_owned(), command]
}

fn ssh_caps(remote_agent_path: Option<&str>) -> Capabilities {
    let unix = remote_agent_path.map(|path| UnixCaps {
        connect: Vec::new(),
        listen: vec![UnixPathRule {
            path: path.to_owned(),
        }],
    });
    Capabilities {
        presence: 0b0000_0001 | u8::from(unix.is_some()) << 6,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Merge { allow: None },
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix,
    }
}

fn ensure_agent_env_allowed(caps: &Capabilities) -> Result<()> {
    let Some(shell) = caps.shell.as_ref() else {
        bail!("portl ssh -A requires a ticket with shell capability");
    };
    match &shell.env_policy {
        EnvPolicy::Merge { allow: None } => Ok(()),
        EnvPolicy::Merge { allow: Some(allow) }
            if allow.iter().any(|key| key == "SSH_AUTH_SOCK") =>
        {
            Ok(())
        }
        _ => bail!("portl ssh -A requires the ticket env policy to allow SSH_AUTH_SOCK"),
    }
}

fn ssh_auth_sock_from_env(value: Option<OsString>) -> Result<String> {
    let Some(value) = value else {
        bail!("portl ssh -A requires SSH_AUTH_SOCK to point at a local ssh-agent socket");
    };
    if value.is_empty() {
        bail!("portl ssh -A requires SSH_AUTH_SOCK to be non-empty");
    }
    let path = PathBuf::from(&value);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
            "portl ssh -A requires SSH_AUTH_SOCK to point at an existing local ssh-agent socket: {}",
            path.display()
        ),
        Err(err) => {
            return Err(err).with_context(|| format!("stat SSH_AUTH_SOCK {}", path.display()));
        }
    };
    if !metadata.file_type().is_socket() {
        bail!("SSH_AUTH_SOCK is not a unix socket: {}", path.display());
    }
    value
        .into_string()
        .map_err(|_| anyhow::anyhow!("SSH_AUTH_SOCK must be valid UTF-8 for Portl forwarding"))
}

fn remote_agent_socket_path(nonce: u64) -> String {
    format!("/tmp/portl-agent-{nonce:016x}/agent.sock")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use portl_core::ticket::schema::EnvPolicy;

    use super::{
        ensure_agent_env_allowed, remote_agent_socket_path, ssh_auth_sock_from_env, ssh_caps,
        validate_native_options, validate_stdio_options,
    };

    #[test]
    fn native_ssh_agent_forward_flag_is_validated_later() {
        validate_native_options(None, &["git-upload-pack".to_owned()]).unwrap();
    }

    #[test]
    fn stdio_ssh_rejects_stdin_null() {
        let err = validate_stdio_options(true, &[]).expect_err("-n would close protocol stdin");
        assert!(err.to_string().contains("cannot combine with -n"));
    }

    #[test]
    fn stdio_ssh_rejects_remote_command_arguments() {
        let err = validate_stdio_options(false, &["hostname".to_owned()])
            .expect_err("stdio mode receives commands over the SSH protocol");
        assert!(err.to_string().contains("does not accept a remote command"));
    }

    #[test]
    fn native_ssh_rejects_forced_tty_with_remote_command() {
        let err = validate_native_options(Some(true), &["top".to_owned()])
            .expect_err("forced tty remote command should be rejected for now");
        assert!(err.to_string().contains("-t with a remote command"));
    }

    #[test]
    fn agent_forward_requires_local_ssh_auth_sock() {
        let err = ssh_auth_sock_from_env(None).expect_err("missing ssh-agent socket must fail");
        assert!(err.to_string().contains("SSH_AUTH_SOCK"));
    }

    #[test]
    fn agent_forward_rejects_stale_ssh_auth_sock() {
        let err = ssh_auth_sock_from_env(Some(OsString::from("/tmp/portl-missing-ssh-agent.sock")))
            .expect_err("stale ssh-agent socket must fail");
        assert!(err.to_string().contains("existing local ssh-agent socket"));
    }

    #[test]
    fn agent_forward_caps_include_shell_and_exact_unix_listen() {
        let caps = ssh_caps(Some("/tmp/portl-agent-0123456789abcdef/agent.sock"));
        assert_eq!(caps.presence, 0b0100_0001);
        assert!(caps.shell.is_some());
        let unix = caps.unix.expect("unix caps");
        assert!(unix.connect.is_empty());
        assert_eq!(
            unix.listen[0].path,
            "/tmp/portl-agent-0123456789abcdef/agent.sock"
        );
    }

    #[test]
    fn agent_forward_rejects_ticket_env_policy_that_strips_ssh_auth_sock() {
        let mut caps = ssh_caps(Some("/tmp/portl-agent-0123456789abcdef/agent.sock"));
        caps.shell.as_mut().expect("shell caps").env_policy = EnvPolicy::Deny;
        let err = ensure_agent_env_allowed(&caps).expect_err("deny env policy must fail");
        assert!(err.to_string().contains("SSH_AUTH_SOCK"));
    }

    #[test]
    fn agent_forward_remote_socket_uses_private_tmp_directory() {
        assert_eq!(
            remote_agent_socket_path(0x1234),
            "/tmp/portl-agent-0000000000001234/agent.sock"
        );
    }
}

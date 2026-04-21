#[allow(dead_code)]
mod common;

use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
use nix::unistd::{User, geteuid, getgroups};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{TicketHandshakeError, open_exec, open_shell, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn shell_exec_echo_returns_output_and_exit_code() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true, true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut exec = open_exec(
        &connection,
        &session,
        None,
        None,
        vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "echo hello".to_owned(),
        ],
    )
    .await?;
    exec.stdin.finish()?;

    let mut stdout = Vec::new();
    AsyncReadExt::read_to_end(&mut exec.stdout, &mut stdout).await?;
    let code = exec.wait_exit().await?;

    assert_eq!(String::from_utf8(stdout)?.trim(), "hello");
    assert_eq!(code, 0);

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn shell_exec_nonzero_exit_surfaced() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true, true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut exec = open_exec(
        &connection,
        &session,
        None,
        None,
        vec!["/bin/sh".to_owned(), "-c".to_owned(), "exit 42".to_owned()],
    )
    .await?;
    exec.stdin.finish()?;

    assert_eq!(exec.wait_exit().await?, 42);

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn shell_with_pty_resize_mid_session_applies_winsz() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true, true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut shell = open_shell(
        &connection,
        &session,
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;

    shell
        .stdin
        .write_all(b"stty size; printf '__PORTL__\\n'; read x; stty size; exit\n")
        .await?;

    let mut stdout = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = shell.stdout.read(&mut buf).await?;
        if read == 0 {
            anyhow::bail!("shell exited before emitting marker")
        }
        stdout.extend_from_slice(&buf[..read]);
        if String::from_utf8_lossy(&stdout).contains("__PORTL__") {
            break;
        }
    }

    shell.resize(120, 40).await?;
    shell.stdin.write_all(b"\n").await?;
    shell.stdin.finish()?;

    AsyncReadExt::read_to_end(&mut shell.stdout, &mut stdout).await?;
    let output = String::from_utf8(stdout)?;
    assert!(output.contains("__PORTL__"), "output was: {output:?}");
    assert!(output.contains("40 120"), "output was: {output:?}");
    assert_eq!(shell.wait_exit().await?, 0);

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn env_policy_deny_does_not_leak_agent_env() -> Result<()> {
    const MARKER: &str = "PORTL_RUN_ENV_DENY_REGRESSION";
    const SECRET: &str = "PORTL_E2E_SECRET";

    if std::env::var_os(MARKER).is_none() {
        #[rustfmt::skip]
        let output = portl_core::runtime::slow_task("shell_e2e_env_deny_subprocess", tokio::task::spawn_blocking(|| {
            Command::new(std::env::current_exe().context("resolve current test binary")?)
                .env(MARKER, "1")
                .env(SECRET, "hunter2")
                .args([
                    "--exact",
                    "env_policy_deny_does_not_leak_agent_env",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .output()
                .context("spawn env deny regression subprocess")
        }))
        .await??;

        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(
        &operator,
        server.addr(),
        shell_caps_with_env_policy(EnvPolicy::Deny),
    );

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut exec = open_exec(
        &connection,
        &session,
        None,
        None,
        vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "echo ${PORTL_E2E_SECRET:-UNSET}".to_owned(),
        ],
    )
    .await?;
    exec.stdin.finish()?;

    let mut stdout = Vec::new();
    AsyncReadExt::read_to_end(&mut exec.stdout, &mut stdout).await?;
    assert_eq!(String::from_utf8(stdout)?, "UNSET\n");
    assert_eq!(exec.wait_exit().await?, 0);

    shutdown(connection, client, server, agent).await
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
#[tokio::test]
#[ignore = "requires root and a secondary target user such as nobody"]
async fn exec_user_switch_drops_supplementary_groups() -> Result<()> {
    if !geteuid().is_root() {
        anyhow::bail!("test requires root")
    }

    let target = User::from_name("nobody")?.context("test requires a nobody user")?;
    let inherited_groups = getgroups()?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true, true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut exec = open_exec(
        &connection,
        &session,
        Some(target.name.clone()),
        None,
        vec!["/usr/bin/id".to_owned(), "-G".to_owned()],
    )
    .await?;
    exec.stdin.finish()?;

    let mut stdout = Vec::new();
    AsyncReadExt::read_to_end(&mut exec.stdout, &mut stdout).await?;
    assert_eq!(exec.wait_exit().await?, 0);

    let groups = String::from_utf8(stdout)?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let target_gid = target.gid.as_raw();

    assert!(groups.contains(&target_gid), "groups were {groups:?}");
    for inherited in inherited_groups {
        let inherited = inherited.as_raw();
        if inherited != target_gid {
            assert!(
                !groups.contains(&inherited),
                "supplementary group {inherited} leaked into {groups:?}"
            );
        }
    }

    shutdown(connection, client, server, agent).await
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
#[tokio::test]
async fn pty_user_switch_returns_actionable_error() -> Result<()> {
    if !geteuid().is_root() {
        return Ok(());
    }
    let Some(target) = User::from_name("nobody")? else {
        return Ok(());
    };

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true, true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let Err(err) = open_shell(
        &connection,
        &session,
        Some(target.name),
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await
    else {
        anyhow::bail!("pty user switch should be rejected")
    };
    assert!(
        err.to_string().contains("pty mode does not support --user"),
        "error was: {err:#}"
    );

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn shell_rejects_mode_not_permitted_by_caps() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true, false));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let Err(err) = open_exec(
        &connection,
        &session,
        None,
        None,
        vec!["/bin/echo".to_owned(), "nope".to_owned()],
    )
    .await
    else {
        anyhow::bail!("exec should be rejected")
    };
    assert!(err.to_string().contains("rejected"));

    shutdown(connection, client, server, agent).await
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-shell-revocations-{}.json",
        rand::random::<u64>()
    ));
    run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        revocations_path: Some(revocations_path),
        endpoint: Some(server),
        ..AgentConfig::default()
    })
    .await
}

fn root_ticket(
    operator: &Identity,
    addr: iroh_base::EndpointAddr,
    caps: Capabilities,
) -> PortlTicket {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs();
    mint_root(operator.signing_key(), addr, caps, now, now + 300, None).expect("mint root")
}

fn shell_caps(pty_allowed: bool, exec_allowed: bool) -> Capabilities {
    shell_caps_with_env_policy_and_modes(
        EnvPolicy::Merge { allow: None },
        pty_allowed,
        exec_allowed,
    )
}

fn shell_caps_with_env_policy(env_policy: EnvPolicy) -> Capabilities {
    shell_caps_with_env_policy_and_modes(env_policy, true, true)
}

fn shell_caps_with_env_policy_and_modes(
    env_policy: EnvPolicy,
    pty_allowed: bool,
    exec_allowed: bool,
) -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed,
            exec_allowed,
            command_allowlist: None,
            env_policy,
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

async fn shutdown(
    connection: iroh::endpoint::Connection,
    client: portl_core::endpoint::Endpoint,
    server: portl_core::endpoint::Endpoint,
    agent: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    let join_result = tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .context("agent join timeout")?;
    let run_result = join_result.context("agent join error")?;
    run_result?;
    Ok(())
}

fn _downcast_reason(err: anyhow::Error) -> Option<portl_core::net::AckReason> {
    err.downcast::<TicketHandshakeError>()
        .ok()
        .and_then(|err| err.reason)
}

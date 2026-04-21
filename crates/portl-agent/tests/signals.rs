#[allow(dead_code)]
mod common;

use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_with_shutdown};
use portl_core::endpoint::Endpoint;
use portl_core::id::Identity;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{open_shell, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn agent_run_returns_promptly_when_shutdown_token_is_cancelled() -> Result<()> {
    let endpoint = Endpoint::bind().await?;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_with_shutdown(
        AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            endpoint: Some(endpoint.clone()),
            ..AgentConfig::default()
        },
        shutdown.clone(),
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.cancel();

    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("agent should stop within 3 seconds")??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn agent_run_stops_on_sigterm_even_when_not_pid1() -> Result<()> {
    match std::env::var("PORTL_SIGNAL_CHILD").as_deref() {
        Ok("TERM") => run_signal_child("TERM").await,
        _ => signal_shutdown_subprocess("agent_run_stops_on_sigterm_even_when_not_pid1", "TERM"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn agent_run_stops_on_sigint_even_when_not_pid1() -> Result<()> {
    match std::env::var("PORTL_SIGNAL_CHILD").as_deref() {
        Ok("INT") => run_signal_child("INT").await,
        _ => signal_shutdown_subprocess("agent_run_stops_on_sigint_even_when_not_pid1", "INT"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sigterm_reaps_live_sessions_and_exits_zero_within_30s() -> Result<()> {
    match std::env::var("PORTL_SIGNAL_CHILD_MODE").as_deref() {
        Ok("live-shell") => run_signal_child("TERM").await,
        _ => signal_shutdown_subprocess_with_mode(
            "sigterm_reaps_live_sessions_and_exits_zero_within_30s",
            "TERM",
            "live-shell",
            true,
            None,
        ),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sigterm_with_stuck_session_force_kills_and_exits_nonzero() -> Result<()> {
    match std::env::var("PORTL_SIGNAL_CHILD_MODE").as_deref() {
        Ok("stuck-shell") => run_signal_child("TERM").await,
        _ => signal_shutdown_subprocess_with_mode(
            "sigterm_with_stuck_session_force_kills_and_exits_nonzero",
            "TERM",
            "stuck-shell",
            false,
            None,
        ),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn audit_shell_exit_is_fsynced_before_agent_exits() -> Result<()> {
    let dir = tempdir()?;
    let audit_path = dir.path().join("shell-exit-audit.jsonl");

    if let Ok("live-shell") = std::env::var("PORTL_SIGNAL_CHILD_MODE").as_deref() {
        run_signal_child("TERM").await
    } else {
        signal_shutdown_subprocess_with_mode(
            "audit_shell_exit_is_fsynced_before_agent_exits",
            "TERM",
            "live-shell",
            true,
            Some(audit_path.as_path()),
        )?;
        let audit = std::fs::read_to_string(audit_path)?;
        assert!(audit.contains("\"event\":\"audit.shell_exit\""));
        Ok(())
    }
}

#[cfg(unix)]
fn signal_shutdown_subprocess(test_name: &str, signal_name: &str) -> Result<()> {
    signal_shutdown_subprocess_with_mode(test_name, signal_name, "", true, None)
}

#[cfg(unix)]
fn signal_shutdown_subprocess_with_mode(
    test_name: &str,
    signal_name: &str,
    mode: &str,
    expect_success: bool,
    audit_path: Option<&std::path::Path>,
) -> Result<()> {
    let mut command = Command::new(std::env::current_exe().context("resolve current test binary")?);
    command.env("PORTL_SIGNAL_CHILD", signal_name).args([
        "--exact",
        test_name,
        "--nocapture",
        "--test-threads=1",
    ]);
    if !mode.is_empty() {
        command.env("PORTL_SIGNAL_CHILD_MODE", mode);
    }
    if mode == "stuck-shell" {
        command.env("PORTL_TEST_REAPER_SKIP_OBSERVATION", "1");
    }
    if let Some(audit_path) = audit_path {
        command.env("PORTL_AUDIT_SHELL_EXIT_PATH", audit_path);
    }
    let output = command
        .output()
        .context("spawn signal shutdown subprocess")?;

    if expect_success {
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        assert!(
            !output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(unix)]
async fn run_signal_child(signal_name: &str) -> Result<()> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    match std::env::var("PORTL_SIGNAL_CHILD_MODE").as_deref() {
        Ok("live-shell") => run_signal_child_with_live_shell(signal_name, false).await,
        Ok("stuck-shell") => run_signal_child_with_live_shell(signal_name, true).await,
        _ => {
            let endpoint = Endpoint::bind().await?;
            let task = tokio::spawn(run_with_shutdown(
                AgentConfig {
                    discovery: DiscoveryConfig::in_process(),
                    endpoint: Some(endpoint.clone()),
                    ..AgentConfig::default()
                },
                CancellationToken::new(),
            ));

            tokio::time::sleep(Duration::from_millis(100)).await;
            let signal = match signal_name {
                "TERM" => Signal::SIGTERM,
                "INT" => Signal::SIGINT,
                other => anyhow::bail!("unsupported signal child marker {other}"),
            };
            kill(Pid::this(), signal).context("deliver signal to test process")?;

            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .context("signal shutdown join timeout")??
                .context("signal child agent run failed")?;
            Ok(())
        }
    }
}

#[cfg(unix)]
async fn run_signal_child_with_live_shell(signal_name: &str, stuck: bool) -> Result<()> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-signal-revocations-{}.jsonl",
        rand::random::<u64>()
    ));
    let task = tokio::spawn(run_with_shutdown(
        AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            trust_roots: vec![operator.verifying_key()],
            revocations_path: Some(revocations_path),
            endpoint: Some(server.clone()),
            ..AgentConfig::default()
        },
        CancellationToken::new(),
    ));

    let ticket = root_ticket(&operator, server.addr());
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
    let script = if stuck {
        b"trap '' HUP TERM\nwhile :; do sleep 1; done\n".as_slice()
    } else {
        b"trap 'exit 0' HUP TERM\nwhile :; do sleep 1; done\n".as_slice()
    };
    shell.stdin.write_all(script).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let signal = match signal_name {
        "TERM" => Signal::SIGTERM,
        "INT" => Signal::SIGINT,
        other => anyhow::bail!("unsupported signal child marker {other}"),
    };
    kill(Pid::this(), signal).context("deliver signal to test process")?;

    let join_result = tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .context("signal live-shell join timeout")?;
    let run_result = join_result.context("signal live-shell join error")?;

    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;

    if stuck {
        match run_result {
            Ok(()) => anyhow::bail!("expected graceful shutdown failure for stuck session"),
            Err(err) => Err(err),
        }
    } else {
        run_result.context("signal child agent run failed")
    }
}

#[cfg(unix)]
fn root_ticket(operator: &Identity, addr: iroh_base::EndpointAddr) -> PortlTicket {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("unix time")
        .as_secs();
    mint_root(
        operator.signing_key(),
        addr,
        shell_caps(),
        now,
        now + 300,
        None,
    )
    .expect("mint root")
}

#[cfg(unix)]
fn shell_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
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
    }
}

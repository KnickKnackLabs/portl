//! Verifies that an accepted exec session emits exactly one
//! `audit.shell_start` and one `audit.shell_exit` record, and that
//! both carry the same hex-encoded wire `session_id` field.

#![cfg(unix)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::{open_exec, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};
use tokio::io::AsyncReadExt;

#[allow(dead_code)]
mod common;

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn accepted_session_emits_start_and_exit_with_same_session_id() -> Result<()> {
    let capture = common::install_audit_capture();

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps_exec_only());
    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;

    let mut exec = open_exec(
        &connection,
        &session,
        None,
        None,
        vec!["/bin/sh".to_owned(), "-c".to_owned(), "true".to_owned()],
    )
    .await?;
    exec.stdin.finish()?;
    let mut stdout = Vec::new();
    AsyncReadExt::read_to_end(&mut exec.stdout, &mut stdout).await?;
    let code = exec.wait_exit().await?;
    assert_eq!(code, 0);

    // Drain any in-flight audit emits.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let records = capture.records();
    let starts: Vec<_> = records
        .iter()
        .filter(|r| r.event == "audit.shell_start")
        .collect();
    let exits: Vec<_> = records
        .iter()
        .filter(|r| r.event == "audit.shell_exit")
        .collect();
    assert_eq!(starts.len(), 1, "expected 1 shell_start, got {records:#?}");
    assert_eq!(exits.len(), 1, "expected 1 shell_exit, got {records:#?}");
    let start = starts[0];
    let exit = exits[0];
    let start_sid = start
        .fields
        .get("session_id")
        .expect("shell_start missing session_id");
    let exit_sid = exit
        .fields
        .get("session_id")
        .expect("shell_exit missing session_id");
    assert_eq!(start_sid, exit_sid, "session_id mismatch");
    assert_eq!(start_sid.len(), 32, "session_id not hex: {start_sid}");
    assert!(start_sid.chars().all(|ch| ch.is_ascii_hexdigit()));

    // Spec 150 §3.2 field schema.
    for rec in [start, exit] {
        assert!(
            rec.fields.contains_key("ticket_id"),
            "{} missing ticket_id: {:?}",
            rec.event,
            rec.fields
        );
        assert!(
            rec.fields.contains_key("caller_endpoint_id"),
            "{} missing caller_endpoint_id: {:?}",
            rec.event,
            rec.fields
        );
        assert!(
            !rec.fields.contains_key("ticket_id_hex"),
            "{} should not use legacy ticket_id_hex",
            rec.event
        );
        assert!(
            !rec.fields.contains_key("caller_endpoint_id_hex"),
            "{} should not use legacy caller_endpoint_id_hex",
            rec.event
        );
    }
    // shell_start-specific: pid > 0 and mode is exec|pty.
    let audited_pid: u32 = start
        .fields
        .get("pid")
        .expect("shell_start missing pid")
        .parse()
        .expect("shell_start pid u32");
    assert!(audited_pid > 0, "pid must be > 0, got {audited_pid}");
    let mode = start.fields.get("mode").expect("shell_start missing mode");
    assert!(
        mode == "exec" || mode == "pty",
        "mode must be exec|pty, got {mode}"
    );
    // shell_exit-specific: exit_code (not `code`) and duration_ms >= 0.
    let exit_code: i32 = exit
        .fields
        .get("exit_code")
        .expect("shell_exit missing exit_code")
        .parse()
        .expect("shell_exit exit_code i32");
    assert_eq!(exit_code, 0);
    assert!(
        !exit.fields.contains_key("code"),
        "shell_exit should not use legacy `code` field"
    );
    let duration_ms: u64 = exit
        .fields
        .get("duration_ms")
        .expect("shell_exit missing duration_ms")
        .parse()
        .expect("shell_exit duration_ms u64");
    let _ = duration_ms; // u64 is always >= 0

    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
    Ok(())
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-audit-balance-revocations-{}.json",
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
    .context("spawn agent")
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

fn shell_caps_exec_only() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: false,
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

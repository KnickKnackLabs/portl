//! Verifies that spawn rejections emit an `audit.shell_reject` record
//! with an enumerated reason string, and do NOT emit a matching
//! `audit.shell_start` / `audit.shell_exit` pair.

#![cfg(unix)]
#![allow(clippy::await_holding_lock)]

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{open_exec, open_shell, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};

mod common;

// The audit capture is process-global; serialize the three reject
// tests so their captures do not interleave.
fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[tokio::test]
async fn invalid_user_switch_emits_shell_reject() -> Result<()> {
    let _guard = serial_guard();
    let capture = common::install_audit_capture();

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps_exec_only());
    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;

    let result = open_exec(
        &connection,
        &session,
        Some("nonexistent-user-xyz".to_owned()),
        None,
        vec!["/bin/true".to_owned()],
    )
    .await;
    assert!(
        result.is_err(),
        "exec with nonexistent user should be rejected"
    );

    // Drain any in-flight audit emits.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let records = capture.records();
    let rejects: Vec<_> = records
        .iter()
        .filter(|r| r.event == "audit.shell_reject")
        .collect();
    let starts: Vec<_> = records
        .iter()
        .filter(|r| r.event == "audit.shell_start")
        .collect();
    let exits: Vec<_> = records
        .iter()
        .filter(|r| r.event == "audit.shell_exit")
        .collect();
    assert_eq!(rejects.len(), 1, "one reject expected, got {records:#?}");
    assert!(starts.is_empty(), "no shell_start expected on rejection");
    assert!(exits.is_empty(), "no shell_exit expected on rejection");
    assert_eq!(
        rejects[0].fields.get("reason").map(String::as_str),
        Some("user_switch_refused"),
    );
    // Spec 150 §3.2 field schema on shell_reject.
    assert!(
        rejects[0].fields.contains_key("ticket_id"),
        "shell_reject missing ticket_id: {:?}",
        rejects[0].fields
    );
    assert!(
        rejects[0].fields.contains_key("caller_endpoint_id"),
        "shell_reject missing caller_endpoint_id: {:?}",
        rejects[0].fields
    );
    assert!(
        !rejects[0].fields.contains_key("ticket_id_hex"),
        "shell_reject should not use legacy ticket_id_hex"
    );
    assert!(
        !rejects[0].fields.contains_key("caller_endpoint_id_hex"),
        "shell_reject should not use legacy caller_endpoint_id_hex"
    );

    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
    Ok(())
}

#[tokio::test]
async fn exec_missing_binary_emits_path_probe_failed() -> Result<()> {
    let _guard = serial_guard();
    let capture = common::install_audit_capture();

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps_exec_only());
    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;

    let result = open_exec(
        &connection,
        &session,
        None,
        None,
        vec!["/no/such/portl-binary-xyz".to_owned()],
    )
    .await;
    assert!(
        result.is_err(),
        "exec with nonexistent binary should be rejected"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    let records = capture.records();
    let rejects: Vec<_> = records
        .iter()
        .filter(|r| r.event == "audit.shell_reject")
        .collect();
    assert_eq!(rejects.len(), 1, "one reject expected, got {records:#?}");
    assert_eq!(
        rejects[0].fields.get("reason").map(String::as_str),
        Some("path_probe_failed"),
    );

    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
    Ok(())
}

#[tokio::test]
async fn pty_with_bad_cwd_emits_pty_allocation_failed() -> Result<()> {
    let _guard = serial_guard();
    let capture = common::install_audit_capture();

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps_pty_only());
    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;

    let result = open_shell(
        &connection,
        &session,
        None,
        Some("/no/such/dir-portl-xyz".to_owned()),
        PtyCfg {
            rows: 24,
            cols: 80,
            term: "xterm".to_owned(),
        },
    )
    .await;
    assert!(
        result.is_err(),
        "pty with nonexistent cwd should be rejected"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    let records = capture.records();
    let rejects: Vec<_> = records
        .iter()
        .filter(|r| r.event == "audit.shell_reject")
        .collect();
    assert_eq!(rejects.len(), 1, "one reject expected, got {records:#?}");
    assert_eq!(
        rejects[0].fields.get("reason").map(String::as_str),
        Some("pty_allocation_failed"),
    );

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
        "portl-agent-audit-reject-revocations-{}.json",
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

fn shell_caps_pty_only() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: false,
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

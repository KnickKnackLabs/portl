#[allow(dead_code)]
mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{
    open_session_attach, open_session_entries, open_session_history, open_session_list,
    open_session_list_detailed, open_session_run, open_ticket_v1,
};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn session_zmx_provider_maps_core_ops_over_session_protocol() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_zmx = temp.path().join("zmx");
    write_fake_zmx(&fake_zmx)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_zmx)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;

    let providers = portl_core::net::open_session_providers(&connection, &session).await?;
    assert_eq!(providers.default_provider.as_deref(), Some("zmx"));
    assert!(
        providers
            .providers
            .iter()
            .any(|p| p.name == "zmx" && p.available)
    );
    assert!(
        providers
            .providers
            .iter()
            .any(|p| p.name == "raw" && p.available)
    );

    let listed = open_session_list(&connection, &session, Some("zmx".to_owned())).await?;
    assert_eq!(listed, vec!["dev".to_owned(), "frontend".to_owned()]);
    let detailed =
        open_session_list_detailed(&connection, &session, Some("zmx".to_owned())).await?;
    assert_eq!(detailed.len(), 1);
    assert_eq!(detailed[0].provider, "zmx");
    assert!(detailed[0].default);
    assert_eq!(detailed[0].sessions[0].name, "dev");
    assert_eq!(detailed[0].sessions[0].provider, "zmx");

    let run = open_session_run(
        &connection,
        &session,
        Some("zmx".to_owned()),
        "dev".to_owned(),
        vec!["echo".to_owned(), "hi".to_owned()],
    )
    .await?;
    assert_eq!(run.code, 0);
    assert_eq!(run.stdout.trim(), "run:dev:echo hi");

    let history = open_session_history(
        &connection,
        &session,
        Some("zmx".to_owned()),
        "dev".to_owned(),
    )
    .await?;
    assert_eq!(history.trim(), "history:dev");

    let mut attach = open_session_attach(
        &connection,
        &session,
        Some("zmx".to_owned()),
        "dev".to_owned(),
        Some(vec!["top".to_owned()]),
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;
    assert!(
        String::from_utf8_lossy(&attached).contains("attach:dev:top"),
        "attach output was {:?}",
        String::from_utf8_lossy(&attached)
    );
    assert_eq!(attach.wait_exit().await?, 0);

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_attach_prefers_zmx_control_when_probe_succeeds() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_zmx = temp.path().join("zmx");
    let log = temp.path().join("zmx.log");
    write_fake_zmx_control(&fake_zmx, &log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_zmx)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let providers = portl_core::net::open_session_providers(&connection, &session).await?;
    let zmx = providers
        .providers
        .iter()
        .find(|provider| provider.name == "zmx")
        .context("missing zmx provider")?;
    assert_eq!(zmx.tier.as_deref(), Some("control"));
    assert!(zmx.features.contains(&"live_output.v1".to_owned()));

    let mut attach = open_session_attach(
        &connection,
        &session,
        None,
        "dev".to_owned(),
        Some(vec!["echo".to_owned(), "from-control".to_owned()]),
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;
    assert_eq!(
        String::from_utf8_lossy(&attached),
        "viewport:dev\nlive:dev\n"
    );
    assert_eq!(attach.wait_exit().await?, 0);

    let calls = fs::read_to_string(log)?;
    assert!(calls.contains("control\n--protocol\nzmx-control/v1\n--probe\n"));
    assert!(calls.contains(
        "control\n--protocol\nzmx-control/v1\n--rows\n24\n--cols\n80\ndev\necho\nfrom-control\n"
    ));
    let user = current_user()?;
    let home = user.dir.display().to_string();
    let shell = user.shell.display().to_string();
    assert!(
        calls.contains(&format!("env:PWD={home}\n")),
        "calls were {calls:?}"
    );
    assert!(
        calls.contains(&format!("env:HOME={home}\n")),
        "calls were {calls:?}"
    );
    assert!(
        calls.contains(&format!("env:SHELL={shell}\n")),
        "calls were {calls:?}"
    );
    assert!(
        calls.contains(&format!("env:USER={}\n", user.name)),
        "calls were {calls:?}"
    );
    assert!(
        calls.contains(&format!("env:LOGNAME={}\n", user.name)),
        "calls were {calls:?}"
    );
    assert!(
        calls.contains("env:TERM=xterm-256color\n"),
        "calls were {calls:?}"
    );
    assert!(!calls.contains("attach\ndev\n"));

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_list_aggregates_available_providers_and_resolves_unique_attach() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_provider = temp.path().join("tmux");
    let log = temp.path().join("provider.log");
    write_fake_dual_session_provider(&fake_provider, &log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_provider)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;

    let entries = open_session_entries(&connection, &session, None).await?;
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.provider.as_str(), entry.name.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("zmx", "dev"),
            ("zmx", "frontend"),
            ("tmux", "ops"),
            ("tmux", "scratch"),
            ("tmux", "dev"),
        ]
    );

    let tmux_only = open_session_list(&connection, &session, Some("tmux".to_owned())).await?;
    assert_eq!(
        tmux_only,
        vec!["ops".to_owned(), "scratch".to_owned(), "dev".to_owned()]
    );

    let mut attach = open_session_attach(
        &connection,
        &session,
        None,
        "ops".to_owned(),
        None,
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;
    assert_eq!(
        String::from_utf8_lossy(&attached),
        "viewport:ops\ntmux:ops\n"
    );
    assert_eq!(attach.wait_exit().await?, 0);

    let calls = fs::read_to_string(log)?;
    assert!(calls.contains("zmx:list\n"));
    assert!(calls.contains("tmux:list-sessions\n"));
    assert!(
        calls.contains("tmux:-CC\n-CC\nnew-session\n-A\n-s\nops\n"),
        "calls were {calls:?}"
    );

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_providerless_attach_falls_back_to_default_for_new_session() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_provider = temp.path().join("tmux");
    let log = temp.path().join("provider.log");
    write_fake_dual_session_provider(&fake_provider, &log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_provider)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut attach = open_session_attach(
        &connection,
        &session,
        None,
        "new".to_owned(),
        None,
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;
    assert_eq!(
        String::from_utf8_lossy(&attached),
        "viewport:new\nlive:new\n"
    );
    assert_eq!(attach.wait_exit().await?, 0);

    let calls = fs::read_to_string(log)?;
    assert!(calls.contains("zmx:control\n"), "calls were {calls:?}");

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_providerless_attach_rejects_ambiguous_names() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_provider = temp.path().join("tmux");
    let log = temp.path().join("provider.log");
    write_fake_dual_session_provider(&fake_provider, &log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_provider)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let Err(err) = open_session_attach(
        &connection,
        &session,
        None,
        "dev".to_owned(),
        None,
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await
    else {
        anyhow::bail!("duplicate provider session name should be ambiguous");
    };
    let message = err.to_string();
    assert!(message.contains("multiple providers"), "{message}");
    assert!(message.contains("zmx"), "{message}");
    assert!(message.contains("tmux"), "{message}");

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_tmux_provider_attaches_with_control_mode() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_tmux = temp.path().join("tmux");
    let log = temp.path().join("tmux.log");
    write_fake_tmux_control(&fake_tmux, &log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_tmux)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let providers = portl_core::net::open_session_providers(&connection, &session).await?;
    assert_eq!(providers.default_provider.as_deref(), Some("tmux"));
    assert!(
        providers
            .providers
            .iter()
            .any(|p| p.name == "tmux" && p.available)
    );

    let listed = open_session_list(&connection, &session, Some("tmux".to_owned())).await?;
    assert_eq!(listed, vec!["dev".to_owned(), "frontend".to_owned()]);

    let history = open_session_history(
        &connection,
        &session,
        Some("tmux".to_owned()),
        "dev".to_owned(),
    )
    .await?;
    assert_eq!(history.trim(), "history:dev");

    let mut attach = open_session_attach(
        &connection,
        &session,
        Some("tmux".to_owned()),
        "dev".to_owned(),
        Some(vec!["top".to_owned()]),
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    attach.stdin.write_all(b"A\x03").await?;
    attach.resize(100, 40).await?;
    for _ in 0..50 {
        if fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("stdin:resize-window -x 100 -y 40\n")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;
    assert_eq!(
        String::from_utf8_lossy(&attached),
        "viewport:dev\ntmux:dev\n"
    );
    assert_eq!(attach.wait_exit().await?, 0);

    let calls = fs::read_to_string(log)?;
    let home = current_user()?.dir.display().to_string();
    assert!(
        calls.contains(&format!(
            "-CC\nnew-session\n-A\n-s\ndev\n-x\n80\n-y\n24\n-c\n{home}\ntop\n"
        )),
        "calls were {calls:?}"
    );
    assert!(calls.contains("stdin:send-keys -H 41 03\n"));
    assert!(calls.contains("stdin:refresh-client -C 100,40\n"));
    assert!(calls.contains("stdin:resize-window -x 100 -y 40\n"));

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_provider_command_failure_returns_session_ack() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_zmx = temp.path().join("zmx");
    write_failing_zmx(&fake_zmx)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_zmx)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let err = open_session_list(&connection, &session, None)
        .await
        .expect_err("failing zmx list should return a rejection ack");
    assert!(
        err.to_string()
            .contains("failed to start persistent session provider"),
        "error was: {err:#}"
    );

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_rejects_with_session_vocabulary_when_shell_caps_missing() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(false));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let err = portl_core::net::open_session_providers(&connection, &session)
        .await
        .expect_err("session provider discovery should be rejected");
    assert!(
        err.to_string().contains("persistent sessions"),
        "error was: {err:#}"
    );

    shutdown(connection, client, server, agent).await
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
    zmx_path: Option<std::path::PathBuf>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-session-revocations-{}.json",
        rand::random::<u64>()
    ));
    run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        revocations_path: Some(revocations_path),
        endpoint: Some(server),
        session_provider_path: zmx_path,
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

fn shell_caps(allow: bool) -> Capabilities {
    Capabilities {
        presence: u8::from(allow),
        shell: allow.then_some(ShellCaps {
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

fn write_failing_zmx(path: &std::path::Path) -> Result<()> {
    fs::write(
        path,
        r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.fake" ;;
  list) echo "list exploded" >&2; exit 77 ;;
esac
"#,
    )?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn write_fake_dual_session_provider(path: &std::path::Path, log: &std::path::Path) -> Result<()> {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
case "$1" in
  control)
    if [ "$2" = "--protocol" ] && [ "$3" = "zmx-control/v1" ] && [ "$4" = "--probe" ]; then
      printf 'protocol=zmx-control/v1\n'
      printf 'tier=control\n'
      printf 'features=viewport_snapshot.v1,live_output.v1\n'
      exit 0
    fi
    printf 'zmx:control\n' >> "{}"
    if [ "$4" = "--rows" ] && [ "$6" = "--cols" ]; then
      session="$8"
    else
      session="$4"
    fi
    case "$session" in
      dev|frontend|new) printf '\016\015\000\000\000viewport:%s\n\017\011\000\000\000live:%s\n' "$session" "$session" ;;
      *) exit 65 ;;
    esac
    ;;
  version) echo "zmx 0.0.fake" ;;
  list) printf 'zmx:list\n' >> "{}"; printf 'dev\nfrontend\n' ;;
  history) echo "history:$2" ;;
  kill) echo "killed:$2" ;;
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'tmux:list-sessions\n' >> "{}"; printf 'ops\nscratch\ndev\n' ;;
  capture-pane)
    if [ "$5" = "0" ]; then
      echo "viewport:$9"
    else
      echo "history:$9"
    fi
    ;;
  kill-session) echo "killed:$3" ;;
  -CC)
    stty -echo 2>/dev/null || true
    printf 'tmux:-CC\n' >> "{}"
    printf '%s\n' "$@" >> "{}"
    session=""
    prev=""
    for arg in "$@"; do
      if [ "$prev" = "-s" ]; then session="$arg"; fi
      prev="$arg"
    done
    printf '\033P1000p%%output %%1 tmux:%s\\012\r\n' "$session"
    while IFS= read -r line; do
      printf 'stdin:%s\n' "$line" >> "{}"
      [ "$line" = "detach-client" ] && exit 0
    done
    ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
            log.display(),
            log.display(),
            log.display(),
            log.display(),
            log.display(),
            log.display()
        ),
    )?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn write_fake_tmux_control(path: &std::path::Path, log: &std::path::Path) -> Result<()> {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$@" >> "{}"
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'dev\nfrontend\n' ;;
  capture-pane)
    if [ "$5" = "0" ]; then
      echo "viewport:$9"
    else
      echo "history:$9"
    fi
    ;;
  kill-session) echo "killed:$3" ;;
  -CC)
    stty -echo 2>/dev/null || true
    printf '\033P1000p%%output %%1 tmux:dev\\012\r\n'
    while IFS= read -r line; do
      printf 'stdin:%s\n' "$line" >> "{}"
      [ "$line" = "detach-client" ] && exit 0
    done
    ;;
  *) echo "not zmx" >&2; exit 64 ;;
esac
"#,
            log.display(),
            log.display()
        ),
    )?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn current_user() -> Result<nix::unistd::User> {
    nix::unistd::User::from_uid(nix::unistd::geteuid())?
        .context("current uid should resolve to a user")
}

fn write_fake_zmx_control(path: &std::path::Path, log: &std::path::Path) -> Result<()> {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$@" >> "{}"
if [ "$1" = "control" ] && [ "$2" = "--protocol" ] && [ "$3" = "zmx-control/v1" ] && [ "$4" = "--probe" ]; then
  printf 'protocol=zmx-control/v1\n'
  printf 'tier=control\n'
  printf 'features=viewport_snapshot.v1,live_output.v1,priority_input.v1,adapter_sequence.v1\n'
  exit 0
fi
if [ "$1" = "control" ] && [ "$2" = "--protocol" ] && [ "$3" = "zmx-control/v1" ]; then
  printf 'env:PWD=%s\n' "$(pwd)" >> "{}"
  printf 'env:HOME=%s\n' "${{HOME:-}}" >> "{}"
  printf 'env:SHELL=%s\n' "${{SHELL:-}}" >> "{}"
  printf 'env:USER=%s\n' "${{USER:-}}" >> "{}"
  printf 'env:LOGNAME=%s\n' "${{LOGNAME:-}}" >> "{}"
  printf 'env:TERM=%s\n' "${{TERM:-}}" >> "{}"
  if [ "$4" = "--rows" ] && [ "$6" = "--cols" ]; then
    session="$8"
  else
    session="$4"
  fi
  case "$session" in
    dev) printf '\016\015\000\000\000viewport:dev\n\017\011\000\000\000live:dev\n' ;;
    *) exit 65 ;;
  esac
  exit 0
fi
case "$1" in
  version) echo "zmx 0.0.fake" ;;
  list) printf 'dev\nfrontend\n' ;;
  run) session="$2"; shift 2; echo "run:${{session}}:$*" ;;
  history) echo "history:$2" ;;
  kill) echo "killed:$2" ;;
  attach) session="$2"; shift 2; echo "attach:${{session}}:$*" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
            log.display(),
            log.display(),
            log.display(),
            log.display(),
            log.display(),
            log.display(),
            log.display()
        ),
    )?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn write_fake_zmx(path: &std::path::Path) -> Result<()> {
    fs::write(
        path,
        r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.fake" ;;
  list) printf 'dev\nfrontend\n' ;;
  run) session="$2"; shift 2; echo "run:${session}:$*" ;;
  history) echo "history:$2" ;;
  kill) echo "killed:$2" ;;
  attach) session="$2"; shift 2; echo "attach:${session}:$*" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
    )?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
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

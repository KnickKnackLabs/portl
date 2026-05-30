#[allow(dead_code)]
mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::herdr_wire::{
    ClientKeybindings, ClientMessage, FrameDirection, HERDR_PROTOCOL_VERSION, RawHerdrFrame,
    RenderEncoding, ServerMessage,
};
use portl_core::id::Identity;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{
    open_session_attach, open_session_attach_herdr_checked, open_session_entries,
    open_session_history, open_session_list, open_session_list_detailed, open_session_run,
    open_ticket_v1,
};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};
use tokio::io::AsyncReadExt;

const QUERY_EMISSION_PRINTF: &str =
    "printf 'pre\\033[c\\033[>c\\033[6n\\033[?u\\033[>1u\\033[=15u\\033[<upost'";
#[allow(dead_code)]
const QUERY_EMISSION_BYTES: &[u8] = b"pre\x1b[c\x1b[>c\x1b[6n\x1b[?u\x1b[>1u\x1b[=15u\x1b[<upost";
const QUERY_STRIPPED_EXPECTED: &[u8] = b"prepost";

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
    #[cfg(feature = "ghostty-vt")]
    assert_eq!(providers.default_provider.as_deref(), Some("ghostty"));
    #[cfg(not(feature = "ghostty-vt"))]
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
async fn session_herdr_provider_bridges_protocol_lanes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_herdr = temp.path().join("herdr");
    let log = temp.path().join("herdr.log");
    let welcome = RawHerdrFrame::encode_server(&ServerMessage::Welcome {
        version: HERDR_PROTOCOL_VERSION,
        encoding: RenderEncoding::SemanticFrame,
        error: None,
    })?;
    write_fake_herdr(&fake_herdr, &log, &hex::encode(welcome.framed_bytes()))?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_herdr)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut attach = open_session_attach_herdr_checked(
        &connection,
        &session,
        "default".to_owned(),
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;

    assert_eq!(attach.provider, "herdr");
    let hello = RawHerdrFrame::encode_client(&ClientMessage::Hello {
        version: HERDR_PROTOCOL_VERSION,
        cols: 80,
        rows: 24,
        cell_width_px: 0,
        cell_height_px: 0,
        requested_encoding: RenderEncoding::SemanticFrame,
        keybindings: ClientKeybindings::Server,
    })?;
    attach
        .client_control
        .write_all(hello.framed_bytes())
        .await?;

    let received_welcome =
        read_test_herdr_frame(&mut attach.server_control, FrameDirection::ServerToClient).await?;
    assert!(matches!(
        received_welcome.decode_server()?,
        ServerMessage::Welcome {
            version: HERDR_PROTOCOL_VERSION,
            ..
        }
    ));

    let resize = RawHerdrFrame::encode_client(&ClientMessage::Resize {
        cols: 120,
        rows: 40,
        cell_width_px: 0,
        cell_height_px: 0,
    })?;
    let input = RawHerdrFrame::encode_client(&ClientMessage::Input {
        data: b"echo from portl\n".to_vec(),
    })?;
    attach
        .client_resize
        .write_all(resize.framed_bytes())
        .await?;
    attach.client_input.write_all(input.framed_bytes()).await?;
    let _ = attach.client_control.finish();
    let _ = attach.client_input.finish();
    let _ = attach.client_resize.finish();
    let _ = attach.client_bulk.finish();

    wait_for_log_contains(&log, "argv:remote-client-bridge").await?;
    wait_for_log_contains(
        &log,
        &format!("frame:{}", hex::encode(hello.framed_bytes())),
    )
    .await?;
    wait_for_log_contains(
        &log,
        &format!("frame:{}", hex::encode(resize.framed_bytes())),
    )
    .await?;
    wait_for_log_contains(
        &log,
        &format!("frame:{}", hex::encode(input.framed_bytes())),
    )
    .await?;
    let calls = fs::read_to_string(&log)?;
    assert!(
        calls.contains("env:HERDR_SESSION=<unset>"),
        "calls were {calls:?}"
    );

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
async fn session_zmx_legacy_attach_strips_terminal_queries_without_answers() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_zmx = temp.path().join("zmx");
    let stdin_log = temp.path().join("zmx.stdin");
    write_fake_zmx_query_strip_legacy(&fake_zmx, &stdin_log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_zmx)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut attach = open_session_attach(
        &connection,
        &session,
        Some("zmx".to_owned()),
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
    .await?;
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;

    assert_eq!(attached, b"prepost");
    assert_no_query_bytes(&attached);
    let stdin_bytes = fs::read(stdin_log)?;
    assert_no_response_bytes(&stdin_bytes);
    assert_eq!(attach.wait_exit().await?, 0);

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_zmx_control_attach_strips_terminal_queries_without_answers() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_zmx = temp.path().join("zmx");
    let stdin_log = temp.path().join("zmx-control.stdin");
    write_fake_zmx_query_strip_control(&fake_zmx, &stdin_log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_zmx)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut attach = open_session_attach(
        &connection,
        &session,
        Some("zmx".to_owned()),
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
    .await?;
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;

    assert_eq!(attached, b"prepost");
    assert_no_query_bytes(&attached);
    let stdin_bytes = fs::read(stdin_log)?;
    assert_no_response_bytes(&stdin_bytes);
    assert_eq!(attach.wait_exit().await?, 0);

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_provider_parity_real_paths_strip_queries_to_identical_wire_capture() -> Result<()>
{
    let temp = tempfile::tempdir()?;
    let mut captures = Vec::new();

    #[cfg(feature = "ghostty-vt")]
    let ghostty_guest_pty_input = {
        let (wire_capture, guest_pty_input) =
            portl_agent::ghostty_provider_query_strip_capture_for_test(QUERY_EMISSION_BYTES)?;
        captures.push(("ghostty", wire_capture));
        guest_pty_input
    };

    let fake_zmx_legacy = temp.path().join("zmx-legacy");
    let zmx_legacy_stdin = temp.path().join("zmx-legacy.stdin");
    write_fake_zmx_query_strip_legacy(&fake_zmx_legacy, &zmx_legacy_stdin)?;
    captures.push((
        "zmx-legacy",
        run_query_strip_capture(Some("zmx"), Some(fake_zmx_legacy), None).await?,
    ));

    let fake_zmx_control = temp.path().join("zmx-control");
    let zmx_control_stdin = temp.path().join("zmx-control.stdin");
    write_fake_zmx_query_strip_control(&fake_zmx_control, &zmx_control_stdin)?;
    captures.push((
        "zmx-control",
        run_query_strip_capture(Some("zmx"), Some(fake_zmx_control), None).await?,
    ));

    let fake_tmux = temp.path().join("tmux");
    let tmux_stdin = temp.path().join("tmux.stdin");
    write_fake_tmux_parity_control(&fake_tmux, &tmux_stdin)?;
    captures.push((
        "tmux-control",
        run_query_strip_capture(Some("tmux"), Some(fake_tmux), None).await?,
    ));

    let raw_stdin = temp.path().join("raw.stdin");
    captures.push((
        "raw",
        run_query_strip_capture(
            Some("raw"),
            None,
            Some(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
            format!(
                "{QUERY_EMISSION_PRINTF}; stty -echo -icanon min 0 time 2 2>/dev/null || true; dd of={} bs=1024 count=1 2>/dev/null || true",
                raw_stdin.display()
            ),
            ]),
        )
        .await?,
    ));

    assert!(
        captures.len() >= if cfg!(feature = "ghostty-vt") { 5 } else { 4 },
        "provider parity should exercise ghostty, zmx legacy, zmx-control, tmux-control, and raw shell actual paths when ghostty-vt is enabled"
    );
    for (provider, capture) in &captures {
        assert_eq!(
            capture, QUERY_STRIPPED_EXPECTED,
            "provider {provider} should strip to the known wire capture"
        );
        assert_no_query_bytes(capture);
    }
    for window in captures.windows(2) {
        assert_eq!(
            window[0].1, window[1].1,
            "wire captures should match byte-for-byte for {} and {}",
            window[0].0, window[1].0
        );
    }

    for (provider, path) in [
        ("zmx-legacy", zmx_legacy_stdin),
        ("zmx-control", zmx_control_stdin),
        ("tmux-control", tmux_stdin),
        ("raw", raw_stdin),
    ] {
        let stdin_bytes = fs::read(path)?;
        assert_no_response_bytes(&stdin_bytes);
        assert_no_query_bytes(&stdin_bytes);
        let _ = provider;
    }

    #[cfg(feature = "ghostty-vt")]
    {
        for response in [b"\x1b[?62;1;6;22c".as_slice(), b"\x1b[>1;1;0c", b"\x1b[?0u"] {
            assert!(
                contains_bytes(&ghostty_guest_pty_input, response),
                "ghostty guest PTY input missing canonical responder bytes {} in {}",
                escaped(response),
                escaped(&ghostty_guest_pty_input)
            );
        }
        assert_no_query_bytes(&ghostty_guest_pty_input);
    }

    Ok(())
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
            .filter(|entry| entry.provider != "ghostty" && entry.provider != "herdr")
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
        "\x1b[0m\x1b[H\x1b[2J\x1b[1;1Hviewport:ops\x1b[K\x1b[1;1Htmux:ops\n"
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

#[cfg(not(feature = "ghostty-vt"))]
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
    #[cfg(feature = "ghostty-vt")]
    assert_eq!(providers.default_provider.as_deref(), Some("ghostty"));
    #[cfg(not(feature = "ghostty-vt"))]
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
        "\x1b[0m\x1b[H\x1b[2J\x1b[1;1Hviewport:dev\x1b[K\x1b[1;1Htmux:dev\n"
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
async fn session_tmux_control_attach_strips_terminal_queries_without_answers() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake_tmux = temp.path().join("tmux");
    let log = temp.path().join("tmux.log");
    write_fake_tmux_query_strip_control(&fake_tmux, &log)?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(fake_tmux)).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut attach = open_session_attach(
        &connection,
        &session,
        Some("tmux".to_owned()),
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
    .await?;
    attach.close_stdin()?;
    let mut attached = Vec::new();
    AsyncReadExt::read_to_end(&mut attach.stdout, &mut attached).await?;

    assert_eq!(
        attached,
        b"prepostmalformed:\x1b[Xhello\x1b[?Xhello\x1b[?;;uhello\x1bZdone"
    );
    assert_no_query_bytes(&attached);
    assert_eq!(attach.wait_exit().await?, 0);
    let calls = fs::read_to_string(log)?;
    assert_no_response_bytes(calls.as_bytes());

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn session_raw_shell_attach_strips_terminal_queries_without_answers() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let stdin_log = temp.path().join("raw.stdin");
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut attach = open_session_attach(
        &connection,
        &session,
        Some("raw".to_owned()),
        "raw".to_owned(),
        Some(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            format!(
                "{QUERY_EMISSION_PRINTF}; stty -echo -icanon min 0 time 2 2>/dev/null || true; dd of={} bs=1024 count=1 2>/dev/null || true",
                stdin_log.display()
            ),
        ]),
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

    assert_eq!(attached, b"prepost");
    assert_no_query_bytes(&attached);
    assert_no_response_bytes(&attached);
    let stdin_bytes = fs::read(stdin_log)?;
    assert_no_response_bytes(&stdin_bytes);
    assert!(
        stdin_bytes.is_empty(),
        "raw provider wrote guest PTY input bytes: {}",
        escaped(&stdin_bytes)
    );
    assert_eq!(attach.wait_exit().await?, 0);

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
    let home = std::env::temp_dir().join(format!(
        "portl-agent-session-home-{}",
        rand::random::<u64>()
    ));
    let paths = portl_core::paths::for_home(&home);
    let revocations_path = paths.revocations_path();
    run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        peers_path: Some(paths.peers_path()),
        revocations_path: Some(revocations_path),
        endpoint: Some(server),
        session_provider_path: zmx_path,
        ..AgentConfig::default()
    })
    .await
}

async fn run_query_strip_capture(
    provider: Option<&str>,
    provider_path: Option<std::path::PathBuf>,
    argv: Option<Vec<String>>,
) -> Result<Vec<u8>> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, provider_path).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut attach = open_session_attach(
        &connection,
        &session,
        provider.map(str::to_owned),
        "dev".to_owned(),
        argv,
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
    assert_eq!(attach.wait_exit().await?, 0);

    shutdown(connection, client, server, agent).await?;
    Ok(attached)
}

async fn read_test_herdr_frame<R>(
    reader: &mut R,
    direction: FrameDirection,
) -> Result<RawHerdrFrame>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len = [0_u8; 4];
    reader.read_exact(&mut len).await?;
    let payload_len = u32::from_le_bytes(len) as usize;
    let mut framed = Vec::with_capacity(4 + payload_len);
    framed.extend_from_slice(&len);
    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload).await?;
    framed.extend_from_slice(&payload);
    Ok(match direction {
        FrameDirection::ClientToServer => RawHerdrFrame::decode_client_from_bytes(&framed)?,
        FrameDirection::ServerToClient => RawHerdrFrame::decode_server_from_bytes(&framed)?,
    })
}

async fn wait_for_log_contains(path: &std::path::Path, needle: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if fs::read_to_string(path).is_ok_and(|contents| contents.contains(needle)) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for {needle:?} in {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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

fn write_fake_herdr(
    path: &std::path::Path,
    log: &std::path::Path,
    welcome_hex: &str,
) -> Result<()> {
    let script = r#"#!/usr/bin/env python3
import os
import struct
import sys

LOG = __LOG__
WELCOME = bytes.fromhex(__WELCOME__)

def log(line):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()

def read_frame():
    length = sys.stdin.buffer.read(4)
    if not length:
        return None
    if len(length) != 4:
        log("partial-length")
        return None
    size = struct.unpack("<I", length)[0]
    payload = sys.stdin.buffer.read(size)
    if len(payload) != size:
        log("partial-payload")
        return None
    framed = length + payload
    log("frame:" + framed.hex())
    return framed

args = sys.argv[1:]
log("argv:" + " ".join(args))
log("env:HERDR_SESSION=" + os.environ.get("HERDR_SESSION", "<unset>"))
if args == ["--version"]:
    print("herdr 0.6.4")
    raise SystemExit(0)
if args == ["session", "list", "--json"]:
    print('{"sessions":[{"name":"default"}]}')
    raise SystemExit(0)
if args == ["remote-client-bridge"]:
    if read_frame() is not None:
        sys.stdout.buffer.write(WELCOME)
        sys.stdout.buffer.flush()
        while read_frame() is not None:
            pass
    raise SystemExit(0)
print("unknown herdr args: " + " ".join(args), file=sys.stderr)
raise SystemExit(64)
"#
    .replace("__LOG__", &format!("{:?}", log.display().to_string()))
    .replace("__WELCOME__", &format!("{:?}", welcome_hex));
    fs::write(path, script)?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
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
  display-message)
    printf 'PORTL_CURSOR 0 0\n'
    target="${{16:-$4}}"
    echo "viewport:$target"
    ;;
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
  display-message)
    printf 'PORTL_CURSOR 0 0\n'
    target="${{16:-$4}}"
    echo "viewport:$target"
    ;;
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

fn write_fake_tmux_query_strip_control(
    path: &std::path::Path,
    log: &std::path::Path,
) -> Result<()> {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$@" >> "{}"
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'dev\n' ;;
  display-message) exit 1 ;;
  list-panes) exit 1 ;;
  -CC)
    stty -echo 2>/dev/null || true
    printf '\033P1000p%%output %%1 pre\\033[c\\033[>c\\033[6n\\033[?u\\033[>1u\\033[=15u\\033[<upostmalformed:\\033[Xhello\\033[?Xhello\\033[?;;uhello\\033Zdone\r\n'
    stty -echo -icanon min 0 time 2 2>/dev/null || true
    dd of="{}" bs=1024 count=1 2>/dev/null || true
    ;;
  *) echo "not tmux query fixture" >&2; exit 64 ;;
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

fn write_fake_tmux_parity_control(
    path: &std::path::Path,
    stdin_log: &std::path::Path,
) -> Result<()> {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'dev\n' ;;
  display-message) exit 1 ;;
  list-panes) exit 1 ;;
  -CC)
    stty -echo 2>/dev/null || true
    printf '\033P1000p%%output %%1 pre\\033[c\\033[>c\\033[6n\\033[?u\\033[>1u\\033[=15u\\033[<upost\r\n'
    stty -echo -icanon min 0 time 2 2>/dev/null || true
    dd of="{}" bs=1024 count=1 2>/dev/null || true
    ;;
  *) echo "not tmux parity fixture" >&2; exit 64 ;;
esac
"#,
            stdin_log.display()
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

fn write_fake_zmx_query_strip_legacy(
    path: &std::path::Path,
    stdin_log: &std::path::Path,
) -> Result<()> {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.fake" ;;
  list) printf 'dev\n' ;;
  attach)
    printf 'pre\033[c\033[>c\033[6n\033[?u\033[>1u\033[=15u\033[<upost'
    stty -echo -icanon min 0 time 2 2>/dev/null || true
    dd of="{}" bs=1024 count=1 2>/dev/null || true
    ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
            stdin_log.display()
        ),
    )?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn write_fake_zmx_query_strip_control(
    path: &std::path::Path,
    stdin_log: &std::path::Path,
) -> Result<()> {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
if [ "$1" = "control" ] && [ "$2" = "--protocol" ] && [ "$3" = "zmx-control/v1" ] && [ "$4" = "--probe" ]; then
  printf 'protocol=zmx-control/v1\n'
  printf 'tier=control\n'
  printf 'features=viewport_snapshot.v1,live_output.v1\n'
  exit 0
fi
if [ "$1" = "control" ] && [ "$2" = "--protocol" ] && [ "$3" = "zmx-control/v1" ]; then
  printf '\001\045\000\000\000pre\033[c\033[>c\033[6n\033[?u\033[>1u\033[=15u\033[<upost'
  cat > "{}"
  exit 0
fi
case "$1" in
  version) echo "zmx 0.0.fake" ;;
  list) printf 'dev\n' ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
            stdin_log.display()
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

fn assert_no_query_bytes(bytes: &[u8]) {
    for query in [
        b"\x1b[c".as_slice(),
        b"\x1b[>c",
        b"\x1b[6n",
        b"\x1b[?u",
        b"\x1b[>1u",
        b"\x1b[=15u",
        b"\x1b[<u",
    ] {
        assert!(
            !contains_bytes(bytes, query),
            "query {} leaked in {}",
            escaped(query),
            escaped(bytes)
        );
    }
}

fn assert_no_response_bytes(bytes: &[u8]) {
    assert!(
        !contains_response_shape(bytes),
        "response shape leaked in {}",
        escaped(bytes)
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn contains_response_shape(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 2 < bytes.len() {
        if bytes[offset] != 0x1b || bytes[offset + 1] != b'[' {
            offset += 1;
            continue;
        }
        let body_start = offset + 2;
        let Some(final_rel) = bytes[body_start..]
            .iter()
            .position(|byte| (0x40..=0x7e).contains(byte))
        else {
            return false;
        };
        let final_byte = bytes[body_start + final_rel];
        let body = &bytes[body_start..body_start + final_rel];
        let response = match final_byte {
            b'c' => body
                .strip_prefix(b"?")
                .or_else(|| body.strip_prefix(b">"))
                .is_some_and(semicolon_digits),
            b'u' => body.strip_prefix(b"?").is_some_and(colon_semicolon_digits),
            b'R' => body
                .strip_prefix(b"?")
                .unwrap_or(body)
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b';'),
            _ => false,
        };
        if response {
            return true;
        }
        offset = body_start + final_rel + 1;
    }
    false
}

fn semicolon_digits(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b';')
}

fn colon_semicolon_digits(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b';' || *byte == b':')
}

fn escaped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
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

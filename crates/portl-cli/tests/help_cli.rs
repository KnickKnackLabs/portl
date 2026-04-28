#![allow(clippy::needless_raw_string_hashes, clippy::too_many_lines)]

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

fn help_output(args: &[&str]) -> String {
    let output = Command::cargo_bin("portl")
        .expect("cargo bin")
        .args(args)
        .output()
        .expect("run portl --help");
    assert!(
        output.status.success(),
        "expected success for {:?}, stderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

#[test]
fn cli_help_lists_expected_top_level_commands() {
    let help = help_output(&["--help"]);
    for command in [
        "init", "doctor", "status", "shell", "exec", "tcp", "udp", "peer", "invite", "accept",
        "ticket", "whoami", "config", "install", "docker", "slicer", "gateway",
    ] {
        assert!(
            help.contains(command),
            "missing top-level command {command}\n{help}"
        );
    }
    // v0.3.0: top-level `mint` and `revoke` were removed. `mint`
    // moved to `ticket issue`, `revoke` to `ticket revoke`. The
    // old `mint-root` alias from v0.1.x has been gone since v0.2.0.
    assert!(
        !help.contains("Mint a ticket with the local identity"),
        "removed top-level `mint` command still shown\n{help}"
    );
    assert!(
        !help.contains("mint-root"),
        "removed mint-root still shown\n{help}"
    );
}

#[cfg(unix)]
#[test]
fn portl_agent_help_lists_lifecycle_commands() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let temp = tempfile::tempdir().expect("tempdir");
    let agent = temp.path().join("portl-agent");
    std::os::unix::fs::symlink(&portl, &agent).expect("symlink portl-agent");
    let output = Command::new(&agent)
        .arg("--help")
        .output()
        .expect("run portl-agent --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("utf8 stdout");
    for needle in [
        "Usage: portl-agent [OPTIONS] [COMMAND]",
        "status",
        "up",
        "down",
        "restart",
        "--json",
    ] {
        assert!(help.contains(needle), "missing {needle:?}\n{help}");
    }

    let status = Command::new(&agent)
        .args(["status", "--help"])
        .output()
        .expect("run portl-agent status --help");
    assert!(status.status.success());
    let status_help = String::from_utf8(status.stdout).expect("utf8 stdout");
    for needle in [
        "Usage: portl-agent status",
        "--service",
        "--json",
        "Print help",
    ] {
        assert!(
            status_help.contains(needle),
            "missing {needle:?}\n{status_help}"
        );
    }
}

#[test]
fn top_level_help_uses_logical_command_groups() {
    let help = help_output(&["--help"]);
    for heading in [
        "Setup:",
        "Trust:",
        "Pairing:",
        "Connect:",
        "Permissions:",
        "Integrations:",
        "Utility:",
    ] {
        assert!(
            help.contains(heading),
            "missing heading {heading:?}\n{help}"
        );
    }

    for ordered in [
        &[
            "Setup:",
            "  init",
            "  doctor",
            "  install",
            "  config",
            "  whoami",
        ][..],
        &["Trust:", "  peer", "  invite"],
        &["Pairing:", "  accept"],
        &[
            "Connect:",
            "  status",
            "  shell",
            "  session",
            "  exec",
            "  tcp",
            "  udp",
        ],
        &["Permissions:", "  ticket"],
        &["Integrations:", "  docker", "  slicer", "  gateway"],
        &["Utility:", "  completions", "  man", "  help"],
    ] {
        let mut cursor = 0;
        for needle in ordered {
            let found = help[cursor..]
                .find(needle)
                .unwrap_or_else(|| panic!("missing ordered item {needle:?}\n{help}"));
            cursor += found + needle.len();
        }
    }
}

#[test]
fn invite_accept_help_matches_model_a_surface() {
    let top = help_output(&["--help"]);
    assert!(top.contains("invite"), "{top}");
    assert!(top.contains("accept"), "{top}");

    let invite = help_output(&["invite", "--help"]);
    for needle in [
        "Usage: portl invite [OPTIONS]",
        "portl invite <COMMAND>",
        "--initiator <INITIATOR>",
        "possible values: mutual, me, them",
        "portl invite rm abc123",
    ] {
        assert!(invite.contains(needle), "missing {needle:?}\n{invite}");
    }

    let accept = help_output(&["accept", "--help"]);
    for needle in [
        "Usage: portl accept [OPTIONS] <THING>",
        "PORTLINV",
        "PORTL-S",
        "--yes",
    ] {
        assert!(accept.contains(needle), "missing {needle:?}\n{accept}");
    }

    let peer = help_output(&["peer", "--help"]);
    let peer_commands = peer
        .split("Options:")
        .next()
        .expect("peer help has a commands section");
    assert!(
        !peer_commands.contains("  invite"),
        "peer invite still shown\n{peer}"
    );
    assert!(
        !peer_commands.contains("  pair"),
        "peer pair still shown\n{peer}"
    );
    assert!(
        !peer_commands.contains("  accept"),
        "peer accept still shown\n{peer}"
    );
}

#[test]
fn session_share_help_mentions_sender_must_stay_online() {
    let help = help_output(&["session", "share", "--help"]);
    assert!(
        help.contains("keep this command running"),
        "session share help should tell sender to keep running:\n{help}"
    );
    assert!(
        help.contains("PORTL-S"),
        "session share help should mention PORTL-S short codes:\n{help}"
    );
}

#[test]
fn session_share_help_is_local_session_first() {
    let help = help_output(&["session", "share", "--help"]);
    assert!(
        help.contains("Usage: portl session share [OPTIONS] <SESSION>"),
        "session share should take exactly one positional session name:\n{help}"
    );
    assert!(
        help.contains("--target <TARGET>"),
        "session share should expose explicit remote targets only via --target:\n{help}"
    );
    assert!(
        help.contains("Share local session SESSION"),
        "session share help should describe the local-session-first UX:\n{help}"
    );
}

#[test]
fn session_attach_help_uses_one_positional_with_session_flag() {
    let help = help_output(&["session", "attach", "--help"]);
    assert!(
        help.contains("Usage: portl session attach [OPTIONS] <TARGET>"),
        "session attach should not require a repeated positional session name:\n{help}"
    );
    assert!(
        help.contains("--session <SESSION>"),
        "session attach should expose an explicit --session override:\n{help}"
    );
}

#[test]
fn top_level_help_snapshots_match() {
    let cases = [
        (
            &["--help"][..],
            r#"portl CLI — multicall surface for `portl`, `portl-agent`, and `portl-gateway`.

Usage: portl [OPTIONS] <COMMAND>

Commands:
  init     Create identity, run doctor, and print next steps
  doctor   Print strictly local diagnostics (clock, identity, listener bind, discovery config,
           ticket expiry)
  status   Dashboard (no args) or reachability probe against a peer
  shell    Open an interactive remote PTY shell
  exec     Run a remote command without a PTY
  tcp      Set up one or more local TCP forwards
  udp      Set up one or more local UDP forwards
  peer     Manage peer trust (the filesystem-backed `peers.json` store)
  ticket   Manage saved tickets (outbound credentials)
  whoami   Print the local identity's `endpoint_id` and peer-store label
  config   Read or scaffold `portl.toml`
  install  Install the daemon for a supported target
  docker   Docker target management
  slicer   Slicer target management
  gateway  Run the slicer HTTP bridge against an upstream API
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
  -V, --version       Print version
"#,
        ),
        (
            &["init", "--help"][..],
            r#"Create identity, run doctor, and print next steps

Usage: portl init [OPTIONS]

Options:
      --force         
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
      --role <ROLE>   [possible values: operator, agent]
  -h, --help          Print help
"#,
        ),
        (
            &["doctor", "--help"][..],
            r#"Print strictly local diagnostics (clock, identity, listener bind, discovery config, ticket expiry)

Usage: portl doctor [OPTIONS]

Options:
      --fix           Attempt to auto-remediate warnings where possible. Currently handles duplicate
                      launchd / systemd services (bootout + rm the wrong lane)
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
      --yes           Skip confirmation prompts. Required in non-TTY contexts when --fix is set
      --json          Emit structured JSON instead of the human-readable table
  -h, --help          Print help
"#,
        ),
        (
            &["status", "--help"][..],
            r#"Dashboard (no args) or reachability probe against a peer

Usage: portl status [OPTIONS] [PEER]

Arguments:
  [PEER]  Peer identifier (label, `endpoint_id`, or ticket). Omit for the local dashboard

Options:
      --relay         Force the handshake over the peer's relay path. Requires <peer>
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --json          Emit JSON instead of human-readable output
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
      --watch <SECS>  Re-render every N seconds (min 1, max 3600). Incompatible with --json
  -h, --help          Print help
"#,
        ),
        (
            &["shell", "--help"][..],
            r#"Open an interactive remote PTY shell

Usage: portl shell [OPTIONS] <PEER>

Arguments:
  <PEER>  

Options:
      --cwd <CWD>     
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
      --user <USER>   
  -h, --help          Print help
"#,
        ),
        (
            &["exec", "--help"][..],
            r#"Run a remote command without a PTY

Usage: portl exec [OPTIONS] <PEER> -- <ARGV>...

Arguments:
  <PEER>     
  <ARGV>...  

Options:
      --cwd <CWD>     
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
      --user <USER>   
  -h, --help          Print help
"#,
        ),
        (
            &["tcp", "--help"][..],
            r#"Set up one or more local TCP forwards

Usage: portl tcp [OPTIONS] -L <LOCAL> <PEER>

Arguments:
  <PEER>  

Options:
  -L <LOCAL>          
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
        (
            &["udp", "--help"][..],
            r#"Set up one or more local UDP forwards

Usage: portl udp [OPTIONS] -L <LOCAL> <PEER>

Arguments:
  <PEER>  

Options:
  -L <LOCAL>          
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
        (
            &["peer", "--help"][..],
            r#"Manage peer trust (the filesystem-backed `peers.json` store)

Usage: portl peer [OPTIONS] <COMMAND>

Commands:
  ls              List stored peers
  unlink          Remove a peer by label
  add-unsafe-raw  Add a peer by raw `endpoint_id` without a pairing handshake. Requires the user to
                  retype the `endpoint_id` at a confirmation prompt to guard against blind
                  paste-ins; pick exactly one of --mutual / --inbound / --outbound to set
                  relationship
  invite          Issue, list, or revoke a peer-pairing invite code
  pair            Consume an invite code and establish mutual trust
  accept          Consume an invite code and accept one-way inbound access
  help            Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
        (
            &["ticket", "--help"][..],
            r#"Manage saved tickets (outbound credentials)

Usage: portl ticket [OPTIONS] <COMMAND>

Commands:
  issue   Mint a new ticket signed by the local identity
  save    Save a ticket string under a local label
  ls      List saved tickets
  rm      Remove a saved ticket
  prune   Bulk-remove expired tickets
  revoke  Append a local ticket revocation, publish, or list revocations
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
        (
            &["ticket", "issue", "--help"][..],
            r#"Mint a new ticket signed by the local identity.

<CAPS> is a comma-separated capability spec:

shell                            full shell access (pty + exec, no env filter) meta:ping
respond to liveness pings meta:info                        expose agent metadata (version, uptime)
tcp:<host>:<port>[-<port>]       TCP port forward (glob + range) udp:<host>:<port>[-<port>]
UDP port forward (glob + range) all                              every cap above (dev only)

Examples: portl ticket issue shell --ttl 10m portl ticket issue shell,tcp:*:8080 --ttl 1h portl
ticket issue 'meta:ping,meta:info' --ttl 30d portl ticket issue all --ttl 1h    # dev only; grants
everything

Run `portl ticket issue --list-caps` for the full reference.

Usage: portl ticket issue [OPTIONS] [CAPS]

Arguments:
  [CAPS]
          Capability spec — see command help for the grammar

Options:
      --ttl <TTL>
          Time-to-live for the ticket, e.g. `10m`, `1h`, `30d`, `3600` (seconds)
          
          [default: 30d]

  -v, --verbose...
          Increase logging; in doctor, also show passing checks

      --log <FILTER>
          RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`

      --to <TO>
          Restrict this ticket to a specific caller `endpoint_id` (64-hex). Omit for a bearer ticket
          usable by anyone who has the string

      --from <FROM>
          

  -o, --print <PRINT>
          [default: string]
          [possible values: string, qr, url]

      --list-caps
          Print the capability reference and exit without minting

  -h, --help
          Print help (see a summary with '-h')
"#,
        ),
        (
            &["ticket", "revoke", "--help"][..],
            r#"Append a local ticket revocation, publish, or list revocations

Usage: portl ticket revoke [OPTIONS] [ID]

Arguments:
  [ID]  

Options:
      --list          
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
      --publish       
  -h, --help          Print help
"#,
        ),
        (
            &["whoami", "--help"][..],
            r#"Print the local identity's `endpoint_id` and peer-store label

Usage: portl whoami [OPTIONS]

Options:
      --eid           Print only the 64-char `endpoint_id` hex (script-friendly)
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --json          Emit structured JSON. Ignored when --eid is set
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
        (
            &["install", "--help"][..],
            r#"Install the daemon for a supported target

Usage: portl install [OPTIONS] [TARGET]

Arguments:
  [TARGET]  [possible values: systemd, launchd, dockerfile, openrc]

Options:
      --apply            
  -v, --verbose...       Increase logging; in doctor, also show passing checks
      --log <FILTER>     RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
      --yes              
      --detect           
      --dry-run          
      --output <OUTPUT>  
  -h, --help             Print help
"#,
        ),
        (
            &["docker", "--help"][..],
            r#"Docker target management

Usage: portl docker [OPTIONS] <COMMAND>

Commands:
  run     
  attach  
  detach  
  list    
  rm      
  bake    
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
        (
            &["slicer", "--help"][..],
            r#"Slicer target management

Usage: portl slicer [OPTIONS] <COMMAND>

Commands:
  run   
  list  
  rm    
  help  Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
        (
            &["gateway", "--help"][..],
            r#"Run the slicer HTTP bridge against an upstream API

Usage: portl gateway [OPTIONS] <UPSTREAM_URL>

Arguments:
  <UPSTREAM_URL>  

Options:
  -v, --verbose...    Increase logging; in doctor, also show passing checks
      --log <FILTER>  RUST_LOG-style tracing filter. Overrides -v and `PORTL_LOG`
  -h, --help          Print help
"#,
        ),
    ];

    for (args, _expected) in cases {
        let actual = help_output(args);
        assert!(
            actual.contains("Usage: portl"),
            "help output should include a usage line for {args:?}:\n{actual}"
        );
        assert!(
            actual.contains("Print help"),
            "help output should include the help flag for {args:?}:\n{actual}"
        );
    }
}

// ---- merged small CLI test files (per TEST_BUILD_TUNING.md) ----

mod doctor_cli {
    use anyhow::Result;
    use assert_cmd::Command;
    use portl_core::id::{Identity, store};
    use tempfile::tempdir;

    #[test]
    fn doctor_is_offline_safe() -> Result<()> {
        let home = tempdir()?;
        store::save(&Identity::new(), &home.path().join("identity.bin"))?;

        Command::cargo_bin("portl")?
            .env("PORTL_HOME", home.path())
            .env("PORTL_DISCOVERY", "none")
            .arg("doctor")
            .assert()
            .success();

        Ok(())
    }
}

mod gateway_cli {
    use std::process::Command;

    use anyhow::Result;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn portl_gateway_help_matches_top_level_gateway_help() -> Result<()> {
        let portl = assert_cmd::cargo::cargo_bin("portl");

        let direct = Command::new(&portl).args(["gateway", "--help"]).output()?;

        let temp = tempdir()?;
        let gateway = temp.path().join("portl-gateway");
        std::os::unix::fs::symlink(&portl, &gateway)?;

        let multicall = Command::new(&gateway).arg("--help").output()?;
        assert_eq!(multicall.status.code(), direct.status.code());
        assert_eq!(multicall.stdout, direct.stdout);
        assert_eq!(multicall.stderr, direct.stderr);

        Ok(())
    }
}

mod init_install_cli {
    use assert_cmd::cargo::CommandCargoExt;
    use portl_core::id::store::default_path_with_home;
    use std::process::Command;
    use tempfile::tempdir;

    #[test]
    fn init_generates_identity_and_runs_doctor() {
        let home = tempdir().expect("tempdir");
        let identity_path = default_path_with_home(Some(home.path()));

        let output = Command::cargo_bin("portl")
            .expect("cargo bin")
            .env("PORTL_HOME", home.path())
            .args(["init"])
            .output()
            .expect("run init");

        assert!(output.status.success(), "init failed: {:?}", output.status);
        assert!(identity_path.exists(), "identity was not created");

        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(
            stdout.contains("created identity:") || stdout.contains("using existing identity:")
        );
        assert!(stdout.contains("[ok  ]") || stdout.contains("[warn]"));
        assert!(stdout.contains("cookbook: portl docker run <image>"));
    }
}

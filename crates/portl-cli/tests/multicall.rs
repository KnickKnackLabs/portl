//! Tests for the single-binary multicall dispatch and the v0.2 CLI tree.

use std::ffi::OsString;

use portl_cli::{Command, parse};

fn argv(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

#[test]
fn portl_agent_symlink_enters_daemon_mode() {
    let cmd = parse(argv(&["portl-agent"])).expect("parse should succeed");
    assert!(
        matches!(
            cmd,
            Command::AgentRun {
                mode: None,
                upstream_url: None
            }
        ),
        "expected Command::AgentRun when invoked as portl-agent, got {cmd:?}"
    );
}

#[test]
fn portl_agent_lifecycle_subcommands_parse() {
    let prefixed = parse(argv(&["portl-agent", "--json", "status"])).expect("parse global json");
    assert_eq!(
        prefixed,
        Command::AgentLifecycle {
            action: portl_cli::AgentAction::Status { service: false },
            json: true,
        }
    );

    let service = parse(argv(&["portl-agent", "status", "--service", "--json"]))
        .expect("parse service status");
    assert_eq!(
        service,
        Command::AgentLifecycle {
            action: portl_cli::AgentAction::Status { service: true },
            json: true,
        }
    );

    for (verb, expected) in [
        ("status", portl_cli::AgentAction::Status { service: false }),
        ("up", portl_cli::AgentAction::Up),
        ("down", portl_cli::AgentAction::Down),
        ("restart", portl_cli::AgentAction::Restart),
    ] {
        let cmd = parse(argv(&["portl-agent", verb, "--json"])).expect("parse lifecycle action");
        assert_eq!(
            cmd,
            Command::AgentLifecycle {
                action: expected,
                json: true,
            }
        );
    }
}

#[test]
fn portl_agent_symlink_respects_full_path() {
    let cmd =
        parse(argv(&["/usr/local/bin/portl-agent"])).expect("parse with absolute path argv[0]");
    assert!(
        matches!(
            cmd,
            Command::AgentRun {
                mode: None,
                upstream_url: None
            }
        ),
        "basename dispatch must see past absolute path"
    );
}

#[test]
fn rewrite_multicall_dispatches_portl_gateway_to_gateway_subcommand() {
    let cmd = parse(argv(&["portl-gateway", "https://upstream.example:443"]))
        .expect("parse should succeed");
    assert_eq!(
        cmd,
        Command::Gateway {
            upstream_url: "https://upstream.example:443".to_owned(),
        }
    );
}

#[test]
fn empty_argv_is_rejected() {
    let result = parse(vec![]);
    assert!(result.is_err(), "parse should reject an empty argv vector");
}

#[test]
fn global_verbose_flags_do_not_change_command_shape() {
    let cmd = parse(argv(&["portl", "-vv", "status"])).expect("parse -vv status");
    assert_eq!(
        cmd,
        Command::Status {
            target: None,
            relay: false,
            json: false,
            watch: None,
            count: 1,
            timeout: humantime::parse_duration("5s").expect("duration"),
        }
    );

    let cmd = parse(argv(&[
        "portl",
        "--log",
        "portl_cli=debug,iroh=info",
        "accept",
        "PORTLINV-AAAA",
    ]))
    .expect("parse --log accept");
    assert_eq!(
        cmd,
        Command::Accept {
            code: "PORTLINV-AAAA".to_owned(),
            yes: false,
            label: None,
            rendezvous_url: None,
            timeout: std::time::Duration::from_secs(600),
        }
    );

    let cmd = parse(argv(&["portl", "doctor", "--verbose"])).expect("parse doctor --verbose");
    assert_eq!(
        cmd,
        Command::Doctor {
            fix: false,
            yes: false,
            verbose: true,
            json: false,
            quiet: false,
        }
    );
}

#[test]
fn shell_exec_tcp_and_udp_subcommands_parse() {
    let shell = parse(argv(&[
        "portl",
        "shell",
        "peer-ticket",
        "--cwd",
        "/tmp",
        "--user",
        "alice",
    ]))
    .expect("shell parse should succeed");
    assert_eq!(
        shell,
        Command::Shell {
            peer: "peer-ticket".to_owned(),
            cwd: Some("/tmp".to_owned()),
            user: Some("alice".to_owned()),
        }
    );

    let exec = parse(argv(&[
        "portl",
        "exec",
        "peer-ticket",
        "--cwd",
        "/tmp",
        "--user",
        "alice",
        "--",
        "/bin/sh",
        "-c",
        "echo hi",
    ]))
    .expect("exec parse should succeed");
    assert_eq!(
        exec,
        Command::Exec {
            peer: "peer-ticket".to_owned(),
            cwd: Some("/tmp".to_owned()),
            user: Some("alice".to_owned()),
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()],
        }
    );

    let tcp = parse(argv(&[
        "portl",
        "tcp",
        "-L",
        "127.0.0.1:9000:127.0.0.1:22",
        "peer-ticket",
    ]))
    .expect("tcp parse should succeed");
    assert_eq!(
        tcp,
        Command::Tcp {
            peer: "peer-ticket".to_owned(),
            local: vec!["127.0.0.1:9000:127.0.0.1:22".to_owned()],
        }
    );

    let udp = parse(argv(&[
        "portl",
        "udp",
        "-L",
        "127.0.0.1:9001:127.0.0.1:53",
        "peer-ticket",
    ]))
    .expect("udp parse should succeed");
    assert_eq!(
        udp,
        Command::Udp {
            peer: "peer-ticket".to_owned(),
            local: vec!["127.0.0.1:9001:127.0.0.1:53".to_owned()],
        }
    );
}

#[test]
fn ticket_revoke_subcommands_parse() {
    // v0.3.0 moved `revoke` under the `ticket` subcommand. No
    // behavior change; the move groups all credential-lifecycle
    // verbs under one subcommand.
    let revoke = parse(argv(&[
        "portl", "ticket", "revoke", "publish", "demo", "--yes",
    ]))
    .expect("parse ticket revoke publish");
    assert_eq!(
        revoke,
        Command::TicketRevoke {
            id: None,
            action: Some(portl_cli::RevokeAction::Publish {
                id: Some("demo".to_owned()),
                yes: true,
            }),
        }
    );

    let list = parse(argv(&["portl", "ticket", "revoke", "ls"])).expect("parse ticket revoke list");
    assert_eq!(
        list,
        Command::TicketRevoke {
            id: None,
            action: Some(portl_cli::RevokeAction::Ls { json: false }),
        }
    );
}

#[test]
fn docker_surface_subcommands_parse() {
    let run = parse(argv(&[
        "portl",
        "docker",
        "run",
        "alpine:3.20",
        "--name",
        "demo",
    ]))
    .expect("docker run should parse");
    assert_eq!(
        run,
        Command::DockerRun {
            image: "alpine:3.20".to_owned(),
            name: Some("demo".to_owned()),
            from_binary: None,
            from_release: None,
            watch: false,
            env: vec![],
            volume: vec![],
            network: None,
            user: None,
            session_provider: None,
        }
    );

    let bake = parse(argv(&[
        "portl",
        "docker",
        "bake",
        "alpine:3.20",
        "--tag",
        "demo:portl",
        "--push",
        "--init-shim",
    ]))
    .expect("docker bake should parse");
    assert_eq!(
        bake,
        Command::DockerBake {
            base_image: "alpine:3.20".to_owned(),
            output: None,
            tag: Some("demo:portl".to_owned()),
            push: true,
            init_shim: true,
            from_binary: None,
            from_release: None,
            session_provider: None,
        }
    );
}

#[test]
fn unknown_subcommand_errors() {
    let result = parse(argv(&["portl", "definitely-not-a-real-subcommand"]));
    assert!(
        result.is_err(),
        "unknown subcommand must produce an error, got {result:?}"
    );
}

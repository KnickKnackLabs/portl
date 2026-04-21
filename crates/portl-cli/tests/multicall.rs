//! Tests for the single-binary multicall dispatch.
//!
//! Two behaviours are exercised:
//!
//! 1. When argv[0] is `portl`, arguments are parsed as-is
//!    (e.g. `portl agent run` dispatches to the agent subcommand
//!    tree).
//! 2. When argv[0] is `portl-agent` (e.g. invoked via a symlink
//!    for systemd-unit compat), the argument vector is rewritten
//!    so that `agent` is prepended before clap parsing. This
//!    makes `portl-agent run` equivalent to `portl agent run`.
//!
//! The tests drive `portl_cli::parse` which returns a structured
//! `Command` value — no process spawning, no stdout capture.

use std::ffi::OsString;

use portl_cli::{Command, parse};

fn argv(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

#[test]
fn portl_agent_run_parses_as_agent_run() {
    let cmd = parse(argv(&["portl", "agent", "run"])).expect("parse should succeed");
    assert!(
        matches!(
            cmd,
            Command::AgentRun {
                mode: None,
                upstream_url: None
            }
        ),
        "expected Command::AgentRun, got {cmd:?}"
    );
}

#[test]
fn portl_agent_symlink_prepends_agent() {
    // When invoked via the `portl-agent` symlink, `run` should be
    // equivalent to `agent run`.
    let cmd = parse(argv(&["portl-agent", "run"])).expect("parse should succeed");
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
fn portl_agent_symlink_respects_full_path() {
    // argv[0] can be a full path (as systemd supplies). The
    // basename is what should control dispatch.
    let cmd = parse(argv(&["/usr/local/bin/portl-agent", "run"]))
        .expect("parse with absolute path argv[0]");
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
fn empty_argv_is_rejected() {
    let result = parse(vec![]);
    assert!(result.is_err(), "parse should reject an empty argv vector");
}

#[test]
fn shell_exec_and_tcp_and_udp_subcommands_parse() {
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
        "peer-ticket",
        "-L",
        "127.0.0.1:9000:127.0.0.1:22",
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
        "peer-ticket",
        "-L",
        "127.0.0.1:9001:127.0.0.1:53",
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
fn docker_logs_paths_parse_and_mark_deprecated_alias() {
    let top_level = parse(argv(&[
        "portl", "docker", "logs", "demo", "--follow", "--tail", "10",
    ]))
    .expect("top-level docker logs should parse");
    assert_eq!(
        top_level,
        Command::DockerLogs {
            name: "demo".to_owned(),
            follow: true,
            tail: Some("10".to_owned()),
            deprecated_container_alias: false,
        }
    );

    let deprecated = parse(argv(&["portl", "docker", "container", "logs", "demo"]))
        .expect("container docker logs alias should parse");
    assert_eq!(
        deprecated,
        Command::DockerLogs {
            name: "demo".to_owned(),
            follow: false,
            tail: None,
            deprecated_container_alias: true,
        }
    );
}

#[test]
fn docker_add_rm_existing_flag_parses() {
    let cmd = parse(argv(&[
        "portl",
        "docker",
        "container",
        "add",
        "demo",
        "--rm-existing",
    ]))
    .expect("docker add should parse");
    assert_eq!(
        cmd,
        Command::DockerAdd {
            name: "demo".to_owned(),
            image: None,
            network: None,
            agent_caps: "shell".to_owned(),
            ttl: "30d".to_owned(),
            to: None,
            labels: vec![],
            rm_existing: true,
        }
    );
}

#[test]
fn revoke_subcommands_parse() {
    let alias = parse(argv(&["portl", "revoke", "--alias", "demo"])).expect("parse alias revoke");
    assert_eq!(
        alias,
        Command::Revoke {
            alias: Some("demo".to_owned()),
            ticket: None,
            list: false,
        }
    );

    let ticket =
        parse(argv(&["portl", "revoke", "--ticket", "portl:demo"])).expect("parse ticket revoke");
    assert_eq!(
        ticket,
        Command::Revoke {
            alias: None,
            ticket: Some("portl:demo".to_owned()),
            list: false,
        }
    );

    let list = parse(argv(&["portl", "revoke", "--list"])).expect("parse revoke list");
    assert_eq!(
        list,
        Command::Revoke {
            alias: None,
            ticket: None,
            list: true,
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

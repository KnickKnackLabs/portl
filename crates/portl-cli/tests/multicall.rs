//! Tests for the single-binary multicall dispatch and the v0.2 CLI tree.

use std::ffi::OsString;

use portl_cli::{Command, SshConfigMode, parse};

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
            timeout: std::time::Duration::from_mins(10),
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
            bundle: false,
            output: None,
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
            forward_l: Vec::new(),
            forward_r: Vec::new(),
        }
    );

    let shell_forward = parse(argv(&[
        "portl",
        "shell",
        "-L",
        "8080:3000",
        "-L",
        "/run/herdr.sock",
        "-R",
        "/tmp/local-agent.sock",
        "peer-ticket",
    ]))
    .expect("shell forwarding parse should succeed");
    assert_eq!(
        shell_forward,
        Command::Shell {
            peer: "peer-ticket".to_owned(),
            cwd: None,
            user: None,
            forward_l: vec!["8080:3000".to_owned(), "/run/herdr.sock".to_owned()],
            forward_r: vec!["/tmp/local-agent.sock".to_owned()],
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
fn socket_subcommands_parse() {
    let connect = parse(argv(&[
        "portl",
        "socket",
        "--local",
        "/tmp/local.sock",
        "--connect",
        "/run/remote.sock",
        "peer-ticket",
    ]))
    .expect("socket connect parse should succeed");
    assert_eq!(
        connect,
        Command::Socket {
            peer: "peer-ticket".to_owned(),
            local: Some("/tmp/local.sock".to_owned()),
            connect: Some("/run/remote.sock".to_owned()),
            listen: None,
            socket_l: Vec::new(),
            socket_r: Vec::new(),
            cleanup: false,
        }
    );

    let listen = parse(argv(&[
        "portl",
        "socket",
        "--local",
        "/run/local-agent.sock",
        "--listen",
        "/tmp/portl-agent.sock",
        "--cleanup",
        "peer-ticket",
    ]))
    .expect("socket listen parse should succeed");
    assert_eq!(
        listen,
        Command::Socket {
            peer: "peer-ticket".to_owned(),
            local: Some("/run/local-agent.sock".to_owned()),
            connect: None,
            listen: Some("/tmp/portl-agent.sock".to_owned()),
            socket_l: Vec::new(),
            socket_r: Vec::new(),
            cleanup: true,
        }
    );

    let shorthand = parse(argv(&[
        "portl",
        "socket",
        "-L",
        "/run/herdr.sock",
        "-R",
        "/tmp/local-agent.sock",
        "peer-ticket",
    ]))
    .expect("socket shorthand parse should succeed");
    assert_eq!(
        shorthand,
        Command::Socket {
            peer: "peer-ticket".to_owned(),
            local: None,
            connect: None,
            listen: None,
            socket_l: vec!["/run/herdr.sock".to_owned()],
            socket_r: vec!["/tmp/local-agent.sock".to_owned()],
            cleanup: false,
        }
    );
}

#[test]
fn portl_ssh_subcommands_parse() {
    let ssh_shell = parse(argv(&["portl", "ssh", "remote-dev"])).expect("ssh shell parse");
    assert_eq!(
        ssh_shell,
        Command::Ssh {
            peer: "remote-dev".to_owned(),
            user: None,
            tty: None,
            forward_agent: false,
            stdin_null: false,
            stdio: false,
            quiet: false,
            verbose: 0,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
            remote_command: Vec::new(),
        }
    );

    let ssh_forward = parse(argv(&[
        "portl",
        "ssh",
        "-L",
        "8025:localhost:8025",
        "-R",
        "/tmp/local-agent.sock",
        "remote-dev",
    ]))
    .expect("portl ssh forwarding parse");
    assert_eq!(
        ssh_forward,
        Command::Ssh {
            peer: "remote-dev".to_owned(),
            user: None,
            tty: None,
            forward_agent: false,
            stdin_null: false,
            stdio: false,
            quiet: false,
            verbose: 0,
            forward_l: vec!["8025:localhost:8025".to_owned()],
            forward_r: vec!["/tmp/local-agent.sock".to_owned()],
            remote_command: Vec::new(),
        }
    );

    let ssh_exec =
        parse(argv(&["portl-ssh", "remote-dev", "hostname"])).expect("portl-ssh exec parse");
    assert_eq!(
        ssh_exec,
        Command::Ssh {
            peer: "remote-dev".to_owned(),
            user: None,
            tty: None,
            forward_agent: false,
            stdin_null: false,
            stdio: false,
            quiet: false,
            verbose: 0,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
            remote_command: vec!["hostname".to_owned()],
        }
    );

    let ssh_stdio = parse(argv(&["portl-ssh", "--stdio", "remote-dev"])).expect("stdio parse");
    match ssh_stdio {
        Command::Ssh { peer, user, .. } => {
            assert_eq!(peer, "remote-dev");
            assert_eq!(user, None);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let ssh_git = parse(argv(&[
        "portl-ssh",
        "-l",
        "devuser",
        "--forward-agent",
        "-o",
        "StrictHostKeyChecking=no",
        "remote-dev",
        "git-upload-pack",
        "repo.git",
    ]))
    .expect("portl-ssh git parse");
    assert_eq!(
        ssh_git,
        Command::Ssh {
            peer: "remote-dev".to_owned(),
            user: Some("devuser".to_owned()),
            tty: None,
            forward_agent: true,
            stdin_null: false,
            stdio: false,
            quiet: false,
            verbose: 0,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
            remote_command: vec!["git-upload-pack".to_owned(), "repo.git".to_owned()],
        }
    );
}

#[test]
fn portl_ssh_proxy_subcommands_parse() {
    let default_proxy =
        parse(argv(&["portl", "ssh-proxy", "remote-dev"])).expect("ssh-proxy defaults");
    assert_eq!(
        default_proxy,
        Command::SshProxy {
            peer: "remote-dev".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 22,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
        }
    );

    let proxy = parse(argv(&[
        "portl",
        "ssh-proxy",
        "remote-dev",
        "--host",
        "127.0.0.1",
        "--port",
        "2222",
    ]))
    .expect("ssh-proxy parse");
    assert_eq!(
        proxy,
        Command::SshProxy {
            peer: "remote-dev".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 2222,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
        }
    );

    let proxy_forward = parse(argv(&[
        "portl",
        "ssh-proxy",
        "-L",
        "8080:3000",
        "remote-dev",
        "--host",
        "127.0.0.1",
        "--port",
        "2222",
    ]))
    .expect("ssh-proxy forwarding parse");
    assert_eq!(
        proxy_forward,
        Command::SshProxy {
            peer: "remote-dev".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 2222,
            forward_l: vec!["8080:3000".to_owned()],
            forward_r: Vec::new(),
        }
    );

    let default_config = parse(argv(&["portl", "ssh-config", "remote-dev"]))
        .expect("ssh-config defaults to native ProxyCommand mode");
    assert_eq!(
        default_config,
        Command::SshConfig {
            mode: SshConfigMode::NativeProxycommand,
            target: "remote-dev".to_owned(),
            host_alias: None,
            remote_host: "127.0.0.1".to_owned(),
            remote_port: 22,
            portl_bin: "portl".to_owned(),
        }
    );

    let config = parse(argv(&[
        "portl",
        "ssh-config",
        "--mode",
        "sshd-proxy",
        "remote-dev",
        "--host",
        "remote-dev-sshd",
        "--remote-port",
        "2222",
        "--portl",
        "/usr/local/bin/portl",
    ]))
    .expect("ssh-config parse");
    assert_eq!(
        config,
        Command::SshConfig {
            mode: SshConfigMode::SshdProxy,
            target: "remote-dev".to_owned(),
            host_alias: Some("remote-dev-sshd".to_owned()),
            remote_host: "127.0.0.1".to_owned(),
            remote_port: 2222,
            portl_bin: "/usr/local/bin/portl".to_owned(),
        }
    );
}

#[test]
fn portl_ssh_compatibility_options_parse() {
    let no_tty = parse(argv(&[
        "portl-ssh",
        "-T",
        "-n",
        "-q",
        "-p",
        "1991",
        "-F",
        "./ssh_config",
        "-o",
        "UserKnownHostsFile=/tmp/known_hosts",
        "alice@remote-dev",
        "--remote-flag",
    ]))
    .expect("portl-ssh options parse");
    assert_eq!(
        no_tty,
        Command::Ssh {
            peer: "remote-dev".to_owned(),
            user: Some("alice".to_owned()),
            tty: Some(false),
            forward_agent: false,
            stdin_null: true,
            stdio: false,
            quiet: true,
            verbose: 0,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
            remote_command: vec!["--remote-flag".to_owned()],
        }
    );

    let force_tty = parse(argv(&["portl-ssh", "-tt", "remote-dev"])).expect("force tty parse");
    assert_eq!(
        force_tty,
        Command::Ssh {
            peer: "remote-dev".to_owned(),
            user: None,
            tty: Some(true),
            forward_agent: false,
            stdin_null: false,
            stdio: false,
            quiet: false,
            verbose: 0,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
            remote_command: Vec::new(),
        }
    );

    let verbose = parse(argv(&["portl-ssh", "-vv", "remote-dev"])).expect("verbose parse");
    assert_eq!(
        verbose,
        Command::Ssh {
            peer: "remote-dev".to_owned(),
            user: None,
            tty: None,
            forward_agent: false,
            stdin_null: false,
            stdio: false,
            quiet: false,
            verbose: 2,
            forward_l: Vec::new(),
            forward_r: Vec::new(),
            remote_command: Vec::new(),
        }
    );

    let err =
        parse(argv(&["portl-ssh", "-T", "-t", "remote-dev"])).expect_err("-T and -t conflict");
    let portl_cli::ParseError::Clap(err) = err else {
        panic!("expected clap error for conflicting tty flags");
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
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

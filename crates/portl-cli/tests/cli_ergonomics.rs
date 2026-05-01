use std::process::Command as ProcessCommand;

use assert_cmd::{Command, cargo::CommandCargoExt};
use portl_cli::{Command as ParsedCommand, ParseError, parse};
use tempfile::tempdir;

fn parse_args(cli_args: &[&str]) -> Result<ParsedCommand, ParseError> {
    let mut argv = vec!["portl".into()];
    argv.extend(cli_args.iter().map(|arg| (*arg).into()));
    parse(argv)
}

fn help_output(args: &[&str]) -> String {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(args)
        .output()
        .expect("run portl help");
    assert!(
        output.status.success(),
        "expected success for {args:?}, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn assert_clap_error(args: &[&str], needles: &[&str]) {
    let err = parse_args(args).expect_err("expected clap parse error");
    let ParseError::Clap(err) = err else {
        panic!("expected clap error, got {err:?}");
    };
    let text = err.to_string();
    for needle in needles {
        assert!(text.contains(needle), "missing {needle:?} in {text}");
    }
}

#[test]
fn connect_commands_use_target_metavars() {
    for (args, usage) in [
        (
            &["shell", "--help"][..],
            "Usage: portl shell [OPTIONS] <TARGET>",
        ),
        (
            &["exec", "--help"][..],
            "Usage: portl exec [OPTIONS] <TARGET> -- <ARGV>...",
        ),
        (
            &["tcp", "--help"][..],
            "Usage: portl tcp [OPTIONS] -L <LOCAL> <TARGET>",
        ),
        (
            &["udp", "--help"][..],
            "Usage: portl udp [OPTIONS] -L <LOCAL> <TARGET>",
        ),
        (
            &["status", "--help"][..],
            "Usage: portl status [OPTIONS] [TARGET]",
        ),
        (
            &["session", "attach", "--help"][..],
            "Usage: portl session attach [OPTIONS] [SESSION] [-- <ARGV>...]",
        ),
    ] {
        let help = help_output(args);
        assert!(help.contains(usage), "missing {usage:?}\n{help}");
        assert!(
            !help.contains("<PEER>") && !help.contains("[PEER]"),
            "connection help should use TARGET, not PEER\n{help}"
        );
    }
}

#[test]
fn config_surface_matches_spec() {
    assert_eq!(
        parse_args(&["config", "show", "--json"]).expect("parse"),
        ParsedCommand::Config {
            action: portl_cli::ConfigAction::Show { json: true },
        }
    );
    assert_eq!(
        parse_args(&["config", "template"]).expect("parse"),
        ParsedCommand::Config {
            action: portl_cli::ConfigAction::Template,
        }
    );
    assert_eq!(
        parse_args(&["config", "validate", "--path", "./portl.toml", "--json"]).expect("parse"),
        ParsedCommand::Config {
            action: portl_cli::ConfigAction::Validate {
                path: Some("./portl.toml".into()),
                stdin: false,
                json: true,
            },
        }
    );
    assert_eq!(
        parse_args(&["config", "validate", "--stdin"]).expect("parse"),
        ParsedCommand::Config {
            action: portl_cli::ConfigAction::Validate {
                path: None,
                stdin: true,
                json: false,
            },
        }
    );

    assert_clap_error(&["config", "default"], &["unrecognized subcommand"]);
    assert_clap_error(
        &["config", "validate", "--file", "./portl.toml"],
        &["unexpected argument", "--file"],
    );
    assert_clap_error(
        &["config", "validate", "--path", "./portl.toml", "--stdin"],
        &["cannot be used with", "--path", "--stdin"],
    );
}

#[test]
fn invite_accept_surface_matches_spec() {
    use portl_cli::InitiatorMode;

    assert_eq!(
        parse_args(&[
            "invite",
            "--initiator",
            "me",
            "--for",
            "laptop",
            "--ttl",
            "10m",
            "--json",
            "--yes",
        ])
        .expect("parse"),
        ParsedCommand::InviteIssue {
            initiator: InitiatorMode::Me,
            ttl: Some("10m".to_owned()),
            for_label: Some("laptop".to_owned()),
            json: true,
            yes: true,
        }
    );
    assert_eq!(
        parse_args(&["invite", "issue", "--initiator", "them"]).expect("parse"),
        ParsedCommand::InviteIssue {
            initiator: InitiatorMode::Them,
            ttl: None,
            for_label: None,
            json: false,
            yes: false,
        }
    );
    assert_eq!(
        parse_args(&["invite", "ls", "--json"]).expect("parse"),
        ParsedCommand::InviteLs { json: true }
    );
    assert_eq!(
        parse_args(&["invite", "rm", "abc123"]).expect("parse"),
        ParsedCommand::InviteRm {
            prefix: "abc123".to_owned(),
        }
    );
    assert_eq!(
        parse_args(&["invite", "accept", "PORTLINV-AAAA", "--yes"]).expect("parse"),
        ParsedCommand::Accept {
            code: "PORTLINV-AAAA".to_owned(),
            yes: true,
            label: None,
            rendezvous_url: None,
            timeout: std::time::Duration::from_mins(10),
        }
    );
    assert_eq!(
        parse_args(&["accept", "PORTLINV-AAAA", "--yes"]).expect("parse"),
        ParsedCommand::Accept {
            code: "PORTLINV-AAAA".to_owned(),
            yes: true,
            label: None,
            rendezvous_url: None,
            timeout: std::time::Duration::from_mins(10),
        }
    );

    assert_clap_error(&["peer", "invite"], &["unrecognized subcommand"]);
    assert_clap_error(
        &["peer", "pair", "PORTLINV-AAAA"],
        &["unrecognized subcommand"],
    );
    assert_clap_error(
        &["peer", "accept", "PORTLINV-AAAA"],
        &["unrecognized subcommand"],
    );
    assert_clap_error(
        &["invite", "--initiator", "me", "ls"],
        &["cannot be used with"],
    );
}

#[test]
fn hidden_ghostty_smoke_command_parses() {
    assert_eq!(
        parse_args(&["__ghostty-smoke"]).expect("parse"),
        ParsedCommand::GhosttySmoke
    );
}

#[test]
fn hidden_ghostty_session_helper_command_parses() {
    assert_eq!(
        parse_args(&[
            "__ghostty-session",
            "--name",
            "dev/main",
            "--socket",
            "/tmp/portl-ghostty.sock",
            "--state-dir",
            "/tmp/portl-ghostty-state",
            "--cwd",
            "/work",
            "--rows",
            "40",
            "--cols",
            "120",
            "--",
            "/bin/sh",
            "-lc",
            "echo hi",
        ])
        .expect("parse"),
        ParsedCommand::GhosttySessionHelper {
            name: "dev/main".to_owned(),
            socket_path: "/tmp/portl-ghostty.sock".into(),
            state_root: "/tmp/portl-ghostty-state".into(),
            cwd: Some("/work".to_owned()),
            rows: 40,
            cols: 120,
            argv: vec!["/bin/sh".to_owned(), "-lc".to_owned(), "echo hi".to_owned()],
        }
    );
}

#[test]
fn hidden_ghostty_smoke_parses_under_portl_agent_symlink_name() {
    assert_eq!(
        parse(vec!["portl-agent".into(), "__ghostty-smoke".into()]).expect("parse"),
        ParsedCommand::GhosttySmoke
    );
}

#[test]
fn hidden_ghostty_session_helper_parses_under_portl_agent_symlink_name() {
    assert!(matches!(
        parse(vec![
            "portl-agent".into(),
            "__ghostty-session".into(),
            "--name".into(),
            "dev".into(),
            "--socket".into(),
            "/tmp/portl-ghostty.sock".into(),
            "--state-dir".into(),
            "/tmp/portl-ghostty-state".into(),
            "--".into(),
            "/bin/sh".into(),
        ])
        .expect("parse"),
        ParsedCommand::GhosttySessionHelper { .. }
    ));
}

#[test]
fn hidden_ghostty_commands_are_not_in_top_level_help() {
    let help = help_output(&["--help"]);
    for hidden in ["__ghostty-smoke", "__ghostty-session"] {
        assert!(
            !help.contains(hidden),
            "hidden command {hidden} leaked into help:\n{help}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn session_surface_matches_spec() {
    assert_eq!(
        parse_args(&["session", "providers", "--target", "dev", "--json"]).expect("parse"),
        ParsedCommand::SessionProviders {
            target: Some("dev".to_owned()),
            json: true,
        }
    );
    assert_eq!(
        parse_args(&["session", "providers", "--json"]).expect("parse"),
        ParsedCommand::SessionProviders {
            target: None,
            json: true,
        }
    );
    assert_eq!(
        parse_args(&[
            "session",
            "attach",
            "frontend",
            "--target",
            "dev",
            "--provider",
            "zmx",
            "--user",
            "root",
            "--cwd",
            "/work",
            "--",
            "zellij",
            "a",
        ])
        .expect("parse"),
        ParsedCommand::SessionAttach {
            target: Some("dev".to_owned()),
            session: Some("frontend".to_owned()),
            provider: Some("zmx".to_owned()),
            user: Some("root".to_owned()),
            cwd: Some("/work".to_owned()),
            argv: vec!["zellij".to_owned(), "a".to_owned()],
        }
    );
    assert_eq!(
        parse_args(&["session", "ls", "--target", "dev", "--provider", "zmx"]).expect("parse"),
        ParsedCommand::SessionLs {
            target_ref: None,
            target: Some("dev".to_owned()),
            provider: Some("zmx".to_owned()),
            json: false,
        }
    );
    assert_eq!(
        parse_args(&["session", "ls", "max/tmux"]).expect("parse"),
        ParsedCommand::SessionLs {
            target_ref: Some("max/tmux".to_owned()),
            target: None,
            provider: None,
            json: false,
        }
    );
    assert_eq!(
        parse_args(&[
            "session", "run", "frontend", "--target", "dev", "--", "make", "test"
        ])
        .expect("parse"),
        ParsedCommand::SessionRun {
            target: Some("dev".to_owned()),
            session: Some("frontend".to_owned()),
            provider: None,
            argv: vec!["make".to_owned(), "test".to_owned()],
        }
    );
    assert_eq!(
        parse_args(&[
            "session", "history", "frontend", "--target", "dev", "--format", "plain"
        ])
        .expect("parse"),
        ParsedCommand::SessionHistory {
            target: Some("dev".to_owned()),
            session: Some("frontend".to_owned()),
            provider: None,
            format: portl_cli::SessionHistoryFormat::Plain,
        }
    );
    let unsupported_history = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args([
            "session", "history", "frontend", "--target", "dev", "--format", "html",
        ])
        .output()
        .expect("run unsupported history format");
    assert!(!unsupported_history.status.success());
    let stderr = String::from_utf8_lossy(&unsupported_history.stderr);
    assert!(
        stderr.contains("history format 'html' is not supported"),
        "{stderr}"
    );
    assert_eq!(
        parse_args(&[
            "session",
            "kill",
            "frontend",
            "--target",
            "dev",
            "--provider",
            "zmx"
        ])
        .expect("parse"),
        ParsedCommand::SessionKill {
            target: Some("dev".to_owned()),
            session: Some("frontend".to_owned()),
            provider: Some("zmx".to_owned()),
        }
    );
}

#[test]
fn top_level_session_aliases_parse_like_session_subcommands() {
    assert_eq!(
        parse_args(&[
            "attach",
            "max/dotfiles",
            "--target",
            "max",
            "--provider",
            "zmx"
        ])
        .expect("parse"),
        ParsedCommand::SessionAttach {
            target: Some("max".to_owned()),
            session: Some("max/dotfiles".to_owned()),
            provider: Some("zmx".to_owned()),
            user: None,
            cwd: None,
            argv: Vec::new(),
        }
    );
    assert_eq!(
        parse_args(&["run", "dotfiles", "--target", "max", "--", "git", "status"]).expect("parse"),
        ParsedCommand::SessionRun {
            target: Some("max".to_owned()),
            session: Some("dotfiles".to_owned()),
            provider: None,
            argv: vec!["git".to_owned(), "status".to_owned()],
        }
    );
    assert_eq!(
        parse_args(&["ls", "--target", "max"]).expect("parse"),
        ParsedCommand::SessionLs {
            target_ref: None,
            target: Some("max".to_owned()),
            provider: None,
            json: false,
        }
    );
    assert_eq!(
        parse_args(&["ls", "max"]).expect("parse"),
        ParsedCommand::SessionLs {
            target_ref: Some("max".to_owned()),
            target: None,
            provider: None,
            json: false,
        }
    );
    assert_eq!(
        parse_args(&["ls", "max/tmux"]).expect("parse"),
        ParsedCommand::SessionLs {
            target_ref: Some("max/tmux".to_owned()),
            target: None,
            provider: None,
            json: false,
        }
    );
    assert_eq!(
        parse_args(&["history", "dotfiles"]).expect("parse"),
        ParsedCommand::SessionHistory {
            target: None,
            session: Some("dotfiles".to_owned()),
            provider: None,
            format: portl_cli::SessionHistoryFormat::Plain,
        }
    );
    assert_eq!(
        parse_args(&["kill", "dotfiles"]).expect("parse"),
        ParsedCommand::SessionKill {
            target: None,
            session: Some("dotfiles".to_owned()),
            provider: None,
        }
    );
}

#[test]
fn old_target_first_session_positionals_are_rejected() {
    assert_clap_error(
        &["session", "attach", "shared-box", "dev"],
        &["unexpected argument"],
    );
    assert_clap_error(
        &["session", "run", "shared-box", "dev", "--", "true"],
        &["unexpected argument"],
    );
}

#[test]
fn session_share_parses_local_session_first() {
    let parsed = parse_args(&["session", "share", "dev"]).expect("parse");
    assert!(matches!(
        parsed,
        ParsedCommand::SessionShare {
            ref session,
            target: None,
            ..
        } if session == "dev"
    ));
}

#[test]
fn session_share_rejects_old_target_session_positionals() {
    assert_clap_error(
        &["session", "share", "shared-box", "dev"],
        &["unexpected argument"],
    );
}

#[test]
fn session_share_parses_full_option_set() {
    let parsed = parse_args(&[
        "session",
        "share",
        "dev",
        "--target",
        "shared-box",
        "--provider",
        "zmx",
        "--ttl",
        "5m",
        "--access-ttl",
        "30m",
        "--label",
        "alice-laptop",
        "--rendezvous-url",
        "ws://relay.example.invalid/v1",
        "--yes",
        "--allow-bearer-fallback",
    ])
    .expect("parse");
    match parsed {
        ParsedCommand::SessionShare {
            target,
            session,
            provider,
            ttl,
            access_ttl,
            label,
            rendezvous_url,
            yes,
            allow_bearer_fallback,
        } => {
            assert_eq!(target.as_deref(), Some("shared-box"));
            assert_eq!(session, "dev");
            assert_eq!(provider.as_deref(), Some("zmx"));
            assert_eq!(ttl, std::time::Duration::from_mins(5));
            assert_eq!(access_ttl, std::time::Duration::from_mins(30));
            assert_eq!(label.as_deref(), Some("alice-laptop"));
            assert_eq!(
                rendezvous_url.as_deref(),
                Some("ws://relay.example.invalid/v1")
            );
            assert!(yes);
            assert!(allow_bearer_fallback);
        }
        other => panic!("expected SessionShare, got {other:?}"),
    }
}

#[test]
fn session_share_unsupported_ticket_target_does_not_echo_input() {
    // Use a long bogus `portl…` string that nonetheless fails ticket
    // deserialization gracefully and falls through to "unsupported"
    // — but the error path must still avoid echoing the raw target.
    // We use a `portl ticket save` style label so it routes through
    // the saved-ticket guard.
    //
    // Instead, drive the share command with a wholly-unknown name to
    // confirm error text never echoes raw input.
    let secret_label = "this-is-a-secret-target-string";
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["session", "share", "dev", "--target", secret_label])
        .output()
        .expect("run session share");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(secret_label),
        "stderr must not echo raw target input: {stderr}"
    );
    assert!(
        stderr.contains("unsupported share target") || stderr.contains("Supported forms"),
        "stderr must explain supported forms: {stderr}"
    );
}

#[test]
fn accept_and_ticket_save_teach_wrong_prefix() {
    let accept = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["accept", "PORTLTKT-abc"])
        .output()
        .expect("run accept");
    assert!(!accept.status.success());
    let stderr = String::from_utf8_lossy(&accept.stderr);
    assert!(stderr.contains("looks like a ticket string"), "{stderr}");
    assert!(
        stderr.contains("portl ticket save <label> <ticket>"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("PORTLTKT-abc"),
        "accept must not echo ticket credentials: {stderr}"
    );

    let save = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["ticket", "save", "PORTLINV-abc"])
        .output()
        .expect("run ticket save");
    assert!(!save.status.success());
    let stderr = String::from_utf8_lossy(&save.stderr);
    assert!(stderr.contains("looks like an invite code"), "{stderr}");
    assert!(stderr.contains("portl accept PORTLINV-abc"), "{stderr}");
}

#[test]
fn ticket_caps_and_revoke_surface_match_spec() {
    assert_eq!(
        parse_args(&["ticket", "caps", "--cap", "tcp", "--json"]).expect("parse"),
        ParsedCommand::TicketCaps {
            cap: Some("tcp".to_owned()),
            json: true,
        }
    );
    assert_eq!(
        parse_args(&["ticket", "revoke", "0011223344556677"]).expect("parse"),
        ParsedCommand::TicketRevoke {
            id: Some("0011223344556677".to_owned()),
            action: None,
        }
    );
    assert_eq!(
        parse_args(&["ticket", "revoke", "ls", "--json"]).expect("parse"),
        ParsedCommand::TicketRevoke {
            id: None,
            action: Some(portl_cli::RevokeAction::Ls { json: true }),
        }
    );
    assert_eq!(
        parse_args(&["ticket", "revoke", "publish", "0011223344556677", "--yes"]).expect("parse"),
        ParsedCommand::TicketRevoke {
            id: None,
            action: Some(portl_cli::RevokeAction::Publish {
                id: Some("0011223344556677".to_owned()),
                yes: true,
            }),
        }
    );

    assert_clap_error(
        &["ticket", "issue", "--list-caps"],
        &["unexpected argument"],
    );
    assert_clap_error(&["ticket", "revoke", "--list"], &["unexpected argument"]);
    assert_clap_error(&["ticket", "revoke", "--publish"], &["unexpected argument"]);
}

#[test]
fn ls_rm_and_status_flag_matrix_match_spec() {
    assert_eq!(
        parse_args(&["docker", "ls", "--json"]).expect("parse"),
        parse_args(&["docker", "list", "--json"]).expect("parse")
    );
    assert_eq!(
        parse_args(&["slicer", "ls", "--base-url", "http://example", "--json"]).expect("parse"),
        parse_args(&["slicer", "list", "--base-url", "http://example", "--json"]).expect("parse")
    );
    assert_eq!(
        parse_args(&["peer", "rm", "laptop"]).expect("parse"),
        ParsedCommand::PeerRm {
            label: "laptop".to_owned(),
        }
    );
    assert_clap_error(&["peer", "unlink", "laptop"], &["unrecognized subcommand"]);

    assert_eq!(
        parse_args(&[
            "status",
            "laptop",
            "--relay",
            "--count",
            "3",
            "--timeout",
            "200ms",
            "--json",
        ])
        .expect("parse"),
        ParsedCommand::Status {
            target: Some("laptop".to_owned()),
            relay: true,
            json: true,
            watch: None,
            count: 3,
            timeout: humantime::parse_duration("200ms").expect("duration"),
        }
    );
    assert_clap_error(&["status", "--relay"], &["required", "TARGET"]);
    assert_clap_error(&["status", "--count", "2"], &["required", "TARGET"]);
    assert_clap_error(
        &["status", "laptop", "--watch", "2"],
        &["cannot be used with"],
    );
}

#[test]
fn exit_code_and_env_contracts_match_spec() {
    Command::cargo_bin("portl")
        .expect("cargo bin")
        .arg("definitely-not-a-command")
        .assert()
        .code(2);

    let invalid_env = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .env("PORTL_JSON", "maybe")
        .arg("status")
        .output()
        .expect("run invalid env");
    assert_eq!(invalid_env.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&invalid_env.stderr);
    assert!(
        stderr.contains("PORTL_JSON must be a boolean value"),
        "{stderr}"
    );
}

#[test]
fn relationship_map_appears_in_trust_help() {
    for args in [
        vec!["invite", "--help"],
        vec!["peer", "--help"],
        vec!["ticket", "--help"],
    ] {
        let output = ProcessCommand::cargo_bin("portl")
            .expect("cargo bin")
            .args(args)
            .output()
            .expect("run help");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Relationship between portl trust objects"),
            "{stdout}"
        );
        assert!(stdout.contains("first contact"), "{stdout}");
        assert!(stdout.contains("portl invite` + `portl accept"), "{stdout}");
    }
}

#[test]
fn completions_man_and_init_quiet_are_available() {
    let completion = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["completions", "bash"])
        .output()
        .expect("run completions");
    assert!(
        completion.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&completion.stderr)
    );
    assert!(String::from_utf8_lossy(&completion.stdout).contains("_portl"));

    let man = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .arg("man")
        .output()
        .expect("run man");
    assert!(
        man.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&man.stderr)
    );
    assert!(String::from_utf8_lossy(&man.stdout).contains(".TH portl"));

    let home = tempdir().expect("tempdir");
    Command::cargo_bin("portl")
        .expect("cargo bin")
        .env("PORTL_HOME", home.path())
        .args(["init", "--quiet"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn config_template_validates_from_stdin() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let template = ProcessCommand::new(&portl)
        .args(["config", "template"])
        .output()
        .expect("template");
    assert!(template.status.success());

    let mut validate = ProcessCommand::new(&portl)
        .args(["config", "validate", "--stdin", "--json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn validate");
    std::io::Write::write_all(validate.stdin.as_mut().expect("stdin"), &template.stdout)
        .expect("write stdin");
    let output = validate.wait_with_output().expect("wait validate");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["ok"], true);
}

//! Generic `portl accept` router behavior introduced in Task 10.

use std::process::Command as ProcessCommand;

use assert_cmd::cargo::CommandCargoExt;
use portl_cli::{Command as ParsedCommand, parse};

fn parse_args(cli_args: &[&str]) -> ParsedCommand {
    let mut argv = vec!["portl".into()];
    argv.extend(cli_args.iter().map(|arg| (*arg).into()));
    parse(argv).expect("parse")
}

#[test]
fn accept_invite_still_parses() {
    assert_eq!(
        parse_args(&["accept", "PORTLINV-test"]),
        ParsedCommand::Accept {
            code: "PORTLINV-test".to_owned(),
            yes: false,
            label: None,
            rendezvous_url: None,
            timeout: std::time::Duration::from_secs(600),
        }
    );
}

#[test]
fn accept_short_code_parses() {
    assert_eq!(
        parse_args(&["accept", "PORTL-S-2-nebula-involve"]),
        ParsedCommand::Accept {
            code: "PORTL-S-2-nebula-involve".to_owned(),
            yes: false,
            label: None,
            rendezvous_url: None,
            timeout: std::time::Duration::from_secs(600),
        }
    );
}

#[test]
fn top_level_help_mentions_accept_and_short_codes() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .arg("--help")
        .output()
        .expect("run portl --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("utf8");
    assert!(help.contains("accept"), "{help}");
    assert!(help.contains("PORTL-S"), "{help}");
}

#[test]
fn accept_help_describes_generic_receiver() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["accept", "--help"])
        .output()
        .expect("run portl accept --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("utf8");
    assert!(
        help.contains("PORTL-S"),
        "accept help should mention PORTL-S short codes:\n{help}"
    );
    assert!(
        help.contains("PORTLINV"),
        "accept help should mention PORTLINV invites:\n{help}"
    );
}

#[test]
fn accept_bad_short_code_reports_prefix_guidance() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["accept", "PORTL-WH-2-nebula-involve"])
        .output()
        .expect("run accept");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PORTL-S-"),
        "stderr should guide toward PORTL-S-:\n{stderr}"
    );
}

#[test]
fn accept_short_code_attempts_online_rendezvous() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .env("PORTL_HOME", tempfile::TempDir::new().unwrap().path())
        .args([
            "accept",
            "PORTL-S-2-nebula-involve",
            "--rendezvous-url",
            "ws://127.0.0.1:9/v1",
            "--timeout",
            "1ms",
        ])
        .output()
        .expect("run accept");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("not implemented"),
        "PORTL-S accept should be wired to the online rendezvous path:\n{stderr}"
    );
    assert!(
        stderr.contains("load local identity")
            || stderr.contains("connect to rendezvous server")
            || stderr.contains("accept timed out"),
        "stderr should come from real accept plumbing:\n{stderr}"
    );
}

#[test]
fn accept_invite_rejects_share_only_flags() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["accept", "PORTLINV-test", "--label", "dev"])
        .output()
        .expect("run accept");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only apply to PORTL-S"),
        "stderr should reject share-only flags:\n{stderr}"
    );
}

#[test]
fn accept_ticket_rejects_share_only_flags_without_echoing_ticket() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args([
            "accept",
            "portlAAAA",
            "--rendezvous-url",
            "ws://example.invalid/v1",
        ])
        .output()
        .expect("run accept");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only apply to PORTL-S"),
        "stderr should reject share-only flags:\n{stderr}"
    );
    assert!(
        !stderr.contains("portlAAAA"),
        "must not echo ticket: {stderr}"
    );
}

#[test]
fn accept_share_token_is_not_yet_implemented() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["accept", "PORTL-SHARE1-abcdef"])
        .output()
        .expect("run accept");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("offline share tokens") && stderr.contains("not implemented"),
        "stderr should say share tokens not implemented:\n{stderr}"
    );
    assert!(
        !stderr.contains("short online session shares"),
        "PORTL-SHARE1-* must not be classified as PORTL-S-*:\n{stderr}"
    );
}

#[test]
fn accept_ticket_string_suggests_ticket_save() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["accept", "portlAAAA"])
        .output()
        .expect("run accept");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("portl ticket save <label> <ticket>"),
        "stderr should suggest `portl ticket save`:\n{stderr}"
    );
    assert!(
        !stderr.contains("portlAAAA"),
        "stderr should not echo ticket credentials:\n{stderr}"
    );
}

#[test]
fn accept_unknown_lists_supported_forms() {
    let output = ProcessCommand::cargo_bin("portl")
        .expect("cargo bin")
        .args(["accept", "totally-unknown"])
        .output()
        .expect("run accept");
    assert!(!output.status.success(), "expected failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in ["PORTLINV-", "PORTL-S-", "PORTL-SHARE1-"] {
        assert!(
            stderr.contains(needle),
            "stderr should list {needle}:\n{stderr}"
        );
    }
}

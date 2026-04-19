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
        matches!(cmd, Command::AgentRun),
        "expected Command::AgentRun, got {cmd:?}"
    );
}

#[test]
fn portl_agent_symlink_prepends_agent() {
    // When invoked via the `portl-agent` symlink, `run` should be
    // equivalent to `agent run`.
    let cmd = parse(argv(&["portl-agent", "run"])).expect("parse should succeed");
    assert!(
        matches!(cmd, Command::AgentRun),
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
        matches!(cmd, Command::AgentRun),
        "basename dispatch must see past absolute path"
    );
}

#[test]
fn empty_argv_is_rejected() {
    let result = parse(vec![]);
    assert!(result.is_err(), "parse should reject an empty argv vector");
}

#[test]
fn unknown_subcommand_errors() {
    let result = parse(argv(&["portl", "definitely-not-a-real-subcommand"]));
    assert!(
        result.is_err(),
        "unknown subcommand must produce an error, got {result:?}"
    );
}

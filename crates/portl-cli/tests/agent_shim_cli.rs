use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

const SHIM: &str = "portl: `portl agent *` was removed in v0.2.0. Use `portl-agent` instead.\n      See https://github.com/KnickKnackLabs/portl/blob/v0.2.0/docs/specs/140-v0.2-operability.md#12-multicall-only-daemon\n";

#[test]
fn portl_agent_run_prints_deprecation_and_exits_two() {
    let output = Command::cargo_bin("portl")
        .expect("cargo bin")
        .args(["agent", "run"])
        .output()
        .expect("run deprecated agent path");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), SHIM);
}

#[test]
fn portl_agent_with_any_args_prints_deprecation() {
    let output = Command::cargo_bin("portl")
        .expect("cargo bin")
        .args(["agent", "anything", "else"])
        .output()
        .expect("run deprecated agent path");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(String::from_utf8(output.stderr).expect("utf8 stderr"), SHIM);
}

#[test]
fn portl_help_shows_no_agent_subcommand() {
    let output = Command::cargo_bin("portl")
        .expect("cargo bin")
        .args(["--help"])
        .output()
        .expect("run help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        !stdout
            .lines()
            .any(|line| line.trim_start().starts_with("agent  "))
    );
}

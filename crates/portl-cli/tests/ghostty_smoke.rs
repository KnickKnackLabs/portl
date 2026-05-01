use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

#[test]
#[cfg(feature = "ghostty-vt")]
fn ghostty_smoke_command_runs_when_feature_enabled() {
    let output = Command::cargo_bin("portl")
        .expect("cargo bin")
        .arg("__ghostty-smoke")
        .output()
        .expect("run ghostty smoke");

    assert!(
        output.status.success(),
        "expected ghostty smoke success, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("ghostty-vt smoke ok cols=80 rows=24"),
        "unexpected stdout:\n{stdout}"
    );
}

#[test]
#[cfg(not(feature = "ghostty-vt"))]
fn ghostty_smoke_command_fails_when_feature_disabled() {
    let output = Command::cargo_bin("portl")
        .expect("cargo bin")
        .arg("__ghostty-smoke")
        .output()
        .expect("run ghostty smoke");

    assert!(
        !output.status.success(),
        "expected ghostty smoke to fail without feature"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("ghostty-vt support is not built"),
        "unexpected stderr:\n{stderr}"
    );
}

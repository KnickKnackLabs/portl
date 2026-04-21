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
    assert!(stdout.contains("created identity:") || stdout.contains("using existing identity:"));
    assert!(stdout.contains("[ok  ]") || stdout.contains("[warn]"));
    assert!(stdout.contains("cookbook: portl docker run <image>"));
}

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

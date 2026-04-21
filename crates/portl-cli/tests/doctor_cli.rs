use anyhow::Result;
use assert_cmd::Command;
use portl_core::id::{Identity, store};
use tempfile::tempdir;

#[test]
fn doctor_is_offline_safe() -> Result<()> {
    let home = tempdir()?;
    store::save(&Identity::new(), &home.path().join("identity.bin"))?;

    Command::cargo_bin("portl")?
        .env("PORTL_HOME", home.path())
        .env("PORTL_DISCOVERY", "none")
        .arg("doctor")
        .assert()
        .success();

    Ok(())
}

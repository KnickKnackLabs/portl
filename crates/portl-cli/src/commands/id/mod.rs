use std::io::{IsTerminal, Write};
use std::process::Command;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

pub mod export;
pub mod import;
pub mod new;
pub mod show;

pub(crate) fn read_passphrase(
    prompt: &str,
    passphrase_cmd: Option<&str>,
) -> Result<Zeroizing<String>> {
    if let Some(passphrase_cmd) = passphrase_cmd {
        return read_passphrase_from_cmd(passphrase_cmd);
    }

    if std::io::stdin().is_terminal() {
        eprint!("{prompt}");
        std::io::stderr().flush().context("flush stderr")?;
        let passphrase = rpassword::read_password().context("read passphrase from terminal")?;
        return Ok(Zeroizing::new(passphrase));
    }

    eprintln!("warning: PORTL_PASSPHRASE is insecure; prefer --passphrase-cmd or a TTY prompt");
    let passphrase = std::env::var("PORTL_PASSPHRASE")
        .context("PORTL_PASSPHRASE is required when stdin is not a TTY")?;
    Ok(Zeroizing::new(passphrase))
}

fn read_passphrase_from_cmd(passphrase_cmd: &str) -> Result<Zeroizing<String>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(passphrase_cmd)
        .output()
        .with_context(|| format!("run passphrase command: {passphrase_cmd}"))?;
    if !output.status.success() {
        bail!("passphrase command failed with status {}", output.status);
    }

    let stdout =
        String::from_utf8(output.stdout).context("passphrase command output is not valid UTF-8")?;
    Ok(Zeroizing::new(
        stdout.lines().next().unwrap_or_default().to_owned(),
    ))
}

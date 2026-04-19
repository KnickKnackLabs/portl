use std::io::{IsTerminal, Write};

use anyhow::{Context, Result};

pub mod export;
pub mod import;
pub mod new;
pub mod show;

pub(crate) fn read_passphrase(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        eprint!("{prompt}");
        std::io::stderr().flush().context("flush stderr")?;
        rpassword::read_password().context("read passphrase from terminal")
    } else {
        std::env::var("PORTL_PASSPHRASE")
            .context("PORTL_PASSPHRASE is required when stdin is not a TTY")
    }
}

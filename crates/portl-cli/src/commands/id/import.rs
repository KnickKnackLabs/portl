use std::fs;
use std::process::ExitCode;

use anyhow::Result;
use portl_core::id::store;

use super::read_passphrase;

pub fn run(from: &std::path::Path) -> Result<ExitCode> {
    let bytes = fs::read(from)?;
    let passphrase = read_passphrase("passphrase: ")?;
    let identity = store::import(&bytes, &passphrase)?;
    store::save(&identity, &store::default_path())?;
    println!("imported identity: {}", identity.endpoint_id());
    Ok(ExitCode::SUCCESS)
}

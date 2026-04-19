use std::fs;
use std::process::ExitCode;

use anyhow::Result;
use portl_core::error::PortlError;
use portl_core::id::store;

use super::read_passphrase;

pub fn run(from: &std::path::Path, force: bool, passphrase_cmd: Option<&str>) -> Result<ExitCode> {
    let bytes = fs::read(from)?;
    let passphrase = read_passphrase("passphrase: ", passphrase_cmd)?;
    let identity = store::import(&bytes, passphrase.as_str())?;
    let path = store::default_path();
    if path.exists() && !force {
        return Err(PortlError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "identity already exists at {}; pass --force to overwrite",
                path.display()
            ),
        ))
        .into());
    }
    store::save(&identity, &path)?;
    println!("imported identity: {}", identity.endpoint_id());
    Ok(ExitCode::SUCCESS)
}

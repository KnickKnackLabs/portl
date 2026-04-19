use std::fs;
use std::process::ExitCode;

use anyhow::Result;
use portl_core::id::store;

use super::read_passphrase;

pub fn run(out: &std::path::Path) -> Result<ExitCode> {
    let identity = store::load(&store::default_path())?;
    let passphrase = read_passphrase("passphrase: ")?;
    let bytes = store::export(&identity, &passphrase)?;

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out, bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600))?;
    }

    println!("exported identity to {}", out.display());
    Ok(ExitCode::SUCCESS)
}

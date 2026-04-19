use std::process::ExitCode;

use anyhow::{Result, bail};
use portl_core::id::{Identity, store};

pub fn run(force: bool) -> Result<ExitCode> {
    let path = store::default_path();
    if path.exists() && !force {
        bail!(
            "identity already exists at {}; pass --force to overwrite",
            path.display()
        );
    }

    let identity = Identity::new();
    store::save(&identity, &path)?;
    println!("created identity: {}", identity.endpoint_id());
    Ok(ExitCode::SUCCESS)
}

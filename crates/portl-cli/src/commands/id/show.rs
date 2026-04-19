use std::process::ExitCode;

use anyhow::Result;
use portl_core::id::store;

pub fn run() -> Result<ExitCode> {
    let identity = store::load(&store::default_path())?;
    println!("endpoint_id: {}", identity.endpoint_id());
    Ok(ExitCode::SUCCESS)
}

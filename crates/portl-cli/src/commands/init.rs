use std::process::ExitCode;

use anyhow::{Context, Result};
use portl_core::id::{Identity, store};

use crate::commands::install::{DetectMatch, detect_host};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InitRole {
    Operator,
    Agent,
}

pub fn run(force: bool, role: Option<InitRole>) -> Result<ExitCode> {
    let path = store::default_path();
    let identity = if force || !path.exists() {
        let identity = Identity::new();
        store::save(&identity, &path).with_context(|| format!("write {}", path.display()))?;
        println!("created identity: {}", identity.endpoint_id());
        identity
    } else {
        let identity = store::load(&path).with_context(|| format!("load {}", path.display()))?;
        println!("using existing identity: {}", identity.endpoint_id());
        identity
    };

    let doctor = crate::commands::doctor::run();
    if doctor != ExitCode::SUCCESS {
        return Ok(doctor);
    }

    let detect = detect_host();
    if matches!(role, Some(InitRole::Agent))
        || matches!(
            detect.matched,
            Some(DetectMatch::Systemd | DetectMatch::Launchd | DetectMatch::Openrc)
        )
    {
        println!("next: portl install");
    }
    println!("cookbook: portl docker run <image>");
    println!("cookbook: portl slicer run <image>");
    let _ = identity;
    Ok(ExitCode::SUCCESS)
}

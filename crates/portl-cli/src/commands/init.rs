use std::process::ExitCode;

use anyhow::{Context, Result};
use portl_core::id::{Identity, store};

use crate::commands::install::{DetectMatch, detect_host, seed_peer_store_self_row_if_missing};

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

    // v0.3.1: seed the peer-store self-row on init. Previously this
    // lived only in `install --apply`, but containers can't run the
    // service-install path (it refuses inside docker), which left
    // container operators with an empty peer store and a BadChain
    // rejection on every ticket. `init` is the right place — you
    // can't have a self-row without an identity, and both are
    // produced at first-boot. Idempotent on re-run.
    if let Err(err) = seed_peer_store_self_row_if_missing() {
        eprintln!(
            "warning: failed to seed peer store self-row ({err:#}); \
             add manually with `portl peer add-unsafe-raw $(portl whoami | awk '/endpoint_id/{{print $2}}') --label self --mutual --yes`"
        );
    }

    // `init` is a one-shot onboarding flow; operators want to see
    // every check passed explicitly, so force verbose output even
    // though the default (for `portl doctor`) hides passing rows.
    let doctor = crate::commands::doctor::run(crate::commands::doctor::RunOpts {
        verbose: true,
        ..Default::default()
    });
    if doctor != ExitCode::SUCCESS {
        return Ok(doctor);
    }

    let detect = detect_host();
    if detect.inside_docker {
        println!("next: portl-agent &       # start the agent in the background");
    } else if matches!(role, Some(InitRole::Agent))
        || matches!(
            detect.matched,
            Some(DetectMatch::Systemd | DetectMatch::Launchd | DetectMatch::Openrc)
        )
    {
        println!("next: portl install --apply --yes");
    }
    println!("cookbook: portl docker run <image>");
    println!("cookbook: portl slicer run <image>");
    let _ = identity;
    Ok(ExitCode::SUCCESS)
}

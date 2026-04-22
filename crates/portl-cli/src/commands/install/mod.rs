use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore};
use serde::Serialize;

mod apply;
mod detect;
mod render;
mod resolve;

use self::apply::{apply_install_target, set_mode_0755, validate_install_target};
use self::detect::{DetectionContext, detect_host_with};
use self::render::render_target;
use self::resolve::{
    install_binary_path, install_service_path, resolve_output_dir, resolve_target,
};

#[cfg(test)]
use self::render::{render_launchd_plist, render_systemd_unit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
pub enum InstallTarget {
    Systemd,
    Launchd,
    Dockerfile,
    Openrc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectResult {
    pub matched: Option<InstallTarget>,
    pub reason: String,
    pub inside_docker: bool,
    pub root: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<PathBuf>,
}

pub type DetectMatch = InstallTarget;

pub fn detect_host() -> DetectResult {
    detect_host_with(&DetectionContext::from_host())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn run(
    target: Option<InstallTarget>,
    apply: bool,
    yes: bool,
    detect: bool,
    dry_run: bool,
    output: Option<&Path>,
) -> Result<ExitCode> {
    let detect_result = detect_host();
    if detect {
        println!("{}", serde_json::to_string_pretty(&detect_result)?);
        return Ok(ExitCode::SUCCESS);
    }

    let target = resolve_target(target, &detect_result)?;
    let output = resolve_output_dir(target, output)?;
    let binary_path = install_binary_path(
        target,
        detect_result.root,
        detect_result.home.as_deref(),
        output.as_deref(),
    )?;
    let service_path = install_service_path(
        target,
        detect_result.root,
        detect_result.home.as_deref(),
        output.as_deref(),
    )?;
    let rendered = render_target(
        target,
        &binary_path,
        detect_result.root,
        detect_result.home.as_deref(),
    )?;

    if dry_run || !apply {
        print!("{rendered}");
        return Ok(ExitCode::SUCCESS);
    }

    if !yes {
        bail!("`portl install --apply` requires `--yes`");
    }

    if let Some(parent) = binary_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if let Some(parent) = service_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    std::fs::copy(std::env::current_exe()?, &binary_path).with_context(|| {
        format!(
            "copy {} to {}",
            std::env::current_exe().map_or_else(
                |_| "current executable".to_owned(),
                |path| path.display().to_string(),
            ),
            binary_path.display()
        )
    })?;
    std::fs::write(&service_path, &rendered)
        .with_context(|| format!("write {}", service_path.display()))?;
    if matches!(target, InstallTarget::Dockerfile | InstallTarget::Openrc) {
        set_mode_0755(&binary_path)?;
    }
    if matches!(target, InstallTarget::Openrc) {
        set_mode_0755(&service_path)?;
    }
    validate_install_target(target, &service_path)?;

    // Seed the peer store so the local agent accepts tickets minted
    // by this machine (the "paved path" self-host contract). v0.3.0
    // replaces v0.2.6's env-var injection with a filesystem entry
    // that the agent reloads live.
    seed_peer_store_self_row_with_reporting();

    apply_install_target(target, detect_result.root, &service_path)?;
    println!("installed {}", service_path.display());
    Ok(ExitCode::SUCCESS)
}

/// Write the local identity to `peers.json` as `label="self"`,
/// `is_self=true`, `mutual` relationship. Returns `Ok(Some(hex))`
/// if a row was created or updated, `Ok(None)` if no identity
/// exists yet (install running before `portl init`), `Err` on I/O
/// failures.
///
/// Idempotent: running install twice against the same identity
/// leaves the row unchanged. Running install after `portl init`
/// creates a new identity will overwrite the self-row with the new
/// `endpoint_id` (correct behavior — you can only have one self).
/// Wrapper that translates the outcome of
/// [`seed_peer_store_self_row`] into user-facing messaging.
/// Extracted so that the `--apply` flow's match expression stays
/// short enough to keep clippy happy (it flagged the inline one as
/// a `let...else` candidate).
fn seed_peer_store_self_row_with_reporting() {
    match seed_peer_store_self_row() {
        Ok(Some(eid_hex)) => println!(
            "seeded peer store with self-row: {eid_short}…",
            eid_short = &eid_hex[..16]
        ),
        Ok(None) => {}
        Err(err) => eprintln!(
            "warning: failed to seed peer store self-row ({err:#}); \
             run `portl init` and re-run install, or add the self-row \
             with `portl peer add-unsafe-raw <your_eid> --label self --mutual` \
             manually."
        ),
    }
}

fn seed_peer_store_self_row() -> Result<Option<String>> {
    use portl_core::id::store;
    let Ok(identity) = store::load(&store::default_path()) else {
        return Ok(None);
    };
    let eid = identity.verifying_key();
    let eid_hex = hex::encode(eid);
    let path = PeerStore::default_path();
    let mut peers = PeerStore::load(&path).context("load peer store")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    peers
        .insert_or_update(PeerEntry {
            label: "self".to_owned(),
            endpoint_id_hex: eid_hex.clone(),
            accepts_from_them: true,
            they_accept_from_me: true,
            since: now,
            origin: PeerOrigin::Zelf,
            last_hold_at: None,
            is_self: true,
        })
        .context("insert self-row in peer store")?;
    peers.save(&path).context("save peer store")?;
    Ok(Some(eid_hex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn install_systemd_emits_valid_unit_file() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl-agent");
        std::fs::write(&binary, b"#!/bin/sh\nexit 0\n").expect("write fake binary");
        set_mode_0755(&binary).expect("chmod fake binary");

        let unit = render_systemd_unit(&binary, true, None).expect("render systemd unit");
        assert!(unit.contains(&format!("ExecStart={}", binary.display())));
        assert!(unit.contains("EnvironmentFile=-/etc/portl/agent.env"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("StartLimitBurst=5"));

        if Path::new("/usr/bin/systemd-analyze").exists()
            || Path::new("/bin/systemd-analyze").exists()
        {
            let path = dir.path().join("portl-agent.service");
            std::fs::write(&path, unit).expect("write unit");
            validate_install_target(InstallTarget::Systemd, &path).expect("verify unit");
        }
    }

    #[test]
    fn install_launchd_plist_is_minimal_without_env() {
        // v0.3.0 removed env-var injection; plist should contain
        // neither `EnvironmentVariables` nor `PORTL_TRUST_ROOTS`.
        // Trust is now peer-store-backed.
        let plist = render_launchd_plist(Path::new("/usr/local/bin/portl-agent"));
        assert!(plist.contains("<string>/usr/local/bin/portl-agent</string>"));
        assert!(plist.contains("<key>SuccessfulExit</key><false/>"));
        assert!(!plist.contains("EnvironmentVariables"));
        assert!(!plist.contains("PORTL_TRUST_ROOTS"));

        if Path::new("/usr/bin/plutil").exists() {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("com.portl.agent.plist");
            std::fs::write(&path, plist).expect("write plist");
            validate_install_target(InstallTarget::Launchd, &path).expect("lint plist");
        }
    }

    // NOTE: The full end-to-end test for `seed_peer_store_self_row`
    // requires mutating `PORTL_HOME`, which the workspace forbids in
    // safe code (unsafe_code = deny). Peer store seeding is covered
    // indirectly by the store's unit tests (`peer_store::tests`) +
    // a manual smoke via `cargo run -- install launchd && cat
    // ~/Library/Application\ Support/computer.KnickKnackLabs.portl/\
    // peers.json`. If we ever want first-class coverage, expose a
    // `seed_peer_store_self_row_at(path: &Path)` variant and drive
    // that from a tempdir test.

    #[test]
    fn install_refuses_to_target_systemd_inside_docker() {
        let detect = DetectResult {
            matched: None,
            reason: "inside docker".to_owned(),
            inside_docker: true,
            root: true,
            home: None,
        };
        let err = resolve_target(Some(InstallTarget::Systemd), &detect).expect_err("must refuse");
        assert!(
            err.to_string()
                .contains("refusing to target systemd inside docker")
        );
    }

    #[test]
    fn install_autodetect_picks_systemd_on_linux_user() {
        let detect = detect_host_with(&DetectionContext {
            os: "linux".to_owned(),
            has_launchctl: false,
            inside_docker: false,
            has_systemd_dir: true,
            has_openrc: false,
            root: false,
            home: Some(PathBuf::from("/tmp/test-home")),
        });
        assert_eq!(detect.matched, Some(InstallTarget::Systemd));
        assert!(!detect.root);
    }

    #[test]
    fn user_systemd_uses_user_env_file() {
        // Sidecar file path is preserved so operators can drop in
        // knobs for rate_limit / metrics / etc. even though install
        // itself no longer writes it.
        let unit = render_systemd_unit(
            Path::new("/tmp/home/.local/bin/portl-agent"),
            false,
            Some(Path::new("/tmp/home")),
        )
        .expect("render user unit");
        assert!(unit.contains("EnvironmentFile=-/tmp/home/.config/portl/agent.env"));
    }

    #[test]
    fn dockerfile_output_paths_use_requested_directory() {
        let output = Path::new("/tmp/portl-image");
        assert_eq!(
            install_binary_path(InstallTarget::Dockerfile, false, None, Some(output))
                .expect("binary path"),
            output.join("portl-agent")
        );
        assert_eq!(
            install_service_path(InstallTarget::Dockerfile, false, None, Some(output))
                .expect("service path"),
            output.join("Dockerfile")
        );
    }
}

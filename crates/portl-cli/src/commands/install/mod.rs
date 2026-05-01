use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore};
use serde::Serialize;

mod apply;
mod detect;
mod render;
mod resolve;

use self::apply::{
    apply_install_target, set_mode_0755, stop_install_target, validate_install_target,
};
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

pub fn stop_existing_agent_for_upgrade(target: Option<InstallTarget>) -> Result<()> {
    let detect_result = detect_host();
    if detect_result.inside_docker {
        return Ok(());
    }
    let target = resolve_target(target, &detect_result)?;
    if matches!(target, InstallTarget::Dockerfile) {
        return Ok(());
    }
    let service_path = install_service_path(
        target,
        detect_result.root,
        detect_result.home.as_deref(),
        None,
    )?;
    stop_install_target(target, detect_result.root, &service_path);
    if managed_agent_is_loaded() {
        bail!(
            "managed portl-agent service is still loaded after stop; stop it with the appropriate service manager or rerun the installer with sufficient privileges before migrating state"
        );
    }
    Ok(())
}

pub fn managed_agent_is_loaded() -> bool {
    #[cfg(target_os = "macos")]
    {
        let uid = nix::unistd::Uid::effective().as_raw();
        launchctl_is_loaded(&format!("gui/{uid}/com.portl.agent"))
            || launchctl_is_loaded("system/com.portl.agent")
    }
    #[cfg(target_os = "linux")]
    {
        systemd_is_active(&["--user"]) || systemd_is_active(&[]) || openrc_is_active()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
fn launchctl_is_loaded(target: &str) -> bool {
    ProcessCommand::new("launchctl")
        .args(["print", target])
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(target_os = "linux")]
fn systemd_is_active(extra: &[&str]) -> bool {
    let mut args = extra.to_vec();
    args.extend_from_slice(&["is-active", "portl-agent.service"]);
    ProcessCommand::new("systemctl")
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(target_os = "linux")]
fn openrc_is_active() -> bool {
    ProcessCommand::new("rc-service")
        .args(["portl-agent", "status"])
        .output()
        .is_ok_and(|output| output.status.success())
        || ProcessCommand::new("service")
            .args(["portl-agent", "status"])
            .output()
            .is_ok_and(|output| output.status.success())
}

/// v0.3.1: expose self-row seeding so `portl init` can call it.
/// Idempotent — returns `Ok(None)` if the row already exists and
/// points at the current identity (no disk write).
pub fn seed_peer_store_self_row_if_missing() -> Result<Option<String>> {
    use portl_core::id::store;
    let Ok(identity) = store::load(&store::default_path()) else {
        return Ok(None);
    };
    let eid = identity.verifying_key();
    let eid_hex = hex::encode(eid);
    let path = PeerStore::default_path();
    let mut peers = PeerStore::load(&path).context("load peer store")?;
    let self_label = crate::commands::local_machine_label(&eid_hex);
    if let Some(existing) = peers.get_by_endpoint(&eid)
        && existing.is_self
        && existing.accepts_from_them
        && existing.they_accept_from_me
        && existing.label == self_label
    {
        // Already seeded correctly; avoid touching disk (the agent
        // reload task picks up on mtime changes).
        return Ok(None);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    peers
        .insert_or_update(PeerEntry {
            label: self_label,
            endpoint_id_hex: eid_hex.clone(),
            accepts_from_them: true,
            they_accept_from_me: true,
            since: now,
            origin: PeerOrigin::Zelf,
            last_hold_at: None,
            is_self: true,
            relay_hint: None,
            schema_version: 2,
        })
        .context("insert self-row in peer store")?;
    peers.save(&path).context("save peer store")?;
    Ok(Some(eid_hex))
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

    // v0.3.1: inside a container `portl install --apply` is
    // effectively peers-only — seed the self-row so the agent
    // accepts its own tickets, then point the operator at
    // `portl-agent` direct invocation. launchctl / systemctl
    // inside a container is a dead end and the original
    // `resolve_target` refuses such installs outright, which is
    // correct for service install but not for peer seeding.
    if detect_result.inside_docker {
        if apply && !yes {
            bail!("`portl install --apply` inside a container requires `--yes`");
        }
        if apply {
            seed_peer_store_self_row_with_reporting();
            println!(
                "container detected; skipping service install.\n\
                 next: portl-agent &           # start the agent in the background\n\
                 note: launchd / systemd aren't available in containers; run\n\
                       portl-agent directly under your container supervisor."
            );
            return Ok(ExitCode::SUCCESS);
        }
        println!("container detected; `portl install --apply --yes` will seed peers.json only");
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

    install_binary_safely(&binary_path)?;
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
    verify_agent_ready_after_apply(target)?;
    println!("installed {}", service_path.display());
    Ok(ExitCode::SUCCESS)
}

fn verify_agent_ready_after_apply(target: InstallTarget) -> Result<()> {
    if matches!(target, InstallTarget::Dockerfile) {
        return Ok(());
    }
    let socket = crate::agent_ipc::default_socket_path();
    let runtime =
        tokio::runtime::Runtime::new().context("create runtime for agent readiness check")?;
    let mut first_error = None;
    let mut last_error = None;
    for _ in 0..40 {
        match runtime.block_on(crate::agent_ipc::fetch_status(&socket)) {
            Ok(_) => {
                println!("agent service is ready at {}", socket.display());
                return Ok(());
            }
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err.to_string());
                }
                last_error = Some(err.to_string());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    print_service_diagnostics(target);
    let detail = first_error
        .or(last_error)
        .unwrap_or_else(|| "status unavailable".to_owned());
    bail!(
        "portl-agent did not become ready at {} after install: {detail}",
        socket.display()
    )
}

fn print_service_diagnostics(target: InstallTarget) {
    match target {
        InstallTarget::Launchd => {
            let domain = if nix::unistd::Uid::effective().is_root() {
                "system".to_owned()
            } else {
                format!("gui/{}", nix::unistd::Uid::effective().as_raw())
            };
            let _ = ProcessCommand::new("launchctl")
                .args(["print", &format!("{domain}/com.portl.agent")])
                .status();
        }
        InstallTarget::Systemd => {
            let detect = detect_host();
            let args = if detect.root {
                vec!["status", "--no-pager", "portl-agent.service"]
            } else {
                vec!["--user", "status", "--no-pager", "portl-agent.service"]
            };
            let _ = ProcessCommand::new("systemctl").args(args).status();
        }
        InstallTarget::Openrc => {
            let _ = ProcessCommand::new("rc-service")
                .args(["portl-agent", "status"])
                .status();
        }
        InstallTarget::Dockerfile => {}
    }
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
    match seed_peer_store_self_row_if_missing() {
        Ok(Some(eid_hex)) => println!(
            "seeded peer store with self-row: {eid_short}",
            eid_short = crate::eid::format_short(&eid_hex)
        ),
        Ok(None) => {
            // Row already present (idempotent re-run) or identity
            // hasn't been created yet (`portl install` before
            // `portl init`, unusual but possible).
        }
        Err(err) => eprintln!(
            "warning: failed to seed peer store self-row ({err:#}); \
             run `portl init` and re-run install, or add the self-row \
             with `portl peer add-unsafe-raw <your_eid> --label self --mutual` \
             manually."
        ),
    }
}

/// Copy the current executable to `dst` safely, tolerating the case
/// where `dst` already resolves to the same file (symlink or hardlink
/// pointing at `current_exe`).
///
/// The naive [`std::fs::copy`] opens `dst` with `O_TRUNC` *before*
/// reading `src`. When `dst` is a symlink pointing at `src`, the open
/// follows the symlink and truncates `src` to zero bytes, and the
/// subsequent read returns an empty file. Net result: a zero-byte
/// binary at the install prefix. See the v0.3.1.1 postmortem for the
/// original bug report.
///
/// Defense in three steps:
///
/// 1. Canonicalize `src` and `dst` (following symlinks). If they
///    resolve to the same inode, the copy is a no-op; return early.
/// 2. Otherwise, unlink `dst` first. This breaks any inode identity
///    between `src` and `dst` *before* we open `dst` for writing.
/// 3. Perform a regular `fs::copy`. At this point `dst` does not
///    exist, so `fs::copy` creates a fresh file with the source
///    content.
fn install_binary_safely(dst: &Path) -> Result<()> {
    let src = std::env::current_exe().context("resolve current executable")?;

    if let (Ok(src_canonical), Ok(dst_canonical)) = (src.canonicalize(), dst.canonicalize())
        && src_canonical == dst_canonical
    {
        // Already installed at this path (or dst is a symlink pointing
        // back at src). Nothing to do — and critically, do NOT call
        // fs::copy, which would truncate src.
        return Ok(());
    }

    match std::fs::remove_file(dst) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("unlink {} before copy", dst.display()));
        }
    }

    std::fs::copy(&src, dst)
        .with_context(|| format!("copy {} to {}", src.display(), dst.display()))?;
    Ok(())
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

    /// Regression: v0.3.1's install.sh symlinked `portl-agent → portl`,
    /// then `portl install --apply` called `fs::copy(current_exe, dst)`
    /// with `dst = portl-agent`. `fs::copy` opens `dst` with `O_TRUNC`
    /// and follows the symlink, truncating `portl` to 0 bytes before
    /// reading it. Result: 0-byte binary on disk, unusable install.
    ///
    /// `install_binary_safely` must detect the same-inode case and
    /// return without touching the source.
    #[test]
    fn install_binary_safely_is_noop_when_dst_is_symlink_to_src() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = tempdir().expect("tempdir");
            let src = std::env::current_exe().expect("current_exe");
            let src_len = std::fs::metadata(&src).expect("stat src").len();
            assert!(src_len > 0, "current_exe must be non-empty for this test");

            let dst = dir.path().join("portl-agent");
            symlink(&src, &dst).expect("create symlink");

            install_binary_safely(&dst).expect("install_binary_safely");

            let src_len_after = std::fs::metadata(&src).expect("stat src after").len();
            assert_eq!(
                src_len, src_len_after,
                "source binary was truncated! same-inode guard failed."
            );
        }
    }

    /// When `dst` is a regular file (not a symlink to src), copy
    /// proceeds normally.
    #[test]
    fn install_binary_safely_copies_when_dst_is_distinct() {
        let dir = tempdir().expect("tempdir");
        let src = std::env::current_exe().expect("current_exe");
        let src_len = std::fs::metadata(&src).expect("stat src").len();

        let dst = dir.path().join("portl-agent");
        // Pre-existing unrelated file at dst — should be overwritten.
        std::fs::write(&dst, b"stale").expect("seed dst");

        install_binary_safely(&dst).expect("install_binary_safely");

        let dst_len = std::fs::metadata(&dst).expect("stat dst").len();
        assert_eq!(
            dst_len, src_len,
            "copy should produce a file the same size as src"
        );
    }

    /// When `dst` does not exist, copy proceeds normally (no spurious
    /// errors from the pre-unlink step).
    #[test]
    fn install_binary_safely_copies_when_dst_is_absent() {
        let dir = tempdir().expect("tempdir");
        let src = std::env::current_exe().expect("current_exe");
        let src_len = std::fs::metadata(&src).expect("stat src").len();

        let dst = dir.path().join("portl-agent");
        assert!(!dst.exists());

        install_binary_safely(&dst).expect("install_binary_safely");

        let dst_len = std::fs::metadata(&dst).expect("stat dst").len();
        assert_eq!(dst_len, src_len);
    }
}

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
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
    apply_install_target(target, detect_result.root, &service_path)?;
    println!("installed {}", service_path.display());
    Ok(ExitCode::SUCCESS)
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
    fn install_launchd_emits_valid_plist() {
        let plist = render_launchd_plist(Path::new("/usr/local/bin/portl-agent"));
        assert!(plist.contains("<string>/usr/local/bin/portl-agent</string>"));
        assert!(plist.contains("<key>SuccessfulExit</key><false/>"));

        if Path::new("/usr/bin/plutil").exists() {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("com.portl.agent.plist");
            std::fs::write(&path, plist).expect("write plist");
            validate_install_target(InstallTarget::Launchd, &path).expect("lint plist");
        }
    }

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

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};

use super::{DetectResult, InstallTarget};

pub(super) fn resolve_target(
    target: Option<InstallTarget>,
    detect: &DetectResult,
) -> Result<InstallTarget> {
    if matches!(target, Some(InstallTarget::Systemd)) && detect.inside_docker {
        bail!(
            "refusing to target systemd inside docker; use `portl docker bake` or `portl install dockerfile`"
        );
    }
    if let Some(target) = target {
        return Ok(target);
    }
    detect.matched.ok_or_else(|| anyhow!("{}", detect.reason))
}

pub(super) fn resolve_output_dir(
    target: InstallTarget,
    output: Option<&Path>,
) -> Result<Option<PathBuf>> {
    if !matches!(target, InstallTarget::Dockerfile) && output.is_some() {
        bail!("`--output DIR` is only supported for `portl install dockerfile`");
    }
    Ok(output.map(Path::to_path_buf))
}

pub(super) fn install_binary_path(
    target: InstallTarget,
    root: bool,
    home: Option<&Path>,
    output: Option<&Path>,
) -> Result<PathBuf> {
    match target {
        InstallTarget::Systemd if !root => Ok(home
            .ok_or_else(|| anyhow!("HOME is required for user-level systemd installs"))?
            .join(".local/bin/portl-agent")),
        InstallTarget::Launchd if !root => Ok(home
            .ok_or_else(|| anyhow!("HOME is required for launchd installs"))?
            .join(".local/bin/portl-agent")),
        InstallTarget::Dockerfile => {
            Ok(output.unwrap_or_else(|| Path::new(".")).join("portl-agent"))
        }
        _ => Ok(PathBuf::from("/usr/local/bin/portl-agent")),
    }
}

pub(super) fn install_service_path(
    target: InstallTarget,
    root: bool,
    home: Option<&Path>,
    output: Option<&Path>,
) -> Result<PathBuf> {
    match target {
        InstallTarget::Systemd if root => {
            Ok(PathBuf::from("/etc/systemd/system/portl-agent.service"))
        }
        InstallTarget::Systemd => Ok(home
            .ok_or_else(|| anyhow!("HOME is required for user-level systemd installs"))?
            .join(".config/systemd/user/portl-agent.service")),
        InstallTarget::Launchd if root => Ok(PathBuf::from(
            "/Library/LaunchDaemons/com.portl.agent.plist",
        )),
        InstallTarget::Launchd => Ok(home
            .ok_or_else(|| anyhow!("HOME is required for launchd installs"))?
            .join("Library/LaunchAgents/com.portl.agent.plist")),
        InstallTarget::Dockerfile => {
            Ok(output.unwrap_or_else(|| Path::new(".")).join("Dockerfile"))
        }
        InstallTarget::Openrc => Ok(PathBuf::from("/etc/init.d/portl-agent")),
    }
}

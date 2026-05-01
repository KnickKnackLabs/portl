use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use nix::unistd::Uid;

use super::InstallTarget;

pub(super) fn stop_install_target(target: InstallTarget, root: bool, path: &Path) {
    match target {
        InstallTarget::Systemd => stop_systemd(root),
        InstallTarget::Launchd => stop_launchd(root, path),
        InstallTarget::Dockerfile => {}
        InstallTarget::Openrc => {
            let _ = ProcessCommand::new("rc-service")
                .args(["portl-agent", "stop"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

pub(super) fn apply_install_target(target: InstallTarget, root: bool, path: &Path) -> Result<()> {
    match target {
        InstallTarget::Systemd => apply_systemd(root, path),
        InstallTarget::Launchd => apply_launchd(root, path),
        InstallTarget::Dockerfile => {
            println!(
                "dockerfile target is write-only; `--apply` writes {} and does not start a service",
                path.display()
            );
            Ok(())
        }
        InstallTarget::Openrc => apply_openrc(path),
    }
}

fn stop_systemd(root: bool) {
    let args = user_scoped_systemd_args(root);
    let _ = ProcessCommand::new("systemctl")
        .args(append_args(args, &["stop", "portl-agent.service"]))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub(super) fn apply_systemd(root: bool, _path: &Path) -> Result<()> {
    let args = user_scoped_systemd_args(root);
    run_checked("systemctl", &append_args(args, &["daemon-reload"]))?;
    run_checked(
        "systemctl",
        &append_args(args, &["enable", "--now", "portl-agent.service"]),
    )?;
    run_checked(
        "systemctl",
        &append_args(args, &["status", "--no-pager", "portl-agent.service"]),
    )?;
    let journal_args = if root {
        vec!["-u", "portl-agent.service", "-n", "20", "--no-pager"]
    } else {
        vec![
            "--user",
            "-u",
            "portl-agent.service",
            "-n",
            "20",
            "--no-pager",
        ]
    };
    run_checked("journalctl", &journal_args)
}

fn stop_launchd(root: bool, path: &Path) {
    let domain = if root {
        "system".to_owned()
    } else {
        format!("gui/{}", Uid::effective().as_raw())
    };
    if let Some(path_str) = path.to_str() {
        let _ = ProcessCommand::new("launchctl")
            .args(["bootout", &domain, path_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = ProcessCommand::new("launchctl")
        .args(["bootout", &format!("{domain}/com.portl.agent")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub(super) fn apply_launchd(root: bool, path: &Path) -> Result<()> {
    let domain = if root {
        "system".to_owned()
    } else {
        format!("gui/{}", Uid::effective().as_raw())
    };
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("launchd path is not valid UTF-8: {}", path.display()))?;
    stop_launchd(root, path);
    run_checked("launchctl", &["bootstrap", &domain, path_str])?;
    run_checked(
        "launchctl",
        &["kickstart", "-k", &format!("{domain}/com.portl.agent")],
    )?;
    Ok(())
}

pub(super) fn apply_openrc(_path: &Path) -> Result<()> {
    run_checked("rc-update", &["add", "portl-agent", "default"])?;
    run_checked("rc-service", &["portl-agent", "start"])?;
    run_checked("rc-service", &["portl-agent", "status"])
}

pub(super) fn user_scoped_systemd_args(root: bool) -> &'static [&'static str] {
    if root { &[] } else { &["--user"] }
}

pub(super) fn append_args<'a>(prefix: &'a [&'a str], suffix: &'a [&'a str]) -> Vec<&'a str> {
    prefix
        .iter()
        .copied()
        .chain(suffix.iter().copied())
        .collect()
}

pub(super) fn run_checked(program: &str, args: &[&str]) -> Result<()> {
    let status = ProcessCommand::new(program)
        .args(args)
        .status()
        .with_context(|| format!("run {} {}", program, args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        bail!(
            "{} {} failed with status {}",
            program,
            args.join(" "),
            status
        )
    }
}

pub(super) fn validate_install_target(target: InstallTarget, path: &Path) -> Result<()> {
    match target {
        InstallTarget::Systemd
            if Path::new("/usr/bin/systemd-analyze").exists()
                || Path::new("/bin/systemd-analyze").exists() =>
        {
            let status = ProcessCommand::new("systemd-analyze")
                .args(["verify"])
                .arg(path)
                .status()
                .context("run systemd-analyze verify")?;
            if status.success() {
                Ok(())
            } else {
                bail!("systemd-analyze verify failed for {}", path.display())
            }
        }
        InstallTarget::Launchd if Path::new("/usr/bin/plutil").exists() => {
            let status = ProcessCommand::new("plutil")
                .args(["-lint"])
                .arg(path)
                .status()
                .context("run plutil -lint")?;
            if status.success() {
                Ok(())
            } else {
                bail!("plutil -lint failed for {}", path.display())
            }
        }
        _ => Ok(()),
    }
}

pub(super) fn set_mode_0755(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 0755 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(super) fn inside_docker() -> bool {
    Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .is_ok_and(|contents| contents.contains("docker") || contents.contains("containerd"))
}

use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use nix::unistd::Uid;
use serde::Serialize;

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

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
struct DetectionContext {
    os: String,
    has_launchctl: bool,
    inside_docker: bool,
    has_systemd_dir: bool,
    has_openrc: bool,
    root: bool,
    home: Option<PathBuf>,
}

pub fn detect_host() -> DetectResult {
    detect_host_with(&DetectionContext::from_host())
}

impl DetectionContext {
    fn from_host() -> Self {
        Self {
            os: std::env::consts::OS.to_owned(),
            has_launchctl: Path::new("/bin/launchctl").exists(),
            inside_docker: inside_docker(),
            has_systemd_dir: Path::new("/run/systemd/system").is_dir(),
            has_openrc: Path::new("/sbin/openrc-run").exists(),
            root: Uid::effective().is_root(),
            home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }
}

fn detect_host_with(ctx: &DetectionContext) -> DetectResult {
    if ctx.os == "macos" && ctx.has_launchctl {
        return DetectResult {
            matched: Some(InstallTarget::Launchd),
            reason: "launchctl is present on Darwin".to_owned(),
            inside_docker: ctx.inside_docker,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    if ctx.inside_docker {
        return DetectResult {
            matched: None,
            reason: "container environment detected; use `portl docker bake` or choose an explicit non-system init target".to_owned(),
            inside_docker: true,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    if ctx.has_systemd_dir {
        return DetectResult {
            matched: Some(InstallTarget::Systemd),
            reason: if ctx.root {
                "systemd detected".to_owned()
            } else {
                "systemd detected; using user service install".to_owned()
            },
            inside_docker: false,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    if ctx.has_openrc {
        return DetectResult {
            matched: Some(InstallTarget::Openrc),
            reason: "openrc-run is present".to_owned(),
            inside_docker: false,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    DetectResult {
        matched: None,
        reason: "no supported init system detected".to_owned(),
        inside_docker: false,
        root: ctx.root,
        home: ctx.home.clone(),
    }
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

fn resolve_target(target: Option<InstallTarget>, detect: &DetectResult) -> Result<InstallTarget> {
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

fn resolve_output_dir(target: InstallTarget, output: Option<&Path>) -> Result<Option<PathBuf>> {
    if !matches!(target, InstallTarget::Dockerfile) && output.is_some() {
        bail!("`--output DIR` is only supported for `portl install dockerfile`");
    }
    Ok(output.map(Path::to_path_buf))
}

fn install_binary_path(
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

fn install_service_path(
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

fn render_target(
    target: InstallTarget,
    binary_path: &Path,
    root: bool,
    home: Option<&Path>,
) -> Result<String> {
    match target {
        InstallTarget::Systemd => render_systemd_unit(binary_path, root, home),
        InstallTarget::Launchd => Ok(render_launchd_plist(binary_path)),
        InstallTarget::Dockerfile => Ok(render_service_dockerfile()),
        InstallTarget::Openrc => Ok(render_openrc_script(binary_path)),
    }
}

fn render_systemd_unit(binary_path: &Path, root: bool, home: Option<&Path>) -> Result<String> {
    let wanted_by = if root {
        "multi-user.target"
    } else {
        "default.target"
    };
    let env_file = if root {
        PathBuf::from("/etc/portl/agent.env")
    } else {
        home.ok_or_else(|| anyhow!("HOME is required for user-level systemd installs"))?
            .join(".config/portl/agent.env")
    };
    Ok(format!(
        "[Unit]\nDescription=portl agent\nAfter=network-online.target\nWants=network-online.target\nStartLimitBurst=5\nStartLimitIntervalSec=60s\n\n[Service]\nExecStart={}\nEnvironmentFile=-{}\nRestart=on-failure\nRestartSec=5s\n\n[Install]\nWantedBy={}\n",
        binary_path.display(),
        env_file.display(),
        wanted_by
    ))
}

fn render_launchd_plist(binary_path: &Path) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "  <key>Label</key><string>com.portl.agent</string>\n",
            "  <key>ProgramArguments</key>\n",
            "  <array>\n",
            "    <string>{}</string>\n",
            "  </array>\n",
            "  <key>KeepAlive</key>\n",
            "  <dict>\n",
            "    <key>SuccessfulExit</key><false/>\n",
            "  </dict>\n",
            "  <key>RunAtLoad</key><true/>\n",
            "</dict>\n",
            "</plist>\n"
        ),
        binary_path.display()
    )
}

fn render_openrc_script(binary_path: &Path) -> String {
    format!(
        concat!(
            "#!/sbin/openrc-run\n",
            "command=\"{}\"\n",
            "command_background=true\n",
            "pidfile=\"/run/portl-agent.pid\"\n",
            "supervisor=supervise-daemon\n",
            "supervise_daemon_args=\"--respawn-delay 5 --respawn-max 5\"\n"
        ),
        binary_path.display()
    )
}

fn render_service_dockerfile() -> String {
    "FROM debian:stable-slim\nCOPY portl-agent /usr/local/bin/portl-agent\nRUN chmod +x /usr/local/bin/portl-agent\nENTRYPOINT [\"/usr/local/bin/portl-agent\"]\n".to_owned()
}

fn apply_install_target(target: InstallTarget, root: bool, path: &Path) -> Result<()> {
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

fn apply_systemd(root: bool, _path: &Path) -> Result<()> {
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

fn apply_launchd(root: bool, path: &Path) -> Result<()> {
    let domain = if root {
        "system".to_owned()
    } else {
        format!("gui/{}", Uid::effective().as_raw())
    };
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("launchd path is not valid UTF-8: {}", path.display()))?;
    let _ = run_checked("launchctl", &["bootout", &domain, path_str]);
    run_checked("launchctl", &["bootstrap", &domain, path_str])?;
    run_checked(
        "launchctl",
        &["kickstart", "-k", &format!("{domain}/com.portl.agent")],
    )?;
    run_checked(
        "launchctl",
        &["print", &format!("{domain}/com.portl.agent")],
    )
}

fn apply_openrc(_path: &Path) -> Result<()> {
    run_checked("rc-update", &["add", "portl-agent", "default"])?;
    run_checked("rc-service", &["portl-agent", "start"])?;
    run_checked("rc-service", &["portl-agent", "status"])
}

fn user_scoped_systemd_args(root: bool) -> &'static [&'static str] {
    if root { &[] } else { &["--user"] }
}

fn append_args<'a>(prefix: &'a [&'a str], suffix: &'a [&'a str]) -> Vec<&'a str> {
    prefix
        .iter()
        .copied()
        .chain(suffix.iter().copied())
        .collect()
}

fn run_checked(program: &str, args: &[&str]) -> Result<()> {
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

fn validate_install_target(target: InstallTarget, path: &Path) -> Result<()> {
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

fn set_mode_0755(path: &Path) -> Result<()> {
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

fn inside_docker() -> bool {
    Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|contents| contents.contains("docker") || contents.contains("containerd"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn install_systemd_emits_valid_unit_file() {
        let unit = render_systemd_unit(Path::new("/usr/local/bin/portl-agent"), true, None)
            .expect("render systemd unit");
        assert!(unit.contains("ExecStart=/usr/local/bin/portl-agent"));
        assert!(unit.contains("EnvironmentFile=-/etc/portl/agent.env"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("StartLimitBurst=5"));

        if Path::new("/usr/bin/systemd-analyze").exists()
            || Path::new("/bin/systemd-analyze").exists()
        {
            let dir = tempdir().expect("tempdir");
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

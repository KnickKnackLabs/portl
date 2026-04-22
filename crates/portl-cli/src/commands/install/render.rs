use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use super::InstallTarget;

/// v0.3.0 moved trust-root policy out of env vars and into a
/// filesystem-backed peer store that the agent reloads live. The
/// install flow seeds that store with the local identity's self-row
/// (see `install::mod.rs::seed_peer_store_self_row`) instead of
/// writing env vars. This module's only job is to render the
/// service definition — no env plumbing needed.
pub(super) fn render_target(
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

pub(super) fn render_systemd_unit(
    binary_path: &Path,
    root: bool,
    home: Option<&Path>,
) -> Result<String> {
    let wanted_by = if root {
        "multi-user.target"
    } else {
        "default.target"
    };
    // We still honor operator-provided env at `-agent.env` for
    // advanced knobs (rate_limit, metrics, etc.); leaving the
    // `EnvironmentFile=-…` directive is harmless when the file is
    // absent and useful when it isn't.
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

pub(super) fn render_launchd_plist(binary_path: &Path) -> String {
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

pub(super) fn render_openrc_script(binary_path: &Path) -> String {
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

pub(super) fn render_service_dockerfile() -> String {
    "FROM debian:stable-slim\nCOPY portl-agent /usr/local/bin/portl-agent\nRUN chmod +x /usr/local/bin/portl-agent\nENTRYPOINT [\"/usr/local/bin/portl-agent\"]\n".to_owned()
}

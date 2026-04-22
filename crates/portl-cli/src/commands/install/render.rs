use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use super::InstallTarget;

/// Env vars that the install flow should bake into the service
/// definition. Today this is just the local identity's public key
/// as `PORTL_TRUST_ROOTS`, which makes `portl install` produce an
/// agent that accepts tickets minted by this machine by default
/// (fixes the `"BadChain on fresh install"` footgun). Additional
/// keys can be added here in the future without touching call sites.
#[derive(Debug, Default, Clone)]
pub(super) struct AgentEnv {
    pub trust_roots_hex: Option<String>,
}

impl AgentEnv {
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.trust_roots_hex
            .as_deref()
            .map(|v| ("PORTL_TRUST_ROOTS", v))
            .into_iter()
    }

    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }
}

pub(super) fn render_target(
    target: InstallTarget,
    binary_path: &Path,
    root: bool,
    home: Option<&Path>,
    env: &AgentEnv,
) -> Result<String> {
    match target {
        InstallTarget::Systemd => render_systemd_unit(binary_path, root, home),
        InstallTarget::Launchd => Ok(render_launchd_plist(binary_path, env)),
        InstallTarget::Dockerfile => Ok(render_service_dockerfile(env)),
        InstallTarget::Openrc => Ok(render_openrc_script(binary_path, env)),
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

pub(super) fn render_launchd_plist(binary_path: &Path, env: &AgentEnv) -> String {
    use std::fmt::Write as _;
    let env_block = if env.is_empty() {
        String::new()
    } else {
        let mut s = String::from("  <key>EnvironmentVariables</key>\n  <dict>\n");
        for (k, v) in env.iter() {
            // SAFETY(write!): writing to a String cannot fail.
            let _ = writeln!(s, "    <key>{k}</key><string>{v}</string>");
        }
        s.push_str("  </dict>\n");
        s
    };
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
            "{}",
            "</dict>\n",
            "</plist>\n"
        ),
        binary_path.display(),
        env_block,
    )
}

pub(super) fn render_openrc_script(binary_path: &Path, env: &AgentEnv) -> String {
    use std::fmt::Write as _;
    let mut env_lines = String::new();
    for (k, v) in env.iter() {
        // SAFETY(write!): writing to a String cannot fail.
        let _ = writeln!(env_lines, "export {k}=\"{v}\"");
    }
    format!(
        concat!(
            "#!/sbin/openrc-run\n",
            "{}",
            "command=\"{}\"\n",
            "command_background=true\n",
            "pidfile=\"/run/portl-agent.pid\"\n",
            "supervisor=supervise-daemon\n",
            "supervise_daemon_args=\"--respawn-delay 5 --respawn-max 5\"\n"
        ),
        env_lines,
        binary_path.display()
    )
}

pub(super) fn render_service_dockerfile(env: &AgentEnv) -> String {
    use std::fmt::Write as _;
    let mut env_lines = String::new();
    for (k, v) in env.iter() {
        // SAFETY(write!): writing to a String cannot fail.
        let _ = writeln!(env_lines, "ENV {k}={v}");
    }
    format!(
        "FROM debian:stable-slim\nCOPY portl-agent /usr/local/bin/portl-agent\nRUN chmod +x /usr/local/bin/portl-agent\n{env_lines}ENTRYPOINT [\"/usr/local/bin/portl-agent\"]\n",
    )
}

/// Path where the systemd unit's `EnvironmentFile=-…` directive expects
/// to find environment assignments (in `KEY=value` form, one per line).
/// Mirrors the `env_file` selection in [`render_systemd_unit`] so
/// callers that write the file can target the right location without
/// re-deriving the rule.
pub(super) fn systemd_env_file_path(root: bool, home: Option<&Path>) -> Result<PathBuf> {
    if root {
        Ok(PathBuf::from("/etc/portl/agent.env"))
    } else {
        Ok(home
            .ok_or_else(|| anyhow!("HOME is required for user-level systemd installs"))?
            .join(".config/portl/agent.env"))
    }
}

/// Serialize `env` into the `KEY=value\n` format systemd's
/// `EnvironmentFile=` directive reads. Empty when `env` has no entries.
pub(super) fn render_env_file(env: &AgentEnv) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for (k, v) in env.iter() {
        // SAFETY(write!): writing to a String cannot fail.
        let _ = writeln!(s, "{k}={v}");
    }
    s
}

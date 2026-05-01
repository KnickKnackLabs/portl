use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use portl_proto::session_v1::{
    ProviderCapabilities, ProviderReport, ProviderStatus, SessionInfo, SessionRunResult,
};
use tokio::process::Command;

pub(crate) const ZMX_CONTROL_PROTOCOL: &str = "zmx-control/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderPathSource {
    Config,
    StablePath,
    UserBin,
    MiseShim,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProviderPathProbe {
    pub(crate) path: PathBuf,
    pub(crate) source: ProviderPathSource,
    pub(crate) exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProviderPathDiscovery {
    pub(crate) path: Option<PathBuf>,
    pub(crate) source: Option<ProviderPathSource>,
    pub(crate) probes: Vec<ProviderPathProbe>,
}

#[derive(Debug, Clone)]
pub(crate) struct ZmxProvider {
    path: Option<PathBuf>,
    env: Vec<(String, String)>,
    target_home: Option<PathBuf>,
}

impl ZmxProvider {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            env: Vec::new(),
            target_home: default_target_home(),
        }
    }

    pub(crate) fn with_target_home(mut self, target_home: Option<PathBuf>) -> Self {
        self.target_home = target_home;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_path(path: PathBuf) -> Self {
        Self::new(Some(path))
    }

    #[cfg(test)]
    pub(crate) fn with_env(mut self, key: &str, value: &Path) -> Self {
        self.env.push((key.to_owned(), value.display().to_string()));
        self
    }

    pub(crate) async fn probe(&self) -> Result<ProviderStatus> {
        let Some(path) = self.resolve_path() else {
            return Ok(provider_status(
                false,
                None,
                Some("not found".to_owned()),
                None,
                Vec::new(),
            ));
        };
        if let Some((tier, features, notes)) = self.probe_control(&path).await? {
            return Ok(provider_status(
                true,
                Some(path.display().to_string()),
                notes,
                Some(tier),
                features,
            ));
        }
        let output = self.command(&path).arg("version").output().await;
        match output {
            Ok(output) if output.status.success() => Ok(provider_status(
                true,
                Some(path.display().to_string()),
                Some(String::from_utf8_lossy(&output.stdout).trim().to_owned()),
                Some("attach".to_owned()),
                Vec::new(),
            )),
            Ok(output) => Ok(provider_status(
                false,
                Some(path.display().to_string()),
                Some(String::from_utf8_lossy(&output.stderr).trim().to_owned()),
                None,
                Vec::new(),
            )),
            Err(err) => Ok(provider_status(
                false,
                Some(path.display().to_string()),
                Some(err.to_string()),
                None,
                Vec::new(),
            )),
        }
    }

    pub(crate) async fn control_available(&self) -> Result<bool> {
        let Some(path) = self.resolve_path() else {
            return Ok(false);
        };
        Ok(self.probe_control(&path).await?.is_some())
    }

    #[cfg(test)]
    pub(crate) async fn list(&self) -> Result<Vec<String>> {
        Ok(self
            .list_detailed()
            .await?
            .into_iter()
            .map(|session| session.name)
            .collect())
    }

    pub(crate) async fn list_detailed(&self) -> Result<Vec<SessionInfo>> {
        let json_output = self.run_capture(&["list", "--json"]).await?;
        if json_output.code == 0
            && let Ok(sessions) = parse_zmx_session_json(&json_output.stdout)
        {
            return Ok(sessions);
        }

        let output = self.run_capture(&["list"]).await?;
        ensure_success("zmx list", &output)?;
        Ok(output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|name| SessionInfo {
                name: name.to_owned(),
                provider: "zmx".to_owned(),
                metadata: BTreeMap::new(),
            })
            .collect())
    }

    pub(crate) async fn run(&self, session: &str, argv: &[String]) -> Result<SessionRunResult> {
        let mut zmx_args = vec!["run".to_owned(), session.to_owned()];
        zmx_args.extend(argv.iter().cloned());
        self.run_capture(&zmx_args.iter().map(String::as_str).collect::<Vec<_>>())
            .await
    }

    pub(crate) async fn history(&self, session: &str) -> Result<String> {
        let output = self.run_capture(&["history", session]).await?;
        ensure_success("zmx history", &output)?;
        Ok(output.stdout)
    }

    pub(crate) async fn kill(&self, session: &str) -> Result<()> {
        let output = self.run_capture(&["kill", session]).await?;
        ensure_success("zmx kill", &output)
    }

    pub(crate) fn control_command(
        &self,
        session: &str,
        cwd: Option<&str>,
        pty: Option<&portl_proto::shell_v1::PtyCfg>,
        argv: Option<&[String]>,
        workload_env: Option<&[(String, String)]>,
    ) -> Result<Command> {
        let path = self
            .resolve_path()
            .ok_or_else(|| anyhow!("zmx is not installed on the target"))?;
        let mut command = self.command(&path);
        if let Some(env) = workload_env {
            command.envs(env.iter().cloned());
            for (key, value) in &self.env {
                command.env(key, value);
            }
        }
        command.args(["control", "--protocol", ZMX_CONTROL_PROTOCOL]);
        if let Some(pty) = pty {
            command
                .arg("--rows")
                .arg(pty.rows.to_string())
                .arg("--cols")
                .arg(pty.cols.to_string());
        }
        command.arg(session);
        if let Some(argv) = argv {
            command.args(argv);
        }
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        Ok(command)
    }

    #[cfg(test)]
    pub(crate) fn control_argv(&self, session: &str) -> Result<Vec<String>> {
        let path = self
            .resolve_path()
            .ok_or_else(|| anyhow!("zmx is not installed on the target"))?;
        Ok(vec![
            path.display().to_string(),
            "control".to_owned(),
            "--protocol".to_owned(),
            ZMX_CONTROL_PROTOCOL.to_owned(),
            session.to_owned(),
        ])
    }

    pub(crate) fn attach_argv(
        &self,
        session: &str,
        argv: Option<&[String]>,
    ) -> Result<Vec<String>> {
        let path = self
            .resolve_path()
            .ok_or_else(|| anyhow!("zmx is not installed on the target"))?;
        let mut out = vec![
            path.display().to_string(),
            "attach".to_owned(),
            session.to_owned(),
        ];
        if let Some(argv) = argv {
            out.extend(argv.iter().cloned());
        }
        Ok(out)
    }

    async fn probe_control(
        &self,
        path: &Path,
    ) -> Result<Option<(String, Vec<String>, Option<String>)>> {
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            self.command(path)
                .args(["control", "--protocol", ZMX_CONTROL_PROTOCOL, "--probe"])
                .stdin(Stdio::null())
                .output(),
        )
        .await;
        let Ok(Ok(output)) = output else {
            return Ok(None);
        };
        if !output.status.success() {
            return Ok(None);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut protocol_ok = false;
        let mut tier = None;
        let mut features = Vec::new();
        for line in stdout.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "protocol" if value.trim() == ZMX_CONTROL_PROTOCOL => protocol_ok = true,
                "tier" => tier = Some(value.trim().to_owned()),
                "features" => {
                    features = value
                        .split(',')
                        .map(str::trim)
                        .filter(|feature| !feature.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                }
                _ => {}
            }
        }
        if protocol_ok && tier.as_deref() == Some("control") {
            Ok(Some((
                tier.unwrap_or_else(|| "control".to_owned()),
                features,
                Some(stdout.trim().to_owned()),
            )))
        } else {
            Ok(None)
        }
    }

    async fn run_capture(&self, args: &[&str]) -> Result<SessionRunResult> {
        let path = self
            .resolve_path()
            .ok_or_else(|| anyhow!("zmx is not installed on the target"))?;
        let output = self
            .command(&path)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("run {} {}", path.display(), args.join(" ")))?;
        let code = output.status.code().unwrap_or(1);
        Ok(SessionRunResult {
            code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    pub(crate) fn path_discovery(&self) -> ProviderPathDiscovery {
        discover_provider_path("zmx", self.path.clone(), self.target_home.as_deref())
    }

    fn resolve_path(&self) -> Option<PathBuf> {
        self.path_discovery().path
    }

    fn command(&self, path: &Path) -> Command {
        let mut command = Command::new(path);
        apply_provider_env(&mut command, &self.env, self.target_home.as_deref());
        command
    }
}

fn discover_provider_path(
    program: &str,
    configured: Option<PathBuf>,
    target_home: Option<&Path>,
) -> ProviderPathDiscovery {
    discover_provider_path_with_dirs(
        program,
        configured,
        &stable_provider_dirs(),
        target_home,
        None,
    )
}

fn discover_provider_path_with_dirs(
    program: &str,
    configured: Option<PathBuf>,
    stable_dirs: &[PathBuf],
    target_home: Option<&Path>,
    xdg_data_home: Option<&Path>,
) -> ProviderPathDiscovery {
    let mut probes = Vec::new();
    let mut seen = HashSet::new();

    if let Some(path) = configured {
        push_probe(
            &mut probes,
            &mut seen,
            path.clone(),
            ProviderPathSource::Config,
        );
        return ProviderPathDiscovery {
            path: path.exists().then_some(path),
            source: probes
                .first()
                .and_then(|probe| probe.exists.then_some(probe.source)),
            probes,
        };
    }

    for dir in stable_dirs {
        push_probe(
            &mut probes,
            &mut seen,
            dir.join(program),
            ProviderPathSource::StablePath,
        );
    }
    if let Some(home) = target_home {
        for relative in [".local/bin", "bin", ".cargo/bin"] {
            push_probe(
                &mut probes,
                &mut seen,
                home.join(relative).join(program),
                ProviderPathSource::UserBin,
            );
        }
        let mise_data = xdg_data_home.map_or_else(|| home.join(".local/share"), Path::to_path_buf);
        push_probe(
            &mut probes,
            &mut seen,
            mise_data.join("mise/shims").join(program),
            ProviderPathSource::MiseShim,
        );
    }

    let selected = probes.iter().find(|probe| probe.exists);
    ProviderPathDiscovery {
        path: selected.map(|probe| probe.path.clone()),
        source: selected.map(|probe| probe.source),
        probes,
    }
}

fn push_probe(
    probes: &mut Vec<ProviderPathProbe>,
    seen: &mut HashSet<PathBuf>,
    path: PathBuf,
    source: ProviderPathSource,
) {
    if seen.insert(path.clone()) {
        probes.push(ProviderPathProbe {
            exists: path.exists(),
            path,
            source,
        });
    }
}

fn stable_provider_dirs() -> Vec<PathBuf> {
    [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/bin",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

fn default_target_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::geteuid())
            .ok()
            .flatten()
            .map(|user| user.dir)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn apply_provider_env(
    command: &mut Command,
    extra_env: &[(String, String)],
    target_home: Option<&Path>,
) {
    command.env_clear();
    command.env("PATH", crate::target_context::default_target_path());
    for key in ["TMPDIR", "XDG_RUNTIME_DIR", "ZMX_DIR", "TMUX_TMPDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(home) = target_home {
        command.env("HOME", home);
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TmuxProvider {
    path: Option<PathBuf>,
    env: Vec<(String, String)>,
    target_home: Option<PathBuf>,
}

pub(crate) struct TmuxSpawnConfig {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) initial_commands: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TmuxTarget {
    pub(crate) session: String,
    pub(crate) target: String,
    pub(crate) has_selector: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TmuxPane {
    pub(crate) target: String,
    pub(crate) window_index: String,
    pub(crate) window_name: String,
    pub(crate) pane_index: String,
    pub(crate) active: bool,
}

pub(crate) fn parse_tmux_target(input: &str) -> TmuxTarget {
    if let Some((session, _selector)) = input.split_once(':') {
        TmuxTarget {
            session: session.to_owned(),
            target: input.to_owned(),
            has_selector: true,
        }
    } else {
        TmuxTarget {
            session: input.to_owned(),
            target: input.to_owned(),
            has_selector: false,
        }
    }
}

pub(crate) fn tmux_lookup_session(input: &str) -> &str {
    input.split_once(':').map_or(input, |(session, _)| session)
}

fn validate_tmux_control_target(target: &str) -> Result<()> {
    if target.is_empty()
        || !target.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b':' | b'.' | b'_' | b'-' | b'#' | b'@' | b'%' | b'$')
        })
    {
        bail!("unsafe tmux target {target:?}");
    }
    Ok(())
}

fn tmux_list_empty_error(stderr: &str) -> bool {
    stderr.contains("no server running")
        || stderr.contains("no sessions")
        || (stderr.contains("error connecting") && stderr.contains("no such file or directory"))
}

fn parse_tmux_panes(stdout: &str) -> Vec<TmuxPane> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let target = parts.next()?.to_owned();
            let window_index = parts.next()?.to_owned();
            let window_name = parts.next()?.to_owned();
            let pane_index = parts.next()?.to_owned();
            let window_active = parts.next()? == "1";
            let pane_active = parts.next()? == "1";
            Some(TmuxPane {
                target,
                window_index,
                window_name,
                pane_index,
                active: window_active && pane_active,
            })
        })
        .collect()
}

fn parse_tmux_cursor_line(line: &str) -> Option<(u16, u16)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "PORTL_CURSOR" {
        return None;
    }
    let x = parts.next()?.parse().ok()?;
    let y = parts.next()?.parse().ok()?;
    Some((x, y))
}

impl TmuxProvider {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            env: Vec::new(),
            target_home: default_target_home(),
        }
    }

    pub(crate) fn with_target_home(mut self, target_home: Option<PathBuf>) -> Self {
        self.target_home = target_home;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_path(path: PathBuf) -> Self {
        Self::new(Some(path))
    }

    #[cfg(test)]
    pub(crate) fn with_env(mut self, key: &str, value: &Path) -> Self {
        self.env.push((key.to_owned(), value.display().to_string()));
        self
    }

    pub(crate) async fn probe(&self) -> Result<ProviderStatus> {
        let Some(path) = self.resolve_path() else {
            return Ok(tmux_provider_status(
                false,
                None,
                Some("not found".to_owned()),
                None,
                Vec::new(),
            ));
        };
        let output = self.command(&path).arg("-V").output().await;
        match output {
            Ok(output) if output.status.success() => Ok(tmux_provider_status(
                true,
                Some(path.display().to_string()),
                Some(String::from_utf8_lossy(&output.stdout).trim().to_owned()),
                Some("control".to_owned()),
                tmux_features(),
            )),
            Ok(output) => Ok(tmux_provider_status(
                false,
                Some(path.display().to_string()),
                Some(String::from_utf8_lossy(&output.stderr).trim().to_owned()),
                None,
                Vec::new(),
            )),
            Err(err) => Ok(tmux_provider_status(
                false,
                Some(path.display().to_string()),
                Some(err.to_string()),
                None,
                Vec::new(),
            )),
        }
    }

    #[cfg(test)]
    pub(crate) async fn list(&self) -> Result<Vec<String>> {
        Ok(self
            .list_detailed()
            .await?
            .into_iter()
            .map(|session| session.name)
            .collect())
    }

    pub(crate) async fn list_detailed(&self) -> Result<Vec<SessionInfo>> {
        let output = self
            .run_capture(&[
                "list-sessions",
                "-F",
                "#{session_name}\t#{session_id}\t#{session_attached}\t#{session_created}\t#{session_windows}\t#{window_width}\t#{window_height}",
            ])
            .await?;
        if output.code != 0 {
            let stderr = output.stderr.to_lowercase();
            if tmux_list_empty_error(&stderr) {
                return Ok(Vec::new());
            }
            ensure_success("tmux list-sessions", &output)?;
        }
        Ok(output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(parse_tmux_session_line)
            .collect())
    }

    pub(crate) async fn list_panes(&self, session: &str) -> Result<Vec<TmuxPane>> {
        let output = self
            .run_capture(&[
                "list-panes",
                "-s",
                "-F",
                "#{session_name}:#{window_index}.#{pane_index}\t#{window_index}\t#{window_name}\t#{pane_index}\t#{window_active}\t#{pane_active}",
                "-t",
                session,
            ])
            .await?;
        ensure_success("tmux list-panes", &output)?;
        Ok(parse_tmux_panes(&output.stdout))
    }

    pub(crate) async fn history(&self, session: &str) -> Result<String> {
        let output = self
            .run_capture(&[
                "capture-pane",
                "-p",
                "-e",
                "-S",
                "-",
                "-E",
                "-",
                "-t",
                session,
            ])
            .await?;
        ensure_success("tmux capture-pane", &output)?;
        Ok(output.stdout)
    }

    pub(crate) async fn viewport_snapshot(&self, session: &str) -> Result<Vec<u8>> {
        let output = self
            .run_capture(&[
                "display-message",
                "-p",
                "-t",
                session,
                "PORTL_CURSOR #{cursor_x} #{cursor_y}",
                ";",
                "capture-pane",
                "-p",
                "-e",
                "-N",
                "-S",
                "0",
                "-E",
                "-",
                "-t",
                session,
            ])
            .await?;
        ensure_success("tmux capture-pane", &output)?;
        let mut lines = output.stdout.lines();
        let (cursor_x, cursor_y) = lines
            .next()
            .and_then(parse_tmux_cursor_line)
            .unwrap_or((0, 0));
        let snapshot = lines.collect::<Vec<_>>().join("\n");
        Ok(portl_core::terminal::tmux_cc::render_viewport_snapshot(
            snapshot.as_bytes(),
            cursor_x,
            cursor_y,
        ))
    }

    pub(crate) async fn kill(&self, session: &str) -> Result<()> {
        let output = self.run_capture(&["kill-session", "-t", session]).await?;
        ensure_success("tmux kill-session", &output)
    }

    pub(crate) fn control_spawn_config_with_env(
        &self,
        session: &str,
        target: Option<&str>,
        cwd: Option<&str>,
        pty: Option<&portl_proto::shell_v1::PtyCfg>,
        argv: Option<&[String]>,
        workload_env: Option<&[(String, String)]>,
    ) -> Result<TmuxSpawnConfig> {
        let path = self
            .resolve_path()
            .ok_or_else(|| anyhow!("tmux is not installed on the target"))?;
        let mut command_args = vec![
            "-CC".to_owned(),
            "new-session".to_owned(),
            "-A".to_owned(),
            "-s".to_owned(),
            session.to_owned(),
        ];
        if let Some(pty) = pty {
            command_args.extend([
                "-x".to_owned(),
                pty.cols.to_string(),
                "-y".to_owned(),
                pty.rows.to_string(),
            ]);
        }
        if let Some(cwd) = cwd {
            command_args.extend(["-c".to_owned(), cwd.to_owned()]);
        }
        if let Some(argv) = argv {
            command_args.extend(argv.iter().cloned());
        }
        let mut env = workload_env.map_or_else(
            || {
                vec![(
                    "PATH".to_owned(),
                    crate::target_context::default_target_path(),
                )]
            },
            <[(String, String)]>::to_vec,
        );
        env.extend(self.env.iter().cloned());
        let mut initial_commands = Vec::new();
        if let Some(target) = target.filter(|target| *target != session) {
            validate_tmux_control_target(target)?;
            initial_commands.push(format!("switch-client -t {target}\n").into_bytes());
        }
        Ok(TmuxSpawnConfig {
            program: path,
            args: command_args,
            env,
            initial_commands,
        })
    }

    async fn run_capture(&self, args: &[&str]) -> Result<SessionRunResult> {
        let path = self
            .resolve_path()
            .ok_or_else(|| anyhow!("tmux is not installed on the target"))?;
        let output = self
            .command(&path)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("run {} {}", path.display(), args.join(" ")))?;
        let code = output.status.code().unwrap_or(1);
        Ok(SessionRunResult {
            code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    pub(crate) fn path_discovery(&self) -> ProviderPathDiscovery {
        discover_provider_path("tmux", self.path.clone(), self.target_home.as_deref())
    }

    fn resolve_path(&self) -> Option<PathBuf> {
        self.path_discovery().path
    }

    fn command(&self, path: &Path) -> Command {
        let mut command = Command::new(path);
        apply_provider_env(&mut command, &self.env, self.target_home.as_deref());
        command
    }
}

fn provider_status(
    available: bool,
    path: Option<String>,
    notes: Option<String>,
    tier: Option<String>,
    features: Vec<String>,
) -> ProviderStatus {
    ProviderStatus {
        name: "zmx".to_owned(),
        available,
        path,
        notes,
        capabilities: ProviderCapabilities::zmx(),
        tier,
        features,
    }
}

fn tmux_provider_status(
    available: bool,
    path: Option<String>,
    notes: Option<String>,
    tier: Option<String>,
    features: Vec<String>,
) -> ProviderStatus {
    ProviderStatus {
        name: "tmux".to_owned(),
        available,
        path,
        notes,
        capabilities: ProviderCapabilities::tmux(),
        tier,
        features,
    }
}

fn parse_zmx_session_json(stdout: &str) -> Result<Vec<SessionInfo>> {
    let value: serde_json::Value = serde_json::from_str(stdout).context("parse zmx list --json")?;
    let Some(items) = value.as_array() else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .filter_map(|item| match item {
            serde_json::Value::String(name) => Some(SessionInfo {
                name: name.clone(),
                provider: "zmx".to_owned(),
                metadata: BTreeMap::new(),
            }),
            serde_json::Value::Object(object) => object
                .get("name")
                .or_else(|| object.get("session"))
                .and_then(serde_json::Value::as_str)
                .map(|name| SessionInfo {
                    name: name.to_owned(),
                    provider: "zmx".to_owned(),
                    metadata: stringify_json_object(object, &["name", "session"]),
                }),
            _ => None,
        })
        .collect())
}

fn parse_tmux_session_line(line: &str) -> SessionInfo {
    let fields = parse_tmux_session_fields(line);
    SessionInfo {
        name: fields.name.to_owned(),
        provider: "tmux".to_owned(),
        metadata: BTreeMap::from([
            ("id".to_owned(), fields.id.to_owned()),
            ("attached".to_owned(), (fields.attached == "1").to_string()),
            ("created_unix".to_owned(), fields.created.to_owned()),
            ("windows".to_owned(), fields.windows.to_owned()),
            ("width".to_owned(), fields.width.to_owned()),
            ("height".to_owned(), fields.height.to_owned()),
        ]),
    }
}

struct TmuxSessionFields<'a> {
    name: &'a str,
    id: &'a str,
    attached: &'a str,
    created: &'a str,
    windows: &'a str,
    width: &'a str,
    height: &'a str,
}

fn parse_tmux_session_fields(line: &str) -> TmuxSessionFields<'_> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() >= 7 {
        return TmuxSessionFields {
            name: parts[0],
            id: parts[1],
            attached: parts[2],
            created: parts[3],
            windows: parts[4],
            width: parts[5],
            height: parts[6],
        };
    }

    parse_tmux_underscore_session_fields(line).unwrap_or(TmuxSessionFields {
        name: line,
        id: "",
        attached: "",
        created: "",
        windows: "",
        width: "",
        height: "",
    })
}

fn parse_tmux_underscore_session_fields(line: &str) -> Option<TmuxSessionFields<'_>> {
    let mut parts = line.rsplitn(7, '_').collect::<Vec<_>>();
    if parts.len() != 7 {
        return None;
    }
    parts.reverse();
    let [name, id, attached, created, windows, width, height] = parts.as_slice() else {
        return None;
    };
    if name.is_empty()
        || !id.starts_with('$')
        || !matches!(*attached, "0" | "1")
        || [*created, *windows, *width, *height]
            .into_iter()
            .any(|field| field.parse::<u64>().is_err())
    {
        return None;
    }
    Some(TmuxSessionFields {
        name,
        id,
        attached,
        created,
        windows,
        width,
        height,
    })
}

fn stringify_json_object(
    object: &serde_json::Map<String, serde_json::Value>,
    skip_keys: &[&str],
) -> BTreeMap<String, String> {
    object
        .iter()
        .filter(|(key, _)| !skip_keys.contains(&key.as_str()))
        .map(|(key, value)| {
            let value = value
                .as_str()
                .map_or_else(|| value.to_string(), ToOwned::to_owned);
            (key.clone(), value)
        })
        .collect()
}

fn tmux_features() -> Vec<String> {
    [
        "tmux_control.v1",
        "tmux_cc.v1",
        "viewport_snapshot.v1",
        "live_output.v1",
        "priority_input.v1",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

fn ensure_success(action: &str, result: &SessionRunResult) -> Result<()> {
    if result.code == 0 {
        Ok(())
    } else {
        bail!(
            "{action} exited with {}: {}",
            result.code,
            result.stderr.trim()
        )
    }
}

pub(crate) fn provider_discovery_info(
    configured_path: Option<&Path>,
) -> crate::status_schema::SessionProvidersInfo {
    let target_home = default_target_home();
    let default_user = default_user_info();
    let tmux_config = configured_path.and_then(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "tmux")
            .then(|| path.to_path_buf())
    });
    let zmx_config = if tmux_config.is_some() {
        None
    } else {
        configured_path.map(Path::to_path_buf)
    };
    let zmx = discover_provider_path("zmx", zmx_config, target_home.as_deref());
    let tmux = discover_provider_path("tmux", tmux_config, target_home.as_deref());
    let default_provider = if zmx.path.is_some() {
        Some("zmx".to_owned())
    } else if tmux.path.is_some() {
        Some("tmux".to_owned())
    } else {
        None
    };
    let mut providers = vec![provider_info("zmx", &zmx), provider_info("tmux", &tmux)];
    providers.push(crate::status_schema::SessionProviderInfo {
        name: "raw".to_owned(),
        detected: true,
        path: None,
        source: Some("builtin".to_owned()),
        notes: Some("one-shot PTY fallback".to_owned()),
    });
    let mut search_paths = Vec::new();
    append_search_paths("zmx", &zmx, &mut search_paths);
    append_search_paths("tmux", &tmux, &mut search_paths);

    crate::status_schema::SessionProvidersInfo {
        default_provider,
        default_user,
        providers,
        search_paths,
    }
}

fn provider_info(
    name: &str,
    discovery: &ProviderPathDiscovery,
) -> crate::status_schema::SessionProviderInfo {
    crate::status_schema::SessionProviderInfo {
        name: name.to_owned(),
        detected: discovery.path.is_some(),
        path: discovery
            .path
            .as_ref()
            .map(|path| path.display().to_string()),
        source: discovery.source.map(source_name),
        notes: None,
    }
}

fn append_search_paths(
    provider: &str,
    discovery: &ProviderPathDiscovery,
    out: &mut Vec<crate::status_schema::SessionProviderSearchPath>,
) {
    out.extend(discovery.probes.iter().map(|probe| {
        crate::status_schema::SessionProviderSearchPath {
            provider: provider.to_owned(),
            path: probe.path.display().to_string(),
            source: source_name(probe.source),
            exists: probe.exists,
        }
    }));
}

fn source_name(source: ProviderPathSource) -> String {
    match source {
        ProviderPathSource::Config => "config",
        ProviderPathSource::StablePath => "stable_path",
        ProviderPathSource::UserBin => "user_bin",
        ProviderPathSource::MiseShim => "mise_shim",
    }
    .to_owned()
}

fn default_user_info() -> Option<crate::status_schema::DefaultUserInfo> {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::geteuid())
            .ok()
            .flatten()
            .map(|user| crate::status_schema::DefaultUserInfo {
                name: user.name,
                home: user.dir.display().to_string(),
                shell: user.shell.display().to_string(),
            })
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("HOME").map(|home| crate::status_schema::DefaultUserInfo {
            name: std::env::var("USER").unwrap_or_default(),
            home: PathBuf::from(home).display().to_string(),
            shell: std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned()),
        })
    }
}

pub(crate) async fn provider_report(
    zmx: &ZmxProvider,
    tmux: &TmuxProvider,
) -> Result<ProviderReport> {
    let zmx_status = zmx.probe().await?;
    let tmux_status = tmux.probe().await?;
    let ghostty_status = ghostty_provider_status();
    let default_provider = ghostty_status
        .as_ref()
        .filter(|status| status.available)
        .map(|status| status.name.clone())
        .or_else(|| zmx_status.available.then(|| "zmx".to_owned()))
        .or_else(|| tmux_status.available.then(|| "tmux".to_owned()));
    let mut providers = Vec::new();
    if let Some(status) = ghostty_status {
        providers.push(status);
    }
    providers.extend([
        zmx_status,
        tmux_status,
        ProviderStatus {
            name: "raw".to_owned(),
            available: true,
            path: None,
            notes: Some("one-shot PTY fallback".to_owned()),
            capabilities: ProviderCapabilities::raw(),
            tier: Some("raw".to_owned()),
            features: Vec::new(),
        },
    ]);
    Ok(ProviderReport {
        default_provider,
        providers,
    })
}

#[cfg(feature = "ghostty-vt")]
#[allow(clippy::unnecessary_wraps)]
fn ghostty_provider_status() -> Option<ProviderStatus> {
    Some(crate::session_handler::ghostty::GhosttyProvider::new().status())
}

#[cfg(not(feature = "ghostty-vt"))]
fn ghostty_provider_status() -> Option<ProviderStatus> {
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Result;

    use super::*;

    #[test]
    fn provider_discovery_prefers_configured_path() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let configured = temp.path().join("configured-zmx");
        let stable = temp.path().join("stable");
        fs::create_dir_all(&stable)?;
        fs::write(&configured, "")?;
        fs::write(stable.join("zmx"), "")?;

        let discovery = discover_provider_path_with_dirs(
            "zmx",
            Some(configured.clone()),
            &[stable],
            None,
            None,
        );

        assert_eq!(discovery.path.as_deref(), Some(configured.as_path()));
        assert_eq!(discovery.source, Some(ProviderPathSource::Config));
        assert_eq!(discovery.probes[0].source, ProviderPathSource::Config);
        Ok(())
    }

    #[test]
    fn provider_discovery_searches_homebrew_before_usr_local() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let homebrew = temp.path().join("opt-homebrew-bin");
        let usr_local = temp.path().join("usr-local-bin");
        fs::create_dir_all(&homebrew)?;
        fs::create_dir_all(&usr_local)?;
        fs::write(homebrew.join("tmux"), "")?;
        fs::write(usr_local.join("tmux"), "")?;

        let discovery = discover_provider_path_with_dirs(
            "tmux",
            None,
            &[homebrew.clone(), usr_local],
            None,
            None,
        );

        assert_eq!(
            discovery.path.as_deref(),
            Some(homebrew.join("tmux").as_path())
        );
        assert_eq!(discovery.source, Some(ProviderPathSource::StablePath));
        Ok(())
    }

    #[test]
    fn provider_discovery_searches_mise_shims_under_target_home() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let home = temp.path().join("home");
        let shims = home.join(".local/share/mise/shims");
        fs::create_dir_all(&shims)?;
        fs::write(shims.join("zmx"), "")?;

        let discovery = discover_provider_path_with_dirs("zmx", None, &[], Some(&home), None);

        assert_eq!(discovery.path.as_deref(), Some(shims.join("zmx").as_path()));
        assert_eq!(discovery.source, Some(ProviderPathSource::MiseShim));
        assert!(
            discovery
                .probes
                .iter()
                .any(|probe| probe.source == ProviderPathSource::MiseShim)
        );
        Ok(())
    }

    #[test]
    fn provider_discovery_records_missing_candidates() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let stable = temp.path().join("stable");
        let home = temp.path().join("home");

        let discovery = discover_provider_path_with_dirs(
            "zmx",
            None,
            std::slice::from_ref(&stable),
            Some(&home),
            None,
        );

        assert!(discovery.path.is_none());
        assert!(discovery.probes.iter().any(|probe| {
            probe.path == stable.join("zmx")
                && probe.source == ProviderPathSource::StablePath
                && !probe.exists
        }));
        assert!(discovery.probes.iter().any(|probe| {
            probe.path == home.join(".local/share/mise/shims/zmx")
                && probe.source == ProviderPathSource::MiseShim
                && !probe.exists
        }));
        Ok(())
    }

    #[tokio::test]
    async fn zmx_provider_maps_commands_to_target_cli() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("zmx");
        fs::write(
            &fake,
            r#"#!/bin/sh
printf '%s\n' "$@" >> "$PORTL_FAKE_ZMX_LOG"
case "$1" in
  version) echo "zmx fake" ;;
  list) echo "alpha" ;;
  run) echo "ran:$2:${3}" ;;
  history) echo "hist:$2" ;;
  kill) echo "killed:$2" ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let log = temp.path().join("log");
        let provider = ZmxProvider::with_path(fake).with_env("PORTL_FAKE_ZMX_LOG", &log);

        assert!(provider.probe().await?.available);
        assert_eq!(provider.list().await?, vec!["alpha".to_owned()]);
        assert_eq!(
            provider
                .run("alpha", &["date".to_owned()])
                .await?
                .stdout
                .trim(),
            "ran:alpha:date"
        );
        assert_eq!(provider.history("alpha").await?.trim(), "hist:alpha");
        provider.kill("alpha").await?;

        let calls = fs::read_to_string(log)?;
        assert!(calls.contains("version\n"));
        assert!(calls.contains("list\n"));
        assert!(calls.contains("run\nalpha\ndate\n"));
        assert!(calls.contains("history\nalpha\n"));
        assert!(calls.contains("kill\nalpha\n"));
        Ok(())
    }

    #[tokio::test]
    async fn zmx_provider_prefers_control_probe_when_available() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("zmx");
        fs::write(
            &fake,
            r#"#!/bin/sh
printf '%s\n' "$@" >> "$PORTL_FAKE_ZMX_LOG"
if [ "$1" = "control" ] && [ "$2" = "--protocol" ] && [ "$3" = "zmx-control/v1" ] && [ "$4" = "--probe" ]; then
  printf 'protocol=zmx-control/v1\n'
  printf 'tier=control\n'
  printf 'features=viewport_snapshot.v1,live_output.v1,priority_input.v1,adapter_sequence.v1\n'
  exit 0
fi
case "$1" in
  version) echo "zmx fake" ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let log = temp.path().join("log");
        let provider = ZmxProvider::with_path(fake).with_env("PORTL_FAKE_ZMX_LOG", &log);

        let status = provider.probe().await?;
        assert!(status.available);
        assert_eq!(status.tier.as_deref(), Some("control"));
        assert_eq!(
            status.features,
            vec![
                "viewport_snapshot.v1".to_owned(),
                "live_output.v1".to_owned(),
                "priority_input.v1".to_owned(),
                "adapter_sequence.v1".to_owned(),
            ]
        );
        assert_eq!(
            provider.control_argv("dev")?,
            vec![
                status.path.unwrap(),
                "control".to_owned(),
                "--protocol".to_owned(),
                "zmx-control/v1".to_owned(),
                "dev".to_owned(),
            ]
        );

        let calls = fs::read_to_string(log)?;
        assert!(calls.contains("control\n--protocol\nzmx-control/v1\n--probe\n"));
        Ok(())
    }

    #[tokio::test]
    async fn zmx_provider_falls_back_to_attach_when_control_probe_fails() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("zmx");
        fs::write(
            &fake,
            r#"#!/bin/sh
printf '%s\n' "$@" >> "$PORTL_FAKE_ZMX_LOG"
case "$1" in
  control) echo "no control" >&2; exit 64 ;;
  version) echo "zmx fake" ;;
  attach) echo "attach:$2" ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let log = temp.path().join("log");
        let provider = ZmxProvider::with_path(fake).with_env("PORTL_FAKE_ZMX_LOG", &log);

        let status = provider.probe().await?;
        assert!(status.available);
        assert_eq!(status.tier.as_deref(), Some("attach"));
        assert!(status.features.is_empty());
        assert!(!provider.control_available().await?);
        assert_eq!(
            provider.attach_argv("dev", Some(&["top".to_owned()]))?,
            vec![
                status.path.unwrap(),
                "attach".to_owned(),
                "dev".to_owned(),
                "top".to_owned(),
            ]
        );

        let calls = fs::read_to_string(log)?;
        assert!(calls.contains("control\n--protocol\nzmx-control/v1\n--probe\n"));
        assert!(calls.contains("version\n"));
        Ok(())
    }

    #[tokio::test]
    async fn zmx_provider_preserves_runtime_directory_env_for_socket_discovery() -> Result<()> {
        let Some(tmpdir) = std::env::var_os("TMPDIR") else {
            return Ok(());
        };
        let tmpdir = PathBuf::from(tmpdir);
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("zmx");
        fs::write(
            &fake,
            format!(
                r#"#!/bin/sh
case "$1" in
  list)
    if [ "${{TMPDIR:-}}" != "{}" ]; then
      echo "TMPDIR was '${{TMPDIR:-}}'" >&2
      exit 66
    fi
    echo "alpha"
    ;;
esac
"#,
                tmpdir.display()
            ),
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let result = ZmxProvider::with_path(fake).list().await;

        assert_eq!(result?, vec!["alpha".to_owned()]);
        Ok(())
    }

    #[tokio::test]
    async fn zmx_provider_passes_target_home_to_provider_commands() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("zmx");
        let home = temp.path().join("home");
        fs::create_dir_all(&home)?;
        fs::write(
            &fake,
            format!(
                r#"#!/bin/sh
case "$1" in
  list)
    if [ "${{HOME:-}}" != "{}" ]; then
      echo "HOME was '${{HOME:-}}'" >&2
      exit 66
    fi
    echo "alpha"
    ;;
esac
"#,
                home.display()
            ),
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let result = ZmxProvider::with_path(fake)
            .with_target_home(Some(home))
            .list()
            .await;

        assert_eq!(result?, vec!["alpha".to_owned()]);
        Ok(())
    }

    #[tokio::test]
    async fn zmx_provider_does_not_pass_unspecified_portl_env() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("zmx");
        let leak_file = temp.path().join("leak");
        fs::write(
            &fake,
            format!(
                r#"#!/bin/sh
if [ -n "${{PORTL_IDENTITY_SECRET_HEX:-}}" ]; then
  echo "$PORTL_IDENTITY_SECRET_HEX" > {}
fi
case "$1" in
  version) echo "zmx fake" ;;
  list) echo "alpha" ;;
esac
"#,
                leak_file.display()
            ),
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let result = ZmxProvider::with_path(fake).list().await;

        assert_eq!(result?, vec!["alpha".to_owned()]);
        assert!(
            !leak_file.exists(),
            "provider inherited PORTL_IDENTITY_SECRET_HEX"
        );
        Ok(())
    }

    #[test]
    fn tmux_target_parsing_uses_native_session_window_pane_suffix() {
        assert_eq!(
            parse_tmux_target("dev"),
            TmuxTarget {
                session: "dev".to_owned(),
                target: "dev".to_owned(),
                has_selector: false,
            }
        );
        assert_eq!(
            parse_tmux_target("dev:0.1"),
            TmuxTarget {
                session: "dev".to_owned(),
                target: "dev:0.1".to_owned(),
                has_selector: true,
            }
        );
        assert_eq!(tmux_lookup_session("dev:editor.0"), "dev");
    }

    #[test]
    fn parses_tmux_session_lines_with_tab_or_underscore_separators() {
        let tab = parse_tmux_session_line("dotfiles\t$3\t0\t1777557300\t1\t58\t30");
        assert_eq!(tab.name, "dotfiles");
        assert_eq!(tab.metadata["id"], "$3");
        assert_eq!(tab.metadata["attached"], "false");
        assert_eq!(tab.metadata["created_unix"], "1777557300");
        assert_eq!(tab.metadata["windows"], "1");
        assert_eq!(tab.metadata["width"], "58");
        assert_eq!(tab.metadata["height"], "30");

        let underscore = parse_tmux_session_line("aircover_hep_$0_1_1777575845_1_138_72");
        assert_eq!(underscore.name, "aircover_hep");
        assert_eq!(underscore.metadata["id"], "$0");
        assert_eq!(underscore.metadata["attached"], "true");
        assert_eq!(underscore.metadata["created_unix"], "1777575845");
        assert_eq!(underscore.metadata["windows"], "1");
        assert_eq!(underscore.metadata["width"], "138");
        assert_eq!(underscore.metadata["height"], "72");
    }

    #[test]
    fn parses_tmux_pane_list_and_marks_active_target() {
        let panes = parse_tmux_panes(
            "dev:0.0\t0\tshell\t0\t1\t0\ndev:0.1\t0\tshell\t1\t1\t1\ndev:1.0\t1\tlogs\t0\t0\t1\n",
        );
        assert_eq!(panes.len(), 3);
        assert_eq!(panes[1].target, "dev:0.1");
        assert!(panes[1].active);
        assert!(!panes[2].active);
    }

    #[test]
    fn tmux_viewport_snapshot_restores_cursor_for_live_deltas() {
        let rendered =
            portl_core::terminal::tmux_cc::render_viewport_snapshot(b"old spinner\nnext\n", 4, 0);

        assert_eq!(
            rendered,
            b"\x1b[H\x1b[2J\x1b[1;1Hold spinner\x1b[K\x1b[2;1Hnext\x1b[K\x1b[1;5H"
        );
    }

    #[tokio::test]
    async fn tmux_control_target_rejects_command_injection_bytes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("tmux");
        fs::write(
            &fake,
            r#"#!/bin/sh
case "$1" in
  -V) echo "tmux 3.6" ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let provider = TmuxProvider::with_path(fake);
        let Err(err) = provider.control_spawn_config_with_env(
            "dev",
            Some("dev:0.1\nkill-server"),
            None,
            None,
            None,
            None,
        ) else {
            anyhow::bail!("tmux target with newline must be rejected");
        };
        assert!(err.to_string().contains("unsafe tmux target"), "{err:#}");

        Ok(())
    }

    #[tokio::test]
    async fn tmux_provider_maps_commands_to_target_cli() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("tmux");
        fs::write(
            &fake,
            r#"#!/bin/sh
printf '%s\n' "$@" >> "$PORTL_FAKE_TMUX_LOG"
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'dev\nfrontend\n' ;;
  capture-pane) echo "history:$9" ;;
  kill-session) echo "killed:$3" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let log = temp.path().join("log");
        let provider = TmuxProvider::with_path(fake).with_env("PORTL_FAKE_TMUX_LOG", &log);

        let status = provider.probe().await?;
        assert!(status.available);
        assert_eq!(status.name, "tmux");
        assert_eq!(status.tier.as_deref(), Some("control"));
        assert!(status.features.contains(&"tmux_control.v1".to_owned()));
        assert_eq!(status.capabilities, ProviderCapabilities::tmux());
        assert_eq!(
            provider.list().await?,
            vec!["dev".to_owned(), "frontend".to_owned()]
        );
        assert_eq!(provider.history("dev").await?.trim(), "history:dev");
        provider.kill("dev").await?;

        let calls = fs::read_to_string(log)?;
        assert!(calls.contains("-V\n"));
        assert!(calls.contains(
            "list-sessions\n-F\n#{session_name}\t#{session_id}\t#{session_attached}\t#{session_created}\t#{session_windows}\t#{window_width}\t#{window_height}\n"
        ));
        assert!(calls.contains("capture-pane\n-p\n-e\n-S\n-\n-E\n-\n-t\ndev\n"));
        assert!(calls.contains("kill-session\n-t\ndev\n"));
        Ok(())
    }

    #[tokio::test]
    async fn tmux_list_treats_no_server_as_empty() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("tmux");
        fs::write(
            &fake,
            r#"#!/bin/sh
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) echo "error connecting to /tmp/tmux-1001/default (No such file or directory)" >&2; exit 1 ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        assert!(TmuxProvider::with_path(fake).list().await?.is_empty());
        Ok(())
    }

    #[cfg(feature = "ghostty-vt")]
    #[tokio::test]
    async fn provider_report_prefers_builtin_ghostty_when_feature_enabled() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let missing = temp.path().join("missing-provider");
        let zmx = ZmxProvider::with_path(missing.clone());
        let tmux = TmuxProvider::with_path(missing);

        let report = provider_report(&zmx, &tmux).await?;

        assert_eq!(report.default_provider.as_deref(), Some("ghostty"));
        assert_eq!(
            report
                .providers
                .iter()
                .map(|status| status.name.as_str())
                .collect::<Vec<_>>(),
            vec!["ghostty", "zmx", "tmux", "raw"]
        );
        let ghostty = &report.providers[0];
        assert!(ghostty.available);
        assert_eq!(ghostty.tier.as_deref(), Some("native"));
        assert_eq!(ghostty.capabilities, ProviderCapabilities::ghostty());
        assert!(ghostty.features.contains(&"ghostty-vt.v1".to_owned()));
        Ok(())
    }

    #[cfg(not(feature = "ghostty-vt"))]
    #[tokio::test]
    async fn provider_report_includes_tmux_and_falls_back_to_it() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fake = temp.path().join("provider");
        fs::write(
            &fake,
            r#"#!/bin/sh
case "$1" in
  -V) echo "tmux 3.6" ;;
  *) echo "not zmx" >&2; exit 64 ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        let zmx = ZmxProvider::with_path(fake.clone());
        let tmux = TmuxProvider::with_path(fake);
        let report = provider_report(&zmx, &tmux).await?;

        assert_eq!(report.default_provider.as_deref(), Some("tmux"));
        assert_eq!(
            report
                .providers
                .iter()
                .map(|status| status.name.as_str())
                .collect::<Vec<_>>(),
            vec!["zmx", "tmux", "raw"]
        );
        Ok(())
    }
}

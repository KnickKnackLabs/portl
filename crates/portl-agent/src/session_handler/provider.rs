use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use portl_proto::session_v1::{
    ProviderCapabilities, ProviderReport, ProviderStatus, SessionRunResult,
};
use tokio::process::Command;

pub(crate) const ZMX_CONTROL_PROTOCOL: &str = "zmx-control/v1";

#[derive(Debug, Clone)]
pub(crate) struct ZmxProvider {
    path: Option<PathBuf>,
    env: Vec<(String, String)>,
}

impl ZmxProvider {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            env: Vec::new(),
        }
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

    pub(crate) async fn list(&self) -> Result<Vec<String>> {
        let output = self.run_capture(&["list"]).await?;
        ensure_success("zmx list", &output)?;
        Ok(output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
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
    ) -> Result<Command> {
        let path = self
            .resolve_path()
            .ok_or_else(|| anyhow!("zmx is not installed on the target"))?;
        let mut command = self.command(&path);
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
            Duration::from_secs(2),
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

    fn resolve_path(&self) -> Option<PathBuf> {
        if let Some(path) = self.path.as_ref() {
            return path.exists().then_some(path.clone());
        }
        find_on_safe_path("zmx")
    }

    fn command(&self, path: &Path) -> Command {
        let mut command = Command::new(path);
        apply_provider_env(&mut command, &self.env);
        command
    }
}

fn find_on_safe_path(program: &str) -> Option<PathBuf> {
    ["/usr/local/bin", "/usr/bin", "/bin"]
        .into_iter()
        .map(|dir| Path::new(dir).join(program))
        .find(|candidate| candidate.exists())
}

fn apply_provider_env(command: &mut Command, extra_env: &[(String, String)]) {
    command.env_clear();
    command.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    for (key, value) in extra_env {
        command.env(key, value);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TmuxProvider {
    path: Option<PathBuf>,
    env: Vec<(String, String)>,
}

pub(crate) struct TmuxSpawnConfig {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
}

impl TmuxProvider {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            env: Vec::new(),
        }
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

    pub(crate) async fn list(&self) -> Result<Vec<String>> {
        let output = self
            .run_capture(&["list-sessions", "-F", "#{session_name}"])
            .await?;
        if output.code != 0 {
            let stderr = output.stderr.to_lowercase();
            if stderr.contains("no server running") || stderr.contains("no sessions") {
                return Ok(Vec::new());
            }
            ensure_success("tmux list-sessions", &output)?;
        }
        Ok(output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect())
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

    pub(crate) async fn kill(&self, session: &str) -> Result<()> {
        let output = self.run_capture(&["kill-session", "-t", session]).await?;
        ensure_success("tmux kill-session", &output)
    }

    pub(crate) fn control_spawn_config(
        &self,
        session: &str,
        cwd: Option<&str>,
        pty: Option<&portl_proto::shell_v1::PtyCfg>,
        argv: Option<&[String]>,
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
        let mut env = vec![("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())];
        env.extend(self.env.iter().cloned());
        Ok(TmuxSpawnConfig {
            program: path,
            args: command_args,
            env,
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

    fn resolve_path(&self) -> Option<PathBuf> {
        if let Some(path) = self.path.as_ref() {
            return path.exists().then_some(path.clone());
        }
        find_on_safe_path("tmux")
    }

    fn command(&self, path: &Path) -> Command {
        let mut command = Command::new(path);
        apply_provider_env(&mut command, &self.env);
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

pub(crate) async fn provider_report(
    zmx: &ZmxProvider,
    tmux: &TmuxProvider,
) -> Result<ProviderReport> {
    let zmx_status = zmx.probe().await?;
    let tmux_status = tmux.probe().await?;
    let default_provider = if zmx_status.available {
        Some("zmx".to_owned())
    } else if tmux_status.available {
        Some("tmux".to_owned())
    } else {
        None
    };
    Ok(ProviderReport {
        default_provider,
        providers: vec![
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
        ],
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Result;

    use super::*;

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
        assert!(calls.contains("list-sessions\n-F\n#{session_name}\n"));
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
  list-sessions) echo "no server running on /tmp/tmux" >&2; exit 1 ;;
esac
"#,
        )?;
        let mut perms = fs::metadata(&fake)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake, perms)?;

        assert!(TmuxProvider::with_path(fake).list().await?.is_empty());
        Ok(())
    }

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

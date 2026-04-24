use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, anyhow, bail};
use portl_proto::session_v1::{
    ProviderCapabilities, ProviderReport, ProviderStatus, SessionRunResult,
};
use tokio::process::Command;

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
            return Ok(ProviderStatus {
                name: "zmx".to_owned(),
                available: false,
                path: None,
                notes: Some("not found".to_owned()),
                capabilities: ProviderCapabilities::zmx(),
            });
        };
        let output = self.command(&path).arg("version").output().await;
        match output {
            Ok(output) if output.status.success() => Ok(ProviderStatus {
                name: "zmx".to_owned(),
                available: true,
                path: Some(path.display().to_string()),
                notes: Some(String::from_utf8_lossy(&output.stdout).trim().to_owned()),
                capabilities: ProviderCapabilities::zmx(),
            }),
            Ok(output) => Ok(ProviderStatus {
                name: "zmx".to_owned(),
                available: false,
                path: Some(path.display().to_string()),
                notes: Some(String::from_utf8_lossy(&output.stderr).trim().to_owned()),
                capabilities: ProviderCapabilities::zmx(),
            }),
            Err(err) => Ok(ProviderStatus {
                name: "zmx".to_owned(),
                available: false,
                path: Some(path.display().to_string()),
                notes: Some(err.to_string()),
                capabilities: ProviderCapabilities::zmx(),
            }),
        }
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

pub(crate) async fn provider_report(zmx: &ZmxProvider) -> Result<ProviderReport> {
    let zmx_status = zmx.probe().await?;
    let default_provider = zmx_status.available.then(|| "zmx".to_owned());
    Ok(ProviderReport {
        default_provider,
        providers: vec![
            zmx_status,
            ProviderStatus {
                name: "raw".to_owned(),
                available: true,
                path: None,
                notes: Some("one-shot PTY fallback".to_owned()),
                capabilities: ProviderCapabilities::raw(),
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
}

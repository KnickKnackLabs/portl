//! `portl config` — read / scaffold `portl.toml`.
//!
//! Verbs:
//!
//! - `portl config show` — effective merged config (file layer only;
//!   env overrides are surfaced in `portl status agent` instead).
//! - `portl config path` — print the absolute path to `portl.toml`.
//! - `portl config default` — print a commented template; pipe into
//!   `> ~/.local/share/portl/portl.toml` (or the `PORTL_HOME`
//!   equivalent) to scaffold.
//! - `portl config validate [PATH]` — parse + type-check a file.
//!   Defaults to `$PORTL_HOME/portl.toml`.

use std::path::PathBuf;

#[cfg(test)]
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use portl_agent::config_file::PortlConfig;

/// Subcommand dispatch.
pub fn run(action: ConfigAction) -> ExitCode {
    match action {
        ConfigAction::Show => match run_show() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("config show: {e:#}");
                ExitCode::FAILURE
            }
        },
        ConfigAction::Path => {
            run_path();
            ExitCode::SUCCESS
        }
        ConfigAction::Default => {
            print!("{}", PortlConfig::default_template());
            ExitCode::SUCCESS
        }
        ConfigAction::Validate { path } => match run_validate(path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("config validate: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    Show,
    Path,
    Default,
    Validate { path: Option<PathBuf> },
}

fn run_show() -> Result<()> {
    let path = effective_path();
    let cfg = PortlConfig::load(&path).with_context(|| format!("load {}", path.display()))?;
    let text = toml::to_string_pretty(&cfg).context("serialize config")?;
    println!("# effective file config (env overrides not shown)");
    println!("# source: {}", path.display());
    print!("{text}");
    Ok(())
}

fn run_path() {
    println!("{}", effective_path().display());
}

fn run_validate(path: Option<PathBuf>) -> Result<()> {
    let path = path.unwrap_or_else(effective_path);
    if !path.exists() {
        anyhow::bail!("{} does not exist", path.display());
    }
    let _cfg = PortlConfig::load(&path).with_context(|| format!("parse {}", path.display()))?;
    println!("ok: {} parses cleanly", path.display());
    Ok(())
}

/// Resolve the effective `portl.toml` path. Honors `PORTL_HOME`;
/// falls back to the platform default home dir.
fn effective_path() -> PathBuf {
    let home = std::env::var_os("PORTL_HOME")
        .map_or_else(portl_agent::config::default_home_dir, PathBuf::from);
    PortlConfig::default_path(&home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn validate_rejects_malformed_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("portl.toml");
        std::fs::write(&path, "not = = toml [[").expect("write");
        let err = run_validate(Some(path)).expect_err("must reject");
        assert!(err.to_string().contains("parse") || err.to_string().contains("TOML"));
    }

    #[test]
    fn validate_accepts_default_template() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("portl.toml");
        std::fs::write(&path, PortlConfig::default_template()).expect("write");
        run_validate(Some(path)).expect("template must validate");
    }

    #[test]
    fn validate_errors_on_missing_file() {
        let path = Path::new("/tmp/does-not-exist-portl-validate.toml").to_owned();
        let err = run_validate(Some(path)).expect_err("must error");
        assert!(err.to_string().contains("does not exist"));
    }
}

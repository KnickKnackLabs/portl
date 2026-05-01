//! `portl config` — read / scaffold `portl.toml`.
//!
//! Verbs:
//!
//! - `portl config show` — effective merged config (file layer only;
//!   env overrides are surfaced in `portl status agent` instead).
//! - `portl config path` — print the absolute path to `portl.toml`.
//! - `portl config template` — print a commented template; pipe into
//!   `> ~/.portl/config/portl.toml` (or the `PORTL_HOME`
//!   equivalent) to scaffold.
//! - `portl config validate [--path PATH|--stdin]` — parse + type-check
//!   TOML. Defaults to `$PORTL_HOME/config/portl.toml`.

use std::io::Read;
use std::path::PathBuf;

#[cfg(test)]
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use portl_agent::config_file::PortlConfig;

/// Subcommand dispatch.
pub fn run(action: ConfigAction) -> ExitCode {
    match action {
        ConfigAction::Show { json } => match run_show(json) {
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
        ConfigAction::Template => {
            print!("{}", PortlConfig::default_template());
            ExitCode::SUCCESS
        }
        ConfigAction::Validate { path, stdin, json } => match run_validate(path, stdin, !json) {
            Ok(()) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"schema": 1, "kind": "config.validate", "ok": true, "errors": []})
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"schema": 1, "kind": "config.validate", "ok": false, "errors": [format!("{e:#}")]})
                    );
                } else {
                    eprintln!("config validate: {e:#}");
                }
                ExitCode::FAILURE
            }
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    Show {
        json: bool,
    },
    Path,
    Template,
    Validate {
        path: Option<PathBuf>,
        stdin: bool,
        json: bool,
    },
}

fn run_show(json: bool) -> Result<()> {
    let path = effective_path();
    let cfg = PortlConfig::load(&path).with_context(|| format!("load {}", path.display()))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&cfg).context("serialize config JSON")?
        );
    } else {
        let text = toml::to_string_pretty(&cfg).context("serialize config")?;
        println!("# effective file config (env overrides not shown)");
        println!("# source: {}", path.display());
        print!("{text}");
    }
    Ok(())
}

fn run_path() {
    println!("{}", effective_path().display());
}

fn run_validate(path: Option<PathBuf>, stdin: bool, human_ok: bool) -> Result<()> {
    if stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("read config from stdin")?;
        let _cfg: PortlConfig = toml::from_str(&input).context("parse stdin")?;
        if human_ok {
            println!("ok: stdin parses cleanly");
        }
        return Ok(());
    }

    let path = path.unwrap_or_else(effective_path);
    if !path.exists() {
        anyhow::bail!("{} does not exist", path.display());
    }
    let _cfg = PortlConfig::load(&path).with_context(|| format!("parse {}", path.display()))?;
    if human_ok {
        println!("ok: {} parses cleanly", path.display());
    }
    Ok(())
}

/// Resolve the effective `portl.toml` path. Honors `PORTL_HOME`;
/// falls back to the platform default home dir.
fn effective_path() -> PathBuf {
    portl_core::paths::config_path()
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
        let err = run_validate(Some(path), false, true).expect_err("must reject");
        assert!(err.to_string().contains("parse") || err.to_string().contains("TOML"));
    }

    #[test]
    fn validate_accepts_default_template() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("portl.toml");
        std::fs::write(&path, PortlConfig::default_template()).expect("write");
        run_validate(Some(path), false, true).expect("template must validate");
    }

    #[test]
    fn validate_errors_on_missing_file() {
        let path = Path::new("/tmp/does-not-exist-portl-validate.toml").to_owned();
        let err = run_validate(Some(path), false, true).expect_err("must error");
        assert!(err.to_string().contains("does not exist"));
    }
}

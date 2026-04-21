use std::process::ExitCode;

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallTarget {
    Systemd,
    Launchd,
    Dockerfile,
    Openrc,
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn run(
    _target: Option<InstallTarget>,
    _apply: bool,
    _yes: bool,
    _detect: bool,
    _dry_run: bool,
) -> Result<ExitCode> {
    anyhow::bail!("`portl install` is implemented in Task 3.4")
}

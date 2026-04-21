use std::process::ExitCode;

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InitRole {
    Operator,
    Agent,
}

pub fn run(_force: bool, _role: Option<InitRole>) -> Result<ExitCode> {
    anyhow::bail!("`portl init` is implemented in Task 3.4")
}

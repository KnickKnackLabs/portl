use std::path::PathBuf;

use anyhow::{Context, Result};

pub(super) trait HostOps {
    fn current_exe(&self) -> Result<PathBuf>;
    fn host_os(&self) -> &'static str;
    fn host_arch(&self) -> &'static str;
}

pub(super) struct RealHostOps;

impl HostOps for RealHostOps {
    fn current_exe(&self) -> Result<PathBuf> {
        std::env::current_exe().context("resolve current executable")
    }

    fn host_os(&self) -> &'static str {
        std::env::consts::OS
    }

    fn host_arch(&self) -> &'static str {
        std::env::consts::ARCH
    }
}

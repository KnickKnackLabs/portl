use std::path::{Path, PathBuf};

use nix::unistd::Uid;

use super::apply::inside_docker;
use super::{DetectResult, InstallTarget};

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub(super) struct DetectionContext {
    pub(super) os: String,
    pub(super) has_launchctl: bool,
    pub(super) inside_docker: bool,
    pub(super) has_systemd_dir: bool,
    pub(super) has_openrc: bool,
    pub(super) root: bool,
    pub(super) home: Option<PathBuf>,
}

impl DetectionContext {
    pub(super) fn from_host() -> Self {
        Self {
            os: std::env::consts::OS.to_owned(),
            has_launchctl: Path::new("/bin/launchctl").exists(),
            inside_docker: inside_docker(),
            has_systemd_dir: Path::new("/run/systemd/system").is_dir(),
            has_openrc: Path::new("/sbin/openrc-run").exists(),
            root: Uid::effective().is_root(),
            home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }
}

pub(super) fn detect_host_with(ctx: &DetectionContext) -> DetectResult {
    if ctx.os == "macos" && ctx.has_launchctl {
        return DetectResult {
            matched: Some(InstallTarget::Launchd),
            reason: "launchctl is present on Darwin".to_owned(),
            inside_docker: ctx.inside_docker,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    if ctx.inside_docker {
        return DetectResult {
            matched: None,
            reason: "container environment detected; use `portl docker bake` or choose an explicit non-system init target".to_owned(),
            inside_docker: true,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    if ctx.has_systemd_dir {
        return DetectResult {
            matched: Some(InstallTarget::Systemd),
            reason: if ctx.root {
                "systemd detected".to_owned()
            } else {
                "systemd detected; using user service install".to_owned()
            },
            inside_docker: false,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    if ctx.has_openrc {
        return DetectResult {
            matched: Some(InstallTarget::Openrc),
            reason: "openrc-run is present".to_owned(),
            inside_docker: false,
            root: ctx.root,
            home: ctx.home.clone(),
        };
    }
    DetectResult {
        matched: None,
        reason: "no supported init system detected".to_owned(),
        inside_docker: false,
        root: ctx.root,
        home: ctx.home.clone(),
    }
}

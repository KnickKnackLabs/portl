use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde::Serialize;

mod apply;
mod detect;
mod render;
mod resolve;

use self::apply::{apply_install_target, set_mode_0755, validate_install_target};
use self::detect::{DetectionContext, detect_host_with};
use self::render::{AgentEnv, render_env_file, render_target, systemd_env_file_path};
use self::resolve::{
    install_binary_path, install_service_path, resolve_output_dir, resolve_target,
};

#[cfg(test)]
use self::render::{render_launchd_plist, render_systemd_unit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
pub enum InstallTarget {
    Systemd,
    Launchd,
    Dockerfile,
    Openrc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectResult {
    pub matched: Option<InstallTarget>,
    pub reason: String,
    pub inside_docker: bool,
    pub root: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<PathBuf>,
}

pub type DetectMatch = InstallTarget;

pub fn detect_host() -> DetectResult {
    detect_host_with(&DetectionContext::from_host())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn run(
    target: Option<InstallTarget>,
    apply: bool,
    yes: bool,
    detect: bool,
    dry_run: bool,
    output: Option<&Path>,
) -> Result<ExitCode> {
    let detect_result = detect_host();
    if detect {
        println!("{}", serde_json::to_string_pretty(&detect_result)?);
        return Ok(ExitCode::SUCCESS);
    }

    let target = resolve_target(target, &detect_result)?;
    let output = resolve_output_dir(target, output)?;
    let binary_path = install_binary_path(
        target,
        detect_result.root,
        detect_result.home.as_deref(),
        output.as_deref(),
    )?;
    let service_path = install_service_path(
        target,
        detect_result.root,
        detect_result.home.as_deref(),
        output.as_deref(),
    )?;
    let agent_env = load_agent_env();
    let rendered = render_target(
        target,
        &binary_path,
        detect_result.root,
        detect_result.home.as_deref(),
        &agent_env,
    )?;

    if dry_run || !apply {
        print!("{rendered}");
        return Ok(ExitCode::SUCCESS);
    }

    if !yes {
        bail!("`portl install --apply` requires `--yes`");
    }

    if let Some(parent) = binary_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if let Some(parent) = service_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    std::fs::copy(std::env::current_exe()?, &binary_path).with_context(|| {
        format!(
            "copy {} to {}",
            std::env::current_exe().map_or_else(
                |_| "current executable".to_owned(),
                |path| path.display().to_string(),
            ),
            binary_path.display()
        )
    })?;
    std::fs::write(&service_path, &rendered)
        .with_context(|| format!("write {}", service_path.display()))?;
    // systemd reads env from a sidecar file referenced via
    // `EnvironmentFile=-…`. Write it alongside the unit so that the
    // installed agent picks up `PORTL_TRUST_ROOTS` without the
    // operator needing to edit anything by hand.
    if matches!(target, InstallTarget::Systemd) && !agent_env.is_empty() {
        let env_path = systemd_env_file_path(detect_result.root, detect_result.home.as_deref())?;
        if let Some(parent) = env_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(&env_path, render_env_file(&agent_env))
            .with_context(|| format!("write {}", env_path.display()))?;
    }
    if matches!(target, InstallTarget::Dockerfile | InstallTarget::Openrc) {
        set_mode_0755(&binary_path)?;
    }
    if matches!(target, InstallTarget::Openrc) {
        set_mode_0755(&service_path)?;
    }
    validate_install_target(target, &service_path)?;
    apply_install_target(target, detect_result.root, &service_path)?;
    println!("installed {}", service_path.display());
    Ok(ExitCode::SUCCESS)
}

/// Load the local identity and surface its `endpoint_id` as
/// `PORTL_TRUST_ROOTS`. Missing identity (e.g. `portl install` run
/// before `portl init`) produces an empty env set plus a warning —
/// we'd rather let install proceed with an explicit "you will need
/// to configure trust roots manually" message than fail here.
fn load_agent_env() -> AgentEnv {
    use portl_core::id::store;
    match store::load(&store::default_path()) {
        Ok(identity) => AgentEnv {
            trust_roots_hex: Some(hex::encode(identity.verifying_key())),
        },
        Err(err) => {
            eprintln!(
                "warning: no local identity found ({err}); installing without \
                 PORTL_TRUST_ROOTS. The agent will reject every ticket until \
                 you run `portl init` and reinstall, or set PORTL_TRUST_ROOTS \
                 manually in the service environment."
            );
            AgentEnv::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn install_systemd_emits_valid_unit_file() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl-agent");
        std::fs::write(&binary, b"#!/bin/sh\nexit 0\n").expect("write fake binary");
        set_mode_0755(&binary).expect("chmod fake binary");

        let unit = render_systemd_unit(&binary, true, None).expect("render systemd unit");
        assert!(unit.contains(&format!("ExecStart={}", binary.display())));
        assert!(unit.contains("EnvironmentFile=-/etc/portl/agent.env"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("StartLimitBurst=5"));

        if Path::new("/usr/bin/systemd-analyze").exists()
            || Path::new("/bin/systemd-analyze").exists()
        {
            let path = dir.path().join("portl-agent.service");
            std::fs::write(&path, unit).expect("write unit");
            validate_install_target(InstallTarget::Systemd, &path).expect("verify unit");
        }
    }

    #[test]
    fn install_launchd_emits_valid_plist() {
        let plist = render_launchd_plist(
            Path::new("/usr/local/bin/portl-agent"),
            &AgentEnv::default(),
        );
        assert!(plist.contains("<string>/usr/local/bin/portl-agent</string>"));
        assert!(plist.contains("<key>SuccessfulExit</key><false/>"));
        // Empty env → no EnvironmentVariables dict emitted; the
        // plist stays minimal when we have nothing to set.
        assert!(!plist.contains("EnvironmentVariables"));

        if Path::new("/usr/bin/plutil").exists() {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("com.portl.agent.plist");
            std::fs::write(&path, plist).expect("write plist");
            validate_install_target(InstallTarget::Launchd, &path).expect("lint plist");
        }
    }

    #[test]
    fn launchd_plist_carries_trust_roots_when_set() {
        // Well-formed 32-byte hex stands in for a real endpoint_id.
        let env = AgentEnv {
            trust_roots_hex: Some("a".repeat(64)),
        };
        let plist = render_launchd_plist(Path::new("/usr/local/bin/portl-agent"), &env);
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains("<key>PORTL_TRUST_ROOTS</key>"));
        assert!(plist.contains(&format!("<string>{}</string>", "a".repeat(64))));

        // Lint via plutil where available; gates this test in local
        // macOS dev, skipped on Linux CI jobs.
        if Path::new("/usr/bin/plutil").exists() {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("com.portl.agent.plist");
            std::fs::write(&path, plist).expect("write plist");
            validate_install_target(InstallTarget::Launchd, &path)
                .expect("plutil -lint must accept the plist with env vars");
        }
    }

    #[test]
    fn systemd_env_file_renders_as_key_value_pairs() {
        let env = AgentEnv {
            trust_roots_hex: Some("b".repeat(64)),
        };
        let contents = render_env_file(&env);
        assert_eq!(contents, format!("PORTL_TRUST_ROOTS={}\n", "b".repeat(64)));

        // Root install targets /etc/portl/agent.env.
        let path = systemd_env_file_path(true, None).expect("root env path");
        assert_eq!(path, PathBuf::from("/etc/portl/agent.env"));

        // User install targets ~/.config/portl/agent.env.
        let user =
            systemd_env_file_path(false, Some(Path::new("/tmp/home"))).expect("user env path");
        assert_eq!(user, PathBuf::from("/tmp/home/.config/portl/agent.env"));
    }

    #[test]
    fn empty_env_produces_empty_env_file() {
        // Nothing to write when there's no identity yet; prevents us
        // from creating a misleading empty agent.env that might later
        // look populated.
        assert!(render_env_file(&AgentEnv::default()).is_empty());
        assert!(AgentEnv::default().is_empty());
    }

    #[test]
    fn install_refuses_to_target_systemd_inside_docker() {
        let detect = DetectResult {
            matched: None,
            reason: "inside docker".to_owned(),
            inside_docker: true,
            root: true,
            home: None,
        };
        let err = resolve_target(Some(InstallTarget::Systemd), &detect).expect_err("must refuse");
        assert!(
            err.to_string()
                .contains("refusing to target systemd inside docker")
        );
    }

    #[test]
    fn install_autodetect_picks_systemd_on_linux_user() {
        let detect = detect_host_with(&DetectionContext {
            os: "linux".to_owned(),
            has_launchctl: false,
            inside_docker: false,
            has_systemd_dir: true,
            has_openrc: false,
            root: false,
            home: Some(PathBuf::from("/tmp/test-home")),
        });
        assert_eq!(detect.matched, Some(InstallTarget::Systemd));
        assert!(!detect.root);
    }

    #[test]
    fn user_systemd_uses_user_env_file() {
        let unit = render_systemd_unit(
            Path::new("/tmp/home/.local/bin/portl-agent"),
            false,
            Some(Path::new("/tmp/home")),
        )
        .expect("render user unit");
        assert!(unit.contains("EnvironmentFile=-/tmp/home/.config/portl/agent.env"));
    }

    #[test]
    fn dockerfile_output_paths_use_requested_directory() {
        let output = Path::new("/tmp/portl-image");
        assert_eq!(
            install_binary_path(InstallTarget::Dockerfile, false, None, Some(output))
                .expect("binary path"),
            output.join("portl-agent")
        );
        assert_eq!(
            install_service_path(InstallTarget::Dockerfile, false, None, Some(output))
                .expect("service path"),
            output.join("Dockerfile")
        );
    }
}

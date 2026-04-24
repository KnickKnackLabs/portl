use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::release_binary;

use super::DEFAULT_NETWORK;
use super::run::platform_matches;
use super::types::{BinarySource, ContainerSnapshot};

pub(super) trait BakeOps {
    fn current_exe(&self) -> Result<PathBuf>;
    fn inspect_image(&self, image: &str) -> Result<ImageMetadata>;
    fn build_image(&self, context_dir: &Path, tag: &str) -> Result<()>;
    fn push_image(&self, tag: &str) -> Result<()>;
}

pub(super) struct RealBakeOps;

impl BakeOps for RealBakeOps {
    fn current_exe(&self) -> Result<PathBuf> {
        std::env::current_exe().context("resolve current executable")
    }

    fn inspect_image(&self, image: &str) -> Result<ImageMetadata> {
        let output = ProcessCommand::new("docker")
            .args(["image", "inspect", image])
            .output()
            .context("run docker image inspect")?;
        if !output.status.success() {
            bail!(
                "docker image inspect {image} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let inspected: Vec<DockerImageInspect> =
            serde_json::from_slice(&output.stdout).context("decode docker image inspect")?;
        let inspected = inspected
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("docker image inspect returned no rows for {image}"))?;
        Ok(ImageMetadata {
            entrypoint: inspected.config.entrypoint,
            cmd: inspected.config.cmd,
            os: inspected.os,
            architecture: inspected.architecture,
        })
    }

    fn build_image(&self, context_dir: &Path, tag: &str) -> Result<()> {
        let status = ProcessCommand::new("docker")
            .args(["build", "-t", tag])
            .arg(context_dir)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("run docker build")?;
        if status.success() {
            Ok(())
        } else {
            bail!("docker build failed for tag {tag}")
        }
    }

    fn push_image(&self, tag: &str) -> Result<()> {
        let status = ProcessCommand::new("docker")
            .args(["push", tag])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("run docker push")?;
        if status.success() {
            Ok(())
        } else {
            bail!("docker push failed for tag {tag}")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImageMetadata {
    pub(super) entrypoint: Vec<String>,
    pub(super) cmd: Vec<String>,
    pub(super) os: Option<String>,
    pub(super) architecture: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DockerImageInspect {
    #[serde(rename = "Architecture")]
    architecture: Option<String>,
    #[serde(rename = "Config")]
    config: DockerImageConfig,
    #[serde(rename = "Os")]
    os: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DockerImageConfig {
    #[serde(rename = "Entrypoint", default)]
    pub(super) entrypoint: Vec<String>,
    #[serde(rename = "Cmd", default)]
    pub(super) cmd: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BakeContext {
    pub(super) dockerfile: String,
    pub(super) wrapper: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn bake_with<O: BakeOps>(
    ops: &O,
    base_image: &str,
    output: Option<&Path>,
    tag: Option<&str>,
    push: bool,
    init_shim: bool,
    binary_source: &BinarySource,
    session_provider: Option<&str>,
) -> Result<()> {
    if push && tag.is_none() {
        bail!("`--push` requires `--tag <image>`");
    }
    if output.is_none() && tag.is_none() {
        bail!("choose either `--output DIR` or `--tag <image>` for `portl docker bake`");
    }

    validate_session_provider(session_provider)?;
    let metadata = ops.inspect_image(base_image)?;
    let binary = resolve_bake_binary(ops, binary_source, &metadata, base_image)?;
    let zmx_binary = resolve_zmx_binary(session_provider);
    let context = render_bake_context(base_image, Some(&metadata), init_shim, session_provider)?;

    let owned_output;
    let context_dir = if let Some(output) = output {
        output.to_path_buf()
    } else {
        owned_output = temp_bake_dir()?;
        owned_output
    };
    write_bake_context(&context_dir, &context, &binary, zmx_binary.as_deref())?;

    if let Some(tag) = tag {
        ops.build_image(&context_dir, tag)?;
        if push {
            ops.push_image(tag)?;
        }
    }

    Ok(())
}

pub(super) fn render_bake_context(
    base_image: &str,
    metadata: Option<&ImageMetadata>,
    init_shim: bool,
    session_provider: Option<&str>,
) -> Result<BakeContext> {
    let provider_dockerfile = session_provider_dockerfile(session_provider)?;
    if !init_shim {
        return Ok(BakeContext {
            dockerfile: format!(
                "FROM {base_image}\nCOPY portl-agent /usr/local/bin/portl-agent\nRUN chmod +x /usr/local/bin/portl-agent\n{provider_dockerfile}"
            ),
            wrapper: None,
        });
    }

    let metadata = metadata.ok_or_else(|| anyhow!("init shim requires image metadata"))?;
    let wrapper = render_init_shim(metadata);
    let mut dockerfile = format!(
        "FROM {base_image}\nCOPY portl-agent /usr/local/bin/portl-agent\nCOPY portl-init-shim /usr/local/bin/portl-init-shim\nRUN chmod +x /usr/local/bin/portl-agent /usr/local/bin/portl-init-shim\n{provider_dockerfile}ENTRYPOINT [\"/usr/local/bin/portl-init-shim\"]\n"
    );
    if !metadata.cmd.is_empty() {
        writeln!(dockerfile, "CMD {}", serde_json::to_string(&metadata.cmd)?)
            .expect("writing to String cannot fail");
    }

    Ok(BakeContext {
        dockerfile,
        wrapper: Some(wrapper),
    })
}

fn validate_session_provider(session_provider: Option<&str>) -> Result<()> {
    match session_provider {
        None | Some("zmx") => Ok(()),
        Some(other) => bail!("unsupported session provider '{other}' (supported: zmx)"),
    }
}

fn resolve_zmx_binary(session_provider: Option<&str>) -> Option<PathBuf> {
    if session_provider != Some("zmx") {
        return None;
    }
    std::env::var_os("PORTL_ZMX_BINARY").map(PathBuf::from)
}

fn session_provider_dockerfile(session_provider: Option<&str>) -> Result<String> {
    match session_provider {
        None => Ok(String::new()),
        Some("zmx") if std::env::var_os("PORTL_ZMX_BINARY").is_some() => Ok(
            "COPY zmx /usr/local/bin/zmx\nRUN chmod +x /usr/local/bin/zmx\nENV PORTL_SESSION_PROVIDER=zmx PORTL_SESSION_PROVIDER_PATH=/usr/local/bin/zmx\n"
                .to_owned(),
        ),
        Some("zmx") => Ok(
            "RUN command -v zmx >/dev/null 2>&1 || { echo 'zmx is not installed; set PORTL_ZMX_BINARY or use a zmx-enabled base image' >&2; exit 127; }\nENV PORTL_SESSION_PROVIDER=zmx\n"
                .to_owned(),
        ),
        Some(other) => bail!("unsupported session provider '{other}' (supported: zmx)"),
    }
}

pub(super) fn render_init_shim(metadata: &ImageMetadata) -> String {
    let target = if metadata.entrypoint.is_empty() {
        "exec \"$@\"".to_owned()
    } else {
        let quoted = metadata
            .entrypoint
            .iter()
            .map(|part| shell_quote(part))
            .collect::<Vec<_>>()
            .join(" ");
        format!("exec {quoted} \"$@\"")
    };
    format!("#!/bin/sh\n/usr/local/bin/portl-agent & {target}\n")
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) fn resolve_bake_binary<O: BakeOps>(
    ops: &O,
    source: &BinarySource,
    metadata: &ImageMetadata,
    base_image: &str,
) -> Result<PathBuf> {
    let target = ContainerSnapshot {
        id: String::new(),
        name: base_image.to_owned(),
        image: base_image.to_owned(),
        network: DEFAULT_NETWORK.to_owned(),
        running: false,
        pid: None,
        target_os: metadata.os.clone(),
        target_arch: metadata.architecture.clone(),
    };
    match source {
        BinarySource::ExplicitPath(path) => Ok(path.clone()),
        BinarySource::ReleaseTag(tag) => release_binary::download_release_binary(
            tag,
            target.target_os.as_deref().unwrap_or("unknown"),
            target.target_arch.as_deref().unwrap_or("unknown"),
        ),
        BinarySource::CurrentExecutable => {
            if !platform_matches(std::env::consts::OS, std::env::consts::ARCH, &target) {
                bail!(
                    "image '{}' targets {}/{}, but the running CLI is {}/{}; pass --from-release <tag> or --from-binary <path>",
                    base_image,
                    target.target_os.as_deref().unwrap_or("unknown"),
                    target.target_arch.as_deref().unwrap_or("unknown"),
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                );
            }
            ops.current_exe()
        }
    }
}

pub(super) fn write_bake_context(
    context_dir: &Path,
    context: &BakeContext,
    binary: &Path,
    zmx_binary: Option<&Path>,
) -> Result<()> {
    fs::create_dir_all(context_dir)
        .with_context(|| format!("create bake context {}", context_dir.display()))?;
    fs::write(context_dir.join("Dockerfile"), &context.dockerfile)
        .with_context(|| format!("write Dockerfile in {}", context_dir.display()))?;
    fs::copy(binary, context_dir.join("portl-agent")).with_context(|| {
        format!(
            "copy {} into {}",
            binary.display(),
            context_dir.join("portl-agent").display()
        )
    })?;
    if let Some(zmx_binary) = zmx_binary {
        fs::copy(zmx_binary, context_dir.join("zmx")).with_context(|| {
            format!(
                "copy {} into {}",
                zmx_binary.display(),
                context_dir.join("zmx").display()
            )
        })?;
    }
    if let Some(wrapper) = &context.wrapper {
        fs::write(context_dir.join("portl-init-shim"), wrapper)
            .with_context(|| format!("write {}", context_dir.join("portl-init-shim").display()))?;
    }
    Ok(())
}

pub(super) fn temp_bake_dir() -> Result<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("portl-docker-bake-{unique}"));
    fs::create_dir_all(&path)
        .with_context(|| format!("create temp bake dir {}", path.display()))?;
    Ok(path)
}

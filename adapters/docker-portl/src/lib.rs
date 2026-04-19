use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::errors::Error as DockerError;
use bollard::image::CreateImageOptions;
use bollard::models::{ContainerInspectResponse, HostConfig};
use bollard::secret::ContainerStateStatusEnum;
use futures_util::stream::TryStreamExt;
use portl_core::bootstrap::{Bootstrapper, Handle, TargetSpec, TargetStatus};
use portl_core::id::{Identity, store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

pub const ADAPTER_NAME: &str = "docker-portl";
pub const DEFAULT_NETWORK: &str = "bridge";
pub const SECRET_MOUNT_PATH: &str = "/var/lib/portl/secret";
pub const CONFIG_MOUNT_PATH: &str = "/etc/portl/agent.toml";

#[derive(Clone)]
pub struct DockerBootstrapper {
    docker: Docker,
    trust_roots: Vec<[u8; 32]>,
}

impl DockerBootstrapper {
    pub fn new(docker: Docker, trust_roots: Vec<[u8; 32]>) -> Self {
        Self {
            docker,
            trust_roots,
        }
    }

    pub fn connect_with_local_defaults(trust_roots: Vec<[u8; 32]>) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults().context("connect to docker daemon")?;
        Ok(Self::new(docker, trust_roots))
    }

    pub fn docker(&self) -> &Docker {
        &self.docker
    }
}

#[async_trait]
impl Bootstrapper for DockerBootstrapper {
    async fn provision(&self, spec: &TargetSpec) -> Result<Handle> {
        validate_spec(spec)?;

        let identity = Identity::new();
        let endpoint_id = hex::encode(identity.endpoint_id().as_bytes());
        let secret_path = temp_artifact_path("portl-secret", &endpoint_id);
        let config_path = temp_artifact_path("portl-agent", &endpoint_id);
        store::save(&identity, &secret_path)
            .with_context(|| format!("write secret to {}", secret_path.display()))?;
        fs::write(&config_path, render_agent_config(&self.trust_roots)?)
            .with_context(|| format!("write config to {}", config_path.display()))?;

        let cleanup = CleanupPaths {
            secret_path: secret_path.clone(),
            config_path: config_path.clone(),
        };

        if let Err(err) = self.pull_image(&spec.image).await {
            cleanup.best_effort();
            return Err(err);
        }

        let labels = docker_labels(spec, &endpoint_id);
        let binds = docker_binds(&secret_path, &config_path);
        let host_config = HostConfig {
            binds: Some(binds),
            network_mode: Some(spec.network.clone()),
            ..HostConfig::default()
        };
        let config = Config {
            image: Some(spec.image.clone()),
            labels: Some(labels),
            host_config: Some(host_config),
            cmd: Some(vec!["--config".to_owned(), CONFIG_MOUNT_PATH.to_owned()]),
            ..Config::default()
        };

        let options = Some(CreateContainerOptions {
            name: spec.name.clone(),
            platform: None,
        });
        let response = match self.docker.create_container(options, config).await {
            Ok(response) => response,
            Err(err) => {
                cleanup.best_effort();
                return Err(err).context("create docker container");
            }
        };
        let container_id = response.id;

        if let Err(err) = self
            .docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await
            .context("start docker container")
        {
            let _ = self.teardown_container(&container_id).await;
            cleanup.best_effort();
            return Err(err);
        }

        if let Err(err) = self.wait_for_running(&container_id).await {
            let _ = self.teardown_container(&container_id).await;
            cleanup.best_effort();
            return Err(err);
        }

        if let Err(err) = fs::remove_file(&secret_path) {
            warn!(?err, path = %secret_path.display(), "failed to remove host secret after container start");
        }

        Ok(Handle {
            adapter: ADAPTER_NAME.to_owned(),
            inner: json!(DockerHandle {
                container_id,
                endpoint_id,
                image: spec.image.clone(),
                network: spec.network.clone(),
                name: spec.name.clone(),
                config_path,
            }),
        })
    }

    async fn register(&self, handle: &Handle, endpoint_id: iroh_base::EndpointId) -> Result<()> {
        let inner = DockerHandle::from_handle(handle)?;
        let inspect = self.inspect(&inner.container_id).await?;
        let labels = inspect
            .config
            .and_then(|config| config.labels)
            .unwrap_or_default();
        let actual = labels
            .get("portl.endpoint_id")
            .context("container missing portl.endpoint_id label")?;
        let expected = hex::encode(endpoint_id.as_bytes());
        if actual != &expected {
            bail!("container label endpoint id mismatch: expected {expected}, found {actual}");
        }
        Ok(())
    }

    async fn resolve(&self, handle: &Handle) -> Result<TargetStatus> {
        let inner = DockerHandle::from_handle(handle)?;
        match self.inspect(&inner.container_id).await {
            Ok(inspect) => Ok(map_target_status(inspect)),
            Err(err) if is_not_found_anyhow(&err) => Ok(TargetStatus::NotFound),
            Err(err) => Err(err),
        }
    }

    async fn teardown(&self, handle: &Handle) -> Result<()> {
        let inner = DockerHandle::from_handle(handle)?;
        if let Err(err) = self.teardown_container(&inner.container_id).await
            && !is_not_found_anyhow(&err)
        {
            return Err(err);
        }
        if let Err(err) = fs::remove_file(&inner.config_path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            warn!(?err, path = %inner.config_path.display(), "failed to remove docker adapter config file");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerHandle {
    pub container_id: String,
    pub endpoint_id: String,
    pub image: String,
    pub network: String,
    pub name: String,
    pub config_path: PathBuf,
}

impl DockerHandle {
    pub fn from_handle(handle: &Handle) -> Result<Self> {
        if handle.adapter != ADAPTER_NAME {
            bail!(
                "expected adapter handle for {ADAPTER_NAME}, found {}",
                handle.adapter
            );
        }
        serde_json::from_value(handle.inner.clone()).context("decode docker adapter handle")
    }
}

impl DockerBootstrapper {
    async fn pull_image(&self, image: &str) -> Result<()> {
        if self.docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }

        let options = Some(CreateImageOptions {
            from_image: normalize_image(image),
            ..CreateImageOptions::default()
        });
        let mut stream = self.docker.create_image(options, None, None);
        while stream.try_next().await.context("pull image")?.is_some() {}
        Ok(())
    }

    async fn wait_for_running(&self, container_id: &str) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let inspect = self.inspect(container_id).await?;
            let running = inspect
                .state
                .as_ref()
                .and_then(|state| state.running)
                .unwrap_or(false);
            if running {
                // The agent process starts immediately after docker marks the
                // container running, but the iroh endpoint needs a moment to
                // bind and publish. A fixed 1 s delay keeps the adapter simple
                // and is exercised by the M4 smoke test.
                tokio::time::sleep(Duration::from_secs(1)).await;
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("timed out waiting for container {container_id} to reach running state");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn inspect(&self, container_id: &str) -> Result<ContainerInspectResponse> {
        self.docker
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
            .with_context(|| format!("inspect docker container {container_id}"))
    }

    async fn teardown_container(&self, container_id: &str) -> Result<()> {
        if let Err(err) = self
            .docker
            .stop_container(container_id, Some(StopContainerOptions { t: 10 }))
            .await
            && !is_not_found_docker(&err)
        {
            return Err(err).with_context(|| format!("stop docker container {container_id}"));
        }
        self.docker
            .remove_container(
                container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..RemoveContainerOptions::default()
                }),
            )
            .await
            .with_context(|| format!("remove docker container {container_id}"))
    }

    pub async fn list_portl_containers(&self) -> Result<Vec<DockerHandle>> {
        let filters = HashMap::from([(
            "label".to_owned(),
            vec![format!("portl.adapter={ADAPTER_NAME}")],
        )]);
        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true,
                filters,
                ..ListContainersOptions::default()
            }))
            .await
            .context("list docker containers")?;

        let mut handles = Vec::with_capacity(containers.len());
        for container in containers {
            let labels = container.labels.unwrap_or_default();
            let Some(endpoint_id) = labels.get("portl.endpoint_id") else {
                continue;
            };
            let Some(image) = container.image else {
                continue;
            };
            let Some(id) = container.id else {
                continue;
            };
            let name = container
                .names
                .unwrap_or_default()
                .into_iter()
                .find_map(|name| name.strip_prefix('/').map(str::to_owned))
                .unwrap_or_else(|| id.clone());
            handles.push(DockerHandle {
                container_id: id,
                endpoint_id: endpoint_id.clone(),
                image,
                network: DEFAULT_NETWORK.to_owned(),
                name,
                config_path: PathBuf::new(),
            });
        }
        Ok(handles)
    }
}

fn validate_spec(spec: &TargetSpec) -> Result<()> {
    if spec.network == "none" {
        bail!("docker network mode 'none' is not supported for portl targets");
    }
    if spec.name.trim().is_empty() {
        bail!("container name must not be empty");
    }
    if spec.image.trim().is_empty() {
        bail!("container image must not be empty");
    }
    Ok(())
}

fn map_target_status(inspect: ContainerInspectResponse) -> TargetStatus {
    let Some(state) = inspect.state else {
        return TargetStatus::Unknown("missing state".to_owned());
    };
    match state.status {
        Some(ContainerStateStatusEnum::RUNNING) => TargetStatus::Running,
        Some(ContainerStateStatusEnum::EXITED) => TargetStatus::Exited {
            code: exit_code_to_i32(state.exit_code.unwrap_or_default()),
        },
        Some(other) => TargetStatus::Unknown(other.to_string()),
        None => TargetStatus::Unknown("missing status".to_owned()),
    }
}

fn exit_code_to_i32(code: i64) -> i32 {
    i32::try_from(code).unwrap_or_else(|_| {
        if code.is_negative() {
            i32::MIN
        } else {
            i32::MAX
        }
    })
}

fn render_agent_config(trust_roots: &[[u8; 32]]) -> Result<String> {
    if trust_roots.is_empty() {
        bail!("docker bootstrapper requires at least one trust root");
    }
    let trust_roots = trust_roots
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        "identity_path = \"{SECRET_MOUNT_PATH}\"\nrevocations_path = \"/var/lib/portl/revocations.json\"\nbind_addr = \"0.0.0.0:0\"\ndiscovery = {{ dns = false, pkarr = true, local = true }}\ntrust_roots = [{}]\n",
        trust_roots
            .split(", ")
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

fn docker_labels(spec: &TargetSpec, endpoint_id: &str) -> HashMap<String, String> {
    let mut labels = HashMap::from([
        ("portl.adapter".to_owned(), ADAPTER_NAME.to_owned()),
        ("portl.endpoint_id".to_owned(), endpoint_id.to_owned()),
    ]);
    for (key, value) in &spec.labels {
        labels.insert(key.clone(), value.clone());
    }
    labels
}

fn docker_binds(secret_path: &Path, config_path: &Path) -> Vec<String> {
    vec![
        format!("{}:{SECRET_MOUNT_PATH}:ro", secret_path.display()),
        format!("{}:{CONFIG_MOUNT_PATH}:ro", config_path.display()),
    ]
}

fn normalize_image(image: &str) -> String {
    if image.contains('@') {
        return image.to_owned();
    }

    let last_segment = image.rsplit('/').next().unwrap_or(image);
    if last_segment.contains(':') {
        image.to_owned()
    } else {
        format!("{image}:latest")
    }
}

fn temp_artifact_path(prefix: &str, endpoint_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{endpoint_id}"))
}

fn is_not_found_anyhow(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<DockerError>())
        .any(is_not_found_docker)
}

fn is_not_found_docker(err: &DockerError) -> bool {
    match err {
        DockerError::DockerResponseServerError { status_code, .. } => *status_code == 404,
        _ => err.to_string().contains("No such container"),
    }
}

struct CleanupPaths {
    secret_path: PathBuf,
    config_path: PathBuf,
}

impl CleanupPaths {
    fn best_effort(&self) {
        for path in [&self.secret_path, &self.config_path] {
            if let Err(err) = fs::remove_file(path)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                warn!(?err, path = %path.display(), "failed to clean up docker adapter temp file");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use portl_core::ticket::schema::Capabilities;

    use super::{
        ADAPTER_NAME, CONFIG_MOUNT_PATH, DEFAULT_NETWORK, SECRET_MOUNT_PATH, docker_binds,
        docker_labels, normalize_image, render_agent_config,
    };
    use portl_core::bootstrap::TargetSpec;

    fn empty_caps() -> Capabilities {
        Capabilities {
            presence: 0,
            shell: None,
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
        }
    }

    #[test]
    fn label_builder_includes_portl_labels_and_user_labels() {
        let spec = TargetSpec {
            name: "demo".to_owned(),
            image: "portl-agent".to_owned(),
            network: DEFAULT_NETWORK.to_owned(),
            caps: empty_caps(),
            ttl_secs: 60,
            to: None,
            labels: vec![("com.example.demo".to_owned(), "true".to_owned())],
        };

        let labels = docker_labels(&spec, "abc123");

        assert_eq!(labels.get("portl.adapter"), Some(&ADAPTER_NAME.to_owned()));
        assert_eq!(labels.get("portl.endpoint_id"), Some(&"abc123".to_owned()));
        assert_eq!(labels.get("com.example.demo"), Some(&"true".to_owned()));
    }

    #[test]
    fn bind_builder_mounts_secret_and_config_read_only() {
        let binds = docker_binds(Path::new("/tmp/secret"), Path::new("/tmp/agent.toml"));

        assert_eq!(
            binds,
            vec![
                format!("/tmp/secret:{SECRET_MOUNT_PATH}:ro"),
                format!("/tmp/agent.toml:{CONFIG_MOUNT_PATH}:ro"),
            ]
        );
    }

    #[test]
    fn image_normalization_adds_latest_tag_when_missing() {
        assert_eq!(normalize_image("portl-agent"), "portl-agent:latest");
        assert_eq!(normalize_image("portl-agent:local"), "portl-agent:local");
        assert_eq!(
            normalize_image("ghcr.io/example/portl-agent@sha256:deadbeef"),
            "ghcr.io/example/portl-agent@sha256:deadbeef"
        );
    }

    #[test]
    fn rendered_agent_config_lists_trust_roots() {
        let config = render_agent_config(&[[7; 32]]).expect("render config");
        assert!(config.contains("identity_path = \"/var/lib/portl/secret\""));
        assert!(config.contains("bind_addr = \"0.0.0.0:0\""));
        assert!(config.contains("discovery = { dns = false, pkarr = true, local = true }"));
        assert!(config.contains(&hex::encode([7; 32])));
    }
}

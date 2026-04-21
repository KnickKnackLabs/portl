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
use bollard::models::{ContainerInspectResponse, HostConfig, RestartPolicy, RestartPolicyNameEnum};
use bollard::secret::ContainerStateStatusEnum;
use futures_util::stream::TryStreamExt;
use portl_core::bootstrap::{Bootstrapper, Handle, ProvisionSpec, TargetStatus};
use portl_core::id::{Identity, store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

pub const ADAPTER_NAME: &str = "docker-portl";
pub const DEFAULT_NETWORK: &str = "bridge";
pub const PORTL_HOME_IN_CONTAINER: &str = "/var/lib/portl";
pub const SECRET_MOUNT_PATH: &str = "/var/lib/portl/identity.bin";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DockerProvisionParams {
    image: String,
    network: String,
    #[serde(default)]
    rm_existing: bool,
}

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
    async fn provision(&self, spec: &ProvisionSpec) -> Result<Handle> {
        let params = parse_adapter_params(&spec.adapter_params)?;
        validate_spec(spec, &params)?;

        let identity = Identity::new();
        let endpoint_id = hex::encode(identity.endpoint_id().as_bytes());
        let secret_path = temp_artifact_path("portl-secret", &endpoint_id);
        store::save(&identity, &secret_path)
            .with_context(|| format!("write secret to {}", secret_path.display()))?;

        let cleanup = CleanupPaths {
            secret_path: secret_path.clone(),
        };

        if let Err(err) = self.pull_image(&params.image).await {
            cleanup.best_effort();
            return Err(err);
        }

        let labels = docker_labels(spec, &endpoint_id);
        let binds = docker_binds(&secret_path);
        let config = build_container_config(&params, labels, binds, &self.trust_roots)?;

        let options = Some(CreateContainerOptions {
            name: spec.name.clone(),
            platform: None,
        });
        let response = match self
            .docker
            .create_container(options.clone(), config.clone())
            .await
        {
            Ok(response) => response,
            Err(err) if is_conflict_docker(&err) && params.rm_existing => {
                self.teardown_container(&spec.name)
                    .await
                    .with_context(|| format!("remove existing container {}", spec.name))?;
                self.docker
                    .create_container(options, config)
                    .await
                    .context("create docker container after removing existing one")?
            }
            Err(err) if is_conflict_docker(&err) => {
                cleanup.best_effort();
                bail!(
                    "container '{}' already exists; remove it first with `portl docker container rm {}` or pass --rm-existing",
                    spec.name,
                    spec.name
                );
            }
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
                image: params.image.clone(),
                network: params.network.clone(),
                name: spec.name.clone(),
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
                // container running, but the iroh endpoint may need a moment to
                // bind and publish. Keep the readiness grace period short so
                // CLI follow-up operations can probe the endpoint promptly.
                tokio::time::sleep(Duration::from_millis(500)).await;
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
            let network = container
                .network_settings
                .as_ref()
                .and_then(|settings| settings.networks.as_ref())
                .and_then(|networks| networks.keys().next().cloned())
                .unwrap_or_else(|| DEFAULT_NETWORK.to_owned());
            handles.push(DockerHandle {
                container_id: id,
                endpoint_id: endpoint_id.clone(),
                image,
                network,
                name,
            });
        }
        Ok(handles)
    }
}

fn parse_adapter_params(adapter_params: &serde_json::Value) -> Result<DockerProvisionParams> {
    serde_json::from_value(adapter_params.clone()).context(
        "docker adapter_params must be an object like {\"image\":\"...\",\"network\":\"...\"}",
    )
}

fn validate_spec(spec: &ProvisionSpec, params: &DockerProvisionParams) -> Result<()> {
    if params.network == "none" {
        bail!("docker network mode 'none' is not supported for portl targets");
    }
    if spec.name.trim().is_empty() {
        bail!("container name must not be empty");
    }
    if params.image.trim().is_empty() {
        bail!("container image must not be empty");
    }
    if params.network.trim().is_empty() {
        bail!("container network must not be empty");
    }
    Ok(())
}

fn map_target_status(inspect: ContainerInspectResponse) -> TargetStatus {
    let Some(state) = inspect.state else {
        return TargetStatus::Unknown("missing state".to_owned());
    };
    match state.status {
        Some(ContainerStateStatusEnum::CREATED | ContainerStateStatusEnum::RESTARTING) => {
            TargetStatus::Provisioning
        }
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

fn build_container_config(
    params: &DockerProvisionParams,
    labels: HashMap<String, String>,
    binds: Vec<String>,
    trust_roots: &[[u8; 32]],
) -> Result<Config<String>> {
    let host_config = HostConfig {
        binds: Some(binds),
        network_mode: Some(params.network.clone()),
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        }),
        ..HostConfig::default()
    };

    Ok(Config {
        image: Some(params.image.clone()),
        labels: Some(labels),
        host_config: Some(host_config),
        entrypoint: Some(vec![
            "portl".to_owned(),
            "agent".to_owned(),
            "run".to_owned(),
        ]),
        env: Some(agent_env(trust_roots)?),
        ..Config::default()
    })
}

fn docker_labels(spec: &ProvisionSpec, endpoint_id: &str) -> HashMap<String, String> {
    let mut labels = HashMap::from([
        ("portl.adapter".to_owned(), ADAPTER_NAME.to_owned()),
        ("portl.endpoint_id".to_owned(), endpoint_id.to_owned()),
    ]);
    for (key, value) in &spec.labels {
        labels.insert(key.clone(), value.clone());
    }
    labels
}

fn agent_env(trust_roots: &[[u8; 32]]) -> Result<Vec<String>> {
    if trust_roots.is_empty() {
        bail!("docker bootstrapper requires at least one trust root");
    }
    Ok(vec![
        format!("PORTL_HOME={PORTL_HOME_IN_CONTAINER}"),
        format!(
            "PORTL_TRUST_ROOTS={}",
            trust_roots
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(",")
        ),
        "PORTL_DISCOVERY=pkarr,local".to_owned(),
    ])
}

fn docker_binds(secret_path: &Path) -> Vec<String> {
    vec![format!("{}:{SECRET_MOUNT_PATH}:ro", secret_path.display())]
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

fn is_conflict_docker(err: &DockerError) -> bool {
    matches!(
        err,
        DockerError::DockerResponseServerError {
            status_code: 409,
            ..
        }
    )
}

struct CleanupPaths {
    secret_path: PathBuf,
}

impl CleanupPaths {
    fn best_effort(&self) {
        if let Err(err) = fs::remove_file(&self.secret_path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            warn!(?err, path = %self.secret_path.display(), "failed to clean up docker adapter temp file");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use portl_core::bootstrap::ProvisionSpec;
    use serde_json::json;

    use super::{
        ADAPTER_NAME, DEFAULT_NETWORK, DockerProvisionParams, PORTL_HOME_IN_CONTAINER,
        SECRET_MOUNT_PATH, agent_env, build_container_config, docker_binds, docker_labels,
        normalize_image, parse_adapter_params,
    };

    #[test]
    fn label_builder_includes_portl_labels_and_user_labels() {
        let spec = ProvisionSpec {
            name: "demo".to_owned(),
            adapter_params: json!({
                "image": "portl-agent",
                "network": DEFAULT_NETWORK,
            }),
            labels: vec![("com.example.demo".to_owned(), "true".to_owned())],
        };

        let labels = docker_labels(&spec, "abc123");

        assert_eq!(labels.get("portl.adapter"), Some(&ADAPTER_NAME.to_owned()));
        assert_eq!(labels.get("portl.endpoint_id"), Some(&"abc123".to_owned()));
        assert_eq!(labels.get("com.example.demo"), Some(&"true".to_owned()));
    }

    #[test]
    fn docker_adapter_params_parse_expected_object() {
        let params = parse_adapter_params(&json!({
            "image": "portl-agent:latest",
            "network": "bridge",
        }))
        .expect("parse params");

        assert_eq!(params.image, "portl-agent:latest");
        assert_eq!(params.network, "bridge");
        assert!(!params.rm_existing);
    }

    #[test]
    fn docker_adapter_params_reject_invalid_shape() {
        let err = parse_adapter_params(&json!("portl-agent:latest")).expect_err("reject string");
        assert!(
            err.to_string()
                .contains("docker adapter_params must be an object")
        );
    }

    #[test]
    fn docker_adapter_params_parse_rm_existing_flag() {
        let params = parse_adapter_params(&json!({
            "image": "portl-agent:latest",
            "network": "bridge",
            "rm_existing": true,
        }))
        .expect("parse params");

        assert!(params.rm_existing);
    }

    #[test]
    fn container_config_sets_entrypoint_cmd_and_restart_policy() {
        let config = build_container_config(
            &DockerProvisionParams {
                image: "portl-agent:latest".to_owned(),
                network: DEFAULT_NETWORK.to_owned(),
                rm_existing: false,
            },
            docker_labels(
                &ProvisionSpec {
                    name: "demo".to_owned(),
                    adapter_params: json!({
                        "image": "portl-agent:latest",
                        "network": DEFAULT_NETWORK,
                    }),
                    labels: vec![],
                },
                "endpoint-1",
            ),
            docker_binds(Path::new("/tmp/secret")),
            &[[7; 32]],
        )
        .expect("build container config");

        assert_eq!(
            config.entrypoint,
            Some(vec![
                "portl".to_owned(),
                "agent".to_owned(),
                "run".to_owned()
            ])
        );
        assert_eq!(
            config.env,
            Some(vec![
                format!("PORTL_HOME={PORTL_HOME_IN_CONTAINER}"),
                format!("PORTL_TRUST_ROOTS={}", hex::encode([7; 32])),
                "PORTL_DISCOVERY=pkarr,local".to_owned(),
            ])
        );
        assert_eq!(
            config
                .host_config
                .and_then(|host| host.restart_policy)
                .and_then(|policy| policy.name),
            Some(bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED)
        );
    }

    #[test]
    fn bind_builder_mounts_secret_read_only() {
        let binds = docker_binds(Path::new("/tmp/secret"));

        assert_eq!(binds, vec![format!("/tmp/secret:{SECRET_MOUNT_PATH}:ro")]);
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
    fn agent_env_lists_trust_roots() {
        let env = agent_env(&[[7; 32]]).expect("build agent env");
        assert!(env.contains(&format!("PORTL_HOME={PORTL_HOME_IN_CONTAINER}")));
        assert!(env.contains(&format!("PORTL_TRUST_ROOTS={}", hex::encode([7; 32]))));
        assert!(env.contains(&"PORTL_DISCOVERY=pkarr,local".to_owned()));
    }
}

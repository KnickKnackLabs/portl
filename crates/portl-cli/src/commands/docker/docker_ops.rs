use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, DownloadFromContainerOptions, InspectContainerOptions,
    StartContainerOptions, UploadToContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::image::CreateImageOptions;
use bollard::system::EventsOptions;
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt, TryStreamExt};

use super::aliases::container_snapshot;
use super::run::{normalize_image, run_container_command};
use super::types::{ContainerEvent, ContainerSnapshot, ExecSnapshot, RunRuntimeSpec};

#[async_trait]
pub(super) trait DockerOps {
    async fn ensure_image(&self, image: &str) -> Result<()>;
    async fn create_container(
        &self,
        image: &str,
        name: Option<&str>,
        labels: &HashMap<String, String>,
        runtime: &RunRuntimeSpec,
    ) -> Result<String>;
    async fn start_container(&self, container: &str) -> Result<()>;
    async fn inspect_container(&self, container: &str) -> Result<ContainerSnapshot>;
    async fn copy_file(&self, source: &Path, container: &str, dest: &Path) -> Result<()>;
    async fn create_exec(
        &self,
        container: &str,
        cmd: Vec<String>,
        env: Vec<String>,
    ) -> Result<String>;
    async fn start_exec_with_logs(
        &self,
        exec_id: &str,
    ) -> Result<BoxStream<'static, Result<String>>>;
    async fn inspect_exec(&self, exec_id: &str) -> Result<ExecSnapshot>;
    async fn path_exists(&self, container: &str, path: &Path) -> Result<bool>;
    async fn run_command(&self, container: &str, cmd: Vec<String>) -> Result<()>;
    fn container_events(&self, container: &str) -> BoxStream<'static, Result<ContainerEvent>>;
}

pub(super) struct RealDockerOps {
    docker: Docker,
}

impl RealDockerOps {
    pub(super) fn connect() -> Result<Self> {
        Ok(Self {
            docker: Docker::connect_with_local_defaults().context("connect to docker daemon")?,
        })
    }
}

#[async_trait]
impl DockerOps for RealDockerOps {
    async fn ensure_image(&self, image: &str) -> Result<()> {
        if self.docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }
        let mut stream = self.docker.create_image(
            Some(CreateImageOptions {
                from_image: normalize_image(image),
                ..CreateImageOptions::default()
            }),
            None,
            None,
        );
        while stream.try_next().await.context("pull image")?.is_some() {}
        Ok(())
    }

    async fn create_container(
        &self,
        image: &str,
        name: Option<&str>,
        labels: &HashMap<String, String>,
        runtime: &RunRuntimeSpec,
    ) -> Result<String> {
        let host_config = (!runtime.volume.is_empty() || runtime.network.is_some()).then(|| {
            bollard::models::HostConfig {
                binds: (!runtime.volume.is_empty()).then_some(runtime.volume.clone()),
                network_mode: runtime.network.clone(),
                ..bollard::models::HostConfig::default()
            }
        });
        let config = Config::<String> {
            image: Some(image.to_owned()),
            labels: Some(labels.clone()),
            env: (!runtime.env.is_empty()).then_some(runtime.env.clone()),
            user: runtime.user.clone(),
            host_config,
            ..Config::default()
        };
        let options = name.map(|name| CreateContainerOptions {
            name: name.to_owned(),
            platform: None,
        });
        self.docker
            .create_container(options, config)
            .await
            .context("create docker container")
            .map(|response| response.id)
    }

    async fn start_container(&self, container: &str) -> Result<()> {
        self.docker
            .start_container(container, None::<StartContainerOptions<String>>)
            .await
            .with_context(|| format!("start docker container {container}"))
    }

    async fn inspect_container(&self, container: &str) -> Result<ContainerSnapshot> {
        let inspect = self
            .docker
            .inspect_container(container, None::<InspectContainerOptions>)
            .await
            .with_context(|| format!("inspect docker container {container}"))?;
        container_snapshot(&self.docker, inspect).await
    }

    async fn copy_file(&self, source: &Path, container: &str, dest: &Path) -> Result<()> {
        let bytes = fs::read(source).with_context(|| format!("read {}", source.display()))?;
        let metadata =
            fs::metadata(source).with_context(|| format!("stat {}", source.display()))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            header.set_mode(metadata.permissions().mode());
        }
        #[cfg(not(unix))]
        {
            header.set_mode(0o755);
        }
        header.set_cksum();
        let parent = dest.parent().unwrap_or_else(|| Path::new("/"));
        let entry_name = dest.file_name().ok_or_else(|| {
            anyhow!(
                "container path must include a file name: {}",
                dest.display()
            )
        })?;
        let mut tarball = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tarball);
            builder
                .append_data(&mut header, entry_name, bytes.as_slice())
                .with_context(|| format!("build tar entry for {}", dest.display()))?;
            builder.finish().context("finish upload tarball")?;
        }
        self.docker
            .upload_to_container(
                container,
                Some(UploadToContainerOptions {
                    path: parent.display().to_string(),
                    ..UploadToContainerOptions::default()
                }),
                Bytes::from(tarball),
            )
            .await
            .with_context(|| format!("upload {} into {}", source.display(), dest.display()))
    }

    async fn create_exec(
        &self,
        container: &str,
        cmd: Vec<String>,
        env: Vec<String>,
    ) -> Result<String> {
        self.docker
            .create_exec(
                container,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    env: Some(env),
                    cmd: Some(cmd),
                    ..CreateExecOptions::default()
                },
            )
            .await
            .with_context(|| format!("create injected exec in {container}"))
            .map(|created| created.id)
    }

    async fn start_exec_with_logs(
        &self,
        exec_id: &str,
    ) -> Result<BoxStream<'static, Result<String>>> {
        let output = self
            .docker
            .start_exec(
                exec_id,
                Some(StartExecOptions {
                    detach: false,
                    tty: false,
                    output_capacity: None,
                }),
            )
            .await
            .with_context(|| format!("start injected exec {exec_id}"))?;
        match output {
            StartExecResults::Attached { output, .. } => Ok(Box::pin(output.map(|item| {
                item.map(|line| line.to_string())
                    .map_err(anyhow::Error::from)
            }))),
            StartExecResults::Detached => {
                bail!("docker returned detached exec output for {exec_id}")
            }
        }
    }

    async fn inspect_exec(&self, exec_id: &str) -> Result<ExecSnapshot> {
        let inspect = self
            .docker
            .inspect_exec(exec_id)
            .await
            .with_context(|| format!("inspect injected exec {exec_id}"))?;
        Ok(ExecSnapshot {
            running: inspect.running.unwrap_or(false),
            pid: inspect.pid,
            exit_code: inspect.exit_code,
        })
    }

    async fn path_exists(&self, container: &str, path: &Path) -> Result<bool> {
        match self
            .docker
            .download_from_container(
                container,
                Some(DownloadFromContainerOptions {
                    path: path.display().to_string(),
                }),
            )
            .try_collect::<Vec<_>>()
            .await
        {
            Ok(_) => Ok(true),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(err) => Err(anyhow!(err)).with_context(|| {
                format!(
                    "check whether {} exists in container {container}",
                    path.display()
                )
            }),
        }
    }

    async fn run_command(&self, container: &str, cmd: Vec<String>) -> Result<()> {
        run_container_command(self, container, cmd).await
    }

    fn container_events(&self, container: &str) -> BoxStream<'static, Result<ContainerEvent>> {
        let mut filters = HashMap::new();
        filters.insert("type".to_owned(), vec!["container".to_owned()]);
        filters.insert("container".to_owned(), vec![container.to_owned()]);
        filters.insert(
            "event".to_owned(),
            vec!["die".to_owned(), "start".to_owned()],
        );
        let docker = self.docker.clone();
        Box::pin(
            docker
                .events(Some(EventsOptions::<String> {
                    since: None,
                    until: None,
                    filters,
                }))
                .map(|event| {
                    let event = event.context("stream docker events")?;
                    Ok(ContainerEvent {
                        action: event.action.unwrap_or_default(),
                    })
                }),
        )
    }
}

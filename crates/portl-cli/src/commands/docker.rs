use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, DownloadFromContainerOptions, InspectContainerOptions,
    StartContainerOptions, UploadToContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::image::CreateImageOptions;
use bollard::models::ContainerInspectResponse;
use bollard::system::EventsOptions;
use bytes::Bytes;
use docker_portl::{ADAPTER_NAME, DockerBootstrapper};
use futures_util::stream::{BoxStream, StreamExt, TryStreamExt};
use iroh_tickets::Ticket;
use portl_agent::{RevocationRecord, revocations};
use portl_core::bootstrap::{Bootstrapper, Handle, TargetStatus};
use portl_core::id::{Identity, store};
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::PortlTicket;
use serde::Deserialize;

use crate::alias_store::{AliasRecord, AliasStore, StoredSpec, now_unix_secs};
use crate::commands::mint_root::{parse_caps, parse_ttl};
use crate::release_binary;

const DEFAULT_NETWORK: &str = "bridge";
const DEFAULT_AGENT_CAPS: &str = "all";
const DEFAULT_TTL: &str = "30d";
const READY_LOG_TOKEN: &str = "portl-agent listening";
const INJECTION_PATHS: [&str; 3] = [
    "/usr/local/bin/portl-agent",
    "/tmp/portl-agent",
    "/dev/shm/portl-agent",
];

#[allow(clippy::too_many_arguments)]
pub fn run(
    image: &str,
    name: Option<&str>,
    from_binary: Option<&Path>,
    from_release: Option<&str>,
    watch: bool,
    env: &[String],
    volume: &[String],
    network: Option<&str>,
    user: Option<&str>,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let docker = RealDockerOps::connect()?;
        let host = RealHostOps;
        let binary_source = resolve_binary_source(from_binary, from_release)?;
        let runtime = RunRuntimeSpec {
            env: env.to_vec(),
            volume: volume.to_vec(),
            network: network.map(str::to_owned),
            user: user.map(str::to_owned),
        };
        let outcome = orchestrate_run(
            &docker,
            &host,
            image,
            name,
            &binary_source,
            &runtime,
            &operator,
        )
        .await?;
        save_injected_alias(&outcome)?;
        println!("{}", outcome.plan.ticket.serialize());
        if watch {
            watch_container_restarts(
                &docker,
                &host,
                &outcome.container.id,
                &binary_source,
                &operator,
            )
            .await?;
        }
        Ok(ExitCode::SUCCESS)
    })
}

pub fn attach(
    container: &str,
    from_binary: Option<&Path>,
    from_release: Option<&str>,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let docker = RealDockerOps::connect()?;
        let host = RealHostOps;
        let binary_source = resolve_binary_source(from_binary, from_release)?;
        let outcome = attach_existing(&docker, &host, container, &binary_source, &operator).await?;
        save_injected_alias(&outcome)?;
        println!("{}", outcome.plan.ticket.serialize());
        Ok(ExitCode::SUCCESS)
    })
}

pub fn detach(container: &str) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let docker = RealDockerOps::connect()?;
        detach_saved_container(&docker, &AliasStore::default(), container).await?;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn bake(
    base_image: &str,
    output: Option<&Path>,
    tag: Option<&str>,
    push: bool,
    init_shim: bool,
    from_binary: Option<&Path>,
    from_release: Option<&str>,
) -> Result<ExitCode> {
    let ops = RealBakeOps;
    let binary_source = resolve_binary_source(from_binary, from_release)?;
    bake_with(
        &ops,
        base_image,
        output,
        tag,
        push,
        init_shim,
        &binary_source,
    )?;
    Ok(ExitCode::SUCCESS)
}

pub fn list(json_output: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let bootstrapper = DockerBootstrapper::connect_with_local_defaults(Vec::new())?;
        let listed_handles = bootstrapper
            .list_portl_containers()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|handle| (handle.container_id, handle.network))
            .collect::<HashMap<_, _>>();
        let aliases = AliasStore::default().list()?;
        let rows = aliases
            .into_iter()
            .map(|alias| {
                let bootstrapper = bootstrapper.clone();
                let network = listed_handles
                    .get(&alias.container_id)
                    .cloned()
                    .unwrap_or_else(|| alias.network.clone());
                async move {
                    let handle = alias_to_handle(&alias);
                    let status = bootstrapper.resolve(&handle).await?;
                    Ok::<_, anyhow::Error>(serde_json::json!({
                        "name": alias.name,
                        "container_id": alias.container_id,
                        "endpoint_id": alias.endpoint_id,
                        "image": alias.image,
                        "network": network,
                        "status": format!("{status:?}"),
                    }))
                }
            })
            .collect::<Vec<_>>();
        let mut rendered = Vec::with_capacity(rows.len());
        for row in rows {
            rendered.push(row.await?);
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&rendered)?);
        } else if rendered.is_empty() {
            println!("No docker aliases found.");
        } else {
            println!("NAME\tSTATUS\tENDPOINT\tNETWORK\tIMAGE");
            for row in &rendered {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    row["name"].as_str().unwrap_or_default(),
                    row["status"].as_str().unwrap_or_default(),
                    row["endpoint_id"].as_str().unwrap_or_default(),
                    row["network"].as_str().unwrap_or_default(),
                    row["image"].as_str().unwrap_or_default(),
                );
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

pub fn rm(name: &str, force: bool, keep_tickets: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let store = AliasStore::default();
        let Some(alias) = resolve_alias_record(&store, name)? else {
            bail!("unknown docker alias {name}");
        };
        let spec = store
            .get_spec(&alias.name)?
            .ok_or_else(|| anyhow!("missing stored spec for docker alias {}", alias.name))?;
        let bootstrapper = DockerBootstrapper::connect_with_local_defaults(Vec::new())?;
        let handle = alias_to_handle(&alias);
        let status = bootstrapper.resolve(&handle).await?;
        ensure_rm_allowed(&alias.name, &status, force)?;

        if force || matches!(status, TargetStatus::Exited { .. }) {
            bootstrapper.teardown(&handle).await?;
        }

        if force
            && !keep_tickets
            && let Some(root_ticket_id) = spec.root_ticket_id
        {
            revoke_ticket(
                root_ticket_id,
                ticket_not_after(alias.created_at, spec.ttl_secs),
                &local_revocations_path(),
            )?;
        }

        store.remove(&alias.name)?;
        Ok(ExitCode::SUCCESS)
    })
}

#[derive(Clone)]
struct InjectionPlan {
    identity: Identity,
    ticket: PortlTicket,
    caps: portl_core::ticket::schema::Capabilities,
    ttl_secs: u64,
    endpoint_id_hex: String,
    holder: [u8; 32],
    root_ticket_id: [u8; 16],
}

#[derive(Clone)]
struct InjectionOutcome {
    container: ContainerSnapshot,
    binary_path: PathBuf,
    binary_path_preexisted: bool,
    exec_id: String,
    plan: InjectionPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerSnapshot {
    id: String,
    name: String,
    image: String,
    network: String,
    running: bool,
    pid: Option<i64>,
    target_os: Option<String>,
    target_arch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecSnapshot {
    running: bool,
    pid: Option<i64>,
    exit_code: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BinarySource {
    CurrentExecutable,
    ExplicitPath(PathBuf),
    ReleaseTag(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RunRuntimeSpec {
    env: Vec<String>,
    volume: Vec<String>,
    network: Option<String>,
    user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerEvent {
    action: String,
}

trait HostOps {
    fn current_exe(&self) -> Result<PathBuf>;
    fn host_os(&self) -> &'static str;
    fn host_arch(&self) -> &'static str;
}

struct RealHostOps;

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

#[async_trait]
trait DockerOps {
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

struct RealDockerOps {
    docker: Docker,
}

impl RealDockerOps {
    fn connect() -> Result<Self> {
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

async fn orchestrate_run<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
    image: &str,
    name: Option<&str>,
    binary_source: &BinarySource,
    runtime: &RunRuntimeSpec,
    operator: &Identity,
) -> Result<InjectionOutcome> {
    let plan = prepare_injection_plan(operator)?;
    let labels = HashMap::from([
        ("portl.adapter".to_owned(), ADAPTER_NAME.to_owned()),
        ("portl.endpoint_id".to_owned(), plan.endpoint_id_hex.clone()),
    ]);
    docker.ensure_image(image).await?;
    let container_id = docker
        .create_container(image, name, &labels, runtime)
        .await?;
    docker.start_container(&container_id).await?;
    let container = docker.inspect_container(&container_id).await?;
    inject_container(docker, host, container, binary_source, operator, plan).await
}

async fn attach_existing<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
    container: &str,
    binary_source: &BinarySource,
    operator: &Identity,
) -> Result<InjectionOutcome> {
    let snapshot = docker.inspect_container(container).await?;
    if !snapshot.running {
        bail!(
            "container '{}' is not running; start it before attaching",
            snapshot.name
        );
    }
    let plan = prepare_injection_plan(operator)?;
    inject_container(docker, host, snapshot, binary_source, operator, plan).await
}

async fn inject_container<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
    container: ContainerSnapshot,
    binary_source: &BinarySource,
    operator: &Identity,
    plan: InjectionPlan,
) -> Result<InjectionOutcome> {
    if !container.running {
        bail!(
            "container '{}' is not running; start it before attaching",
            container.name
        );
    }
    let binary = resolve_binary_path(host, binary_source, &container)?;
    let (binary_path, binary_path_preexisted) =
        copy_binary_with_fallback(docker, &binary, &container.id).await?;
    let exec_env = injected_agent_env(&plan.identity, operator);
    let exec_id = docker
        .create_exec(
            &container.id,
            vec![binary_path.display().to_string()],
            exec_env,
        )
        .await?;
    let logs = docker.start_exec_with_logs(&exec_id).await?;
    wait_for_agent_start(docker, &exec_id, logs).await?;
    Ok(InjectionOutcome {
        container,
        binary_path,
        binary_path_preexisted,
        exec_id,
        plan,
    })
}

async fn detach_saved_container<D: DockerOps>(
    docker: &D,
    store: &AliasStore,
    container: &str,
) -> Result<()> {
    let Some(alias) = resolve_alias_record(store, container)? else {
        bail!("unknown docker alias {container}");
    };
    let spec = store
        .get_spec(&alias.name)?
        .ok_or_else(|| anyhow!("missing stored spec for docker alias {}", alias.name))?;
    let exec_id = spec.docker_exec_id.as_deref().ok_or_else(|| {
        anyhow!(
            "alias {} does not have an injected exec to detach",
            alias.name
        )
    })?;

    if let Ok(exec) = docker.inspect_exec(exec_id).await
        && exec.running
        && let Some(pid) = exec.pid
    {
        docker
            .run_command(
                &alias.container_id,
                vec![
                    "/bin/sh".to_owned(),
                    "-lc".to_owned(),
                    format!("kill -TERM {pid} 2>/dev/null || true"),
                ],
            )
            .await?;
    }

    if let Some(path) = spec.docker_injected_binary_path.as_deref()
        && !spec.docker_injected_binary_preexisted
    {
        docker
            .run_command(
                &alias.container_id,
                vec![
                    "/bin/sh".to_owned(),
                    "-lc".to_owned(),
                    format!("rm -f {}", shell_quote(&path.display().to_string())),
                ],
            )
            .await?;
    }

    store.remove(&alias.name)?;
    Ok(())
}

fn prepare_injection_plan(operator: &Identity) -> Result<InjectionPlan> {
    let identity = Identity::new();
    let caps = parse_caps(DEFAULT_AGENT_CAPS)?;
    let ttl_secs = parse_ttl(DEFAULT_TTL)?;
    let holder = identity.verifying_key();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let endpoint_id = identity.endpoint_id();
    let ticket = mint_root(
        operator.signing_key(),
        iroh_base::EndpointAddr::new(endpoint_id),
        caps.clone(),
        now,
        now.checked_add(ttl_secs).context("ticket ttl overflow")?,
        Some(holder),
    )?;
    Ok(InjectionPlan {
        endpoint_id_hex: hex::encode(endpoint_id.as_bytes()),
        holder,
        root_ticket_id: ticket_id(&ticket.sig),
        identity,
        ticket,
        caps,
        ttl_secs,
    })
}

fn resolve_binary_source(
    from_binary: Option<&Path>,
    from_release: Option<&str>,
) -> Result<BinarySource> {
    match (from_binary, from_release) {
        (Some(path), None) => Ok(BinarySource::ExplicitPath(path.to_path_buf())),
        (None, Some(tag)) => Ok(BinarySource::ReleaseTag(tag.to_owned())),
        (None, None) => Ok(BinarySource::CurrentExecutable),
        (Some(_), Some(_)) => bail!("choose only one of --from-binary or --from-release"),
    }
}

fn resolve_binary_path<H: HostOps>(
    host: &H,
    source: &BinarySource,
    container: &ContainerSnapshot,
) -> Result<PathBuf> {
    let target_os = container.target_os.as_deref().unwrap_or("unknown");
    let target_arch = container.target_arch.as_deref().unwrap_or("unknown");
    match source {
        BinarySource::ExplicitPath(path) => Ok(path.clone()),
        BinarySource::ReleaseTag(tag) => {
            release_binary::download_release_binary(tag, target_os, target_arch)
        }
        BinarySource::CurrentExecutable => {
            if !platform_matches(host.host_os(), host.host_arch(), container) {
                bail!(
                    "container '{}' targets {target_os}/{target_arch}, but the running CLI is {}/{}; pass --from-release <tag>, --from-binary <linux-portl-agent>, or use `portl docker bake`",
                    container.name,
                    host.host_os(),
                    host.host_arch()
                );
            }
            host.current_exe()
        }
    }
}

fn platform_matches(host_os: &str, host_arch: &str, container: &ContainerSnapshot) -> bool {
    let Some(target_os) = container.target_os.as_deref() else {
        return true;
    };
    let Some(target_arch) = container.target_arch.as_deref() else {
        return true;
    };

    normalize_os(host_os) == normalize_os(target_os)
        && normalize_arch(host_arch) == normalize_arch(target_arch)
}

fn normalize_os(value: &str) -> &str {
    match value {
        "macos" => "darwin",
        other => other,
    }
}

fn normalize_arch(value: &str) -> &str {
    match value {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

async fn copy_binary_with_fallback<D: DockerOps>(
    docker: &D,
    binary: &Path,
    container: &str,
) -> Result<(PathBuf, bool)> {
    let mut errors = Vec::new();
    for candidate in INJECTION_PATHS.map(PathBuf::from) {
        let existed = docker.path_exists(container, &candidate).await?;
        match docker.copy_file(binary, container, &candidate).await {
            Ok(()) => return Ok((candidate, existed)),
            Err(err) => errors.push(format!("{}: {err}", candidate.display())),
        }
    }
    bail!(
        "failed to inject portl-agent into container {container}; tried {}. Use `portl docker bake` for images with an unwritable filesystem",
        errors.join("; ")
    )
}

fn injected_agent_env(identity: &Identity, operator: &Identity) -> Vec<String> {
    vec![
        format!(
            "PORTL_IDENTITY_SECRET_HEX={}",
            hex::encode(identity.signing_key().to_bytes())
        ),
        format!(
            "PORTL_TRUST_ROOTS={}",
            hex::encode(operator.verifying_key())
        ),
        "PORTL_DISCOVERY=pkarr,local".to_owned(),
        "PORTL_METRICS=0".to_owned(),
    ]
}

async fn wait_for_agent_start<D: DockerOps>(
    docker: &D,
    exec_id: &str,
    mut logs: BoxStream<'static, Result<String>>,
) -> Result<()> {
    let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        while let Some(line) = logs.next().await {
            match line {
                Ok(line) if line.contains(READY_LOG_TOKEN) => {
                    let _ = ready_tx.send(true);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        tokio::select! {
            changed = ready_rx.changed() => {
                if changed.is_ok() && *ready_rx.borrow() {
                    return Ok(());
                }
            }
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                let exec = docker.inspect_exec(exec_id).await?;
                if let Some(code) = exec.exit_code {
                    bail!("injected agent exited before becoming ready (exit code {code})");
                }
                if tokio::time::Instant::now() >= deadline {
                    bail!("injected agent did not report readiness within 5s");
                }
            }
        }
    }
}

async fn watch_container_restarts<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
    container: &str,
    binary_source: &BinarySource,
    operator: &Identity,
) -> Result<()> {
    let mut events = docker.container_events(container);
    let mut needs_reinject = false;
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("wait for ctrl-c")?;
                return Ok(());
            }
            event = events.next() => match event {
                Some(Ok(ContainerEvent { action })) => match action.as_str() {
                    "die" => needs_reinject = true,
                    "start" if needs_reinject => {
                        match attach_existing(docker, host, container, binary_source, operator).await {
                            Ok(outcome) => {
                                save_injected_alias(&outcome)?;
                                println!("{}", outcome.plan.ticket.serialize());
                                needs_reinject = false;
                            }
                            Err(err) => {
                                eprintln!("warning: failed to re-inject after container restart: {err:#}");
                            }
                        }
                    }
                    _ => {}
                },
                Some(Err(err)) => return Err(err),
                None => return Ok(()),
            }
        }
    }
}

trait BakeOps {
    fn current_exe(&self) -> Result<PathBuf>;
    fn inspect_image(&self, image: &str) -> Result<ImageMetadata>;
    fn build_image(&self, context_dir: &Path, tag: &str) -> Result<()>;
    fn push_image(&self, tag: &str) -> Result<()>;
}

struct RealBakeOps;

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
struct ImageMetadata {
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    os: Option<String>,
    architecture: Option<String>,
}

#[derive(Deserialize)]
struct DockerImageInspect {
    #[serde(rename = "Architecture")]
    architecture: Option<String>,
    #[serde(rename = "Config")]
    config: DockerImageConfig,
    #[serde(rename = "Os")]
    os: Option<String>,
}

#[derive(Deserialize)]
struct DockerImageConfig {
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Vec<String>,
    #[serde(rename = "Cmd", default)]
    cmd: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BakeContext {
    dockerfile: String,
    wrapper: Option<String>,
}

fn bake_with<O: BakeOps>(
    ops: &O,
    base_image: &str,
    output: Option<&Path>,
    tag: Option<&str>,
    push: bool,
    init_shim: bool,
    binary_source: &BinarySource,
) -> Result<()> {
    if push && tag.is_none() {
        bail!("`--push` requires `--tag <image>`");
    }
    if output.is_none() && tag.is_none() {
        bail!("choose either `--output DIR` or `--tag <image>` for `portl docker bake`");
    }

    let metadata = ops.inspect_image(base_image)?;
    let binary = resolve_bake_binary(ops, binary_source, &metadata, base_image)?;
    let context = render_bake_context(base_image, Some(&metadata), init_shim)?;

    let owned_output;
    let context_dir = if let Some(output) = output {
        output.to_path_buf()
    } else {
        owned_output = temp_bake_dir()?;
        owned_output
    };
    write_bake_context(&context_dir, &context, &binary)?;

    if let Some(tag) = tag {
        ops.build_image(&context_dir, tag)?;
        if push {
            ops.push_image(tag)?;
        }
    }

    Ok(())
}

fn render_bake_context(
    base_image: &str,
    metadata: Option<&ImageMetadata>,
    init_shim: bool,
) -> Result<BakeContext> {
    if !init_shim {
        return Ok(BakeContext {
            dockerfile: format!(
                "FROM {base_image}\nCOPY portl-agent /usr/local/bin/portl-agent\nRUN chmod +x /usr/local/bin/portl-agent\n"
            ),
            wrapper: None,
        });
    }

    let metadata = metadata.ok_or_else(|| anyhow!("init shim requires image metadata"))?;
    let wrapper = render_init_shim(metadata);
    let mut dockerfile = format!(
        "FROM {base_image}\nCOPY portl-agent /usr/local/bin/portl-agent\nCOPY portl-init-shim /usr/local/bin/portl-init-shim\nRUN chmod +x /usr/local/bin/portl-agent /usr/local/bin/portl-init-shim\nENTRYPOINT [\"/usr/local/bin/portl-init-shim\"]\n"
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

fn render_init_shim(metadata: &ImageMetadata) -> String {
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn resolve_bake_binary<O: BakeOps>(
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

fn write_bake_context(context_dir: &Path, context: &BakeContext, binary: &Path) -> Result<()> {
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
    if let Some(wrapper) = &context.wrapper {
        fs::write(context_dir.join("portl-init-shim"), wrapper)
            .with_context(|| format!("write {}", context_dir.join("portl-init-shim").display()))?;
    }
    Ok(())
}

fn temp_bake_dir() -> Result<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("portl-docker-bake-{unique}"));
    fs::create_dir_all(&path)
        .with_context(|| format!("create temp bake dir {}", path.display()))?;
    Ok(path)
}

async fn container_snapshot(
    docker: &Docker,
    inspect: ContainerInspectResponse,
) -> Result<ContainerSnapshot> {
    let id = inspect.id.clone().unwrap_or_default();
    let image_ref = inspect
        .image
        .clone()
        .or_else(|| {
            inspect
                .config
                .as_ref()
                .and_then(|config| config.image.clone())
        })
        .unwrap_or_default();
    let image = inspect
        .config
        .as_ref()
        .and_then(|config| config.image.clone())
        .unwrap_or_else(|| image_ref.clone());
    let network = inspect
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.keys().next().cloned())
        .unwrap_or_else(|| DEFAULT_NETWORK.to_owned());
    let running = inspect
        .state
        .as_ref()
        .and_then(|state| state.running)
        .unwrap_or(false);
    let pid = inspect.state.as_ref().and_then(|state| state.pid);
    let name = inspect
        .name
        .as_deref()
        .unwrap_or(&id)
        .trim_start_matches('/')
        .to_owned();

    let (target_os, target_arch) = if image_ref.is_empty() {
        (None, None)
    } else {
        match docker.inspect_image(&image_ref).await {
            Ok(image) => (image.os, image.architecture),
            Err(_) => (None, None),
        }
    };

    Ok(ContainerSnapshot {
        id,
        name,
        image,
        network,
        running,
        pid,
        target_os,
        target_arch,
    })
}

fn save_injected_alias(outcome: &InjectionOutcome) -> Result<()> {
    let ticket_path = local_ticket_path(&outcome.container.name);
    write_ticket(&ticket_path, &outcome.plan.ticket)?;
    AliasStore::default().save(
        &AliasRecord {
            name: outcome.container.name.clone(),
            adapter: ADAPTER_NAME.to_owned(),
            container_id: outcome.container.id.clone(),
            endpoint_id: outcome.plan.endpoint_id_hex.clone(),
            image: outcome.container.image.clone(),
            network: outcome.container.network.clone(),
            created_at: now_unix_secs()?,
        },
        &StoredSpec {
            caps: outcome.plan.caps.clone(),
            ttl_secs: outcome.plan.ttl_secs,
            to: Some(outcome.plan.holder),
            labels: vec![],
            root_ticket_id: Some(outcome.plan.root_ticket_id),
            ticket_file_path: Some(ticket_path),
            group_name: None,
            base_url: None,
            docker_exec_id: Some(outcome.exec_id.clone()),
            docker_injected_binary_path: Some(outcome.binary_path.clone()),
            docker_injected_binary_preexisted: outcome.binary_path_preexisted,
        },
    )
}

fn resolve_alias_record(store: &AliasStore, name_or_id: &str) -> Result<Option<AliasRecord>> {
    if let Some(alias) = store.get(name_or_id)? {
        return Ok(Some(alias));
    }
    Ok(store
        .list()?
        .into_iter()
        .find(|alias| alias.container_id == name_or_id))
}

fn ensure_rm_allowed(name: &str, status: &TargetStatus, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }

    match status {
        TargetStatus::Exited { .. } | TargetStatus::NotFound => Ok(()),
        TargetStatus::Running | TargetStatus::Provisioning => {
            bail!("container '{name}' is still running; use `portl docker rm {name} --force`")
        }
        TargetStatus::Unknown(other) => bail!(
            "container '{name}' is not known to be stopped (status: {other}); use `portl docker rm {name} --force`"
        ),
    }
}

fn local_revocations_path() -> PathBuf {
    store::default_path().parent().map_or_else(
        || PathBuf::from("revocations.jsonl"),
        |parent| parent.join("revocations.jsonl"),
    )
}

fn local_ticket_path(name: &str) -> PathBuf {
    store::default_path().parent().map_or_else(
        || PathBuf::from(format!("{name}.ticket")),
        |parent| parent.join("tickets").join(format!("{name}.ticket")),
    )
}

fn write_ticket(path: &Path, ticket: &PortlTicket) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, ticket.serialize()).with_context(|| format!("write ticket {}", path.display()))
}

fn ticket_not_after(created_at: i64, ttl_secs: u64) -> Option<u64> {
    u64::try_from(created_at).ok()?.checked_add(ttl_secs)
}

fn revoke_ticket(ticket_id: [u8; 16], not_after_of_ticket: Option<u64>, path: &Path) -> Result<()> {
    revocations::append_record(
        path,
        &RevocationRecord::new(
            ticket_id,
            "docker_rm",
            u64::try_from(now_unix_secs()?)?,
            not_after_of_ticket,
        ),
    )
}

fn alias_to_handle(alias: &AliasRecord) -> Handle {
    Handle {
        adapter: alias.adapter.clone(),
        inner: serde_json::json!({
            "container_id": alias.container_id,
            "endpoint_id": alias.endpoint_id,
            "image": alias.image,
            "network": alias.network,
            "name": alias.name,
            "config_path": "",
        }),
    }
}

async fn run_container_command<D: DockerOps>(
    docker: &D,
    container: &str,
    cmd: Vec<String>,
) -> Result<()> {
    let rendered = cmd.join(" ");
    let exec_id = docker.create_exec(container, cmd, Vec::new()).await?;
    let mut logs = docker.start_exec_with_logs(&exec_id).await?;
    let mut output = String::new();
    while let Some(line) = logs.next().await {
        output.push_str(&line?);
    }

    loop {
        let inspect = docker.inspect_exec(&exec_id).await?;
        if !inspect.running {
            let exit_code = inspect.exit_code.unwrap_or_default();
            if exit_code == 0 {
                return Ok(());
            }
            let detail = output.trim();
            if detail.is_empty() {
                bail!("run `{rendered}` in container {container} exited with status {exit_code}");
            }
            bail!(
                "run `{rendered}` in container {container} exited with status {exit_code}: {detail}"
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::Mutex};
    use tempfile::tempdir;

    #[derive(Default)]
    struct MockHostOps {
        current_exe: Mutex<Option<PathBuf>>,
        host_os: &'static str,
        host_arch: &'static str,
    }

    impl MockHostOps {
        fn with_current_exe(path: PathBuf) -> Self {
            Self {
                current_exe: Mutex::new(Some(path)),
                host_os: std::env::consts::OS,
                host_arch: std::env::consts::ARCH,
            }
        }
    }

    impl HostOps for MockHostOps {
        fn current_exe(&self) -> Result<PathBuf> {
            Ok(self
                .current_exe
                .lock()
                .expect("lock")
                .clone()
                .expect("current exe"))
        }

        fn host_os(&self) -> &'static str {
            self.host_os
        }

        fn host_arch(&self) -> &'static str {
            self.host_arch
        }
    }

    #[derive(Default)]
    struct MockBakeOps {
        current_exe: PathBuf,
        metadata: Option<ImageMetadata>,
        builds: Mutex<Vec<(PathBuf, String)>>,
        pushes: Mutex<Vec<String>>,
    }

    impl BakeOps for MockBakeOps {
        fn current_exe(&self) -> Result<PathBuf> {
            Ok(self.current_exe.clone())
        }

        fn inspect_image(&self, _image: &str) -> Result<ImageMetadata> {
            Ok(self.metadata.clone().unwrap_or(ImageMetadata {
                entrypoint: Vec::new(),
                cmd: Vec::new(),
                os: Some(normalize_os(std::env::consts::OS).to_owned()),
                architecture: Some(normalize_arch(std::env::consts::ARCH).to_owned()),
            }))
        }

        fn build_image(&self, context_dir: &Path, tag: &str) -> Result<()> {
            self.builds
                .lock()
                .expect("lock")
                .push((context_dir.to_path_buf(), tag.to_owned()));
            Ok(())
        }

        fn push_image(&self, tag: &str) -> Result<()> {
            self.pushes.lock().expect("lock").push(tag.to_owned());
            Ok(())
        }
    }

    struct MockDockerOps {
        actions: Mutex<Vec<String>>,
        inspect_by_container: Mutex<HashMap<String, ContainerSnapshot>>,
        copy_failures: Mutex<HashMap<String, anyhow::Error>>,
        execs: Mutex<HashMap<String, ExecSnapshot>>,
        existing_paths: Mutex<HashMap<String, bool>>,
        exec_id: String,
        recorded_exec_cmd: Mutex<Option<Vec<String>>>,
        recorded_exec_env: Mutex<Option<Vec<String>>>,
        recorded_runtime: Mutex<Option<RunRuntimeSpec>>,
        command_runs: Mutex<Vec<(String, Vec<String>)>>,
        start_logs: Mutex<Vec<String>>,
        events: Mutex<Vec<ContainerEvent>>,
    }

    impl MockDockerOps {
        fn new(container: ContainerSnapshot) -> Self {
            Self {
                actions: Mutex::new(Vec::new()),
                inspect_by_container: Mutex::new(HashMap::from([(
                    container.id.clone(),
                    container,
                )])),
                copy_failures: Mutex::new(HashMap::new()),
                execs: Mutex::new(HashMap::from([(
                    "exec-1".to_owned(),
                    ExecSnapshot {
                        running: true,
                        pid: Some(4242),
                        exit_code: None,
                    },
                )])),
                existing_paths: Mutex::new(HashMap::new()),
                exec_id: "exec-1".to_owned(),
                recorded_exec_cmd: Mutex::new(None),
                recorded_exec_env: Mutex::new(None),
                recorded_runtime: Mutex::new(None),
                command_runs: Mutex::new(Vec::new()),
                start_logs: Mutex::new(vec![READY_LOG_TOKEN.to_owned()]),
                events: Mutex::new(Vec::new()),
            }
        }

        fn with_copy_failures(
            self,
            failures: impl IntoIterator<Item = (&'static str, &'static str)>,
        ) -> Self {
            let mut this = self;
            this.copy_failures = Mutex::new(
                failures
                    .into_iter()
                    .map(|(path, message)| (path.to_owned(), anyhow!(message)))
                    .collect(),
            );
            this
        }

        fn with_existing_paths(
            self,
            paths: impl IntoIterator<Item = (&'static str, bool)>,
        ) -> Self {
            let mut this = self;
            this.existing_paths = Mutex::new(
                paths
                    .into_iter()
                    .map(|(path, exists)| (path.to_owned(), exists))
                    .collect(),
            );
            this
        }
    }

    #[async_trait]
    impl DockerOps for MockDockerOps {
        async fn ensure_image(&self, image: &str) -> Result<()> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("ensure:{image}"));
            Ok(())
        }

        async fn create_container(
            &self,
            image: &str,
            name: Option<&str>,
            _labels: &HashMap<String, String>,
            runtime: &RunRuntimeSpec,
        ) -> Result<String> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("create:{image}:{}", name.unwrap_or("<auto>")));
            *self.recorded_runtime.lock().expect("lock") = Some(runtime.clone());
            Ok("demo-id".to_owned())
        }

        async fn start_container(&self, container: &str) -> Result<()> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("start:{container}"));
            Ok(())
        }

        async fn inspect_container(&self, container: &str) -> Result<ContainerSnapshot> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("inspect:{container}"));
            self.inspect_by_container
                .lock()
                .expect("lock")
                .get(container)
                .cloned()
                .ok_or_else(|| anyhow!("missing container {container}"))
        }

        async fn copy_file(&self, _source: &Path, container: &str, dest: &Path) -> Result<()> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("copy:{container}:{}", dest.display()));
            if let Some(err) = self
                .copy_failures
                .lock()
                .expect("lock")
                .remove(&dest.display().to_string())
            {
                return Err(err);
            }
            Ok(())
        }

        async fn create_exec(
            &self,
            container: &str,
            cmd: Vec<String>,
            env: Vec<String>,
        ) -> Result<String> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("create-exec:{container}"));
            *self.recorded_exec_cmd.lock().expect("lock") = Some(cmd);
            *self.recorded_exec_env.lock().expect("lock") = Some(env);
            Ok(self.exec_id.clone())
        }

        async fn start_exec_with_logs(
            &self,
            exec_id: &str,
        ) -> Result<BoxStream<'static, Result<String>>> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("start-exec:{exec_id}"));
            let logs = self.start_logs.lock().expect("lock").clone();
            Ok(Box::pin(futures_util::stream::iter(
                logs.into_iter().map(Ok::<_, anyhow::Error>),
            )))
        }

        async fn inspect_exec(&self, exec_id: &str) -> Result<ExecSnapshot> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("inspect-exec:{exec_id}"));
            self.execs
                .lock()
                .expect("lock")
                .get(exec_id)
                .cloned()
                .ok_or_else(|| anyhow!("missing exec {exec_id}"))
        }

        async fn path_exists(&self, container: &str, path: &Path) -> Result<bool> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("exists:{container}:{}", path.display()));
            Ok(*self
                .existing_paths
                .lock()
                .expect("lock")
                .get(&path.display().to_string())
                .unwrap_or(&false))
        }

        async fn run_command(&self, container: &str, cmd: Vec<String>) -> Result<()> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("run:{container}:{}", cmd.join(" ")));
            self.command_runs
                .lock()
                .expect("lock")
                .push((container.to_owned(), cmd));
            Ok(())
        }

        fn container_events(&self, _container: &str) -> BoxStream<'static, Result<ContainerEvent>> {
            let events = self.events.lock().expect("lock").clone();
            Box::pin(futures_util::stream::iter(
                events.into_iter().map(Ok::<_, anyhow::Error>),
            ))
        }
    }

    fn running_container() -> ContainerSnapshot {
        ContainerSnapshot {
            id: "demo-id".to_owned(),
            name: "demo".to_owned(),
            image: "alpine:3.20".to_owned(),
            network: "bridge".to_owned(),
            running: true,
            pid: Some(99),
            target_os: Some(normalize_os(std::env::consts::OS).to_owned()),
            target_arch: Some(normalize_arch(std::env::consts::ARCH).to_owned()),
        }
    }

    fn operator() -> Identity {
        Identity::new()
    }

    #[tokio::test]
    async fn orchestrate_injects_agent_into_running_container() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let host = MockHostOps::with_current_exe(binary);
        let docker = MockDockerOps::new(running_container());

        let outcome = orchestrate_run(
            &docker,
            &host,
            "alpine:3.20",
            Some("demo"),
            &BinarySource::CurrentExecutable,
            &RunRuntimeSpec::default(),
            &operator(),
        )
        .await
        .expect("orchestrate run");

        assert_eq!(outcome.binary_path, PathBuf::from(INJECTION_PATHS[0]));
        assert_eq!(outcome.container.name, "demo");
        let exec_cmd = docker
            .recorded_exec_cmd
            .lock()
            .expect("lock")
            .clone()
            .expect("recorded cmd");
        assert_eq!(exec_cmd, vec![INJECTION_PATHS[0].to_owned()]);
        let exec_env = docker
            .recorded_exec_env
            .lock()
            .expect("lock")
            .clone()
            .expect("recorded env");
        assert!(
            exec_env
                .iter()
                .any(|entry| entry.starts_with("PORTL_IDENTITY_SECRET_HEX="))
        );
        assert!(
            exec_env
                .iter()
                .any(|entry| entry.starts_with("PORTL_TRUST_ROOTS="))
        );
    }

    #[tokio::test]
    async fn docker_run_threads_passthrough_runtime_settings() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let host = MockHostOps::with_current_exe(binary);
        let docker = MockDockerOps::new(running_container());
        let runtime = RunRuntimeSpec {
            env: vec!["FOO=bar".to_owned()],
            volume: vec!["/host:/container:ro".to_owned()],
            network: Some("demo-net".to_owned()),
            user: Some("1000:1000".to_owned()),
        };

        orchestrate_run(
            &docker,
            &host,
            "alpine:3.20",
            Some("demo"),
            &BinarySource::CurrentExecutable,
            &runtime,
            &operator(),
        )
        .await
        .expect("orchestrate run");

        assert_eq!(
            docker.recorded_runtime.lock().expect("lock").clone(),
            Some(runtime)
        );
    }

    #[tokio::test]
    async fn wait_for_agent_start_waits_for_readiness_log() {
        let docker = MockDockerOps::new(running_container());
        let started = tokio::time::Instant::now();
        let logs = Box::pin(futures_util::stream::unfold(0_u8, |state| async move {
            match state {
                0 => Some((Ok::<_, anyhow::Error>("booting".to_owned()), 1)),
                1 => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    Some((Ok::<_, anyhow::Error>(READY_LOG_TOKEN.to_owned()), 2))
                }
                _ => None,
            }
        }));

        wait_for_agent_start(&docker, "exec-1", logs)
            .await
            .expect("wait for readiness");

        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn install_path_fallback_order() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let docker = MockDockerOps::new(running_container())
            .with_copy_failures([
                (INJECTION_PATHS[0], "read-only root"),
                (INJECTION_PATHS[1], "tmp unavailable"),
            ])
            .with_existing_paths([(INJECTION_PATHS[2], true)]);

        let (chosen, existed) = copy_binary_with_fallback(&docker, &binary, "demo-id")
            .await
            .expect("copy with fallback");

        assert_eq!(chosen, PathBuf::from(INJECTION_PATHS[2]));
        assert!(existed);
        let actions = docker.actions.lock().expect("lock").clone();
        assert_eq!(
            actions,
            vec![
                format!("exists:demo-id:{}", INJECTION_PATHS[0]),
                format!("copy:demo-id:{}", INJECTION_PATHS[0]),
                format!("exists:demo-id:{}", INJECTION_PATHS[1]),
                format!("copy:demo-id:{}", INJECTION_PATHS[1]),
                format!("exists:demo-id:{}", INJECTION_PATHS[2]),
                format!("copy:demo-id:{}", INJECTION_PATHS[2]),
            ]
        );
    }

    #[test]
    fn foreign_arch_refusal_without_release_binary() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let host = MockHostOps::with_current_exe(binary);
        let foreign = ContainerSnapshot {
            target_arch: Some(if normalize_arch(std::env::consts::ARCH) == "amd64" {
                "arm64".to_owned()
            } else {
                "amd64".to_owned()
            }),
            ..running_container()
        };

        let err = resolve_binary_path(&host, &BinarySource::CurrentExecutable, &foreign)
            .expect_err("foreign arch must fail");
        assert!(err.to_string().contains("--from-binary"));
        assert!(err.to_string().contains("--from-release"));
        assert!(err.to_string().contains("portl docker bake"));
    }

    #[tokio::test]
    async fn attach_on_stopped_container_errors() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let host = MockHostOps::with_current_exe(binary);
        let stopped = ContainerSnapshot {
            running: false,
            ..running_container()
        };
        let docker = MockDockerOps::new(stopped.clone());
        docker
            .inspect_by_container
            .lock()
            .expect("lock")
            .insert(stopped.name.clone(), stopped.clone());

        let err = attach_existing(
            &docker,
            &host,
            &stopped.name,
            &BinarySource::CurrentExecutable,
            &operator(),
        )
        .await
        .err()
        .expect("stopped container must fail");
        assert!(err.to_string().contains("is not running"));
    }

    #[tokio::test]
    async fn detach_terminates_injected_agent_and_removes_created_binary() {
        let dir = tempdir().expect("tempdir");
        let store = AliasStore::new(dir.path().join("aliases.json"));
        store
            .save(
                &AliasRecord {
                    name: "demo".to_owned(),
                    adapter: ADAPTER_NAME.to_owned(),
                    container_id: "demo-id".to_owned(),
                    endpoint_id: "endpoint".to_owned(),
                    image: "alpine:3.20".to_owned(),
                    network: "bridge".to_owned(),
                    created_at: 1,
                },
                &StoredSpec {
                    caps: parse_caps(DEFAULT_AGENT_CAPS).expect("caps"),
                    ttl_secs: parse_ttl(DEFAULT_TTL).expect("ttl"),
                    to: None,
                    labels: vec![],
                    root_ticket_id: None,
                    ticket_file_path: None,
                    group_name: None,
                    base_url: None,
                    docker_exec_id: Some("exec-1".to_owned()),
                    docker_injected_binary_path: Some(PathBuf::from(INJECTION_PATHS[1])),
                    docker_injected_binary_preexisted: false,
                },
            )
            .expect("save alias");

        let docker = MockDockerOps::new(running_container());
        detach_saved_container(&docker, &store, "demo")
            .await
            .expect("detach container");

        assert_eq!(
            *docker.command_runs.lock().expect("lock"),
            vec![
                (
                    "demo-id".to_owned(),
                    vec![
                        "/bin/sh".to_owned(),
                        "-lc".to_owned(),
                        "kill -TERM 4242 2>/dev/null || true".to_owned(),
                    ],
                ),
                (
                    "demo-id".to_owned(),
                    vec![
                        "/bin/sh".to_owned(),
                        "-lc".to_owned(),
                        format!("rm -f {}", shell_quote(INJECTION_PATHS[1])),
                    ],
                ),
            ]
        );
        assert!(store.get("demo").expect("read alias").is_none());
    }

    #[tokio::test]
    async fn detach_leaves_preexisting_binary_in_place() {
        let dir = tempdir().expect("tempdir");
        let store = AliasStore::new(dir.path().join("aliases.json"));
        store
            .save(
                &AliasRecord {
                    name: "demo".to_owned(),
                    adapter: ADAPTER_NAME.to_owned(),
                    container_id: "demo-id".to_owned(),
                    endpoint_id: "endpoint".to_owned(),
                    image: "alpine:3.20".to_owned(),
                    network: "bridge".to_owned(),
                    created_at: 1,
                },
                &StoredSpec {
                    caps: parse_caps(DEFAULT_AGENT_CAPS).expect("caps"),
                    ttl_secs: parse_ttl(DEFAULT_TTL).expect("ttl"),
                    to: None,
                    labels: vec![],
                    root_ticket_id: None,
                    ticket_file_path: None,
                    group_name: None,
                    base_url: None,
                    docker_exec_id: Some("exec-1".to_owned()),
                    docker_injected_binary_path: Some(PathBuf::from(INJECTION_PATHS[1])),
                    docker_injected_binary_preexisted: true,
                },
            )
            .expect("save alias");

        let docker = MockDockerOps::new(running_container());
        detach_saved_container(&docker, &store, "demo")
            .await
            .expect("detach container with preexisting binary");

        assert_eq!(
            *docker.command_runs.lock().expect("lock"),
            vec![(
                "demo-id".to_owned(),
                vec![
                    "/bin/sh".to_owned(),
                    "-lc".to_owned(),
                    "kill -TERM 4242 2>/dev/null || true".to_owned(),
                ],
            )]
        );
    }

    #[test]
    fn bake_emits_valid_dockerfile_inheriting_entrypoint() {
        let dir = tempdir().expect("tempdir");
        let output = dir.path().join("bake");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let ops = MockBakeOps {
            current_exe: binary,
            ..MockBakeOps::default()
        };

        bake_with(
            &ops,
            "alpine:3.20",
            Some(&output),
            None,
            false,
            false,
            &BinarySource::CurrentExecutable,
        )
        .expect("bake output");

        let dockerfile = fs::read_to_string(output.join("Dockerfile")).expect("read Dockerfile");
        assert!(dockerfile.contains("FROM alpine:3.20"));
        assert!(dockerfile.contains("COPY portl-agent /usr/local/bin/portl-agent"));
        assert!(!dockerfile.contains("ENTRYPOINT"));
        assert!(!dockerfile.contains("CMD ["));
        assert!(output.join("portl-agent").exists());
    }

    #[test]
    fn bake_init_shim_mode_produces_two_line_entrypoint() {
        let dir = tempdir().expect("tempdir");
        let output = dir.path().join("bake");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let ops = MockBakeOps {
            current_exe: binary,
            metadata: Some(ImageMetadata {
                entrypoint: vec!["/usr/local/bin/app".to_owned(), "--serve".to_owned()],
                cmd: vec!["8080".to_owned()],
                os: Some(normalize_os(std::env::consts::OS).to_owned()),
                architecture: Some(normalize_arch(std::env::consts::ARCH).to_owned()),
            }),
            ..MockBakeOps::default()
        };

        bake_with(
            &ops,
            "alpine:3.20",
            Some(&output),
            None,
            false,
            true,
            &BinarySource::CurrentExecutable,
        )
        .expect("bake init shim");

        let dockerfile = fs::read_to_string(output.join("Dockerfile")).expect("read Dockerfile");
        let wrapper = fs::read_to_string(output.join("portl-init-shim")).expect("read wrapper");
        assert!(dockerfile.contains("ENTRYPOINT [\"/usr/local/bin/portl-init-shim\"]"));
        assert!(dockerfile.contains("CMD [\"8080\"]"));
        assert_eq!(wrapper.lines().count(), 2);
        assert!(
            wrapper.contains(
                "/usr/local/bin/portl-agent & exec '/usr/local/bin/app' '--serve' \"$@\""
            )
        );
    }

    #[test]
    fn bake_tag_mode_invokes_docker_build() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        fs::write(&binary, b"portl").expect("write binary");
        let ops = MockBakeOps {
            current_exe: binary,
            ..MockBakeOps::default()
        };

        bake_with(
            &ops,
            "alpine:3.20",
            None,
            Some("demo:portl"),
            false,
            false,
            &BinarySource::CurrentExecutable,
        )
        .expect("bake tag mode");

        let builds = ops.builds.lock().expect("lock");
        assert_eq!(builds.len(), 1);
        assert_eq!(builds[0].1, "demo:portl");
    }

    #[test]
    fn rm_force_revokes_ticket() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");

        revoke_ticket([0x11; 16], Some(99), &path).expect("write revocation");

        let contents = fs::read_to_string(path).expect("read revocations");
        assert!(contents.contains(&hex::encode([0x11; 16])));
        assert!(contents.contains("docker_rm"));
        assert!(contents.contains("99"));
    }

    #[test]
    fn rm_without_force_refuses_running_container() {
        let err = ensure_rm_allowed("demo", &TargetStatus::Running, false)
            .expect_err("running container must be refused");
        assert!(
            err.to_string()
                .contains("container 'demo' is still running")
        );
    }
}

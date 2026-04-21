use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, StartContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecOptions};
use bollard::image::CreateImageOptions;
use bollard::models::ContainerInspectResponse;
use docker_portl::{ADAPTER_NAME, DockerBootstrapper};
use futures_util::stream::TryStreamExt;
use iroh_tickets::Ticket;
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use portl_agent::{RevocationRecord, revocations};
use portl_core::bootstrap::{Bootstrapper, Handle, TargetStatus};
use portl_core::id::{Identity, store};
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::mint::mint_root;

use crate::alias_store::{AliasRecord, AliasStore, StoredSpec, now_unix_secs};
use crate::commands::mint_root::{parse_caps, parse_ttl};

const DEFAULT_NETWORK: &str = "bridge";
const DEFAULT_AGENT_CAPS: &str = "all";
const DEFAULT_TTL: &str = "30d";
const INJECTION_PATHS: [&str; 3] = [
    "/usr/local/bin/portl-agent",
    "/tmp/portl-agent",
    "/dev/shm/portl-agent",
];

pub fn run(
    image: &str,
    name: Option<&str>,
    from_binary: Option<&Path>,
    watch: bool,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let docker = RealDockerOps::connect()?;
        let host = RealHostOps;
        let outcome = orchestrate_run(&docker, &host, image, name, from_binary, &operator).await?;
        save_injected_alias(&outcome)?;
        if watch {
            eprintln!(
                "warning: `portl docker run --watch` is not implemented yet; continuing without a watch loop"
            );
        }
        println!("{}", outcome.plan.ticket.serialize());
        Ok(ExitCode::SUCCESS)
    })
}

pub fn attach(container: &str, from_binary: Option<&Path>) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let docker = RealDockerOps::connect()?;
        let host = RealHostOps;
        let outcome = attach_existing(&docker, &host, container, from_binary, &operator).await?;
        save_injected_alias(&outcome)?;
        println!("{}", outcome.plan.ticket.serialize());
        Ok(ExitCode::SUCCESS)
    })
}

pub fn detach(container: &str) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let docker = RealDockerOps::connect()?;
        let host = RealHostOps;
        detach_saved_container(&docker, &host, &AliasStore::default(), container).await?;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn bake(
    _base_image: &str,
    _output: Option<&Path>,
    _tag: Option<&str>,
    _push: bool,
    _init_shim: bool,
) -> Result<ExitCode> {
    anyhow::bail!("`portl docker bake` is implemented in Task 3.3")
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
    ticket: portl_core::ticket::schema::PortlTicket,
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

trait HostOps {
    fn current_exe(&self) -> Result<PathBuf>;
    fn host_os(&self) -> &'static str;
    fn host_arch(&self) -> &'static str;
    fn kill_pid(&self, pid: i32) -> Result<()>;
    fn remove_container_file(&self, container_pid: i64, path: &Path) -> Result<()>;
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

    fn kill_pid(&self, pid: i32) -> Result<()> {
        match kill(Pid::from_raw(pid), Signal::SIGTERM) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(err) => Err(anyhow!(err)).context("send SIGTERM to injected agent"),
        }
    }

    fn remove_container_file(&self, container_pid: i64, path: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let rel = path.strip_prefix("/").unwrap_or(path);
            let host_path = PathBuf::from(format!("/proc/{container_pid}/root")).join(rel);
            match std::fs::remove_file(&host_path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err)
                    .with_context(|| format!("remove injected binary {}", host_path.display())),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = container_pid;
            let _ = path;
            bail!("detaching injected docker agents is currently supported on Linux hosts only")
        }
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
    async fn start_exec_detached(&self, exec_id: &str) -> Result<()>;
    async fn inspect_exec(&self, exec_id: &str) -> Result<ExecSnapshot>;
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
    ) -> Result<String> {
        let config = Config::<String> {
            image: Some(image.to_owned()),
            labels: Some(labels.clone()),
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
        let source = source
            .to_str()
            .ok_or_else(|| anyhow!("binary path is not valid UTF-8: {}", source.display()))?;
        let dest = dest
            .to_str()
            .ok_or_else(|| anyhow!("container path is not valid UTF-8: {}", dest.display()))?;
        let output = ProcessCommand::new("docker")
            .args(["cp", source, &format!("{container}:{dest}")])
            .output()
            .context("run docker cp")?;
        if output.status.success() {
            Ok(())
        } else {
            bail!(
                "docker cp to {dest} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
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
                    attach_stdout: Some(false),
                    attach_stderr: Some(false),
                    env: Some(env),
                    cmd: Some(cmd),
                    ..CreateExecOptions::default()
                },
            )
            .await
            .with_context(|| format!("create injected exec in {container}"))
            .map(|created| created.id)
    }

    async fn start_exec_detached(&self, exec_id: &str) -> Result<()> {
        self.docker
            .start_exec(
                exec_id,
                Some(StartExecOptions {
                    detach: true,
                    tty: false,
                    output_capacity: None,
                }),
            )
            .await
            .with_context(|| format!("start injected exec {exec_id}"))?;
        Ok(())
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
}

async fn orchestrate_run<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
    image: &str,
    name: Option<&str>,
    from_binary: Option<&Path>,
    operator: &Identity,
) -> Result<InjectionOutcome> {
    let plan = prepare_injection_plan(operator)?;
    let labels = HashMap::from([
        ("portl.adapter".to_owned(), ADAPTER_NAME.to_owned()),
        ("portl.endpoint_id".to_owned(), plan.endpoint_id_hex.clone()),
    ]);
    docker.ensure_image(image).await?;
    let container_id = docker.create_container(image, name, &labels).await?;
    docker.start_container(&container_id).await?;
    let container = docker.inspect_container(&container_id).await?;
    inject_container(docker, host, container, from_binary, operator, plan).await
}

async fn attach_existing<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
    container: &str,
    from_binary: Option<&Path>,
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
    inject_container(docker, host, snapshot, from_binary, operator, plan).await
}

async fn inject_container<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
    container: ContainerSnapshot,
    from_binary: Option<&Path>,
    operator: &Identity,
    plan: InjectionPlan,
) -> Result<InjectionOutcome> {
    if !container.running {
        bail!(
            "container '{}' is not running; start it before attaching",
            container.name
        );
    }
    let binary = resolve_binary_source(host, from_binary, &container)?;
    let binary_path = copy_binary_with_fallback(docker, &binary, &container.id).await?;
    let exec_env = injected_agent_env(&plan.identity, operator);
    let exec_id = docker
        .create_exec(
            &container.id,
            vec![binary_path.display().to_string()],
            exec_env,
        )
        .await?;
    docker.start_exec_detached(&exec_id).await?;
    wait_for_agent_start(docker, &exec_id).await?;
    Ok(InjectionOutcome {
        container,
        binary_path,
        exec_id,
        plan,
    })
}

async fn detach_saved_container<D: DockerOps, H: HostOps>(
    docker: &D,
    host: &H,
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
        host.kill_pid(i32::try_from(pid).context("exec pid exceeds i32")?)?;
    }

    if let Some(path) = spec.docker_injected_binary_path.as_deref() {
        let container_snapshot = docker.inspect_container(&alias.container_id).await?;
        if let Some(container_pid) = container_snapshot.pid {
            host.remove_container_file(container_pid, path)?;
        }
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

fn resolve_binary_source<H: HostOps>(
    host: &H,
    from_binary: Option<&Path>,
    container: &ContainerSnapshot,
) -> Result<PathBuf> {
    if from_binary.is_none() && !platform_matches(host.host_os(), host.host_arch(), container) {
        let target_os = container.target_os.as_deref().unwrap_or("unknown");
        let target_arch = container.target_arch.as_deref().unwrap_or("unknown");
        bail!(
            "container '{}' targets {target_os}/{target_arch}, but the running CLI is {}/{}; pass --from-binary <linux-portl-agent> or use `portl docker bake`",
            container.name,
            host.host_os(),
            host.host_arch()
        );
    }

    from_binary
        .map(Path::to_path_buf)
        .map_or_else(|| host.current_exe(), Ok)
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
) -> Result<PathBuf> {
    let mut errors = Vec::new();
    for candidate in INJECTION_PATHS.map(PathBuf::from) {
        match docker.copy_file(binary, container, &candidate).await {
            Ok(()) => return Ok(candidate),
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

async fn wait_for_agent_start<D: DockerOps>(docker: &D, exec_id: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let exec = docker.inspect_exec(exec_id).await?;
        if exec.running {
            return Ok(());
        }
        if let Some(code) = exec.exit_code {
            bail!("injected agent exited before becoming ready (exit code {code})");
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
            ticket_file_path: None,
            group_name: None,
            base_url: None,
            docker_exec_id: Some(outcome.exec_id.clone()),
            docker_injected_binary_path: Some(outcome.binary_path.clone()),
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
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[derive(Default)]
    struct MockHostOps {
        current_exe: Mutex<Option<PathBuf>>,
        killed_pids: Mutex<Vec<i32>>,
        removed_files: Mutex<Vec<(i64, PathBuf)>>,
        host_os: &'static str,
        host_arch: &'static str,
    }

    impl MockHostOps {
        fn with_current_exe(path: PathBuf) -> Self {
            Self {
                current_exe: Mutex::new(Some(path)),
                host_os: std::env::consts::OS,
                host_arch: std::env::consts::ARCH,
                ..Self::default()
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

        fn kill_pid(&self, pid: i32) -> Result<()> {
            self.killed_pids.lock().expect("lock").push(pid);
            Ok(())
        }

        fn remove_container_file(&self, container_pid: i64, path: &Path) -> Result<()> {
            self.removed_files
                .lock()
                .expect("lock")
                .push((container_pid, path.to_path_buf()));
            Ok(())
        }
    }

    struct MockDockerOps {
        actions: Mutex<Vec<String>>,
        inspect_by_container: Mutex<HashMap<String, ContainerSnapshot>>,
        copy_failures: Mutex<HashMap<String, anyhow::Error>>,
        execs: Mutex<HashMap<String, ExecSnapshot>>,
        exec_id: String,
        recorded_exec_cmd: Mutex<Option<Vec<String>>>,
        recorded_exec_env: Mutex<Option<Vec<String>>>,
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
                exec_id: "exec-1".to_owned(),
                recorded_exec_cmd: Mutex::new(None),
                recorded_exec_env: Mutex::new(None),
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
        ) -> Result<String> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("create:{image}:{}", name.unwrap_or("<auto>")));
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

        async fn start_exec_detached(&self, exec_id: &str) -> Result<()> {
            self.actions
                .lock()
                .expect("lock")
                .push(format!("start-exec:{exec_id}"));
            Ok(())
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
        std::fs::write(&binary, b"portl").expect("write binary");
        let host = MockHostOps::with_current_exe(binary);
        let docker = MockDockerOps::new(running_container());

        let outcome = orchestrate_run(
            &docker,
            &host,
            "alpine:3.20",
            Some("demo"),
            None,
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
    async fn install_path_fallback_order() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        std::fs::write(&binary, b"portl").expect("write binary");
        let docker = MockDockerOps::new(running_container()).with_copy_failures([
            (INJECTION_PATHS[0], "read-only root"),
            (INJECTION_PATHS[1], "tmp unavailable"),
        ]);

        let chosen = copy_binary_with_fallback(&docker, &binary, "demo-id")
            .await
            .expect("copy with fallback");

        assert_eq!(chosen, PathBuf::from(INJECTION_PATHS[2]));
        let actions = docker.actions.lock().expect("lock").clone();
        assert_eq!(
            actions,
            vec![
                format!("copy:demo-id:{}", INJECTION_PATHS[0]),
                format!("copy:demo-id:{}", INJECTION_PATHS[1]),
                format!("copy:demo-id:{}", INJECTION_PATHS[2]),
            ]
        );
    }

    #[test]
    fn foreign_arch_refusal_without_release_binary() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        std::fs::write(&binary, b"portl").expect("write binary");
        let host = MockHostOps::with_current_exe(binary);
        let foreign = ContainerSnapshot {
            target_arch: Some(if normalize_arch(std::env::consts::ARCH) == "amd64" {
                "arm64".to_owned()
            } else {
                "amd64".to_owned()
            }),
            ..running_container()
        };

        let err = resolve_binary_source(&host, None, &foreign).expect_err("foreign arch must fail");
        assert!(err.to_string().contains("--from-binary"));
        assert!(err.to_string().contains("portl docker bake"));
    }

    #[tokio::test]
    async fn attach_on_stopped_container_errors() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("portl");
        std::fs::write(&binary, b"portl").expect("write binary");
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

        let err = attach_existing(&docker, &host, &stopped.name, None, &operator())
            .await
            .err()
            .expect("stopped container must fail");
        assert!(err.to_string().contains("is not running"));
    }

    #[tokio::test]
    async fn detach_removes_injected_binary_and_terminates_injected_agent() {
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
                },
            )
            .expect("save alias");

        let docker = MockDockerOps::new(running_container());
        let host = MockHostOps::default();
        detach_saved_container(&docker, &host, &store, "demo")
            .await
            .expect("detach container");

        assert_eq!(*host.killed_pids.lock().expect("lock"), vec![4242]);
        assert_eq!(
            *host.removed_files.lock().expect("lock"),
            vec![(99, PathBuf::from(INJECTION_PATHS[1]))]
        );
        assert!(store.get("demo").expect("read alias").is_none());
    }

    #[test]
    fn rm_force_revokes_ticket() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");

        revoke_ticket([0x11; 16], Some(99), &path).expect("write revocation");

        let contents = std::fs::read_to_string(path).expect("read revocations");
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

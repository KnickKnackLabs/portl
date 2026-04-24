use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use docker_portl::DockerBootstrapper;
use iroh_tickets::Ticket;
use portl_core::bootstrap::{Bootstrapper, TargetStatus};
use portl_core::id::store;

#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use async_trait::async_trait;
#[cfg(test)]
use docker_portl::ADAPTER_NAME;
#[cfg(test)]
use futures_util::stream::BoxStream;
#[cfg(test)]
use portl_core::id::Identity;

use crate::alias_store::AliasStore;
#[cfg(test)]
use crate::alias_store::{AliasRecord, StoredSpec};
#[cfg(test)]
use crate::commands::mint_root::{parse_caps, parse_ttl};

const DEFAULT_NETWORK: &str = "bridge";
const DEFAULT_AGENT_CAPS: &str = "all";
const DEFAULT_TTL: &str = "30d";
const READY_LOG_TOKEN: &str = "portl-agent listening";
const INJECTION_PATHS: [&str; 3] = [
    "/usr/local/bin/portl-agent",
    "/tmp/portl-agent",
    "/dev/shm/portl-agent",
];

mod aliases;
mod bake;
mod docker_ops;
mod host_ops;
mod run;
mod types;

use self::aliases::{
    alias_to_handle, ensure_rm_allowed, local_revocations_path, resolve_alias_record,
    revoke_ticket, save_injected_alias, ticket_not_after,
};
use self::bake::{RealBakeOps, bake_with};
use self::docker_ops::RealDockerOps;
use self::host_ops::RealHostOps;
use self::run::{
    attach_existing, detach_saved_container, finalize_connectable_ticket, orchestrate_run,
    resolve_binary_source, watch_container_restarts,
};
use self::types::RunRuntimeSpec;

#[cfg(test)]
use self::bake::{BakeOps, ImageMetadata, shell_quote};
#[cfg(test)]
use self::docker_ops::DockerOps;
#[cfg(test)]
use self::host_ops::HostOps;
#[cfg(test)]
use self::run::{
    copy_binary_with_fallback, normalize_arch, normalize_os, resolve_binary_path,
    wait_for_agent_start,
};
#[cfg(test)]
use self::types::{BinarySource, ContainerEvent, ContainerSnapshot, ExecSnapshot};

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
    session_provider: Option<&str>,
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
            session_provider: session_provider.map(str::to_owned),
        };
        let mut outcome = orchestrate_run(
            &docker,
            &host,
            image,
            name,
            &binary_source,
            &runtime,
            &operator,
        )
        .await?;
        finalize_connectable_ticket(&operator, &mut outcome.plan).await?;
        save_injected_alias(&outcome)?;
        println!("{}", outcome.plan.ticket.serialize());
        if watch {
            watch_container_restarts(
                &docker,
                &host,
                &outcome.container.id,
                &binary_source,
                &operator,
                session_provider,
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
    session_provider: Option<&str>,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let docker = RealDockerOps::connect()?;
        let host = RealHostOps;
        let binary_source = resolve_binary_source(from_binary, from_release)?;
        let mut outcome = attach_existing(
            &docker,
            &host,
            container,
            &binary_source,
            &operator,
            session_provider,
        )
        .await?;
        finalize_connectable_ticket(&operator, &mut outcome.plan).await?;
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

#[allow(clippy::too_many_arguments)]
pub fn bake(
    base_image: &str,
    output: Option<&Path>,
    tag: Option<&str>,
    push: bool,
    init_shim: bool,
    from_binary: Option<&Path>,
    from_release: Option<&str>,
    session_provider: Option<&str>,
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
        session_provider,
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
        let store = AliasStore::default();
        let aliases = store.list()?;
        let rows = aliases
            .into_iter()
            .map(|alias| {
                let bootstrapper = bootstrapper.clone();
                let spec = store.get_spec(&alias.name).ok().flatten();
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
                        "session_provider": spec.as_ref().and_then(|spec| spec.session_provider.clone()),
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
            session_provider: Some("zmx".to_owned()),
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
            None,
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
                    session_provider: None,
                    session_provider_install: None,
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
                    session_provider: None,
                    session_provider_install: None,
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
            None,
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
            None,
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
    fn bake_session_provider_zmx_sets_agent_env() {
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
            Some("zmx"),
        )
        .expect("bake zmx provider output");

        let dockerfile = fs::read_to_string(output.join("Dockerfile")).expect("read Dockerfile");
        assert!(dockerfile.contains("PORTL_SESSION_PROVIDER=zmx"));
        assert!(dockerfile.contains("command -v zmx"));
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
            None,
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

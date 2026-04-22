use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use docker_portl::ADAPTER_NAME;
use futures_util::stream::{BoxStream, StreamExt};
use iroh_tickets::Ticket;
use portl_core::id::Identity;
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::mint::mint_root;

use crate::alias_store::AliasStore;
use crate::commands::mint_root::{parse_caps, parse_ttl};
use crate::commands::peer_resolve::{bind_client_endpoint, resolve_peer_ticket};
use crate::release_binary;

use super::aliases::{resolve_alias_record, save_injected_alias};
use super::bake::shell_quote;
use super::docker_ops::DockerOps;
use super::host_ops::HostOps;
use super::types::{
    BinarySource, ContainerEvent, ContainerSnapshot, InjectionOutcome, InjectionPlan,
    RunRuntimeSpec,
};
use super::{DEFAULT_AGENT_CAPS, DEFAULT_TTL, INJECTION_PATHS, READY_LOG_TOKEN};

pub(super) async fn orchestrate_run<D: DockerOps, H: HostOps>(
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

pub(super) async fn attach_existing<D: DockerOps, H: HostOps>(
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

pub(super) async fn inject_container<D: DockerOps, H: HostOps>(
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

pub(super) async fn detach_saved_container<D: DockerOps>(
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

pub(super) async fn finalize_connectable_ticket(
    operator: &Identity,
    plan: &mut InjectionPlan,
) -> Result<()> {
    let endpoint = bind_client_endpoint(operator).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match resolve_peer_ticket(
            &plan.endpoint_id_hex,
            operator,
            &endpoint,
            plan.caps.clone(),
        )
        .await
        {
            Ok(ticket) => {
                plan.root_ticket_id = ticket_id(&ticket.sig);
                plan.ticket = ticket;
                return Ok(());
            }
            Err(err) if tokio::time::Instant::now() < deadline => {
                let _ = err;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(err) => {
                return Err(err).context("resolve injected agent address into connectable ticket");
            }
        }
    }
}

pub(super) fn prepare_injection_plan(operator: &Identity) -> Result<InjectionPlan> {
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

pub(super) fn resolve_binary_source(
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

pub(super) fn resolve_binary_path<H: HostOps>(
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

pub(super) fn platform_matches(
    host_os: &str,
    host_arch: &str,
    container: &ContainerSnapshot,
) -> bool {
    let Some(target_os) = container.target_os.as_deref() else {
        return true;
    };
    let Some(target_arch) = container.target_arch.as_deref() else {
        return true;
    };

    normalize_os(host_os) == normalize_os(target_os)
        && normalize_arch(host_arch) == normalize_arch(target_arch)
}

pub(super) fn normalize_os(value: &str) -> &str {
    match value {
        "macos" => "darwin",
        other => other,
    }
}

pub(super) fn normalize_arch(value: &str) -> &str {
    match value {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

pub(super) async fn run_container_command<D: DockerOps>(
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

pub(super) fn normalize_image(image: &str) -> String {
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

pub(super) async fn copy_binary_with_fallback<D: DockerOps>(
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

pub(super) fn injected_agent_env(identity: &Identity, operator: &Identity) -> Vec<String> {
    vec![
        format!(
            "PORTL_IDENTITY_SECRET_HEX={}",
            hex::encode(identity.signing_key().to_bytes())
        ),
        format!(
            "PORTL_TRUST_ROOTS={}",
            hex::encode(operator.verifying_key())
        ),
        "PORTL_DISCOVERY=dns,pkarr,local,relay".to_owned(),
        "PORTL_METRICS=0".to_owned(),
    ]
}

pub(super) async fn wait_for_agent_start<D: DockerOps>(
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

pub(super) async fn watch_container_restarts<D: DockerOps, H: HostOps>(
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

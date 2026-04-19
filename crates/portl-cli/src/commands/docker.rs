use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use docker_portl::{ADAPTER_NAME, DockerBootstrapper, DockerHandle};
use iroh_tickets::Ticket;
use portl_agent::{RevocationRecord, revocations};
use portl_core::bootstrap::{Bootstrapper, Handle, ProvisionSpec, TargetStatus, TicketSpec};
use portl_core::id::store;
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::verify::MAX_DELEGATION_DEPTH;

use crate::alias_store::{AliasRecord, AliasStore, StoredSpec, now_unix_secs};
use crate::commands::mint_root::{parse_caps, parse_endpoint_bytes, parse_ttl};

const DEFAULT_IMAGE: &str = "ghcr.io/knickknacklabs/portl-agent:latest";
const DEFAULT_NETWORK: &str = "bridge";

#[allow(clippy::too_many_arguments)]
pub fn add(
    name: &str,
    image: Option<&str>,
    network: Option<&str>,
    agent_caps: &str,
    ttl: &str,
    to: Option<&str>,
    labels: &[String],
    rm_existing: bool,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let ticket_spec = TicketSpec {
            caps: parse_caps(agent_caps)?,
            ttl_secs: parse_ttl(ttl)?,
            to: to.map(parse_endpoint_bytes).transpose()?,
            depth: MAX_DELEGATION_DEPTH,
        };
        let label_pairs = parse_labels(labels)?;
        add_with_ticket_spec(
            name,
            image.unwrap_or(DEFAULT_IMAGE),
            network.unwrap_or(DEFAULT_NETWORK),
            label_pairs,
            rm_existing,
            ticket_spec,
            &operator,
        )
        .await
    })
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
            .collect::<std::collections::HashMap<_, _>>();
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
        let Some(alias) = store.get(name)? else {
            bail!("unknown docker alias {name}");
        };
        let spec = store
            .get_spec(name)?
            .ok_or_else(|| anyhow!("missing stored spec for docker alias {name}"))?;
        let bootstrapper = DockerBootstrapper::connect_with_local_defaults(Vec::new())?;
        let handle = alias_to_handle(&alias);
        let status = bootstrapper.resolve(&handle).await?;
        ensure_rm_allowed(name, &status, force)?;

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

        store.remove(name)?;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn rebuild(name: &str) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let store = AliasStore::default();
        let alias = store
            .get(name)?
            .ok_or_else(|| anyhow!("unknown docker alias {name}"))?;
        let spec = store
            .get_spec(name)?
            .ok_or_else(|| anyhow!("missing stored spec for docker alias {name}"))?;
        let operator = store::load(&store::default_path()).context("load operator identity")?;

        rm(name, true, true)?;
        add_with_ticket_spec(
            &alias.name,
            &alias.image,
            &alias.network,
            spec.labels,
            false,
            TicketSpec {
                caps: spec.caps,
                ttl_secs: spec.ttl_secs,
                to: spec.to,
                depth: MAX_DELEGATION_DEPTH,
            },
            &operator,
        )
        .await
    })
}

pub fn logs(
    name: &str,
    follow: bool,
    tail: Option<&str>,
    deprecated_container_alias: bool,
) -> Result<ExitCode> {
    if deprecated_container_alias {
        eprintln!(
            "warning: `portl docker container logs` is deprecated; use `portl docker logs` instead"
        );
    }

    let store = AliasStore::default();
    let alias = store
        .get(name)?
        .ok_or_else(|| anyhow!("unknown docker alias {name}"))?;
    let mut command = ProcessCommand::new("docker");
    command.arg("logs");
    if follow {
        command.arg("--follow");
    }
    if let Some(tail) = tail {
        command.args(["--tail", tail]);
    }
    let status = command
        .arg(alias.container_id)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("run docker logs")?;
    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

async fn add_with_ticket_spec(
    name: &str,
    image: &str,
    network: &str,
    labels: Vec<(String, String)>,
    rm_existing: bool,
    ticket_spec: TicketSpec,
    operator: &portl_core::id::Identity,
) -> Result<ExitCode> {
    let bootstrapper =
        DockerBootstrapper::connect_with_local_defaults(vec![operator.verifying_key()])?;
    let provision_spec = ProvisionSpec {
        name: name.to_owned(),
        adapter_params: serde_json::json!({
            "image": image,
            "network": network,
            "rm_existing": rm_existing,
        }),
        labels: labels.clone(),
    };
    let handle = bootstrapper.provision(&provision_spec).await?;
    let docker_handle = DockerHandle::from_handle(&handle)?;
    let endpoint_bytes = parse_endpoint_bytes(&docker_handle.endpoint_id)?;
    let endpoint_id =
        iroh_base::EndpointId::from_bytes(&endpoint_bytes).context("decode endpoint id")?;
    bootstrapper.register(&handle, endpoint_id).await?;

    let now = u64::try_from(now_unix_secs()?)?;
    let ticket = mint_root(
        operator.signing_key(),
        iroh_base::EndpointAddr::new(endpoint_id),
        ticket_spec.caps.clone(),
        now,
        now.checked_add(ticket_spec.ttl_secs)
            .context("ticket ttl overflow")?,
        ticket_spec.to,
    )?;

    AliasStore::default().save(
        &AliasRecord {
            name: name.to_owned(),
            adapter: ADAPTER_NAME.to_owned(),
            container_id: docker_handle.container_id,
            endpoint_id: docker_handle.endpoint_id,
            image: image.to_owned(),
            network: network.to_owned(),
            created_at: now_unix_secs()?,
        },
        &StoredSpec {
            caps: ticket_spec.caps.clone(),
            ttl_secs: ticket_spec.ttl_secs,
            to: ticket_spec.to,
            labels,
            root_ticket_id: Some(ticket_id(&ticket.sig)),
            ticket_file_path: None,
            group_name: None,
            base_url: None,
        },
    )?;

    println!("{}", ticket.serialize());
    Ok(ExitCode::SUCCESS)
}

fn ensure_rm_allowed(name: &str, status: &TargetStatus, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }

    match status {
        TargetStatus::Exited { .. } | TargetStatus::NotFound => Ok(()),
        TargetStatus::Running | TargetStatus::Provisioning => bail!(
            "container '{name}' is still running; use `portl docker container rm {name} --force`"
        ),
        TargetStatus::Unknown(other) => bail!(
            "container '{name}' is not known to be stopped (status: {other}); use `portl docker container rm {name} --force`"
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

fn parse_labels(labels: &[String]) -> Result<Vec<(String, String)>> {
    labels
        .iter()
        .map(|label| {
            let (key, value) = label
                .split_once('=')
                .ok_or_else(|| anyhow!("label must look like KEY=VALUE: {label}"))?;
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{ensure_rm_allowed, revoke_ticket};
    use portl_core::bootstrap::TargetStatus;

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

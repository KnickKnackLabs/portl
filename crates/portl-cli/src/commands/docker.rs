use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use docker_portl::{ADAPTER_NAME, DockerBootstrapper, DockerHandle};
use iroh_tickets::Ticket;
use portl_core::bootstrap::{Bootstrapper, Handle, TargetSpec};
use portl_core::id::store;
use portl_core::ticket::mint::mint_root;

use crate::alias_store::{AliasRecord, AliasStore, StoredSpec, now_unix_secs};
use crate::commands::mint_root::{parse_caps, parse_endpoint_bytes, parse_ttl};

const DEFAULT_IMAGE: &str = "ghcr.io/knickknacklabs/portl-agent:latest";
const DEFAULT_NETWORK: &str = "bridge";
const DEFAULT_CAPS: &str = "shell";

pub fn add(
    name: &str,
    image: Option<&str>,
    network: Option<&str>,
    agent_caps: &str,
    ttl: &str,
    to: Option<&str>,
    labels: &[String],
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let caps = parse_caps(agent_caps)?;
        let ttl_secs = parse_ttl(ttl)?;
        let to_bytes = to.map(parse_endpoint_bytes).transpose()?;
        let labels = parse_labels(labels)?;
        let bootstrapper =
            DockerBootstrapper::connect_with_local_defaults(vec![operator.verifying_key()])?;
        let spec = TargetSpec {
            name: name.to_owned(),
            image: image.unwrap_or(DEFAULT_IMAGE).to_owned(),
            network: network.unwrap_or(DEFAULT_NETWORK).to_owned(),
            caps: caps.clone(),
            ttl_secs,
            to: to_bytes,
            labels: labels.clone(),
        };
        let handle = bootstrapper.provision(&spec).await?;
        let docker_handle = DockerHandle::from_handle(&handle)?;
        let endpoint_bytes = parse_endpoint_bytes(&docker_handle.endpoint_id)?;
        let endpoint_id =
            iroh_base::EndpointId::from_bytes(&endpoint_bytes).context("decode endpoint id")?;
        bootstrapper.register(&handle, endpoint_id).await?;

        let now = u64::try_from(now_unix_secs()?)?;
        let ticket = mint_root(
            operator.signing_key(),
            iroh_base::EndpointAddr::new(endpoint_id),
            caps.clone(),
            now,
            now.checked_add(ttl_secs).context("ticket ttl overflow")?,
            to_bytes,
        )?;

        AliasStore::default().save(
            &AliasRecord {
                name: name.to_owned(),
                adapter: ADAPTER_NAME.to_owned(),
                container_id: docker_handle.container_id,
                endpoint_id: docker_handle.endpoint_id,
                image: spec.image.clone(),
                network: spec.network.clone(),
                created_at: now_unix_secs()?,
            },
            &StoredSpec {
                caps,
                ttl_secs,
                to: to_bytes,
                labels,
            },
        )?;

        println!("{}", ticket.serialize());
        Ok(ExitCode::SUCCESS)
    })
}

pub fn list(json_output: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let bootstrapper = DockerBootstrapper::connect_with_local_defaults(Vec::new())?;
        let aliases = AliasStore::default().list()?;
        let rows = aliases
            .into_iter()
            .map(|alias| {
                let bootstrapper = bootstrapper.clone();
                async move {
                    let handle = alias_to_handle(&alias);
                    let status = bootstrapper.resolve(&handle).await?;
                    Ok::<_, anyhow::Error>(serde_json::json!({
                        "name": alias.name,
                        "container_id": alias.container_id,
                        "endpoint_id": alias.endpoint_id,
                        "image": alias.image,
                        "network": alias.network,
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
        } else {
            if rendered.is_empty() {
                println!("No docker aliases found.");
            } else {
                println!("NAME\tSTATUS\tENDPOINT\tIMAGE");
                for row in &rendered {
                    println!(
                        "{}\t{}\t{}\t{}",
                        row["name"].as_str().unwrap_or_default(),
                        row["status"].as_str().unwrap_or_default(),
                        row["endpoint_id"].as_str().unwrap_or_default(),
                        row["image"].as_str().unwrap_or_default(),
                    );
                }
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

pub fn rm(name: &str, _force: bool, _keep_tickets: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let store = AliasStore::default();
        let Some(alias) = store.get(name)? else {
            bail!("unknown docker alias {name}");
        };
        let bootstrapper = DockerBootstrapper::connect_with_local_defaults(Vec::new())?;
        bootstrapper.teardown(&alias_to_handle(&alias)).await?;
        store.remove(name)?;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn rebuild(name: &str) -> Result<ExitCode> {
    let store = AliasStore::default();
    let alias = store
        .get(name)?
        .ok_or_else(|| anyhow!("unknown docker alias {name}"))?;
    let spec = store
        .get_spec(name)?
        .ok_or_else(|| anyhow!("missing stored spec for docker alias {name}"))?;
    rm(name, false, false)?;
    let label_args = spec
        .labels
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let caps_json = serde_json::to_string(&spec.caps)?;
    let caps: portl_core::ticket::schema::Capabilities = serde_json::from_str(&caps_json)?;
    add(
        &alias.name,
        Some(&alias.image),
        Some(&alias.network),
        &render_caps(&caps),
        &format!("{}s", spec.ttl_secs),
        spec.to.map(|bytes| hex::encode(bytes)).as_deref(),
        &label_args,
    )
}

pub fn logs(name: &str, follow: bool, tail: Option<&str>) -> Result<ExitCode> {
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

fn render_caps(caps: &portl_core::ticket::schema::Capabilities) -> String {
    if caps.presence == 0b0000_0001 && caps.shell.is_some() {
        "shell".to_owned()
    } else {
        DEFAULT_CAPS.to_owned()
    }
}

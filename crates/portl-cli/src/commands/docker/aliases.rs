use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bollard::Docker;
use bollard::models::ContainerInspectResponse;
use docker_portl::ADAPTER_NAME;
use iroh_tickets::Ticket;
use portl_agent::{RevocationRecord, revocations};
use portl_core::bootstrap::{Handle, TargetStatus};
use portl_core::id::store;
use portl_core::ticket::schema::PortlTicket;

use crate::alias_store::{AliasRecord, AliasStore, StoredSpec, now_unix_secs};

use super::DEFAULT_NETWORK;
use super::types::{ContainerSnapshot, InjectionOutcome};

pub(super) async fn container_snapshot(
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

pub(super) fn save_injected_alias(outcome: &InjectionOutcome) -> Result<()> {
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
            session_provider: outcome.plan.session_provider.clone(),
            session_provider_install: outcome.session_provider_install.clone(),
            docker_exec_id: Some(outcome.exec_id.clone()),
            docker_injected_binary_path: Some(outcome.binary_path.clone()),
            docker_injected_binary_preexisted: outcome.binary_path_preexisted,
        },
    )
}

pub(super) fn resolve_alias_record(
    store: &AliasStore,
    name_or_id: &str,
) -> Result<Option<AliasRecord>> {
    if let Some(alias) = store.get(name_or_id)? {
        return Ok(Some(alias));
    }
    Ok(store
        .list()?
        .into_iter()
        .find(|alias| alias.container_id == name_or_id))
}

pub(super) fn ensure_rm_allowed(name: &str, status: &TargetStatus, force: bool) -> Result<()> {
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

pub(super) fn local_revocations_path() -> PathBuf {
    portl_core::paths::revocations_path()
}

pub(super) fn local_ticket_path(name: &str) -> PathBuf {
    store::default_path().parent().map_or_else(
        || PathBuf::from(format!("{name}.ticket")),
        |parent| parent.join("tickets").join(format!("{name}.ticket")),
    )
}

pub(super) fn write_ticket(path: &Path, ticket: &PortlTicket) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, ticket.serialize()).with_context(|| format!("write ticket {}", path.display()))
}

pub(super) fn ticket_not_after(created_at: i64, ttl_secs: u64) -> Option<u64> {
    u64::try_from(created_at).ok()?.checked_add(ttl_secs)
}

pub(super) fn revoke_ticket(
    ticket_id: [u8; 16],
    not_after_of_ticket: Option<u64>,
    path: &Path,
) -> Result<()> {
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

pub(super) fn alias_to_handle(alias: &AliasRecord) -> Handle {
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

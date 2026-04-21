use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_tickets::Ticket;
use portl_agent::revocations::RevocationRecord;
use portl_core::id::store;
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::schema::PortlTicket;

use crate::{alias_store::AliasStore, commands::revocations};

pub fn run(id_or_target: Option<&str>, list: bool, publish: bool) -> Result<ExitCode> {
    let path = local_revocations_path();
    if list {
        print!("{}", render_list(&path)?);
        return Ok(ExitCode::SUCCESS);
    }

    let target = id_or_target.ok_or_else(|| anyhow!("either <id> or --list is required"))?;
    let id = if AliasStore::default().get(target)?.is_some() {
        revoke_alias(target, &AliasStore::default(), &path)?
    } else {
        revoke_ticket_uri(target, &path)?
    };

    println!("revoked {}", hex::encode(id));
    if publish {
        return revocations::publish(Some(target), false);
    }
    Ok(ExitCode::SUCCESS)
}

fn revoke_alias(name: &str, store: &AliasStore, path: &Path) -> Result<[u8; 16]> {
    let id = alias_ticket_id(name, store)?;
    append_manual_revocation(id, path)?;
    Ok(id)
}

fn revoke_ticket_uri(uri: &str, path: &Path) -> Result<[u8; 16]> {
    let ticket =
        <PortlTicket as Ticket>::deserialize(uri).map_err(|err| anyhow!("parse ticket: {err}"))?;
    let id = ticket_id(&ticket.sig);
    append_manual_revocation(id, path)?;
    Ok(id)
}

fn alias_ticket_id(name: &str, store: &AliasStore) -> Result<[u8; 16]> {
    let _alias = store
        .get(name)?
        .ok_or_else(|| anyhow!("unknown alias {name}"))?;
    let spec = store
        .get_spec(name)?
        .ok_or_else(|| anyhow!("missing stored spec for alias {name}"))?;

    if let Some(id) = spec.root_ticket_id {
        return Ok(id);
    }
    if let Some(ticket_path) = spec.ticket_file_path {
        let raw = fs::read_to_string(&ticket_path)
            .with_context(|| format!("read stored ticket {}", ticket_path.display()))?;
        let ticket = <PortlTicket as Ticket>::deserialize(raw.trim())
            .map_err(|err| anyhow!("parse stored ticket {}: {err}", ticket_path.display()))?;
        return Ok(ticket_id(&ticket.sig));
    }

    bail!("alias {name} does not have a stored root ticket")
}

fn append_manual_revocation(id: [u8; 16], path: &Path) -> Result<()> {
    portl_agent::revocations::append_record(
        path,
        &RevocationRecord::new(id, "manual", unix_now_secs()?, None),
    )
}

fn render_list(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    fs::read_to_string(path).with_context(|| format!("read revocations from {}", path.display()))
}

pub(crate) fn local_revocations_path() -> PathBuf {
    store::default_path().parent().map_or_else(
        || PathBuf::from("revocations.jsonl"),
        |parent| parent.join("revocations.jsonl"),
    )
}

fn unix_now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use iroh_tickets::Ticket;
    use tempfile::tempdir;

    use super::{alias_ticket_id, render_list, revoke_alias, revoke_ticket_uri};
    use crate::alias_store::{AliasRecord, AliasStore, StoredSpec};
    use portl_core::id::Identity;
    use portl_core::ticket::hash::ticket_id;
    use portl_core::ticket::mint::mint_root;
    use portl_core::ticket::schema::Capabilities;

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
    fn revoke_alias_appends_record() {
        let dir = tempdir().expect("tempdir");
        let store = AliasStore::new(dir.path().join("aliases.sqlite"));
        store
            .save(
                &AliasRecord {
                    name: "demo".to_owned(),
                    adapter: "docker-portl".to_owned(),
                    container_id: "cid".to_owned(),
                    endpoint_id: "eid".to_owned(),
                    image: "img".to_owned(),
                    network: "bridge".to_owned(),
                    created_at: 7,
                },
                &StoredSpec {
                    caps: empty_caps(),
                    ttl_secs: 60,
                    to: None,
                    labels: vec![],
                    root_ticket_id: Some([0x11; 16]),
                    ticket_file_path: None,
                    group_name: None,
                    base_url: None,
                    docker_exec_id: None,
                    docker_injected_binary_path: None,
                },
            )
            .expect("save alias");

        let path = dir.path().join("revocations.jsonl");
        let revoked = revoke_alias("demo", &store, &path).expect("revoke alias");
        assert_eq!(revoked, [0x11; 16]);

        let contents = std::fs::read_to_string(path).expect("read revocations");
        assert!(contents.contains(&hex::encode([0x11; 16])));
        assert!(contents.contains("manual"));
    }

    #[test]
    fn revoke_uri_appends_record() {
        let dir = tempdir().expect("tempdir");
        let operator = Identity::new();
        let endpoint_id =
            iroh_base::EndpointId::from_bytes(&operator.verifying_key()).expect("endpoint id");
        let ticket = mint_root(
            operator.signing_key(),
            iroh_base::EndpointAddr::new(endpoint_id),
            empty_caps(),
            10,
            20,
            None,
        )
        .expect("mint root");
        let expected = ticket_id(&ticket.sig);

        let path = dir.path().join("revocations.jsonl");
        let revoked = revoke_ticket_uri(&ticket.serialize(), &path).expect("revoke uri");
        assert_eq!(revoked, expected);

        let contents = std::fs::read_to_string(path).expect("read revocations");
        assert!(contents.contains(&hex::encode(expected)));
        assert!(contents.contains("manual"));
    }

    #[test]
    fn list_renders_current_jsonl() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        std::fs::write(
            &path,
            concat!(
                "{\"ticket_id\":\"00112233445566778899aabbccddeeff\",\"reason\":\"manual\"}\n",
                "{\"ticket_id\":\"ffeeddccbbaa99887766554433221100\",\"reason\":\"manual\"}\n"
            ),
        )
        .expect("write revocations");

        assert_eq!(
            render_list(&path).expect("render list"),
            std::fs::read_to_string(path).expect("read raw")
        );
    }

    #[test]
    fn alias_ticket_id_falls_back_to_ticket_file() {
        let dir = tempdir().expect("tempdir");
        let store = AliasStore::new(dir.path().join("aliases.sqlite"));
        let operator = Identity::new();
        let endpoint_id =
            iroh_base::EndpointId::from_bytes(&operator.verifying_key()).expect("endpoint id");
        let ticket = mint_root(
            operator.signing_key(),
            iroh_base::EndpointAddr::new(endpoint_id),
            empty_caps(),
            10,
            20,
            None,
        )
        .expect("mint root");
        let ticket_path = dir.path().join("demo.ticket");
        std::fs::write(&ticket_path, ticket.serialize()).expect("write ticket");
        store
            .save(
                &AliasRecord {
                    name: "demo".to_owned(),
                    adapter: "slicer-portl".to_owned(),
                    container_id: "cid".to_owned(),
                    endpoint_id: "eid".to_owned(),
                    image: "img".to_owned(),
                    network: "bridge".to_owned(),
                    created_at: 7,
                },
                &StoredSpec {
                    caps: empty_caps(),
                    ttl_secs: 60,
                    to: None,
                    labels: vec![],
                    root_ticket_id: None,
                    ticket_file_path: Some(ticket_path),
                    group_name: None,
                    base_url: None,
                    docker_exec_id: None,
                    docker_injected_binary_path: None,
                },
            )
            .expect("save alias");

        assert_eq!(
            alias_ticket_id("demo", &store).expect("ticket id"),
            ticket_id(&ticket.sig)
        );
    }
}

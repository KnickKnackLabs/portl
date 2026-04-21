#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::Connection;
use iroh_tickets::Ticket;
use portl_agent::{RevocationRecord, revocations};
use portl_core::bootstrap::{Bootstrapper, ProvisionSpec};
use portl_core::endpoint::Endpoint;
use portl_core::id::{Identity, store};
use portl_core::net::{PeerSession, open_tcp, open_ticket_v1};
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::schema::PortlTicket;
use slicer_portl::http::SlicerClient;
use slicer_portl::{
    ADAPTER_NAME, SlicerBootstrapper, SlicerHandle, SlicerProvisionParams, parse_tag,
};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};

use crate::alias_store::{AliasRecord, AliasStore, StoredSpec, now_unix_secs};
use crate::commands::mint_root::{parse_caps, parse_ttl};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_TICKET_TTL: &str = "30d";
const DEFAULT_AGENT_CAPS: &str = "all";
const LOGIN_RECORD_FILE: &str = "slicer-login.json";

pub fn run(
    image: &str,
    base_url: Option<&str>,
    cpus: Option<u8>,
    ram_gb: Option<u16>,
    tags: &[String],
    ticket_out: Option<&Path>,
) -> Result<ExitCode> {
    vm_add(image, base_url, cpus, ram_gb, tags, ticket_out)
}

pub fn list(base_url: Option<&str>, json_output: bool) -> Result<ExitCode> {
    vm_list(base_url, json_output)
}

pub fn rm(name: &str, base_url: Option<&str>) -> Result<ExitCode> {
    vm_delete(name, base_url)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SlicerLoginRecord {
    ticket_file_path: PathBuf,
    base_url: String,
}

pub fn login(master_ticket_uri: &str, base_url: Option<&str>) -> Result<ExitCode> {
    let ticket = read_ticket(master_ticket_uri)?;
    validate_master_ticket_for_login(&ticket)?;

    let record = SlicerLoginRecord {
        ticket_file_path: slicer_home().join("master-tickets").join("slicer.ticket"),
        base_url: resolve_base_url(base_url),
    };
    write_ticket(&record.ticket_file_path, &ticket)?;
    write_login_record(&record)?;
    println!(
        "saved slicer master ticket to {}",
        record.ticket_file_path.display()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn vm_add(
    group: &str,
    base_url: Option<&str>,
    cpus: Option<u8>,
    ram_gb: Option<u16>,
    tags: &[String],
    ticket_out: Option<&Path>,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let label_pairs = tags
            .iter()
            .map(|tag| parse_tag(tag))
            .collect::<Result<Vec<_>>>()?;
        let client = client_for(base_url, &operator).await?;
        let bootstrapper = SlicerBootstrapper::new(client.client.clone());
        let provision = ProvisionSpec {
            name: format!("{group}-requested"),
            adapter_params: serde_json::to_value(SlicerProvisionParams {
                base_url: client.original_base_url.clone(),
                group: group.to_owned(),
                cpus,
                ram_gb,
                tags: label_pairs.clone(),
                relay_list: Vec::new(),
                operator_pubkey: hex::encode(operator.verifying_key()),
                portl_release_url: "github.com/KnickKnackLabs/portl/releases/download/latest"
                    .to_owned(),
                auth_token: None,
            })?,
            labels: Vec::new(),
        };
        let handle = bootstrapper.provision(&provision).await?;
        let inner = SlicerHandle::from_handle(&handle)?;
        let now = u64::try_from(now_unix_secs()?)?;
        let ticket = portl_core::ticket::mint::mint_root(
            operator.signing_key(),
            iroh_base::EndpointAddr::new(
                iroh_base::EndpointId::from_bytes(
                    &hex::decode(&inner.endpoint_id)?
                        .try_into()
                        .map_err(|_| anyhow!("endpoint id must be 32 bytes"))?,
                )
                .context("decode slicer endpoint id")?,
            ),
            parse_caps(DEFAULT_AGENT_CAPS)?,
            now,
            now.checked_add(parse_ttl(DEFAULT_TICKET_TTL)?)
                .context("ticket ttl overflow")?,
            None,
        )?;
        let ticket_path = ticket_out.map_or_else(
            || {
                slicer_home()
                    .join("tickets")
                    .join(format!("{}.ticket", inner.name))
            },
            Path::to_path_buf,
        );
        write_ticket(&ticket_path, &ticket)?;
        AliasStore::default().save(
            &AliasRecord {
                name: inner.name.clone(),
                adapter: ADAPTER_NAME.to_owned(),
                container_id: inner.name.clone(),
                endpoint_id: inner.endpoint_id.clone(),
                image: group.to_owned(),
                network: client.original_base_url.clone(),
                created_at: now_unix_secs()?,
            },
            &StoredSpec {
                caps: parse_caps(DEFAULT_AGENT_CAPS)?,
                ttl_secs: parse_ttl(DEFAULT_TICKET_TTL)?,
                to: None,
                labels: label_pairs,
                root_ticket_id: Some(ticket_id(&ticket.sig)),
                ticket_file_path: Some(ticket_path.clone()),
                group_name: Some(group.to_owned()),
                base_url: Some(client.original_base_url.clone()),
                docker_exec_id: None,
                docker_injected_binary_path: None,
                docker_injected_binary_preexisted: false,
            },
        )?;

        println!("{}", ticket.serialize());
        client.shutdown().await;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn vm_list(base_url: Option<&str>, json_output: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let client = client_for(base_url, &operator).await?;
        let listed = client.client.list_vms().await?;
        let aliases = AliasStore::default()
            .list()?
            .into_iter()
            .filter(|alias| alias.adapter == ADAPTER_NAME)
            .collect::<Vec<_>>();
        let rows = listed
            .into_iter()
            .map(|vm| {
                let alias = aliases.iter().find(|alias| alias.name == vm.name);
                serde_json::json!({
                    "name": vm.name,
                    "group": vm.group,
                    "status": vm.status,
                    "endpoint_id": alias.map_or("", |alias| alias.endpoint_id.as_str()),
                    "ip": vm.ip,
                })
            })
            .collect::<Vec<_>>();
        if json_output {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else if rows.is_empty() {
            println!("No slicer VMs found.");
        } else {
            println!("NAME\tGROUP\tSTATUS\tENDPOINT");
            for row in &rows {
                println!(
                    "{}\t{}\t{}\t{}",
                    row["name"].as_str().unwrap_or_default(),
                    row["group"].as_str().unwrap_or_default(),
                    row["status"].as_str().unwrap_or_default(),
                    row["endpoint_id"].as_str().unwrap_or_default(),
                );
            }
        }
        client.shutdown().await;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn vm_delete(name: &str, base_url: Option<&str>) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let store = AliasStore::default();
        let alias = store
            .get(name)?
            .ok_or_else(|| anyhow!("unknown slicer VM {name}"))?;
        let spec = store
            .get_spec(name)?
            .ok_or_else(|| anyhow!("missing stored spec for slicer VM {name}"))?;
        let group = spec
            .group_name
            .clone()
            .ok_or_else(|| anyhow!("missing slicer group for {name}"))?;
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let client = client_for(base_url.or(spec.base_url.as_deref()), &operator).await?;
        client.client.delete_vm(&group, &alias.container_id).await?;

        if let Some(root_ticket_id) = spec.root_ticket_id {
            append_revocation(
                root_ticket_id,
                ticket_not_after(alias.created_at, spec.ttl_secs),
                &local_revocations_path(),
            )?;
        }
        if let Some(ticket_path) = spec.ticket_file_path
            && let Err(err) = fs::remove_file(&ticket_path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            return Err(err)
                .with_context(|| format!("remove stored ticket {}", ticket_path.display()));
        }
        store.remove(name)?;
        client.shutdown().await;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn vm_logs(name: &str, base_url: Option<&str>, tail: usize) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let store = AliasStore::default();
        let alias = store
            .get(name)?
            .ok_or_else(|| anyhow!("unknown slicer VM {name}"))?;
        let spec = store
            .get_spec(name)?
            .ok_or_else(|| anyhow!("missing stored spec for slicer VM {name}"))?;
        let group = spec
            .group_name
            .clone()
            .ok_or_else(|| anyhow!("missing slicer group for {name}"))?;
        let operator = store::load(&store::default_path()).context("load operator identity")?;
        let client = client_for(base_url.or(spec.base_url.as_deref()), &operator).await?;
        let logs = client
            .client
            .vm_logs(&group, &alias.container_id, tail)
            .await?;
        print!("{logs}");
        client.shutdown().await;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn vm_shell(name: &str) -> Result<ExitCode> {
    crate::commands::shell::run(name, None, None)
}

struct ClientContext {
    client: SlicerClient,
    original_base_url: String,
    tunnel: Option<GatewayTunnel>,
}

impl ClientContext {
    async fn shutdown(self) {
        if let Some(tunnel) = self.tunnel {
            tunnel.shutdown().await;
        }
    }
}

async fn client_for(base_url: Option<&str>, identity: &Identity) -> Result<ClientContext> {
    let original_base_url = resolve_base_url(base_url);
    if let Some(login) = load_login_record()? {
        let tunnel = GatewayTunnel::open(&login, identity).await?;
        return Ok(ClientContext {
            client: SlicerClient::new(&tunnel.local_base_url, None)?,
            original_base_url,
            tunnel: Some(tunnel),
        });
    }

    Ok(ClientContext {
        client: SlicerClient::new(&original_base_url, None)?,
        original_base_url,
        tunnel: None,
    })
}

struct GatewayTunnel {
    endpoint: iroh::Endpoint,
    connection: Connection,
    task: tokio::task::JoinHandle<()>,
    local_base_url: String,
}

impl GatewayTunnel {
    async fn open(record: &SlicerLoginRecord, identity: &Identity) -> Result<Self> {
        let ticket = read_ticket_from_path(&record.ticket_file_path)?;
        let (remote_host, remote_port) = master_ticket_target(&ticket)?;
        let endpoint = portl_agent::endpoint::bind(
            &portl_agent::AgentConfig {
                discovery: portl_agent::DiscoveryConfig::in_process(),
                ..portl_agent::AgentConfig::default()
            },
            identity,
        )
        .await
        .context("bind local gateway client endpoint")?;
        let endpoint_wrapper = Endpoint::from(endpoint.clone());
        let (connection, session) = open_ticket_v1(&endpoint_wrapper, &ticket, &[], identity)
            .await
            .context("connect slicer gateway")?;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("bind local slicer HTTP tunnel")?;
        let local_addr = listener.local_addr().context("local slicer tunnel addr")?;
        let connection_for_task = connection.clone();
        let session_for_task = session.clone();
        let remote_host_for_task = remote_host.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((local, _)) = listener.accept().await else {
                    break;
                };
                let connection = connection_for_task.clone();
                let session = session_for_task.clone();
                let remote_host = remote_host_for_task.clone();
                tokio::spawn(async move {
                    let _ =
                        forward_one(local, connection, session, &remote_host, remote_port).await;
                });
            }
        });

        Ok(Self {
            endpoint,
            connection,
            task,
            local_base_url: format!("http://127.0.0.1:{}", local_addr.port()),
        })
    }

    async fn shutdown(self) {
        self.connection.close(0u32.into(), b"done");
        self.task.abort();
        self.endpoint.close().await;
    }
}

async fn forward_one(
    local: TcpStream,
    connection: Connection,
    session: PeerSession,
    remote_host: &str,
    remote_port: u16,
) -> Result<()> {
    let (mut send, mut recv) = open_tcp(&connection, &session, remote_host, remote_port).await?;
    let (mut local_read, mut local_write) = local.into_split();
    let upstream = async {
        copy(&mut local_read, &mut send)
            .await
            .context("copy local->gateway")?;
        send.finish().context("finish gateway send")?;
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        copy(&mut recv, &mut local_write)
            .await
            .context("copy gateway->local")?;
        local_write
            .shutdown()
            .await
            .context("shutdown local write")?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}

fn master_ticket_target(ticket: &PortlTicket) -> Result<(String, u16)> {
    let rule = ticket
        .body
        .caps
        .tcp
        .as_ref()
        .and_then(|rules| rules.first())
        .ok_or_else(|| anyhow!("master ticket must grant a tcp destination"))?;
    if rule.host_glob.contains('*') || rule.port_min != rule.port_max {
        bail!("master ticket tcp rule must be a single concrete host:port");
    }
    Ok((rule.host_glob.clone(), rule.port_min))
}

fn write_login_record(record: &SlicerLoginRecord) -> Result<()> {
    let path = slicer_home().join(LOGIN_RECORD_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create slicer config dir {}", parent.display()))?;
    }
    fs::write(
        &path,
        serde_json::to_vec_pretty(record).context("encode slicer login record")?,
    )
    .with_context(|| format!("write slicer login record {}", path.display()))
}

fn load_login_record() -> Result<Option<SlicerLoginRecord>> {
    let path = slicer_home().join(LOGIN_RECORD_FILE);
    if !path.exists() {
        return Ok(None);
    }
    serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read slicer login record {}", path.display()))?,
    )
    .map(Some)
    .context("decode slicer login record")
}

fn resolve_base_url(flag: Option<&str>) -> String {
    flag.map(ToOwned::to_owned)
        .or_else(|| std::env::var("SLICER_API_URL").ok())
        .or_else(|| {
            load_login_record()
                .ok()
                .flatten()
                .map(|record| record.base_url)
        })
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned())
}

fn validate_master_ticket_for_login(ticket: &PortlTicket) -> Result<()> {
    if ticket.body.bearer.as_deref().is_none_or(<[u8]>::is_empty) {
        bail!("slicer login requires a master ticket with a non-empty bearer");
    }
    if ticket.body.bearer.is_some() && ticket.body.to.is_none() {
        return Err(anyhow!(
            "master tickets MUST be bound to a holder via --to; this ticket is bearer-only and would grant unrestricted access to anyone"
        ));
    }
    Ok(())
}

fn read_ticket(spec: &str) -> Result<PortlTicket> {
    if Path::new(spec).exists() {
        return read_ticket_from_path(Path::new(spec));
    }
    <PortlTicket as Ticket>::deserialize(spec).map_err(|err| anyhow!("parse ticket: {err}"))
}

fn read_ticket_from_path(path: &Path) -> Result<PortlTicket> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("read ticket {}", path.display()))?;
    <PortlTicket as Ticket>::deserialize(raw.trim())
        .map_err(|err| anyhow!("parse ticket {}: {err}", path.display()))
}

fn write_ticket(path: &Path, ticket: &PortlTicket) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, ticket.serialize()).with_context(|| format!("write ticket {}", path.display()))
}

fn slicer_home() -> PathBuf {
    store::default_path()
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn local_revocations_path() -> PathBuf {
    slicer_home().join("revocations.jsonl")
}

fn ticket_not_after(created_at: i64, ttl_secs: u64) -> Option<u64> {
    u64::try_from(created_at).ok()?.checked_add(ttl_secs)
}

fn append_revocation(
    ticket_id: [u8; 16],
    not_after_of_ticket: Option<u64>,
    path: &Path,
) -> Result<()> {
    revocations::append_record(
        path,
        &RevocationRecord::new(
            ticket_id,
            "slicer_vm_delete",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before unix epoch")?
                .as_secs(),
            not_after_of_ticket,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::{append_revocation, master_ticket_target, validate_master_ticket_for_login};
    use tempfile::tempdir;

    #[test]
    fn append_revocation_writes_jsonl() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("revocations.jsonl");
        append_revocation([0x11; 16], Some(99), &path).expect("append revocation");
        let contents = std::fs::read_to_string(path).expect("read revocations");
        assert!(contents.contains("slicer_vm_delete"));
        assert!(contents.contains(&hex::encode([0x11; 16])));
        assert!(contents.contains("99"));
    }

    #[test]
    fn slicer_login_rejects_bearer_without_to() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[70u8; 32]);
        let addr = iroh_base::EndpointAddr::new(
            iroh_base::EndpointId::from_bytes(&issuer.verifying_key().to_bytes()).unwrap(),
        );
        let mut ticket = portl_core::ticket::master::mint_master(
            &issuer,
            addr,
            portl_core::ticket::schema::Capabilities {
                presence: 0b0000_0010,
                shell: None,
                tcp: Some(vec![portl_core::ticket::schema::PortRule {
                    host_glob: "127.0.0.1".to_owned(),
                    port_min: 8080,
                    port_max: 8080,
                }]),
                udp: None,
                fs: None,
                vpn: None,
                meta: None,
            },
            b"slicer-token".to_vec(),
            60,
            [1u8; 32],
        )
        .expect("mint master ticket");
        ticket.body.to = None;

        let err = validate_master_ticket_for_login(&ticket)
            .expect_err("bearer-only master ticket must be rejected");
        assert!(
            err.to_string()
                .contains("master tickets MUST be bound to a holder")
        );
    }

    #[test]
    fn master_ticket_target_requires_concrete_rule() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[71u8; 32]);
        let addr = iroh_base::EndpointAddr::new(
            iroh_base::EndpointId::from_bytes(&issuer.verifying_key().to_bytes()).unwrap(),
        );
        let mut ticket = portl_core::ticket::master::mint_master(
            &issuer,
            addr,
            portl_core::ticket::schema::Capabilities {
                presence: 0b0000_0010,
                shell: None,
                tcp: Some(vec![portl_core::ticket::schema::PortRule {
                    host_glob: "127.0.0.1".to_owned(),
                    port_min: 8080,
                    port_max: 8080,
                }]),
                udp: None,
                fs: None,
                vpn: None,
                meta: None,
            },
            vec![1],
            60,
            [2u8; 32],
        )
        .expect("mint master ticket");
        assert_eq!(
            master_ticket_target(&ticket).expect("concrete rule"),
            ("127.0.0.1".to_owned(), 8080)
        );
        ticket.body.caps.tcp.as_mut().unwrap()[0].host_glob = "*.example.com".to_owned();
        assert!(master_ticket_target(&ticket).is_err());
    }
}

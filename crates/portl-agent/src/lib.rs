use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use portl_core::id::{Identity, store};
use portl_core::ticket::verify::TrustRoots;
use tokio::task::JoinHandle;
use tracing::{instrument, warn};

pub mod audit;
pub mod caps_enforce;
pub mod config;
pub mod endpoint;
pub mod meta_handler;
pub mod pipeline;
pub mod rate_limit;
pub mod revocations;
pub mod session;
pub mod shell_handler;
pub mod shell_registry;
pub mod stream_io;
pub mod tcp_handler;
pub mod ticket_handler;

pub use config::{AgentConfig, DiscoveryConfig, RateLimitConfig};
pub use pipeline::{AcceptanceInput, AcceptanceOutcome, evaluate_offer};
pub use rate_limit::OfferRateLimiter;
pub use revocations::RevocationSet;

#[allow(dead_code)]
pub(crate) struct AgentState {
    pub trust_roots: TrustRoots,
    pub revocations: RevocationSet,
    pub rate_limit: OfferRateLimiter,
    pub started_at: Instant,
    pub shell_registry: shell_registry::ShellRegistry,
}

#[instrument(skip_all)]
pub async fn run(cfg: AgentConfig) -> Result<()> {
    audit::init();

    let state = Arc::new(AgentState {
        trust_roots: TrustRoots(cfg.trust_roots.iter().copied().collect::<HashSet<_>>()),
        revocations: RevocationSet::load(revocations_path(&cfg))?,
        rate_limit: OfferRateLimiter::new(&cfg.rate_limit)?,
        started_at: Instant::now(),
        shell_registry: shell_registry::ShellRegistry::default(),
    });

    let endpoint = if let Some(endpoint) = cfg.endpoint.clone() {
        endpoint
            .inner()
            .set_alpns(vec![portl_proto::ticket_v1::ALPN_TICKET_V1.to_vec()]);
        endpoint.inner().clone()
    } else {
        let identity = load_identity(&cfg)?;
        endpoint::bind(&cfg, &identity).await?
    };

    while let Some(incoming) = endpoint.accept().await {
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(err) => {
                warn!(?err, "failed to accept incoming connection");
                continue;
            }
        };

        if connection.alpn() == portl_proto::ticket_v1::ALPN_TICKET_V1 {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(err) = ticket_handler::serve_connection(connection, state).await {
                    warn!(?err, "ticket connection failed");
                }
            });
        } else {
            connection.close(0x1003u32.into(), b"unsupported ALPN");
        }
    }

    Ok(())
}

#[instrument(skip_all)]
pub async fn run_task(cfg: AgentConfig) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move { run(cfg).await }))
}

fn load_identity(cfg: &AgentConfig) -> Result<Identity> {
    let path = cfg
        .identity_path
        .clone()
        .unwrap_or_else(store::default_path);
    store::load(&path).map_err(Into::into)
}

fn revocations_path(cfg: &AgentConfig) -> PathBuf {
    cfg.revocations_path.clone().unwrap_or_else(|| {
        cfg.identity_path
            .clone()
            .unwrap_or_else(store::default_path)
            .parent()
            .map_or_else(
                || PathBuf::from("revocations.json"),
                |parent| parent.join("revocations.json"),
            )
    })
}

#[cfg(test)]
mod tests {
    use portl_core::endpoint::Endpoint;

    use super::{AgentConfig, DiscoveryConfig, run_task};

    #[tokio::test]
    async fn run_task_returns_and_stops_when_endpoint_closes() {
        let endpoint = Endpoint::bind().await.expect("bind endpoint");
        let runtime_endpoint = endpoint.clone();
        let handle = run_task(AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            endpoint: Some(runtime_endpoint),
            ..AgentConfig::default()
        })
        .await
        .expect("spawn task");

        endpoint.inner().close().await;
        handle.await.expect("join handle").expect("run result");
    }
}

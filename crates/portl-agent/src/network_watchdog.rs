use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::DiscoveryConfig;
use anyhow::{Context, Result, bail};
use iroh::endpoint::{RelayMode, presets};
use iroh_base::{EndpointAddr, SecretKey, TransportAddr};
use portl_core::endpoint::Endpoint;
use portl_core::id::Identity;
use portl_core::net::open_ticket_v1;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, MetaCaps};
use portl_proto::meta_v1::{MetaReq, MetaResp};
use portl_proto::wire::StreamPreamble;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchdogState {
    Disabled,
    Ok,
    Degraded,
    Refreshing,
    Failed,
}

pub const RECENT_INBOUND_SKIP_MULTIPLIER: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub timeout: Duration,
    pub failures_before_refresh: u32,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_mins(5),
            timeout: Duration::from_secs(5),
            failures_before_refresh: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkHealthSnapshot {
    pub state: WatchdogState,
    pub endpoint_generation: u64,
    pub endpoint_started_at: u64,
    pub last_inbound_handshake_at: Option<u64>,
    pub last_self_probe_ok_at: Option<u64>,
    pub last_self_probe_failed_at: Option<u64>,
    pub consecutive_self_probe_failures: u32,
    pub endpoint_refresh_count: u64,
    pub consecutive_endpoint_refresh_failures: u32,
    pub last_endpoint_refresh_at: Option<u64>,
    pub next_endpoint_refresh_not_before: Option<u64>,
    pub last_endpoint_refresh_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeFailureAction {
    consecutive_failures: u32,
}

impl ProbeFailureAction {
    #[must_use]
    pub fn should_refresh(&self, config: &WatchdogConfig) -> bool {
        config.enabled && self.consecutive_failures >= config.failures_before_refresh.max(1)
    }
}

#[derive(Debug)]
struct Inner {
    state: WatchdogState,
    endpoint_generation: u64,
    endpoint_started_at: u64,
    last_inbound_handshake_at: Option<u64>,
    last_self_probe_ok_at: Option<u64>,
    last_self_probe_failed_at: Option<u64>,
    consecutive_self_probe_failures: u32,
    endpoint_refresh_count: u64,
    consecutive_endpoint_refresh_failures: u32,
    last_endpoint_refresh_at: Option<u64>,
    next_endpoint_refresh_not_before: Option<u64>,
    last_endpoint_refresh_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkWatchdogHealth {
    inner: Arc<RwLock<Inner>>,
}

impl NetworkWatchdogHealth {
    #[must_use]
    pub fn new(now: SystemTime) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                state: WatchdogState::Ok,
                endpoint_generation: 1,
                endpoint_started_at: unix_secs(now),
                last_inbound_handshake_at: None,
                last_self_probe_ok_at: None,
                last_self_probe_failed_at: None,
                consecutive_self_probe_failures: 0,
                endpoint_refresh_count: 0,
                consecutive_endpoint_refresh_failures: 0,
                last_endpoint_refresh_at: None,
                next_endpoint_refresh_not_before: None,
                last_endpoint_refresh_error: None,
            })),
        }
    }

    #[must_use]
    pub fn disabled(now: SystemTime) -> Self {
        let health = Self::new(now);
        health.set_disabled();
        health
    }

    pub fn set_disabled(&self) {
        let mut inner = self.inner.write().expect("watchdog health lock");
        inner.state = WatchdogState::Disabled;
    }

    pub fn record_inbound_handshake(&self, now: SystemTime) {
        let mut inner = self.inner.write().expect("watchdog health lock");
        inner.last_inbound_handshake_at = Some(unix_secs(now));
        inner.consecutive_self_probe_failures = 0;
        inner.consecutive_endpoint_refresh_failures = 0;
        inner.next_endpoint_refresh_not_before = None;
        inner.last_endpoint_refresh_error = None;
        inner.state = WatchdogState::Ok;
    }

    pub fn record_probe_success(&self, now: SystemTime) {
        let mut inner = self.inner.write().expect("watchdog health lock");
        inner.last_self_probe_ok_at = Some(unix_secs(now));
        inner.consecutive_self_probe_failures = 0;
        inner.consecutive_endpoint_refresh_failures = 0;
        inner.next_endpoint_refresh_not_before = None;
        inner.last_endpoint_refresh_error = None;
        inner.state = WatchdogState::Ok;
    }

    pub fn record_probe_failure(&self, now: SystemTime) -> ProbeFailureAction {
        let mut inner = self.inner.write().expect("watchdog health lock");
        inner.last_self_probe_failed_at = Some(unix_secs(now));
        inner.consecutive_self_probe_failures =
            inner.consecutive_self_probe_failures.saturating_add(1);
        if inner.state != WatchdogState::Failed {
            inner.state = WatchdogState::Degraded;
        }
        ProbeFailureAction {
            consecutive_failures: inner.consecutive_self_probe_failures,
        }
    }

    pub fn record_endpoint_refresh_started(&self) {
        let mut inner = self.inner.write().expect("watchdog health lock");
        inner.consecutive_self_probe_failures = 0;
        inner.state = WatchdogState::Refreshing;
    }

    pub fn record_endpoint_refresh_success(&self, now: SystemTime) {
        let mut inner = self.inner.write().expect("watchdog health lock");
        inner.endpoint_generation = inner.endpoint_generation.saturating_add(1);
        inner.endpoint_started_at = unix_secs(now);
        inner.endpoint_refresh_count = inner.endpoint_refresh_count.saturating_add(1);
        inner.last_endpoint_refresh_at = Some(unix_secs(now));
        inner.last_inbound_handshake_at = None;
        inner.last_endpoint_refresh_error = None;
        inner.consecutive_self_probe_failures = 0;
        inner.consecutive_endpoint_refresh_failures = 0;
        inner.next_endpoint_refresh_not_before = None;
        inner.state = WatchdogState::Ok;
    }

    pub fn record_endpoint_refresh_failure(&self, now: SystemTime, error: String) {
        let mut inner = self.inner.write().expect("watchdog health lock");
        let now_secs = unix_secs(now);
        inner.last_endpoint_refresh_at = Some(now_secs);
        inner.consecutive_endpoint_refresh_failures = inner
            .consecutive_endpoint_refresh_failures
            .saturating_add(1);
        inner.next_endpoint_refresh_not_before = Some(now_secs.saturating_add(
            refresh_backoff(inner.consecutive_endpoint_refresh_failures).as_secs(),
        ));
        inner.last_endpoint_refresh_error = Some(error);
        inner.state = WatchdogState::Failed;
    }

    #[must_use]
    pub fn refresh_allowed(&self, now: SystemTime) -> bool {
        let inner = self.inner.read().expect("watchdog health lock");
        inner
            .next_endpoint_refresh_not_before
            .is_none_or(|not_before| unix_secs(now) >= not_before)
    }

    #[must_use]
    pub fn recent_inbound_at(&self) -> Option<u64> {
        self.inner
            .read()
            .expect("watchdog health lock")
            .last_inbound_handshake_at
    }

    pub fn snapshot(&self, _now: SystemTime) -> NetworkHealthSnapshot {
        let inner = self.inner.read().expect("watchdog health lock");
        NetworkHealthSnapshot {
            state: inner.state,
            endpoint_generation: inner.endpoint_generation,
            endpoint_started_at: inner.endpoint_started_at,
            last_inbound_handshake_at: inner.last_inbound_handshake_at,
            last_self_probe_ok_at: inner.last_self_probe_ok_at,
            last_self_probe_failed_at: inner.last_self_probe_failed_at,
            consecutive_self_probe_failures: inner.consecutive_self_probe_failures,
            endpoint_refresh_count: inner.endpoint_refresh_count,
            consecutive_endpoint_refresh_failures: inner.consecutive_endpoint_refresh_failures,
            last_endpoint_refresh_at: inner.last_endpoint_refresh_at,
            next_endpoint_refresh_not_before: inner.next_endpoint_refresh_not_before,
            last_endpoint_refresh_error: inner.last_endpoint_refresh_error.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Success,
    Failure(String),
}

#[must_use]
pub fn apply_probe_outcome(
    config: &WatchdogConfig,
    health: &NetworkWatchdogHealth,
    now: SystemTime,
    outcome: ProbeOutcome,
) -> bool {
    match outcome {
        ProbeOutcome::Success => {
            health.record_probe_success(now);
            false
        }
        ProbeOutcome::Failure(_error) => health.record_probe_failure(now).should_refresh(config),
    }
}

#[derive(Debug)]
pub enum WatchdogCommand {
    RefreshEndpoint,
}

pub fn spawn_watchdog_task(
    config: WatchdogConfig,
    health: NetworkWatchdogHealth,
    probe_identity: Identity,
    discovery: DiscoveryConfig,
    mut endpoint_rx: watch::Receiver<iroh::Endpoint>,
    refresh_tx: mpsc::UnboundedSender<WatchdogCommand>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if !config.enabled {
            health.set_disabled();
            return;
        }
        let mut interval = tokio::time::interval(jittered_interval(config.interval));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    if health.snapshot(SystemTime::now()).state == WatchdogState::Refreshing {
                        debug!("watchdog skipped self-probe while endpoint refresh is in flight");
                        continue;
                    }
                    if should_skip_probe_after_recent_inbound(&health, &config, SystemTime::now()) {
                        debug!("watchdog skipped self-probe after recent inbound connection");
                        continue;
                    }
                    let endpoint = endpoint_rx.borrow_and_update().clone();
                    let outcome = match tokio::time::timeout(
                        config.timeout,
                        self_probe(&probe_identity, &discovery, endpoint),
                    ).await {
                        Ok(Ok(())) => ProbeOutcome::Success,
                        Ok(Err(err)) => ProbeOutcome::Failure(format!("{err:#}")),
                        Err(_) => ProbeOutcome::Failure(format!(
                            "self-probe timed out after {}",
                            humantime::format_duration(config.timeout)
                        )),
                    };
                    let should_refresh = apply_probe_outcome(&config, &health, SystemTime::now(), outcome.clone());
                    match outcome {
                        ProbeOutcome::Success => debug!("watchdog self-probe succeeded"),
                        ProbeOutcome::Failure(error) => warn!(%error, "watchdog self-probe failed"),
                    }
                    if should_refresh && !health.refresh_allowed(SystemTime::now()) {
                        debug!("watchdog skipped endpoint refresh while refresh backoff is active");
                        continue;
                    }
                    if should_refresh {
                        health.record_endpoint_refresh_started();
                        if refresh_tx.send(WatchdogCommand::RefreshEndpoint).is_err() {
                            health.record_endpoint_refresh_failure(
                                SystemTime::now(),
                                "agent accept loop is unavailable".to_owned(),
                            );
                            break;
                        }
                    }
                }
            }
        }
    })
}

fn should_skip_probe_after_recent_inbound(
    health: &NetworkWatchdogHealth,
    config: &WatchdogConfig,
    now: SystemTime,
) -> bool {
    let Some(last) = health.recent_inbound_at() else {
        return false;
    };
    let window = config
        .interval
        .saturating_mul(RECENT_INBOUND_SKIP_MULTIPLIER);
    unix_secs(now).saturating_sub(last) <= window.as_secs()
}

async fn self_probe(
    probe_identity: &Identity,
    discovery: &DiscoveryConfig,
    agent_endpoint: iroh::Endpoint,
) -> Result<()> {
    let agent_endpoint_wrapper = Endpoint::from(agent_endpoint.clone());
    let addr = wait_for_probe_addr(&agent_endpoint_wrapper, discovery).await?;
    let now = unix_secs(SystemTime::now());
    let ticket = mint_root(
        probe_identity.signing_key(),
        addr,
        meta_caps(),
        now,
        now.saturating_add(60),
        None,
    )
    .context("mint watchdog self-probe ticket")?;
    let client_endpoint = bind_probe_endpoint(probe_identity, discovery).await?;
    let client_endpoint_wrapper = Endpoint::from(client_endpoint.clone());
    let result = open_ticket_v1(&client_endpoint_wrapper, &ticket, &[], probe_identity)
        .await
        .context("run watchdog self-probe ticket handshake");
    let (connection, session) = match result {
        Ok(value) => value,
        Err(err) => {
            client_endpoint.close().await;
            return Err(err);
        }
    };
    let envelope = MetaEnvelope {
        preamble: StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1).into_owned(),
        },
        req: MetaReq::Ping {
            t_client_us: unix_micros(SystemTime::now()),
        },
    };
    let bytes = postcard::to_stdvec(&envelope).context("encode watchdog meta ping")?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("open watchdog meta stream")?;
    send.write_all(&bytes)
        .await
        .context("write watchdog meta ping")?;
    send.finish().context("finish watchdog meta ping")?;
    let response_bytes = recv
        .read_to_end(64 * 1024)
        .await
        .context("read watchdog meta ping response")?;
    match postcard::from_bytes::<MetaResp>(&response_bytes).context("decode watchdog meta ping")? {
        MetaResp::Pong { .. } => {
            connection.close(0u32.into(), b"watchdog self-probe complete");
            client_endpoint.close().await;
            Ok(())
        }
        MetaResp::Error(error) => {
            client_endpoint.close().await;
            bail!(
                "watchdog meta ping failed: {} ({:?})",
                error.message,
                error.kind
            )
        }
        other => {
            client_endpoint.close().await;
            bail!("unexpected watchdog meta response: {other:?}")
        }
    }
}

async fn wait_for_probe_addr(
    endpoint: &Endpoint,
    discovery: &DiscoveryConfig,
) -> Result<EndpointAddr> {
    for _ in 0..20 {
        let addr = endpoint.addr();
        if let Some(relay_addr) = relay_only_probe_addr(&addr, discovery) {
            return Ok(relay_addr);
        }
        if discovery.relays.is_empty() && !addr.is_empty() {
            return Ok(addr);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("agent endpoint did not publish a dialable address for watchdog self-probe")
}

fn relay_only_probe_addr(addr: &EndpointAddr, discovery: &DiscoveryConfig) -> Option<EndpointAddr> {
    if discovery.relays.is_empty() {
        return None;
    }
    let relays = addr
        .relay_urls()
        .cloned()
        .map(TransportAddr::Relay)
        .collect::<Vec<_>>();
    (!relays.is_empty()).then(|| EndpointAddr::from_parts(addr.id, relays))
}

async fn bind_probe_endpoint(
    identity: &Identity,
    discovery: &DiscoveryConfig,
) -> Result<iroh::Endpoint> {
    let mut builder = iroh::Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&identity.signing_key().to_bytes()));
    builder = if discovery.relays.is_empty() {
        builder.relay_mode(RelayMode::Disabled)
    } else {
        builder.relay_mode(RelayMode::custom(discovery.relays.iter().cloned()))
    };
    builder.bind().await.map_err(Into::into)
}

fn meta_caps() -> Capabilities {
    Capabilities {
        presence: 0b0010_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: Some(MetaCaps {
            ping: true,
            info: false,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MetaEnvelope {
    preamble: StreamPreamble,
    req: MetaReq,
}

fn refresh_backoff(consecutive_failures: u32) -> Duration {
    match consecutive_failures {
        0 | 1 => Duration::from_mins(5),
        2 => Duration::from_mins(10),
        3 => Duration::from_mins(20),
        _ => Duration::from_hours(1),
    }
}

fn jittered_interval(interval: Duration) -> Duration {
    if interval <= Duration::from_secs(1) {
        return interval;
    }
    let jitter_window = (interval / 10).max(Duration::from_secs(1));
    let jitter = Duration::from_millis(
        u64::from(std::process::id()) % u64::try_from(jitter_window.as_millis()).unwrap_or(1),
    );
    interval.saturating_add(jitter)
}

fn unix_micros(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn inbound_handshake_resets_failures_and_marks_ok() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_probe_failure(ts(110));
        health.record_probe_failure(ts(120));

        health.record_inbound_handshake(ts(130));

        let snapshot = health.snapshot(ts(140));
        assert_eq!(snapshot.state, WatchdogState::Ok);
        assert_eq!(snapshot.consecutive_self_probe_failures, 0);
        assert_eq!(snapshot.last_inbound_handshake_at, Some(130));
    }

    #[test]
    fn repeated_failures_request_endpoint_refresh_at_threshold() {
        let config = WatchdogConfig::default();
        assert_eq!(config.failures_before_refresh, 3);
        let health = NetworkWatchdogHealth::new(ts(100));

        assert!(!health.record_probe_failure(ts(110)).should_refresh(&config));
        assert!(!health.record_probe_failure(ts(120)).should_refresh(&config));
        assert!(health.record_probe_failure(ts(130)).should_refresh(&config));

        let snapshot = health.snapshot(ts(131));
        assert_eq!(snapshot.state, WatchdogState::Degraded);
        assert_eq!(snapshot.consecutive_self_probe_failures, 3);
    }

    #[test]
    fn endpoint_refresh_increments_generation_and_resets_failures() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_probe_failure(ts(110));
        health.record_probe_failure(ts(120));

        health.record_endpoint_refresh_success(ts(130));

        let snapshot = health.snapshot(ts(140));
        assert_eq!(snapshot.state, WatchdogState::Ok);
        assert_eq!(snapshot.endpoint_generation, 2);
        assert_eq!(snapshot.endpoint_refresh_count, 1);
        assert_eq!(snapshot.last_endpoint_refresh_at, Some(130));
        assert_eq!(snapshot.last_inbound_handshake_at, None);
        assert_eq!(snapshot.consecutive_self_probe_failures, 0);
    }

    #[test]
    fn refresh_started_resets_failures_to_prevent_duplicate_refresh_requests() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_probe_failure(ts(110));
        health.record_probe_failure(ts(120));
        health.record_probe_failure(ts(130));

        health.record_endpoint_refresh_started();

        let snapshot = health.snapshot(ts(131));
        assert_eq!(snapshot.state, WatchdogState::Refreshing);
        assert_eq!(snapshot.consecutive_self_probe_failures, 0);
    }

    #[test]
    fn refresh_success_clears_stale_inbound_skip_window() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_inbound_handshake(ts(120));

        health.record_endpoint_refresh_success(ts(130));

        let snapshot = health.snapshot(ts(131));
        assert_eq!(snapshot.last_inbound_handshake_at, None);
    }

    #[test]
    fn refresh_failure_records_error_and_failed_state() {
        let health = NetworkWatchdogHealth::new(ts(100));

        health.record_endpoint_refresh_failure(ts(120), "bind failed".to_owned());

        let snapshot = health.snapshot(ts(121));
        assert_eq!(snapshot.state, WatchdogState::Failed);
        assert_eq!(snapshot.consecutive_endpoint_refresh_failures, 1);
        assert_eq!(snapshot.next_endpoint_refresh_not_before, Some(420));
        assert_eq!(
            snapshot.last_endpoint_refresh_error.as_deref(),
            Some("bind failed")
        );
    }

    #[test]
    fn refresh_failures_apply_exponential_backoff() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_endpoint_refresh_failure(ts(100), "one".to_owned());
        assert!(!health.refresh_allowed(ts(399)));
        assert!(health.refresh_allowed(ts(400)));

        health.record_endpoint_refresh_failure(ts(400), "two".to_owned());
        let snapshot = health.snapshot(ts(401));
        assert_eq!(snapshot.consecutive_endpoint_refresh_failures, 2);
        assert_eq!(snapshot.next_endpoint_refresh_not_before, Some(1_000));
        assert!(!health.refresh_allowed(ts(999)));
        assert!(health.refresh_allowed(ts(1_000)));
    }

    #[test]
    fn probe_success_clears_refresh_failure_backoff() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_endpoint_refresh_failure(ts(100), "bind failed".to_owned());
        assert!(!health.refresh_allowed(ts(399)));

        health.record_probe_success(ts(120));

        let snapshot = health.snapshot(ts(121));
        assert_eq!(snapshot.state, WatchdogState::Ok);
        assert_eq!(snapshot.consecutive_endpoint_refresh_failures, 0);
        assert_eq!(snapshot.next_endpoint_refresh_not_before, None);
        assert_eq!(snapshot.last_endpoint_refresh_error, None);
        assert!(health.refresh_allowed(ts(121)));
    }

    #[test]
    fn inbound_handshake_clears_refresh_failure_backoff() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_endpoint_refresh_failure(ts(100), "bind failed".to_owned());
        assert!(!health.refresh_allowed(ts(399)));

        health.record_inbound_handshake(ts(120));

        let snapshot = health.snapshot(ts(121));
        assert_eq!(snapshot.state, WatchdogState::Ok);
        assert_eq!(snapshot.consecutive_endpoint_refresh_failures, 0);
        assert_eq!(snapshot.next_endpoint_refresh_not_before, None);
        assert_eq!(snapshot.last_endpoint_refresh_error, None);
        assert!(health.refresh_allowed(ts(121)));
    }

    #[test]
    fn probe_failure_preserves_refresh_failed_state() {
        let health = NetworkWatchdogHealth::new(ts(100));
        health.record_endpoint_refresh_failure(ts(100), "bind failed".to_owned());

        let action = health.record_probe_failure(ts(120));

        assert_eq!(action.consecutive_failures, 1);
        let snapshot = health.snapshot(ts(121));
        assert_eq!(snapshot.state, WatchdogState::Failed);
        assert_eq!(
            snapshot.last_endpoint_refresh_error.as_deref(),
            Some("bind failed")
        );
    }

    #[test]
    fn relay_probe_addr_uses_relay_only_when_relay_configured() {
        let relay: iroh_base::RelayUrl = "https://relay.example./".parse().expect("relay url");
        let discovery = DiscoveryConfig {
            relays: vec![relay.clone()],
            ..DiscoveryConfig::in_process()
        };
        let endpoint_id = SecretKey::from_bytes(&[1; 32]).public();
        let addr = EndpointAddr::new(endpoint_id).with_relay_url(relay);
        let probe = relay_only_probe_addr(&addr, &discovery).expect("relay addr");
        assert_eq!(probe.relay_urls().count(), 1);
        assert_eq!(probe.ip_addrs().count(), 0);
    }

    #[test]
    fn relay_probe_addr_waits_for_published_relay_url() {
        let relay: iroh_base::RelayUrl = "https://relay.example./".parse().expect("relay url");
        let discovery = DiscoveryConfig {
            relays: vec![relay],
            ..DiscoveryConfig::in_process()
        };
        let endpoint_id = SecretKey::from_bytes(&[1; 32]).public();
        let addr = EndpointAddr::new(endpoint_id);

        assert!(relay_only_probe_addr(&addr, &discovery).is_none());
    }

    #[test]
    fn watchdog_probe_success_resets_failures() {
        let config = WatchdogConfig::default();
        let health = NetworkWatchdogHealth::new(ts(100));
        assert!(!apply_probe_outcome(
            &config,
            &health,
            ts(110),
            ProbeOutcome::Failure("timeout".to_owned()),
        ));

        assert!(!apply_probe_outcome(
            &config,
            &health,
            ts(120),
            ProbeOutcome::Success,
        ));

        let snapshot = health.snapshot(ts(121));
        assert_eq!(snapshot.state, WatchdogState::Ok);
        assert_eq!(snapshot.consecutive_self_probe_failures, 0);
        assert_eq!(snapshot.last_self_probe_ok_at, Some(120));
    }

    #[test]
    fn watchdog_recent_inbound_skips_probe_window() {
        let config = WatchdogConfig {
            interval: Duration::from_mins(1),
            ..WatchdogConfig::default()
        };
        let health = NetworkWatchdogHealth::new(ts(100));
        assert!(!should_skip_probe_after_recent_inbound(
            &health,
            &config,
            ts(120)
        ));
        health.record_inbound_handshake(ts(130));
        assert!(should_skip_probe_after_recent_inbound(
            &health,
            &config,
            ts(180)
        ));
        assert!(!should_skip_probe_after_recent_inbound(
            &health,
            &config,
            ts(260)
        ));
    }

    #[test]
    fn watchdog_three_failures_request_refresh() {
        let config = WatchdogConfig::default();
        let health = NetworkWatchdogHealth::new(ts(100));

        assert!(!apply_probe_outcome(
            &config,
            &health,
            ts(110),
            ProbeOutcome::Failure("timeout".to_owned()),
        ));
        assert!(!apply_probe_outcome(
            &config,
            &health,
            ts(120),
            ProbeOutcome::Failure("timeout".to_owned()),
        ));
        assert!(apply_probe_outcome(
            &config,
            &health,
            ts(130),
            ProbeOutcome::Failure("timeout".to_owned()),
        ));
    }
}

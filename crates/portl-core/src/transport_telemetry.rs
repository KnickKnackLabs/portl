use std::collections::HashMap;
use std::future::pending;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use iroh::endpoint::{Connection, PathEvent};
use iroh_base::TransportAddr;
use tokio::time::{MissedTickBehavior, interval_at};

pub const TARGET: &str = "portl_transport";

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryRole {
    Cli,
    Agent,
}

impl TelemetryRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Agent => "agent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportTelemetryContext {
    pub role: TelemetryRole,
    pub process_id: u32,
    pub command_id: Option<String>,
    pub command: Option<String>,
    pub target: Option<String>,
    pub provider: Option<String>,
    pub session: Option<String>,
    pub ticket_id: Option<[u8; 16]>,
    pub client_nonce_hash: Option<[u8; 16]>,
    pub local_endpoint_id: Option<[u8; 32]>,
    pub remote_endpoint_id: Option<[u8; 32]>,
    pub caller_endpoint_id: Option<[u8; 32]>,
    pub server_endpoint_id: Option<[u8; 32]>,
    pub ticket_issuer_id: Option<[u8; 32]>,
    pub ticket_holder_id: Option<[u8; 32]>,
}

impl TransportTelemetryContext {
    #[must_use]
    pub fn cli_default() -> Self {
        Self {
            role: TelemetryRole::Cli,
            process_id: std::process::id(),
            command_id: None,
            command: None,
            target: None,
            provider: None,
            session: None,
            ticket_id: None,
            client_nonce_hash: None,
            local_endpoint_id: None,
            remote_endpoint_id: None,
            caller_endpoint_id: None,
            server_endpoint_id: None,
            ticket_issuer_id: None,
            ticket_holder_id: None,
        }
    }

    #[must_use]
    pub fn agent_default() -> Self {
        Self {
            role: TelemetryRole::Agent,
            ..Self::cli_default()
        }
    }

    #[must_use]
    pub fn field_values(&self) -> TelemetryFieldValues {
        TelemetryFieldValues::from(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryFieldValues {
    pub role: &'static str,
    pub process_id: u32,
    pub command_id: Option<String>,
    pub command: Option<String>,
    pub target: Option<String>,
    pub provider: Option<String>,
    pub session: Option<String>,
    pub ticket_id: Option<String>,
    pub client_nonce_hash: Option<String>,
    pub local_endpoint_id: Option<String>,
    pub remote_endpoint_id: Option<String>,
    pub caller_endpoint_id: Option<String>,
    pub server_endpoint_id: Option<String>,
    pub ticket_issuer_id: Option<String>,
    pub ticket_holder_id: Option<String>,
}

impl From<&TransportTelemetryContext> for TelemetryFieldValues {
    fn from(context: &TransportTelemetryContext) -> Self {
        Self {
            role: context.role.as_str(),
            process_id: context.process_id,
            command_id: context.command_id.clone(),
            command: context.command.clone(),
            target: context.target.clone(),
            provider: context.provider.clone(),
            session: context.session.clone(),
            ticket_id: context.ticket_id.as_ref().map(format_id16),
            client_nonce_hash: context.client_nonce_hash.as_ref().map(format_id16),
            local_endpoint_id: context.local_endpoint_id.as_ref().map(format_id32),
            remote_endpoint_id: context.remote_endpoint_id.as_ref().map(format_id32),
            caller_endpoint_id: context.caller_endpoint_id.as_ref().map(format_id32),
            server_endpoint_id: context.server_endpoint_id.as_ref().map(format_id32),
            ticket_issuer_id: context.ticket_issuer_id.as_ref().map(format_id32),
            ticket_holder_id: context.ticket_holder_id.as_ref().map(format_id32),
        }
    }
}

fn format_id16(value: &[u8; 16]) -> String {
    hex::encode(value)
}

fn format_id32(value: &[u8; 32]) -> String {
    hex::encode(value)
}

#[cfg(test)]
fn format_id16_for_test(value: &[u8; 16]) -> String {
    format_id16(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverConfig {
    pub sample_interval: Option<Duration>,
    pub summary_interval: Option<Duration>,
    pub anomaly_repeat_interval: Duration,
    pub raw_addresses: bool,
}

impl ObserverConfig {
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_values(|name| std::env::var(name).ok())
    }

    #[must_use]
    pub fn from_env_values(mut get: impl FnMut(&str) -> Option<String>) -> Self {
        let defaults = Self::default();
        let anomaly_repeat_interval = parse_required_duration_env(
            "PORTL_TRANSPORT_ANOMALY_REPEAT_INTERVAL",
            get("PORTL_TRANSPORT_ANOMALY_REPEAT_INTERVAL"),
            defaults.anomaly_repeat_interval,
        );
        Self {
            sample_interval: parse_optional_duration_env(
                "PORTL_TRANSPORT_SAMPLE_INTERVAL",
                get("PORTL_TRANSPORT_SAMPLE_INTERVAL"),
                defaults.sample_interval,
            ),
            summary_interval: parse_optional_duration_env(
                "PORTL_TRANSPORT_SUMMARY_INTERVAL",
                get("PORTL_TRANSPORT_SUMMARY_INTERVAL"),
                defaults.summary_interval,
            ),
            anomaly_repeat_interval,
            raw_addresses: parse_bool_env(
                "PORTL_TRANSPORT_LOG_RAW_ADDRS",
                get("PORTL_TRANSPORT_LOG_RAW_ADDRS"),
                defaults.raw_addresses,
            ),
        }
    }
}

fn parse_optional_duration_env(
    name: &'static str,
    value: Option<String>,
    default: Option<Duration>,
) -> Option<Duration> {
    let Some(value) = value else {
        return default;
    };
    parse_duration_setting(&value).unwrap_or_else(|err| {
        log_invalid_config(name, &err);
        default
    })
}

fn parse_required_duration_env(
    name: &'static str,
    value: Option<String>,
    default: Duration,
) -> Duration {
    let Some(value) = value else {
        return default;
    };
    match parse_duration_setting(&value) {
        Ok(Some(duration)) => duration,
        Ok(None) => {
            log_invalid_config(name, "duration setting cannot be off");
            default
        }
        Err(err) => {
            log_invalid_config(name, &err);
            default
        }
    }
}

fn parse_bool_env(name: &'static str, value: Option<String>, default: bool) -> bool {
    let Some(value) = value else {
        return default;
    };
    parse_bool_setting(&value).unwrap_or_else(|| {
        log_invalid_config(name, "invalid boolean setting");
        default
    })
}

fn log_invalid_config(name: &'static str, error: &str) {
    tracing::warn!(
        target: TARGET,
        event = "transport.config.invalid",
        schema_version = SCHEMA_VERSION,
        setting = name,
        error,
    );
}

impl Default for ObserverConfig {
    fn default() -> Self {
        Self {
            sample_interval: Some(Duration::from_secs(10)),
            summary_interval: Some(Duration::from_mins(30)),
            anomaly_repeat_interval: Duration::from_mins(1),
            raw_addresses: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Relay,
    DirectUdp,
    Unknown,
}

impl PathKind {
    #[must_use]
    pub const fn from_flags(is_relay: bool, is_ip: bool) -> Self {
        if is_relay {
            Self::Relay
        } else if is_ip {
            Self::DirectUdp
        } else {
            Self::Unknown
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::DirectUdp => "direct_udp",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePathSummary {
    pub path_kind: &'static str,
    pub remote_addr: Option<String>,
    pub local_addr: Option<String>,
}

impl SafePathSummary {
    #[must_use]
    pub fn new(
        path_kind: PathKind,
        remote_addr: Option<String>,
        local_addr: Option<String>,
        raw_addresses: bool,
    ) -> Self {
        Self {
            path_kind: path_kind.as_str(),
            remote_addr: raw_addresses.then_some(remote_addr).flatten(),
            local_addr: raw_addresses.then_some(local_addr).flatten(),
        }
    }

    #[cfg(test)]
    fn for_test(
        path_kind: PathKind,
        remote_addr: Option<&str>,
        local_addr: Option<&str>,
        raw_addresses: bool,
    ) -> Self {
        Self::new(
            path_kind,
            remote_addr.map(ToOwned::to_owned),
            local_addr.map(ToOwned::to_owned),
            raw_addresses,
        )
    }
}

#[must_use]
pub fn rtt_micros_if_sampled(rtt: Duration) -> Option<u64> {
    (!rtt.is_zero()).then(|| u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX))
}

fn parse_bool_setting(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_duration_setting(value: &str) -> Result<Option<Duration>, String> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if trimmed.is_empty() {
        return Err("duration setting cannot be empty".to_owned());
    }

    let (number, multiplier) = if let Some(number) = trimmed.strip_suffix("ms") {
        (number, DurationUnit::Millis)
    } else if let Some(number) = trimmed.strip_suffix('s') {
        (number, DurationUnit::Secs)
    } else if let Some(number) = trimmed.strip_suffix('m') {
        (number, DurationUnit::Mins)
    } else if let Some(number) = trimmed.strip_suffix('h') {
        (number, DurationUnit::Hours)
    } else {
        (trimmed, DurationUnit::Secs)
    };
    let value = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration setting {trimmed:?}"))?;
    if value == 0 {
        return Err("duration setting must be greater than zero or off".to_owned());
    }
    Ok(Some(multiplier.duration(value)))
}

#[derive(Debug, Clone, Copy)]
enum DurationUnit {
    Millis,
    Secs,
    Mins,
    Hours,
}

impl DurationUnit {
    const fn duration(self, value: u64) -> Duration {
        match self {
            Self::Millis => Duration::from_millis(value),
            Self::Secs => Duration::from_secs(value),
            Self::Mins => Duration::from_secs(value.saturating_mul(60)),
            Self::Hours => Duration::from_secs(value.saturating_mul(60 * 60)),
        }
    }
}

#[cfg(test)]
fn parse_duration_setting_for_test(value: &str) -> Result<Option<Duration>, String> {
    parse_duration_setting(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    EmitFirst { suppressed_count: u64 },
    EmitRepeat { suppressed_count: u64 },
    EmitResolved { suppressed_count: u64 },
    Suppress,
}

#[derive(Debug, Clone)]
pub struct AnomalyRateLimiter {
    repeat_interval: Duration,
    active: HashMap<String, ActiveAnomaly>,
}

impl AnomalyRateLimiter {
    #[must_use]
    pub fn new(repeat_interval: Duration) -> Self {
        Self {
            repeat_interval,
            active: HashMap::new(),
        }
    }

    pub fn record_active(&mut self, key: &str, now: Instant) -> RateLimitDecision {
        let Some(active) = self.active.get_mut(key) else {
            self.active.insert(
                key.to_owned(),
                ActiveAnomaly {
                    last_emitted: now,
                    suppressed_count: 0,
                },
            );
            return RateLimitDecision::EmitFirst {
                suppressed_count: 0,
            };
        };

        if now.duration_since(active.last_emitted) >= self.repeat_interval {
            let suppressed_count = active.suppressed_count;
            active.last_emitted = now;
            active.suppressed_count = 0;
            RateLimitDecision::EmitRepeat { suppressed_count }
        } else {
            active.suppressed_count = active.suppressed_count.saturating_add(1);
            RateLimitDecision::Suppress
        }
    }

    pub fn record_resolved(&mut self, key: &str) -> RateLimitDecision {
        if let Some(active) = self.active.remove(key) {
            RateLimitDecision::EmitResolved {
                suppressed_count: active.suppressed_count,
            }
        } else {
            RateLimitDecision::Suppress
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveAnomaly {
    last_emitted: Instant,
    suppressed_count: u64,
}

#[derive(Debug, Default, Clone)]
#[allow(clippy::struct_field_names)]
pub struct SampleAnomalyState {
    black_holes_by_path: HashMap<String, u64>,
    rtt_micros_by_path: HashMap<String, u64>,
    lost_packets_by_path: HashMap<String, u64>,
    lost_bytes_by_path: HashMap<String, u64>,
    tx_datagrams_by_path: HashMap<String, u64>,
    congestion_events_by_path: HashMap<String, u64>,
    mtu_by_path: HashMap<String, u16>,
}

impl SampleAnomalyState {
    pub fn reset(&mut self) {
        self.black_holes_by_path.clear();
        self.rtt_micros_by_path.clear();
        self.lost_packets_by_path.clear();
        self.lost_bytes_by_path.clear();
        self.tx_datagrams_by_path.clear();
        self.congestion_events_by_path.clear();
        self.mtu_by_path.clear();
    }

    pub fn remove_path(&mut self, path_id: &str) {
        self.black_holes_by_path.remove(path_id);
        self.rtt_micros_by_path.remove(path_id);
        self.lost_packets_by_path.remove(path_id);
        self.lost_bytes_by_path.remove(path_id);
        self.tx_datagrams_by_path.remove(path_id);
        self.congestion_events_by_path.remove(path_id);
        self.mtu_by_path.remove(path_id);
    }

    pub fn set_path_baseline(&mut self, path_id: &str, current: PathSampleBaseline) {
        self.black_holes_by_path
            .insert(path_id.to_owned(), current.black_holes_detected);
        if let Some(rtt_micros) = current.rtt_micros {
            self.rtt_micros_by_path
                .insert(path_id.to_owned(), rtt_micros);
        }
        self.lost_packets_by_path
            .insert(path_id.to_owned(), current.lost_packets);
        self.lost_bytes_by_path
            .insert(path_id.to_owned(), current.lost_bytes);
        self.tx_datagrams_by_path
            .insert(path_id.to_owned(), current.tx_datagrams);
        self.congestion_events_by_path
            .insert(path_id.to_owned(), current.congestion_events);
        self.mtu_by_path
            .insert(path_id.to_owned(), current.current_mtu);
    }

    pub fn black_holes_delta(&mut self, path_id: &str, current: u64) -> Option<u64> {
        let previous = self
            .black_holes_by_path
            .insert(path_id.to_owned(), current)
            .unwrap_or(0);
        (current > previous).then_some(current - previous)
    }

    pub fn congestion_events_delta(&mut self, path_id: &str, current: u64) -> Option<u64> {
        counter_delta(&mut self.congestion_events_by_path, path_id, current)
    }

    pub fn mtu_change(&mut self, path_id: &str, current: u16) -> Option<MtuChange> {
        let previous = self
            .mtu_by_path
            .insert(path_id.to_owned(), current)
            .unwrap_or(0);
        (previous != 0 && current != 0 && previous != current)
            .then_some(MtuChange { previous, current })
    }

    pub fn loss_anomaly(
        &mut self,
        path_id: &str,
        lost_packets: u64,
        lost_bytes: u64,
        tx_datagrams: u64,
    ) -> Option<LossAnomaly> {
        let previous_lost_packets = self
            .lost_packets_by_path
            .insert(path_id.to_owned(), lost_packets)
            .unwrap_or(lost_packets);
        let previous_lost_bytes = self
            .lost_bytes_by_path
            .insert(path_id.to_owned(), lost_bytes)
            .unwrap_or(lost_bytes);
        let previous_tx_datagrams = self
            .tx_datagrams_by_path
            .insert(path_id.to_owned(), tx_datagrams)
            .unwrap_or(tx_datagrams);
        let lost_packets_delta = lost_packets.saturating_sub(previous_lost_packets);
        let tx_datagrams_delta = tx_datagrams.saturating_sub(previous_tx_datagrams);
        if lost_packets_delta == 0 || tx_datagrams_delta < LOSS_ANOMALY_MIN_TX_DATAGRAMS {
            return None;
        }
        let loss_rate_basis_points = lost_packets_delta.saturating_mul(10_000) / tx_datagrams_delta;
        (loss_rate_basis_points >= LOSS_ANOMALY_MIN_RATE_BASIS_POINTS).then_some(LossAnomaly {
            lost_packets_delta,
            lost_bytes_delta: lost_bytes.saturating_sub(previous_lost_bytes),
            tx_datagrams_delta,
            loss_rate_basis_points,
        })
    }

    pub fn rtt_spike(&mut self, path_id: &str, current: Option<u64>) -> Option<RttSpike> {
        let current = current?;
        let previous = self
            .rtt_micros_by_path
            .insert(path_id.to_owned(), current)?;
        (current >= previous.saturating_mul(2)
            && current.saturating_sub(previous) >= RTT_SPIKE_MIN_DELTA_MICROS)
            .then_some(RttSpike { previous, current })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PathSampleBaseline {
    rtt_micros: Option<u64>,
    black_holes_detected: u64,
    lost_packets: u64,
    lost_bytes: u64,
    tx_datagrams: u64,
    congestion_events: u64,
    current_mtu: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuChange {
    previous: u16,
    current: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttSpike {
    previous: u64,
    current: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossAnomaly {
    lost_packets_delta: u64,
    lost_bytes_delta: u64,
    tx_datagrams_delta: u64,
    loss_rate_basis_points: u64,
}

const RTT_SPIKE_MIN_DELTA_MICROS: u64 = 100_000;
const LOSS_ANOMALY_MIN_TX_DATAGRAMS: u64 = 100;
const LOSS_ANOMALY_MIN_RATE_BASIS_POINTS: u64 = 500;

fn counter_delta(map: &mut HashMap<String, u64>, path_id: &str, current: u64) -> Option<u64> {
    let previous = map.insert(path_id.to_owned(), current).unwrap_or(current);
    (current > previous).then_some(current - previous)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathFlapDecision {
    LogSelected,
    EmitFlapping { suppressed_count: u64 },
    Suppress,
    Resolved { suppressed_count: u64 },
}

#[derive(Debug, Clone)]
pub struct PathFlapTracker {
    threshold: usize,
    window: Duration,
    selected_changes: Vec<Instant>,
    flapping: bool,
    suppressed_count: u64,
}

impl PathFlapTracker {
    #[must_use]
    pub fn new(threshold: usize, window: Duration) -> Self {
        Self {
            threshold,
            window,
            selected_changes: Vec::new(),
            flapping: false,
            suppressed_count: 0,
        }
    }

    pub fn selected_changed(&mut self, now: Instant) -> PathFlapDecision {
        self.selected_changes
            .retain(|changed_at| now.duration_since(*changed_at) <= self.window);
        self.selected_changes.push(now);

        if self.flapping {
            self.suppressed_count = self.suppressed_count.saturating_add(1);
            return PathFlapDecision::Suppress;
        }

        if self.selected_changes.len() > self.threshold {
            self.flapping = true;
            PathFlapDecision::EmitFlapping {
                suppressed_count: 0,
            }
        } else {
            PathFlapDecision::LogSelected
        }
    }

    pub fn maybe_resolved(&mut self, now: Instant) -> Option<PathFlapDecision> {
        if !self.flapping {
            return None;
        }
        let last_change = self.selected_changes.last().copied()?;
        if now.duration_since(last_change) < self.window {
            return None;
        }
        self.flapping = false;
        self.selected_changes.clear();
        let suppressed_count = std::mem::take(&mut self.suppressed_count);
        Some(PathFlapDecision::Resolved { suppressed_count })
    }
}

#[must_use]
pub fn spawn_connection_observer(
    connection: Connection,
    context: TransportTelemetryContext,
    config: ObserverConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        observe_connection(connection, context, config).await;
    })
}

async fn observe_connection(
    connection: Connection,
    context: TransportTelemetryContext,
    config: ObserverConfig,
) {
    let connection_id = connection.stable_id() as u64;
    let side = format!("{:?}", connection.side());
    let remote_endpoint_id = *connection.remote_id().as_bytes();
    let context = TransportTelemetryContext {
        remote_endpoint_id: context.remote_endpoint_id.or(Some(remote_endpoint_id)),
        ..context
    };
    let fields = context.field_values();
    tracing::info!(
        target: TARGET,
        event = "transport.connection.opened",
        schema_version = SCHEMA_VERSION,
        role = fields.role,
        process_id = fields.process_id,
        command_id = fields.command_id.as_deref().unwrap_or(""),
        command = fields.command.as_deref().unwrap_or(""),
        target_label = fields.target.as_deref().unwrap_or(""),
        provider = fields.provider.as_deref().unwrap_or(""),
        session = fields.session.as_deref().unwrap_or(""),
        ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
        client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
        local_endpoint_id = fields.local_endpoint_id.as_deref().unwrap_or(""),
        remote_endpoint_id = fields.remote_endpoint_id.as_deref().unwrap_or(""),
        caller_endpoint_id = fields.caller_endpoint_id.as_deref().unwrap_or(""),
        server_endpoint_id = fields.server_endpoint_id.as_deref().unwrap_or(""),
        ticket_issuer_id = fields.ticket_issuer_id.as_deref().unwrap_or(""),
        ticket_holder_id = fields.ticket_holder_id.as_deref().unwrap_or(""),
        connection_id,
        side = side.as_str(),
    );
    log_current_paths(connection_id, &connection, &context, &config);

    let mut events = connection.path_events();
    let mut sample_tick = config.sample_interval.map(interval_after);
    let mut summary_tick = config.summary_interval.map(interval_after);
    let mut flap_resolution_tick = Some(interval_after(Duration::from_mins(1)));
    let mut flap_tracker = PathFlapTracker::new(3, Duration::from_mins(1));
    let mut anomaly_limiter = AnomalyRateLimiter::new(config.anomaly_repeat_interval);
    let mut sample_state = SampleAnomalyState::default();
    let mut events_open = true;

    loop {
        tokio::select! {
            reason = connection.closed() => {
                let reason = crate::diagnostics::redact_text(&format!("{reason}"));
                log_connection_closed(connection_id, &context, &reason);
                break;
            }
            event = events.next(), if events_open => {
                let Some(event) = event else {
                    events_open = false;
                    continue;
                };
                handle_path_event(
                    connection_id,
                    &connection,
                    event,
                    &context,
                    &config,
                    &mut flap_tracker,
                    &mut sample_state,
                );
            }
            () = tick_optional(&mut sample_tick) => {
                sample_paths(
                    connection_id,
                    &connection,
                    &context,
                    &config,
                    &mut anomaly_limiter,
                    &mut sample_state,
                );
            }
            () = tick_optional(&mut flap_resolution_tick) => {
                resolve_path_flapping(connection_id, &context, &mut flap_tracker);
            }
            () = tick_optional(&mut summary_tick) => {
                log_summary(connection_id, &connection, &context, &config);
            }
        }
    }
}

fn log_connection_closed(connection_id: u64, context: &TransportTelemetryContext, reason: &str) {
    let fields = context.field_values();
    tracing::info!(
        target: TARGET,
        event = "transport.connection.closed",
        schema_version = SCHEMA_VERSION,
        role = fields.role,
        process_id = fields.process_id,
        command_id = fields.command_id.as_deref().unwrap_or(""),
        command = fields.command.as_deref().unwrap_or(""),
        target_label = fields.target.as_deref().unwrap_or(""),
        provider = fields.provider.as_deref().unwrap_or(""),
        session = fields.session.as_deref().unwrap_or(""),
        ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
        client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
        local_endpoint_id = fields.local_endpoint_id.as_deref().unwrap_or(""),
        remote_endpoint_id = fields.remote_endpoint_id.as_deref().unwrap_or(""),
        caller_endpoint_id = fields.caller_endpoint_id.as_deref().unwrap_or(""),
        server_endpoint_id = fields.server_endpoint_id.as_deref().unwrap_or(""),
        ticket_issuer_id = fields.ticket_issuer_id.as_deref().unwrap_or(""),
        ticket_holder_id = fields.ticket_holder_id.as_deref().unwrap_or(""),
        connection_id,
        reason,
    );
}

fn interval_after(duration: Duration) -> tokio::time::Interval {
    let mut interval = interval_at(tokio::time::Instant::now() + duration, duration);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
}

async fn tick_optional(interval: &mut Option<tokio::time::Interval>) {
    if let Some(interval) = interval {
        interval.tick().await;
    } else {
        pending::<()>().await;
    }
}

fn handle_path_event(
    connection_id: u64,
    connection: &Connection,
    event: PathEvent,
    context: &TransportTelemetryContext,
    config: &ObserverConfig,
    flap_tracker: &mut PathFlapTracker,
    sample_state: &mut SampleAnomalyState,
) {
    match event {
        PathEvent::Opened {
            id,
            remote_addr,
            local_addr,
            ..
        } => {
            let summary = safe_path_summary(&remote_addr, Some(format!("{local_addr:?}")), config);
            let path_id = format!("{id:?}");
            log_path_lifecycle(
                "transport.path.opened",
                connection_id,
                &path_id,
                &summary,
                context,
                None,
                None,
            );
        }
        PathEvent::Closed {
            id,
            remote_addr,
            local_addr,
            last_stats,
            ..
        } => {
            let summary = safe_path_summary(&remote_addr, Some(format!("{local_addr:?}")), config);
            let path_id = format!("{id:?}");
            log_path_lifecycle(
                "transport.path.closed",
                connection_id,
                &path_id,
                &summary,
                context,
                rtt_micros_if_sampled(last_stats.rtt),
                Some(last_stats.lost_packets),
            );
            sample_state.remove_path(&path_id);
        }
        PathEvent::Selected {
            id,
            remote_addr,
            local_addr,
            ..
        } => {
            let now = Instant::now();
            match flap_tracker.selected_changed(now) {
                PathFlapDecision::LogSelected => {
                    let summary =
                        safe_path_summary(&remote_addr, Some(format!("{local_addr:?}")), config);
                    let path_id = format!("{id:?}");
                    log_path_lifecycle(
                        "transport.path.selected",
                        connection_id,
                        &path_id,
                        &summary,
                        context,
                        None,
                        None,
                    );
                }
                PathFlapDecision::EmitFlapping { suppressed_count } => {
                    log_path_flapping(
                        connection_id,
                        context,
                        "transport.path.flapping",
                        suppressed_count,
                    );
                }
                PathFlapDecision::Suppress | PathFlapDecision::Resolved { .. } => {}
            }
        }
        PathEvent::Lagged { missed, .. } => {
            let fields = context.field_values();
            tracing::warn!(
                target: TARGET,
                event = "transport.path.lagged",
                schema_version = SCHEMA_VERSION,
                role = fields.role,
                process_id = fields.process_id,
                command_id = fields.command_id.as_deref().unwrap_or(""),
                command = fields.command.as_deref().unwrap_or(""),
                target_label = fields.target.as_deref().unwrap_or(""),
                provider = fields.provider.as_deref().unwrap_or(""),
                session = fields.session.as_deref().unwrap_or(""),
                ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
                client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
                connection_id,
                missed,
            );
            sample_state.reset();
            for path in connection.paths().iter() {
                let path_id = format!("{:?}", path.id());
                sample_state.set_path_baseline(&path_id, path_sample_baseline(&path));
            }
            log_current_paths(connection_id, connection, context, config);
        }
        _ => {}
    }
}

fn log_current_paths(
    connection_id: u64,
    connection: &Connection,
    context: &TransportTelemetryContext,
    config: &ObserverConfig,
) {
    let paths = connection.paths();
    for path in paths.iter() {
        let summary = SafePathSummary::new(
            PathKind::from_flags(path.is_relay(), path.is_ip()),
            Some(format!("{}", path.remote_addr())),
            Some(format!("{:?}", path.local_addr())),
            config.raw_addresses,
        );
        let path_id = format!("{:?}", path.id());
        log_path_lifecycle(
            if path.is_selected() {
                "transport.path.selected"
            } else {
                "transport.path.opened"
            },
            connection_id,
            &path_id,
            &summary,
            context,
            rtt_micros_if_sampled(path.rtt()),
            Some(path.stats().lost_packets),
        );
    }
}

fn resolve_path_flapping(
    connection_id: u64,
    context: &TransportTelemetryContext,
    flap_tracker: &mut PathFlapTracker,
) {
    if let Some(PathFlapDecision::Resolved { suppressed_count }) =
        flap_tracker.maybe_resolved(Instant::now())
    {
        log_path_flapping(
            connection_id,
            context,
            "transport.path.flapping_resolved",
            suppressed_count,
        );
    }
}

fn sample_paths(
    connection_id: u64,
    connection: &Connection,
    context: &TransportTelemetryContext,
    config: &ObserverConfig,
    anomaly_limiter: &mut AnomalyRateLimiter,
    sample_state: &mut SampleAnomalyState,
) {
    let paths = connection.paths();
    let selected = paths.iter().find(iroh::endpoint::Path::is_selected);
    let Some(path) = selected else {
        return;
    };
    let rtt_micros = rtt_micros_if_sampled(path.rtt());
    let stats = path.stats();
    let path_id = format!("{:?}", path.id());
    let summary = SafePathSummary::new(
        PathKind::from_flags(path.is_relay(), path.is_ip()),
        Some(format!("{}", path.remote_addr())),
        Some(format!("{:?}", path.local_addr())),
        config.raw_addresses,
    );

    let black_holes_delta = sample_state.black_holes_delta(&path_id, stats.black_holes_detected);
    let lost_packets = stats.lost_packets;
    log_sampled_non_counter_anomalies(
        connection_id,
        &path_id,
        &summary,
        context,
        rtt_micros,
        &stats,
        anomaly_limiter,
        sample_state,
    );
    let Some(black_holes_delta) = black_holes_delta else {
        return;
    };
    let anomaly_key = format!("black_hole_detected:{path_id}");
    let decision = anomaly_limiter.record_active(&anomaly_key, Instant::now());
    let suppressed_count = match decision {
        RateLimitDecision::EmitFirst { suppressed_count }
        | RateLimitDecision::EmitRepeat { suppressed_count } => suppressed_count,
        RateLimitDecision::Suppress | RateLimitDecision::EmitResolved { .. } => return,
    };
    log_path_black_hole_detected(
        connection_id,
        &path_id,
        &summary,
        context,
        BlackHoleLogMetrics {
            rtt_micros,
            lost_packets: Some(lost_packets),
            black_holes_delta,
            suppressed_count,
        },
    );
}

fn path_sample_baseline(path: &iroh::endpoint::Path<'_>) -> PathSampleBaseline {
    let stats = path.stats();
    PathSampleBaseline {
        rtt_micros: rtt_micros_if_sampled(path.rtt()),
        black_holes_detected: stats.black_holes_detected,
        lost_packets: stats.lost_packets,
        lost_bytes: stats.lost_bytes,
        tx_datagrams: stats.udp_tx.datagrams,
        congestion_events: stats.congestion_events,
        current_mtu: stats.current_mtu,
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn log_sampled_non_counter_anomalies(
    connection_id: u64,
    path_id: &str,
    summary: &SafePathSummary,
    context: &TransportTelemetryContext,
    rtt_micros: Option<u64>,
    stats: &iroh::endpoint::PathStats,
    anomaly_limiter: &mut AnomalyRateLimiter,
    sample_state: &mut SampleAnomalyState,
) {
    let now = Instant::now();
    if let Some(spike) = sample_state.rtt_spike(path_id, rtt_micros) {
        if let Some(suppressed_count) =
            anomaly_suppressed_count(anomaly_limiter, &format!("rtt_spike:{path_id}"), now)
        {
            log_path_anomaly(PathAnomalyLog {
                event_name: "transport.path.anomaly_detected",
                anomaly_name: "rtt_spike",
                connection_id,
                path_id,
                summary,
                context,
                numbers: PathAnomalyNumbers {
                    rtt_micros,
                    previous: Some(spike.previous),
                    current: Some(spike.current),
                    suppressed_count,
                    ..PathAnomalyNumbers::default()
                },
            });
        }
    } else if rtt_micros.is_some()
        && let RateLimitDecision::EmitResolved { suppressed_count } =
            anomaly_limiter.record_resolved(&format!("rtt_spike:{path_id}"))
    {
        log_path_anomaly(PathAnomalyLog {
            event_name: "transport.path.anomaly_resolved",
            anomaly_name: "rtt_spike",
            connection_id,
            path_id,
            summary,
            context,
            numbers: PathAnomalyNumbers {
                rtt_micros,
                suppressed_count,
                ..PathAnomalyNumbers::default()
            },
        });
    }

    if let Some(loss) = sample_state.loss_anomaly(
        path_id,
        stats.lost_packets,
        stats.lost_bytes,
        stats.udp_tx.datagrams,
    ) {
        if let Some(suppressed_count) =
            anomaly_suppressed_count(anomaly_limiter, &format!("packet_loss:{path_id}"), now)
        {
            log_path_anomaly(PathAnomalyLog {
                event_name: "transport.path.anomaly_detected",
                anomaly_name: "packet_loss",
                connection_id,
                path_id,
                summary,
                context,
                numbers: PathAnomalyNumbers {
                    lost_packets_delta: Some(loss.lost_packets_delta),
                    lost_bytes_delta: Some(loss.lost_bytes_delta),
                    tx_datagrams_delta: Some(loss.tx_datagrams_delta),
                    rate_basis_points: Some(loss.loss_rate_basis_points),
                    suppressed_count,
                    ..PathAnomalyNumbers::default()
                },
            });
        }
    } else if let RateLimitDecision::EmitResolved { suppressed_count } =
        anomaly_limiter.record_resolved(&format!("packet_loss:{path_id}"))
    {
        log_path_anomaly(PathAnomalyLog {
            event_name: "transport.path.anomaly_resolved",
            anomaly_name: "packet_loss",
            connection_id,
            path_id,
            summary,
            context,
            numbers: PathAnomalyNumbers {
                suppressed_count,
                ..PathAnomalyNumbers::default()
            },
        });
    }

    if let Some(delta) = sample_state.congestion_events_delta(path_id, stats.congestion_events)
        && let Some(suppressed_count) =
            anomaly_suppressed_count(anomaly_limiter, &format!("congestion:{path_id}"), now)
    {
        log_path_anomaly(PathAnomalyLog {
            event_name: "transport.path.anomaly_detected",
            anomaly_name: "congestion",
            connection_id,
            path_id,
            summary,
            context,
            numbers: PathAnomalyNumbers {
                delta: Some(delta),
                current: Some(stats.congestion_events),
                suppressed_count,
                ..PathAnomalyNumbers::default()
            },
        });
    }

    if let Some(change) = sample_state.mtu_change(path_id, stats.current_mtu)
        && let Some(suppressed_count) =
            anomaly_suppressed_count(anomaly_limiter, &format!("mtu_change:{path_id}"), now)
    {
        log_path_anomaly(PathAnomalyLog {
            event_name: "transport.path.anomaly_detected",
            anomaly_name: "mtu_change",
            connection_id,
            path_id,
            summary,
            context,
            numbers: PathAnomalyNumbers {
                previous: Some(u64::from(change.previous)),
                current: Some(u64::from(change.current)),
                suppressed_count,
                ..PathAnomalyNumbers::default()
            },
        });
    }
}

fn anomaly_suppressed_count(
    anomaly_limiter: &mut AnomalyRateLimiter,
    key: &str,
    now: Instant,
) -> Option<u64> {
    match anomaly_limiter.record_active(key, now) {
        RateLimitDecision::EmitFirst { suppressed_count }
        | RateLimitDecision::EmitRepeat { suppressed_count } => Some(suppressed_count),
        RateLimitDecision::Suppress | RateLimitDecision::EmitResolved { .. } => None,
    }
}

fn log_summary(
    connection_id: u64,
    connection: &Connection,
    context: &TransportTelemetryContext,
    config: &ObserverConfig,
) {
    let paths = connection.paths();
    let path_count = paths.iter().count();
    let selected = paths.iter().find(iroh::endpoint::Path::is_selected);
    let (selected_path_id, selected_path_kind, rtt_micros) = selected.map_or_else(
        || (String::new(), "none", None),
        |path| {
            (
                format!("{:?}", path.id()),
                PathKind::from_flags(path.is_relay(), path.is_ip()).as_str(),
                rtt_micros_if_sampled(path.rtt()),
            )
        },
    );
    let fields = context.field_values();
    tracing::info!(
        target: TARGET,
        event = "transport.connection.summary",
        schema_version = SCHEMA_VERSION,
        role = fields.role,
        process_id = fields.process_id,
        command_id = fields.command_id.as_deref().unwrap_or(""),
        command = fields.command.as_deref().unwrap_or(""),
        target_label = fields.target.as_deref().unwrap_or(""),
        provider = fields.provider.as_deref().unwrap_or(""),
        session = fields.session.as_deref().unwrap_or(""),
        ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
        client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
        connection_id,
        path_count,
        selected_path_id = selected_path_id.as_str(),
        selected_path_kind,
        rtt_micros = rtt_micros,
        raw_addresses = config.raw_addresses,
    );
}

fn safe_path_summary(
    remote_addr: &TransportAddr,
    local_addr: Option<String>,
    config: &ObserverConfig,
) -> SafePathSummary {
    SafePathSummary::new(
        PathKind::from_flags(remote_addr.is_relay(), remote_addr.is_ip()),
        Some(format!("{remote_addr}")),
        local_addr,
        config.raw_addresses,
    )
}

fn log_path_lifecycle(
    event_name: &'static str,
    connection_id: u64,
    path_id: &str,
    summary: &SafePathSummary,
    context: &TransportTelemetryContext,
    rtt_micros: Option<u64>,
    lost_packets: Option<u64>,
) {
    let fields = context.field_values();
    tracing::info!(
        target: TARGET,
        event = event_name,
        schema_version = SCHEMA_VERSION,
        role = fields.role,
        process_id = fields.process_id,
        command_id = fields.command_id.as_deref().unwrap_or(""),
        command = fields.command.as_deref().unwrap_or(""),
        target_label = fields.target.as_deref().unwrap_or(""),
        provider = fields.provider.as_deref().unwrap_or(""),
        session = fields.session.as_deref().unwrap_or(""),
        ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
        client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
        local_endpoint_id = fields.local_endpoint_id.as_deref().unwrap_or(""),
        remote_endpoint_id = fields.remote_endpoint_id.as_deref().unwrap_or(""),
        caller_endpoint_id = fields.caller_endpoint_id.as_deref().unwrap_or(""),
        server_endpoint_id = fields.server_endpoint_id.as_deref().unwrap_or(""),
        connection_id,
        path_id,
        path_kind = summary.path_kind,
        remote_addr = summary.remote_addr.as_deref().unwrap_or(""),
        local_addr = summary.local_addr.as_deref().unwrap_or(""),
        rtt_micros = rtt_micros,
        lost_packets = lost_packets,
    );
}

#[derive(Clone, Copy)]
struct BlackHoleLogMetrics {
    rtt_micros: Option<u64>,
    lost_packets: Option<u64>,
    black_holes_delta: u64,
    suppressed_count: u64,
}

#[derive(Clone, Copy)]
struct PathAnomalyLog<'a> {
    event_name: &'static str,
    anomaly_name: &'static str,
    connection_id: u64,
    path_id: &'a str,
    summary: &'a SafePathSummary,
    context: &'a TransportTelemetryContext,
    numbers: PathAnomalyNumbers,
}

#[derive(Debug, Default, Clone, Copy)]
struct PathAnomalyNumbers {
    rtt_micros: Option<u64>,
    previous: Option<u64>,
    current: Option<u64>,
    delta: Option<u64>,
    lost_packets_delta: Option<u64>,
    lost_bytes_delta: Option<u64>,
    tx_datagrams_delta: Option<u64>,
    rate_basis_points: Option<u64>,
    suppressed_count: u64,
}

fn log_path_anomaly(log: PathAnomalyLog<'_>) {
    let fields = log.context.field_values();
    tracing::warn!(
        target: TARGET,
        event = log.event_name,
        schema_version = SCHEMA_VERSION,
        role = fields.role,
        process_id = fields.process_id,
        command_id = fields.command_id.as_deref().unwrap_or(""),
        command = fields.command.as_deref().unwrap_or(""),
        target_label = fields.target.as_deref().unwrap_or(""),
        provider = fields.provider.as_deref().unwrap_or(""),
        session = fields.session.as_deref().unwrap_or(""),
        ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
        client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
        connection_id = log.connection_id,
        path_id = log.path_id,
        path_kind = log.summary.path_kind,
        remote_addr = log.summary.remote_addr.as_deref().unwrap_or(""),
        local_addr = log.summary.local_addr.as_deref().unwrap_or(""),
        anomaly = log.anomaly_name,
        rtt_micros = log.numbers.rtt_micros,
        previous = log.numbers.previous,
        current = log.numbers.current,
        delta = log.numbers.delta,
        lost_packets_delta = log.numbers.lost_packets_delta,
        lost_bytes_delta = log.numbers.lost_bytes_delta,
        tx_datagrams_delta = log.numbers.tx_datagrams_delta,
        rate_basis_points = log.numbers.rate_basis_points,
        suppressed_count = log.numbers.suppressed_count,
    );
}

fn log_path_black_hole_detected(
    connection_id: u64,
    path_id: &str,
    summary: &SafePathSummary,
    context: &TransportTelemetryContext,
    metrics: BlackHoleLogMetrics,
) {
    let fields = context.field_values();
    tracing::warn!(
        target: TARGET,
        event = "transport.path.black_hole_detected",
        schema_version = SCHEMA_VERSION,
        role = fields.role,
        process_id = fields.process_id,
        command_id = fields.command_id.as_deref().unwrap_or(""),
        command = fields.command.as_deref().unwrap_or(""),
        target_label = fields.target.as_deref().unwrap_or(""),
        provider = fields.provider.as_deref().unwrap_or(""),
        session = fields.session.as_deref().unwrap_or(""),
        ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
        client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
        connection_id,
        path_id,
        path_kind = summary.path_kind,
        remote_addr = summary.remote_addr.as_deref().unwrap_or(""),
        local_addr = summary.local_addr.as_deref().unwrap_or(""),
        rtt_micros = metrics.rtt_micros,
        lost_packets = metrics.lost_packets,
        black_holes_delta = metrics.black_holes_delta,
        suppressed_count = metrics.suppressed_count,
    );
}

fn log_path_flapping(
    connection_id: u64,
    context: &TransportTelemetryContext,
    event_name: &'static str,
    suppressed_count: u64,
) {
    let fields = context.field_values();
    tracing::warn!(
        target: TARGET,
        event = event_name,
        schema_version = SCHEMA_VERSION,
        role = fields.role,
        process_id = fields.process_id,
        command_id = fields.command_id.as_deref().unwrap_or(""),
        command = fields.command.as_deref().unwrap_or(""),
        target_label = fields.target.as_deref().unwrap_or(""),
        provider = fields.provider.as_deref().unwrap_or(""),
        session = fields.session.as_deref().unwrap_or(""),
        ticket_id = fields.ticket_id.as_deref().unwrap_or(""),
        client_nonce_hash = fields.client_nonce_hash.as_deref().unwrap_or(""),
        connection_id,
        suppressed_count,
    );
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        AnomalyRateLimiter, LossAnomaly, MtuChange, ObserverConfig, PathFlapDecision,
        PathFlapTracker, PathKind, PathSampleBaseline, RateLimitDecision, RttSpike, SCHEMA_VERSION,
        SafePathSummary, SampleAnomalyState, TARGET, TelemetryFieldValues, TelemetryRole,
        TransportTelemetryContext, format_id16_for_test, parse_duration_setting_for_test,
        rtt_micros_if_sampled, spawn_connection_observer,
    };

    #[test]
    fn schema_constants_are_stable() {
        assert_eq!(TARGET, "portl_transport");
        assert_eq!(SCHEMA_VERSION, 1);
    }

    #[test]
    fn telemetry_roles_have_stable_labels() {
        assert_eq!(TelemetryRole::Cli.as_str(), "cli");
        assert_eq!(TelemetryRole::Agent.as_str(), "agent");
    }

    #[test]
    fn context_field_values_format_ids_without_sensitive_material() {
        let context = TransportTelemetryContext {
            role: TelemetryRole::Cli,
            process_id: 42,
            command_id: Some("42-123456".to_owned()),
            command: Some("session.attach".to_owned()),
            target: Some("vn3/herdr".to_owned()),
            provider: Some("herdr".to_owned()),
            session: Some("default".to_owned()),
            ticket_id: Some([1u8; 16]),
            client_nonce_hash: Some([2u8; 16]),
            local_endpoint_id: Some([3u8; 32]),
            remote_endpoint_id: Some([4u8; 32]),
            caller_endpoint_id: None,
            server_endpoint_id: None,
            ticket_issuer_id: None,
            ticket_holder_id: None,
        };

        let fields = context.field_values();

        assert_eq!(fields.role, "cli");
        assert_eq!(fields.process_id, 42);
        assert_eq!(fields.command_id.as_deref(), Some("42-123456"));
        assert_eq!(fields.command.as_deref(), Some("session.attach"));
        assert_eq!(fields.target.as_deref(), Some("vn3/herdr"));
        assert_eq!(
            fields.ticket_id.as_deref(),
            Some("01010101010101010101010101010101")
        );
        assert_eq!(
            fields.client_nonce_hash.as_deref(),
            Some("02020202020202020202020202020202")
        );
        assert_eq!(fields.local_endpoint_id.as_ref().map(String::len), Some(64));
        assert_eq!(
            fields.remote_endpoint_id.as_ref().map(String::len),
            Some(64)
        );
    }

    #[test]
    fn id16_formatting_is_lowercase_hex() {
        assert_eq!(
            format_id16_for_test(&[0xab; 16]),
            "abababababababababababababababab"
        );
    }

    #[test]
    fn telemetry_field_values_defaults_are_empty_not_secret_placeholders() {
        let fields = TelemetryFieldValues::from(&TransportTelemetryContext::agent_default());

        assert_eq!(fields.role, "agent");
        assert_eq!(fields.process_id, std::process::id());
        assert_eq!(fields.ticket_id, None);
        assert_eq!(fields.client_nonce_hash, None);
    }

    #[test]
    fn observer_config_defaults_are_low_noise() {
        let config = ObserverConfig::default();

        assert_eq!(config.sample_interval, Some(Duration::from_secs(10)));
        assert_eq!(config.summary_interval, Some(Duration::from_mins(30)));
        assert_eq!(config.anomaly_repeat_interval, Duration::from_mins(1));
        assert!(!config.raw_addresses);
    }

    #[test]
    fn observer_config_reads_env_style_overrides() {
        let config = ObserverConfig::from_env_values(|name| match name {
            "PORTL_TRANSPORT_SAMPLE_INTERVAL" => Some("off".to_owned()),
            "PORTL_TRANSPORT_SUMMARY_INTERVAL" => Some("1h".to_owned()),
            "PORTL_TRANSPORT_ANOMALY_REPEAT_INTERVAL" => Some("2m".to_owned()),
            "PORTL_TRANSPORT_LOG_RAW_ADDRS" => Some("yes".to_owned()),
            _ => None,
        });

        assert_eq!(config.sample_interval, None);
        assert_eq!(config.summary_interval, Some(Duration::from_hours(1)));
        assert_eq!(config.anomaly_repeat_interval, Duration::from_mins(2));
        assert!(config.raw_addresses);
    }

    #[test]
    fn invalid_observer_config_values_fall_back_to_defaults() {
        let config = ObserverConfig::from_env_values(|name| match name {
            "PORTL_TRANSPORT_SAMPLE_INTERVAL" => Some("not-a-duration".to_owned()),
            "PORTL_TRANSPORT_LOG_RAW_ADDRS" => Some("not-a-bool".to_owned()),
            _ => None,
        });

        assert_eq!(config.sample_interval, Some(Duration::from_secs(10)));
        assert!(!config.raw_addresses);
    }

    #[test]
    fn duration_setting_parser_accepts_units_and_off() {
        assert_eq!(
            parse_duration_setting_for_test("250ms").unwrap(),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            parse_duration_setting_for_test("10s").unwrap(),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_duration_setting_for_test("30m").unwrap(),
            Some(Duration::from_mins(30))
        );
        assert_eq!(
            parse_duration_setting_for_test("2h").unwrap(),
            Some(Duration::from_hours(2))
        );
        assert_eq!(
            parse_duration_setting_for_test("45").unwrap(),
            Some(Duration::from_secs(45))
        );
        assert_eq!(parse_duration_setting_for_test("off").unwrap(), None);
        assert!(parse_duration_setting_for_test("0s").is_err());
        assert!(parse_duration_setting_for_test("garbage").is_err());
    }

    #[test]
    fn path_kind_labels_are_stable() {
        assert_eq!(PathKind::from_flags(true, false).as_str(), "relay");
        assert_eq!(PathKind::from_flags(false, true).as_str(), "direct_udp");
        assert_eq!(PathKind::from_flags(false, false).as_str(), "unknown");
    }

    #[test]
    fn default_path_summary_omits_raw_addresses() {
        let summary = SafePathSummary::for_test(
            PathKind::Relay,
            Some("https://relay.example.invalid"),
            Some("10.0.0.12:12345"),
            false,
        );

        assert_eq!(summary.path_kind, "relay");
        assert_eq!(summary.remote_addr.as_deref(), None);
        assert_eq!(summary.local_addr.as_deref(), None);
    }

    #[test]
    fn raw_path_summary_is_explicit_opt_in() {
        let summary = SafePathSummary::for_test(
            PathKind::DirectUdp,
            Some("203.0.113.10:4433"),
            Some("10.0.0.12:12345"),
            true,
        );

        assert_eq!(summary.path_kind, "direct_udp");
        assert_eq!(summary.remote_addr.as_deref(), Some("203.0.113.10:4433"));
        assert_eq!(summary.local_addr.as_deref(), Some("10.0.0.12:12345"));
    }

    #[test]
    fn zero_rtt_is_treated_as_missing_sample() {
        assert_eq!(rtt_micros_if_sampled(Duration::ZERO), None);
        assert_eq!(rtt_micros_if_sampled(Duration::from_micros(42)), Some(42));
    }

    #[test]
    fn anomaly_rate_limiter_emits_first_repeats_and_resolution() {
        let start = Instant::now();
        let mut limiter = AnomalyRateLimiter::new(Duration::from_mins(1));

        assert_eq!(
            limiter.record_active("rtt_spike", start),
            RateLimitDecision::EmitFirst {
                suppressed_count: 0
            }
        );
        assert_eq!(
            limiter.record_active("rtt_spike", start + Duration::from_secs(10)),
            RateLimitDecision::Suppress
        );
        assert_eq!(
            limiter.record_active("rtt_spike", start + Duration::from_secs(61)),
            RateLimitDecision::EmitRepeat {
                suppressed_count: 1
            }
        );
        assert_eq!(
            limiter.record_resolved("rtt_spike"),
            RateLimitDecision::EmitResolved {
                suppressed_count: 0
            }
        );
        assert_eq!(
            limiter.record_resolved("rtt_spike"),
            RateLimitDecision::Suppress
        );
    }

    #[test]
    fn black_hole_delta_tracking_emits_only_on_counter_increase() {
        let mut state = SampleAnomalyState::default();

        assert_eq!(state.black_holes_delta("PathId(0)", 0), None);
        assert_eq!(state.black_holes_delta("PathId(0)", 1), Some(1));
        assert_eq!(state.black_holes_delta("PathId(0)", 1), None);
        assert_eq!(state.black_holes_delta("PathId(0)", 3), Some(2));
        assert_eq!(state.black_holes_delta("PathId(1)", 2), Some(2));
    }

    #[test]
    fn sample_anomaly_state_resets_and_removes_path_baselines() {
        let mut state = SampleAnomalyState::default();

        assert_eq!(state.black_holes_delta("PathId(0)", 2), Some(2));
        state.remove_path("PathId(0)");
        assert_eq!(state.black_holes_delta("PathId(0)", 2), Some(2));

        assert_eq!(state.black_holes_delta("PathId(1)", 4), Some(4));
        state.reset();
        assert_eq!(state.black_holes_delta("PathId(1)", 4), Some(4));

        state.set_path_baseline(
            "PathId(2)",
            PathSampleBaseline {
                rtt_micros: Some(100),
                black_holes_detected: 7,
                lost_packets: 0,
                lost_bytes: 0,
                tx_datagrams: 0,
                congestion_events: 0,
                current_mtu: 1200,
            },
        );
        assert_eq!(state.black_holes_delta("PathId(2)", 7), None);
        assert_eq!(state.black_holes_delta("PathId(2)", 9), Some(2));
    }

    #[test]
    fn sample_anomaly_state_detects_sampled_counter_and_threshold_anomalies() {
        let mut state = SampleAnomalyState::default();

        assert_eq!(state.rtt_spike("PathId(0)", Some(100_000)), None);
        assert_eq!(state.rtt_spike("PathId(0)", Some(150_000)), None);
        assert_eq!(
            state.rtt_spike("PathId(0)", Some(350_000)),
            Some(RttSpike {
                previous: 150_000,
                current: 350_000
            })
        );

        assert_eq!(state.congestion_events_delta("PathId(0)", 1), None);
        assert_eq!(state.congestion_events_delta("PathId(0)", 3), Some(2));

        assert_eq!(state.mtu_change("PathId(0)", 1200), None);
        assert_eq!(
            state.mtu_change("PathId(0)", 1180),
            Some(MtuChange {
                previous: 1200,
                current: 1180
            })
        );

        assert_eq!(state.loss_anomaly("PathId(0)", 0, 0, 100), None);
        assert_eq!(state.loss_anomaly("PathId(0)", 2, 200, 150), None);
        assert_eq!(
            state.loss_anomaly("PathId(0)", 12, 1_200, 350),
            Some(LossAnomaly {
                lost_packets_delta: 10,
                lost_bytes_delta: 1_000,
                tx_datagrams_delta: 200,
                loss_rate_basis_points: 500
            })
        );
    }

    #[test]
    fn path_flapping_coalesces_after_threshold_and_resolves() {
        let start = Instant::now();
        let mut tracker = PathFlapTracker::new(3, Duration::from_mins(1));

        assert_eq!(
            tracker.selected_changed(start),
            PathFlapDecision::LogSelected
        );
        assert_eq!(
            tracker.selected_changed(start + Duration::from_secs(10)),
            PathFlapDecision::LogSelected
        );
        assert_eq!(
            tracker.selected_changed(start + Duration::from_secs(20)),
            PathFlapDecision::LogSelected
        );
        assert_eq!(
            tracker.selected_changed(start + Duration::from_secs(30)),
            PathFlapDecision::EmitFlapping {
                suppressed_count: 0
            }
        );
        assert_eq!(
            tracker.selected_changed(start + Duration::from_secs(40)),
            PathFlapDecision::Suppress
        );
        assert_eq!(
            tracker.maybe_resolved(start + Duration::from_secs(101)),
            Some(PathFlapDecision::Resolved {
                suppressed_count: 1
            })
        );
    }

    #[tokio::test]
    async fn observer_task_exits_after_connection_closes() {
        const TEST_ALPN: &[u8] = b"portl/transport-telemetry-test/v1";

        let (client, server) = crate::test_util::pair().await.expect("pair bind");
        server.inner().set_alpns(vec![TEST_ALPN.to_vec()]);
        let server_addr = server.addr();
        let accept_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server
                    .inner()
                    .accept()
                    .await
                    .expect("accept should yield incoming connection");
                let connection = incoming.await.expect("server handshake");
                connection.closed().await;
            }
        });

        let connection = client
            .inner()
            .connect(server_addr, TEST_ALPN)
            .await
            .expect("connect should succeed");
        let config = ObserverConfig {
            sample_interval: None,
            summary_interval: None,
            ..ObserverConfig::default()
        };
        let observer = spawn_connection_observer(
            connection.clone(),
            TransportTelemetryContext::cli_default(),
            config,
        );

        connection.close(0u32.into(), b"test close");

        tokio::time::timeout(Duration::from_secs(5), observer)
            .await
            .expect("observer did not finish")
            .expect("observer panicked");
        tokio::time::timeout(Duration::from_secs(5), accept_task)
            .await
            .expect("accept task did not finish")
            .expect("accept task panicked");
    }
}

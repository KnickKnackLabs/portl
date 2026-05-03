//! JSON schema v1 for `GET /status*` endpoints.
//!
//! Stable contract for v0.3.2+. Additive field changes keep
//! `schema: 1`; type changes or removals bump to `schema: 2`.
//!
//! Consumers should tolerate unknown fields (serde does this
//! automatically).

use serde::{Deserialize, Serialize};

use crate::conn_registry::ConnectionSnapshot;
use crate::network_watchdog::{NetworkHealthSnapshot, WatchdogState};
use crate::relay::RelayStatus;

/// Current schema version. Emitted in every response envelope.
pub const SCHEMA_VERSION: u32 = 1;

/// Top-level `/status` response — composite of every subsection the
/// agent can answer for without querying external sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub schema: u32,
    pub kind: String,
    /// RFC3339 UTC timestamp of response generation.
    pub generated_at: String,
    pub agent: AgentInfo,
    pub connections: Vec<ConnectionSnapshot>,
    pub network: NetworkInfo,
    #[serde(default = "NetworkHealthInfo::disabled")]
    pub network_health: NetworkHealthInfo,
    #[serde(default)]
    pub session_providers: SessionProvidersInfo,
    /// Embedded-relay snapshot. Always present; `enabled=false` when
    /// the agent is not acting as a relay.
    #[serde(default = "RelayStatus::disabled")]
    pub relay: RelayStatus,
}

impl StatusResponse {
    #[must_use]
    pub fn new(
        agent: AgentInfo,
        connections: Vec<ConnectionSnapshot>,
        network: NetworkInfo,
        network_health: NetworkHealthInfo,
        session_providers: SessionProvidersInfo,
        relay: RelayStatus,
    ) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            kind: "status".to_owned(),
            generated_at: rfc3339_now(),
            agent,
            connections,
            network,
            network_health,
            session_providers,
            relay,
        }
    }
}

/// `/status/connections` response — just the list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionsResponse {
    pub schema: u32,
    pub kind: String,
    pub generated_at: String,
    pub connections: Vec<ConnectionSnapshot>,
}

impl ConnectionsResponse {
    #[must_use]
    pub fn new(connections: Vec<ConnectionSnapshot>) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            kind: "status.connections".to_owned(),
            generated_at: rfc3339_now(),
            connections,
        }
    }
}

/// `/status/network` response — relay URL list, NAT type placeholder,
/// discovery backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkResponse {
    pub schema: u32,
    pub kind: String,
    pub generated_at: String,
    pub network: NetworkInfo,
}

impl NetworkResponse {
    #[must_use]
    pub fn new(network: NetworkInfo) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            kind: "status.network".to_owned(),
            generated_at: rfc3339_now(),
            network,
        }
    }
}

/// `/status/relay` response — embedded-relay status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayResponse {
    pub schema: u32,
    pub kind: String,
    pub generated_at: String,
    pub relay: RelayStatus,
}

impl RelayResponse {
    #[must_use]
    pub fn new(relay: RelayStatus) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            kind: "status.relay".to_owned(),
            generated_at: rfc3339_now(),
            relay,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub pid: u32,
    pub version: String,
    /// Unix seconds when the agent process started.
    pub started_at_unix: u64,
    /// Absolute path of `$PORTL_HOME`.
    pub home: String,
    /// Absolute path of `metrics.sock`, surfaced so clients don't
    /// re-derive it.
    pub metrics_socket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Ordered list of relay URLs the agent is configured to use.
    /// Empty = relay disabled locally.
    pub relays: Vec<String>,
    pub discovery: DiscoveryInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryInfo {
    pub dns: bool,
    pub pkarr: bool,
    pub local: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealthInfo {
    /// Whether this agent expects the watchdog to be active for its endpoint.
    pub enabled: bool,
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

impl NetworkHealthInfo {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            state: WatchdogState::Disabled,
            endpoint_generation: 0,
            endpoint_started_at: 0,
            last_inbound_handshake_at: None,
            last_self_probe_ok_at: None,
            last_self_probe_failed_at: None,
            consecutive_self_probe_failures: 0,
            endpoint_refresh_count: 0,
            consecutive_endpoint_refresh_failures: 0,
            last_endpoint_refresh_at: None,
            next_endpoint_refresh_not_before: None,
            last_endpoint_refresh_error: None,
        }
    }
}

impl From<NetworkHealthSnapshot> for NetworkHealthInfo {
    fn from(value: NetworkHealthSnapshot) -> Self {
        Self {
            enabled: value.state != WatchdogState::Disabled,
            state: value.state,
            endpoint_generation: value.endpoint_generation,
            endpoint_started_at: value.endpoint_started_at,
            last_inbound_handshake_at: value.last_inbound_handshake_at,
            last_self_probe_ok_at: value.last_self_probe_ok_at,
            last_self_probe_failed_at: value.last_self_probe_failed_at,
            consecutive_self_probe_failures: value.consecutive_self_probe_failures,
            endpoint_refresh_count: value.endpoint_refresh_count,
            consecutive_endpoint_refresh_failures: value.consecutive_endpoint_refresh_failures,
            last_endpoint_refresh_at: value.last_endpoint_refresh_at,
            next_endpoint_refresh_not_before: value.next_endpoint_refresh_not_before,
            last_endpoint_refresh_error: value.last_endpoint_refresh_error,
        }
    }
}

impl Default for NetworkHealthInfo {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionProvidersInfo {
    pub default_provider: Option<String>,
    pub default_user: Option<DefaultUserInfo>,
    pub providers: Vec<SessionProviderInfo>,
    pub search_paths: Vec<SessionProviderSearchPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultUserInfo {
    pub name: String,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProviderInfo {
    pub name: String,
    pub detected: bool,
    pub path: Option<String>,
    pub source: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProviderSearchPath {
    pub provider: String,
    pub path: String,
    pub source: String,
    pub exists: bool,
}

/// JSON error envelope used for 4xx/5xx replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub schema: u32,
    pub kind: String,
    pub error: ErrorBody,
}

impl ErrorResponse {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            kind: "error".to_owned(),
            error: ErrorBody {
                code: code.to_owned(),
                message: message.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Minimal RFC3339 without pulling in chrono/time: render UTC
    // from unix seconds. Good enough for "observability timestamp"
    // (sub-second precision isn't needed for a dashboard).
    let (year, month, day, hh, mm, ss) = unix_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Small RFC3339 UTC decomposer. Gregorian, UTC, no leap-second
/// handling (UNIX time smears them anyway). Uses Howard Hinnant's
/// `civil_from_days` algorithm.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::similar_names
)]
fn unix_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = (secs % 86_400) as u32;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let seconds_of_minute = rem % 60;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y_i64 = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y_i64 + 1 } else { y_i64 };
    (year as u32, month, day, hours, minutes, seconds_of_minute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_decomposes_correctly() {
        assert_eq!(unix_to_ymdhms(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn known_timestamp_decomposes_correctly() {
        // 2024-01-01T00:00:00Z = 1_704_067_200
        assert_eq!(
            unix_to_ymdhms(1_704_067_200),
            (2024, 1, 1, 0, 0, 0),
            "unix_to_ymdhms(2024-01-01 epoch)"
        );
    }

    #[test]
    fn status_response_serializes_with_schema_and_kind() {
        let r = StatusResponse::new(
            AgentInfo {
                pid: 1,
                version: "0.3.2".to_owned(),
                started_at_unix: 1_704_067_200,
                home: "/home".into(),
                metrics_socket: "/home/metrics.sock".into(),
            },
            Vec::new(),
            NetworkInfo {
                relays: vec!["https://relay.example./".into()],
                discovery: DiscoveryInfo {
                    dns: true,
                    pkarr: true,
                    local: false,
                },
            },
            NetworkHealthInfo::disabled(),
            SessionProvidersInfo {
                default_provider: Some("zmx".to_owned()),
                default_user: Some(DefaultUserInfo {
                    name: "demo".to_owned(),
                    home: "/Users/demo".to_owned(),
                    shell: "/bin/zsh".to_owned(),
                }),
                providers: vec![SessionProviderInfo {
                    name: "zmx".to_owned(),
                    detected: true,
                    path: Some("/Users/demo/.local/share/mise/shims/zmx".to_owned()),
                    source: Some("mise_shim".to_owned()),
                    notes: None,
                }],
                search_paths: vec![SessionProviderSearchPath {
                    provider: "zmx".to_owned(),
                    path: "/Users/demo/.local/share/mise/shims/zmx".to_owned(),
                    source: "mise_shim".to_owned(),
                    exists: true,
                }],
            },
            RelayStatus::disabled(),
        );
        let json = serde_json::to_string(&r).expect("serialize");
        assert!(json.contains("\"schema\":1"));
        assert!(json.contains("\"kind\":\"status\""));
        assert!(json.contains("\"version\":\"0.3.2\""));
        assert!(json.contains("\"default_provider\":\"zmx\""));
        assert!(json.contains("\"source\":\"mise_shim\""));
    }

    #[test]
    fn status_response_includes_network_health() {
        let r = StatusResponse::new(
            AgentInfo {
                pid: 42,
                version: "0.0.0-test".to_owned(),
                started_at_unix: 100,
                home: "/tmp/portl".into(),
                metrics_socket: "/tmp/portl/run/metrics.sock".into(),
            },
            Vec::new(),
            NetworkInfo {
                relays: Vec::new(),
                discovery: DiscoveryInfo {
                    dns: false,
                    pkarr: false,
                    local: true,
                },
            },
            NetworkHealthInfo {
                enabled: true,
                state: WatchdogState::Ok,
                endpoint_generation: 1,
                endpoint_started_at: 100,
                last_inbound_handshake_at: Some(120),
                last_self_probe_ok_at: Some(130),
                last_self_probe_failed_at: None,
                consecutive_self_probe_failures: 0,
                endpoint_refresh_count: 0,
                consecutive_endpoint_refresh_failures: 0,
                last_endpoint_refresh_at: None,
                next_endpoint_refresh_not_before: None,
                last_endpoint_refresh_error: None,
            },
            SessionProvidersInfo::default(),
            RelayStatus::disabled(),
        );

        let json = serde_json::to_value(r).expect("serialize status response");
        assert_eq!(json["network_health"]["state"], "ok");
        assert_eq!(json["network_health"]["endpoint_generation"], 1);
    }

    #[test]
    fn error_response_stable_shape() {
        let e = ErrorResponse::new("agent_unreachable", "couldn't reach IPC");
        let json = serde_json::to_string(&e).expect("serialize");
        assert!(json.contains("\"kind\":\"error\""));
        assert!(json.contains("\"code\":\"agent_unreachable\""));
    }
}

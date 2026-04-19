//! Shared bootstrapper abstraction for target provisioning adapters.
//!
//! The core protocol only needs a small lifecycle surface: provision a
//! target, register the target's endpoint locally, query its runtime
//! status, and tear it down. Concrete adapters (docker, slicer, manual,
//! future cloud backends) keep any adapter-specific state inside the
//! opaque [`Handle::inner`] JSON blob so the trait stays object-safe and
//! non-generic.

use anyhow::Result;
use async_trait::async_trait;
use iroh_base::EndpointId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ticket::schema::Capabilities;
use crate::ticket::verify::MAX_DELEGATION_DEPTH;

/// Provisioning lifecycle surface shared by all adapters.
#[async_trait]
pub trait Bootstrapper: Send + Sync {
    /// Provision a new target from the requested specification.
    async fn provision(&self, spec: &ProvisionSpec) -> Result<Handle>;

    /// Register or verify the target's endpoint id with local adapter state.
    async fn register(&self, handle: &Handle, endpoint_id: EndpointId) -> Result<()>;

    /// Resolve the target's current lifecycle status.
    async fn resolve(&self, handle: &Handle) -> Result<TargetStatus>;

    /// Tear down the provisioned target.
    async fn teardown(&self, handle: &Handle) -> Result<()>;
}

/// Adapter-agnostic provisioning request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionSpec {
    pub name: String,
    pub adapter_params: Value,
    pub labels: Vec<(String, String)>,
}

/// Adapter-agnostic ticket minting request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketSpec {
    pub caps: Capabilities,
    pub ttl_secs: u64,
    pub to: Option<[u8; 32]>,
    #[serde(default = "default_ticket_depth")]
    pub depth: u8,
}

fn default_ticket_depth() -> u8 {
    MAX_DELEGATION_DEPTH
}

/// Opaque adapter-specific handle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Handle {
    pub adapter: String,
    pub inner: Value,
}

/// Runtime status for a provisioned target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetStatus {
    Provisioning,
    Running,
    Exited { code: i32 },
    NotFound,
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Handle, ProvisionSpec, TargetStatus, TicketSpec, default_ticket_depth};
    use crate::ticket::schema::Capabilities;

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
    fn handle_round_trips_through_json() {
        let handle = Handle {
            adapter: "docker-portl".to_owned(),
            inner: json!({
                "container_id": "abc123",
                "endpoint_id": "deadbeef",
            }),
        };

        let encoded = serde_json::to_string(&handle).expect("serialize handle");
        let decoded: Handle = serde_json::from_str(&encoded).expect("deserialize handle");

        assert_eq!(decoded, handle);
    }

    #[test]
    fn provision_spec_round_trips_through_json() {
        let spec = ProvisionSpec {
            name: "demo".to_owned(),
            adapter_params: json!({
                "image": "portl-agent:latest",
                "network": "bridge",
            }),
            labels: vec![("com.example.demo".to_owned(), "true".to_owned())],
        };

        let encoded = serde_json::to_string(&spec).expect("serialize provision spec");
        let decoded: ProvisionSpec =
            serde_json::from_str(&encoded).expect("deserialize provision spec");

        assert_eq!(decoded, spec);
    }

    #[test]
    fn ticket_spec_defaults_depth_on_json_decode() {
        let encoded = json!({
            "caps": empty_caps(),
            "ttl_secs": 60,
            "to": null,
        });

        let decoded: TicketSpec = serde_json::from_value(encoded).expect("deserialize ticket");

        assert_eq!(decoded.depth, default_ticket_depth());
    }

    #[test]
    fn target_status_serializes_exited_code() {
        let encoded = serde_json::to_value(TargetStatus::Exited { code: 17 })
            .expect("serialize target status");
        assert_eq!(encoded, json!({"Exited": {"code": 17}}));
    }
}

//! Ticket schema v1 — `PortlTicket`, `PortlBody`, `Capabilities`,
//! and associated sub-types. Structure mirrors
//! `docs/design/030-tickets.md §2` byte-for-byte: field order and
//! field types matter because postcard is positional and
//! signatures are over the encoded body. Any shuffling here is a
//! wire break.

use iroh_base::EndpointAddr;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Top-level ticket struct.
///
/// A `PortlTicket` is signed (ed25519) by its `resolved_issuer` —
/// see `030-tickets.md §2.2` rule 1 for the canonical resolution
/// procedure. `addr` carries the dialing info in iroh's native
/// `EndpointAddr` form so the same bytes can travel through
/// `ticket.iroh.computer` without translation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortlTicket {
    /// Schema version; MUST be `1` for v0.1.
    pub v: u8,
    /// Target endpoint id + transport addresses.
    pub addr: EndpointAddr,
    /// Signed body.
    pub body: PortlBody,
    /// Ed25519 signature over `postcard::to_stdvec(&canonical(&body))`.
    #[serde(with = "BigArray")]
    pub sig: [u8; 64],
}

/// The portion of a ticket that is covered by the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortlBody {
    /// Capabilities granted by this ticket.
    pub caps: Capabilities,
    /// Signed target endpoint id. MUST equal `addr.endpoint_id`.
    #[serde(with = "BigArray")]
    pub target: [u8; 32],
    /// Reserved for app-specific ALPNs such as `portl/example/v1`;
    /// MUST be empty in v0.1.
    pub alpns_extra: Vec<String>,
    /// Unix seconds; inclusive.
    pub not_before: u64,
    /// Unix seconds; exclusive. MUST be finite and `> not_before`.
    pub not_after: u64,
    /// Signer pubkey. `None` means "same as `addr.endpoint_id`"
    /// (self-signed root). See `030-tickets.md §2.2` rule 1.
    pub issuer: Option<[u8; 32]>,
    /// Delegation link. `None` for root tickets.
    pub parent: Option<Delegation>,
    /// Random entropy feeding `ticket_id`. MUST be non-zero.
    pub nonce: [u8; 8],
    /// Master-ticket payload. See `030-tickets.md §7`.
    pub bearer: Option<Vec<u8>>,
    /// Holder pubkey for proof-of-possession. See `§9`.
    pub to: Option<[u8; 32]>,
}

/// Capabilities granted by a ticket.
///
/// `presence` is the bitmap; a set bit MUST correspond to a
/// `Some` field and vice versa (canonicalisation rule §2.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Presence bitmap — bit `i` iff field `i` (in declaration
    /// order below) is `Some`.
    pub presence: u8,
    /// Bit 0.
    pub shell: Option<ShellCaps>,
    /// Bit 1.
    pub tcp: Option<Vec<PortRule>>,
    /// Bit 2.
    pub udp: Option<Vec<PortRule>>,
    /// Bit 3. Deferred to v0.2.
    pub fs: Option<FsCaps>,
    /// Bit 4.
    pub vpn: Option<VpnCaps>,
    /// Bit 5.
    pub meta: Option<MetaCaps>,
}

/// Port-range rule for `tcp` / `udp` caps.
///
/// Canonical form requires these to be lexicographically sorted
/// by `(host_glob, port_min, port_max)` and unique within the vec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub host_glob: String,
    pub port_min: u16,
    pub port_max: u16,
}

/// Shell capability bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellCaps {
    pub user_allowlist: Option<Vec<String>>,
    pub pty_allowed: bool,
    pub exec_allowed: bool,
    pub command_allowlist: Option<Vec<String>>,
    pub env_policy: EnvPolicy,
}

/// Environment-variable policy for `portl/shell/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvPolicy {
    /// All environment vars stripped.
    Deny,
    /// Inherit, then filter by allowlist.
    Merge { allow: Option<Vec<String>> },
    /// Replace with a fixed set of `(key, value)` pairs.
    Replace { base: Vec<(String, String)> },
}

/// Filesystem capability bundle. `portl/fs/v1` is deferred to v0.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsCaps {
    pub roots: Vec<String>,
    pub readonly: bool,
    pub max_size: Option<u64>,
}

/// VPN capability bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnCaps {
    pub my_ula: [u8; 16],
    pub peer_ula: [u8; 16],
    pub mtu: u16,
}

/// Meta-protocol capability bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaCaps {
    pub ping: bool,
    pub info: bool,
}

/// Delegation-chain linkage.
///
/// `parent_ticket_id` is the domain-separated SHA-256 of the
/// parent's signature, truncated to 128 bits (see
/// `030-tickets.md §2.3`). `depth_remaining` bounds further
/// delegation: each hop decrements it; when it reaches zero the
/// ticket MUST NOT be re-delegated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub parent_ticket_id: [u8; 16],
    pub depth_remaining: u8,
}

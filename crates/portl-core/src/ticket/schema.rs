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
    /// Bit 6.
    pub unix: Option<UnixCaps>,
}

/// Bit 7. When set, the `tcp` port rules also grant TCP listen
/// permission for `portl/tcp/v2` reverse forwarding. Leaving this
/// as a signed presence-bit flag avoids changing the postcard field
/// layout of `Capabilities`.
pub const TCP_LISTEN_CAP_BIT: u8 = 0b1000_0000;

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

/// Unix-domain socket forwarding capability bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixCaps {
    pub connect: Vec<UnixPathRule>,
    pub listen: Vec<UnixPathRule>,
}

/// Unix-domain socket path rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixPathRule {
    pub path: String,
}

impl UnixPathRule {
    #[must_use]
    pub fn is_valid_rule(&self, allow_broad_wildcard: bool) -> bool {
        validate_unix_path_rule(&self.path, allow_broad_wildcard).is_ok()
    }

    #[must_use]
    pub fn matches_path(&self, path: &str) -> bool {
        if !unix_socket_path_is_safe(path) {
            return false;
        }
        if self.path == "*" {
            return true;
        }
        if let Some(prefix) = self.path.strip_suffix('*') {
            return is_narrow_unix_glob(prefix) && path.starts_with(prefix);
        }
        self.path == path
    }

    #[must_use]
    pub fn covers(&self, child: &Self) -> bool {
        if !self.is_valid_rule(true) || !child.is_valid_rule(true) {
            return false;
        }
        if self.path == "*" || self.path == child.path {
            return true;
        }
        let Some(parent_prefix) = self.path.strip_suffix('*') else {
            return false;
        };
        if let Some(child_prefix) = child.path.strip_suffix('*') {
            is_narrow_unix_glob(parent_prefix) && child_prefix.starts_with(parent_prefix)
        } else {
            self.matches_path(&child.path)
        }
    }
}

pub fn validate_unix_path_rule(spec: &str, allow_broad_wildcard: bool) -> Result<(), &'static str> {
    if spec.is_empty() {
        return Err("unix path rule must not be empty");
    }
    if spec == "*" {
        return if allow_broad_wildcard {
            Ok(())
        } else {
            Err("broad unix wildcard is only available through the dev/all shortcut")
        };
    }
    if let Some(prefix) = spec.strip_suffix('*') {
        if unix_socket_path_is_safe(prefix) && is_narrow_unix_glob(prefix) {
            Ok(())
        } else {
            Err("unix path glob must have a narrow absolute prefix")
        }
    } else if unix_socket_path_is_safe(spec) {
        Ok(())
    } else {
        Err("unix path rule must be absolute and must not contain . or .. components")
    }
}

#[must_use]
pub fn unix_socket_path_is_safe(path: &str) -> bool {
    use std::path::{Component, Path};

    if path.is_empty() || path.as_bytes().contains(&0) || !path.starts_with('/') {
        return false;
    }
    Path::new(path)
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[must_use]
pub fn is_narrow_unix_glob(prefix: &str) -> bool {
    prefix.starts_with('/') && prefix.len() >= 6 && prefix != "/tmp/" && prefix != "/var/"
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

//! `portl peer` — manage the inbound-authority store (`peers.json`).
//!
//! v0.3.0 replaced the hidden `PORTL_TRUST_ROOTS` env-var surface
//! with a filesystem-backed store the agent reloads live. Every
//! verb here is a direct manipulation of that store; there is no
//! agent round-trip (except `add-unsafe-raw` which only writes).
//!
//! Future: `invite`, `accept`, `pair` (pairing handshake over iroh
//! ALPN `portl/pair/v1`) — deferred past v0.3.0 because the
//! `add-unsafe-raw` escape hatch covers the self-host case that
//! motivated the rework.

pub mod add_unsafe_raw;
pub mod invite;
pub mod ls;
pub mod pair;
pub mod unlink;

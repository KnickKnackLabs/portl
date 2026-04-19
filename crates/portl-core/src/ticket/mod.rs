//! Ticket schema, canonical-form enforcement, codec, hashes,
//! signing, verification, and minting.
//!
//! Public surface is deliberately staged across M1 sub-tasks:
//!   - M1.1 → `schema` (types only)
//!   - M1.2 → `canonical`
//!   - M1.3 → `codec`
//!   - M1.4 → `hash` + `sign`
//!   - M1.5 → `mint`
//!   - M1.6 → `verify`
//!   - M1.8 → `offer`
//!
//! See `docs/design/030-tickets.md` for the authoritative spec.

pub mod canonical;
pub mod codec;
pub mod schema;

pub use canonical::{canonical_check, resolved_issuer};
pub use codec::{decode, encode};

//! Delegation-chain verification.
//!
//! M1.5 needs the depth constant for minting; full chain verification
//! lands in M1.6.

/// Maximum number of delegation hops below a root ticket.
pub const MAX_DELEGATION_DEPTH: u8 = 8;

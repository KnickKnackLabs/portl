//! Shared error type for portl-core.
//!
//! One enum spans ticket codec, canonicalisation, signature,
//! chain-verification, clock-skew, and identity-storage errors.
//! We accept slightly mixed concerns in exchange for a single
//! stable `PortlError` at the crate's public boundary; the
//! `String` / `&'static str` payloads carry the discriminator
//! for callers that need to branch.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PortlError {
    /// Postcard codec (encode/decode).
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),

    /// Base32 decode error with a description.
    #[error("base32: {0}")]
    Base32(&'static str),

    /// Canonical-form violation per `030-tickets.md §2.2`.
    #[error("canonical form violated: {0}")]
    Canonical(&'static str),

    /// Ed25519 signature verification failure.
    #[error("signature: {0}")]
    Signature(&'static str),

    /// Ticket-level invariant violation not specific to a sub-concern.
    #[error("ticket: {0}")]
    Ticket(&'static str),

    /// Delegation-chain verification failure.
    #[error("chain: {0}")]
    Chain(&'static str),

    /// Clock-skew or TTL failure.
    #[error("clock: {0}")]
    Clock(&'static str),

    /// Filesystem or I/O error while touching on-disk identity.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `Result<T, PortlError>`.
pub type Result<T, E = PortlError> = std::result::Result<T, E>;

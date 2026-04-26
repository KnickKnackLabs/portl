//! Rendezvous backend trait and types.

use async_trait::async_trait;
use thiserror::Error;

use super::exchange::PortlExchangeEnvelopeV1;
use super::short_code::ShortCode;

/// An offer being posted to the rendezvous backend.
#[derive(Debug, Clone)]
pub struct ExchangeOffer {
    /// Envelope to be delivered to the accepting peer.
    pub envelope: PortlExchangeEnvelopeV1,
    /// How long the offer remains live in the rendezvous, in seconds.
    pub rendezvous_ttl_secs: u64,
}

/// Handle to a posted offer; carries the short code presented to the user.
#[derive(Debug, Clone)]
pub struct OfferHandle {
    code: ShortCode,
}

impl OfferHandle {
    /// Construct a new handle wrapping a short code.
    pub fn new(code: ShortCode) -> Self {
        Self { code }
    }

    /// The short code the offerer should share with the accepter.
    pub fn code(&self) -> &ShortCode {
        &self.code
    }
}

/// Outcome of a successful accept.
#[derive(Debug, Clone)]
pub struct AcceptOutcome {
    /// The envelope that was offered.
    pub envelope: PortlExchangeEnvelopeV1,
}

/// Errors produced by a [`RendezvousBackend`].
#[derive(Debug, Error)]
pub enum RendezvousError {
    /// The short code has already been accepted by another party.
    #[error("short code was already claimed")]
    AlreadyClaimed,
    /// The short code's TTL has expired.
    #[error("short code expired")]
    Expired,
    /// No offer was found for the supplied short code.
    #[error("short code was not found")]
    NotFound,
    /// The backend itself reported an error.
    #[error("rendezvous backend failed: {0}")]
    Backend(String),
}

/// Backend abstraction for the short-code rendezvous.
#[async_trait]
pub trait RendezvousBackend: Send + Sync {
    /// Post an offer and obtain a handle containing the short code.
    async fn offer(&self, offer: ExchangeOffer) -> Result<OfferHandle, RendezvousError>;
    /// Accept an offer by its short code, consuming it on success.
    async fn accept(&self, code: &ShortCode) -> Result<AcceptOutcome, RendezvousError>;
}

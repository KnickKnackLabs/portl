//! Rendezvous backend trait and types (skeleton).

/// Outcome of an accept attempt.
#[derive(Debug)]
pub enum AcceptOutcome {
    /// Placeholder variant until behavior lands.
    Pending,
}

/// An offer being made to the rendezvous.
#[derive(Debug, Clone)]
pub struct ExchangeOffer;

/// Handle to a posted offer.
#[derive(Debug)]
pub struct OfferHandle;

/// Backend abstraction for the short-code rendezvous.
pub trait RendezvousBackend {}

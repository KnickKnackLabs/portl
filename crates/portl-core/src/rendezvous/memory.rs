//! In-memory rendezvous backend for tests.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::backend::{
    AcceptOutcome, ExchangeOffer, OfferHandle, RendezvousBackend, RendezvousError,
};
use super::short_code::ShortCode;

struct StoredOffer {
    envelope: super::exchange::PortlExchangeEnvelopeV1,
    expires_at: Instant,
}

#[derive(Default)]
struct Inner {
    offers: HashMap<String, StoredOffer>,
    claimed: HashSet<String>,
}

/// In-memory implementation of [`RendezvousBackend`] for tests and local use.
#[derive(Clone, Default)]
pub struct MemoryRendezvousBackend {
    inner: Arc<Mutex<Inner>>,
    next_nameplate: Arc<AtomicU64>,
}

impl MemoryRendezvousBackend {
    /// Create a new empty backend.
    pub fn new() -> Self {
        Self::default()
    }

    fn allocate_nameplate(&self) -> String {
        let n = self.next_nameplate.fetch_add(1, Ordering::Relaxed);
        n.to_string()
    }
}

#[async_trait]
impl RendezvousBackend for MemoryRendezvousBackend {
    async fn offer(&self, offer: ExchangeOffer) -> Result<OfferHandle, RendezvousError> {
        let nameplate = self.allocate_nameplate();
        let code = ShortCode::generate_with_nameplate(nameplate)
            .map_err(|e| RendezvousError::Backend(e.to_string()))?;
        let key = code.display_code();
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(offer.rendezvous_ttl_secs))
            .ok_or_else(|| RendezvousError::Backend("ttl overflow".to_owned()))?;
        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|e| RendezvousError::Backend(e.to_string()))?;
            guard.offers.insert(
                key,
                StoredOffer {
                    envelope: offer.envelope,
                    expires_at,
                },
            );
        }
        Ok(OfferHandle::new(code))
    }

    async fn accept(&self, code: &ShortCode) -> Result<AcceptOutcome, RendezvousError> {
        let key = code.display_code();
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| RendezvousError::Backend(e.to_string()))?;
        if guard.claimed.contains(&key) {
            return Err(RendezvousError::AlreadyClaimed);
        }
        let stored = guard.offers.get(&key).ok_or(RendezvousError::NotFound)?;
        if Instant::now() >= stored.expires_at {
            return Err(RendezvousError::Expired);
        }
        let stored = guard
            .offers
            .remove(&key)
            .expect("offer presence verified above");
        guard.claimed.insert(key);
        Ok(AcceptOutcome {
            envelope: stored.envelope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::exchange::{PortlExchangeEnvelopeV1, SessionShareEnvelopeV1};

    fn fixture_envelope() -> PortlExchangeEnvelopeV1 {
        let share = SessionShareEnvelopeV1 {
            workspace_id: "ws_test".to_owned(),
            friendly_name: "dev".to_owned(),
            conflict_handle: "7k3p".to_owned(),
            origin_label_hint: Some("alice-laptop".to_owned()),
            target_label_hint: Some("max-b265".to_owned()),
            target_endpoint_id_hex: hex::encode([1u8; 32]),
            provider: Some("zmx".to_owned()),
            provider_session: "dev".to_owned(),
            ticket: "portltestticket".to_owned(),
            access_not_after_unix: 2_000_000,
        };
        PortlExchangeEnvelopeV1::session_share(share, 1_000_000, Some(1_000_600))
    }

    #[tokio::test]
    async fn in_memory_offer_accept_exchanges_envelope_once() {
        let backend = MemoryRendezvousBackend::default();
        let offer = ExchangeOffer {
            envelope: fixture_envelope(),
            rendezvous_ttl_secs: 600,
        };
        let handle = backend.offer(offer).await.unwrap();

        let accepted = backend.accept(handle.code()).await.unwrap();
        assert_eq!(accepted.envelope.schema, "portl.exchange.v1");

        let err = backend.accept(handle.code()).await.unwrap_err();
        assert!(err.to_string().contains("already claimed"));
    }

    #[tokio::test]
    async fn accept_unknown_code_returns_not_found() {
        let backend = MemoryRendezvousBackend::default();
        let code = ShortCode::parse("PORTL-S-999-nebula-involve").unwrap();
        let err = backend.accept(&code).await.unwrap_err();
        assert!(matches!(err, RendezvousError::NotFound));
    }

    #[tokio::test]
    async fn accept_expired_offer_returns_expired() {
        let backend = MemoryRendezvousBackend::default();
        let offer = ExchangeOffer {
            envelope: fixture_envelope(),
            rendezvous_ttl_secs: 0,
        };
        let handle = backend.offer(offer).await.unwrap();
        // Zero-second TTL: expires_at == offer instant, so accept must see Expired
        // without sleeping. Repeated accepts must keep returning Expired (the offer
        // is not silently consumed on failure).
        let err = backend.accept(handle.code()).await.unwrap_err();
        assert!(matches!(err, RendezvousError::Expired));
        let err = backend.accept(handle.code()).await.unwrap_err();
        assert!(matches!(err, RendezvousError::Expired));
    }

    #[tokio::test]
    async fn nameplates_are_unique_per_offer() {
        let backend = MemoryRendezvousBackend::default();
        let h1 = backend
            .offer(ExchangeOffer {
                envelope: fixture_envelope(),
                rendezvous_ttl_secs: 60,
            })
            .await
            .unwrap();
        let h2 = backend
            .offer(ExchangeOffer {
                envelope: fixture_envelope(),
                rendezvous_ttl_secs: 60,
            })
            .await
            .unwrap();
        assert_ne!(h1.code().nameplate(), h2.code().nameplate());
    }
}

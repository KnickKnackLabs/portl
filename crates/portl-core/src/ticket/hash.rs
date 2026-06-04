//! Domain-separated ticket hash helpers.
//!
//! Both ids are truncated SHA-256 digests of the signature bytes, but
//! they deliberately use distinct ASCII domain tags so a collision in
//! one context cannot be replayed in the other.

use sha2::{Digest, Sha256};

const TICKET_ID_DOMAIN: &[u8] = b"portl/ticket-id/v1";
const PARENT_TICKET_ID_DOMAIN: &[u8] = b"portl/parent/v1";
const CLIENT_NONCE_LOG_DOMAIN: &[u8] = b"portl/client-nonce-log/v1";

/// Compute `ticket_id = sha256("portl/ticket-id/v1" || sig)[..16]`.
#[must_use]
pub fn ticket_id(sig: &[u8; 64]) -> [u8; 16] {
    hash16(TICKET_ID_DOMAIN, sig)
}

/// Compute `parent_ticket_id = sha256("portl/parent/v1" || sig)[..16]`.
#[must_use]
pub fn parent_ticket_id(sig: &[u8; 64]) -> [u8; 16] {
    hash16(PARENT_TICKET_ID_DOMAIN, sig)
}

/// Compute `client_nonce_hash = sha256("portl/client-nonce-log/v1" || client_nonce)[..16]`.
///
/// This is a log-only correlation helper. It must never replace the raw
/// nonce in protocol messages, and callers should log this derived value
/// instead of logging `TicketOffer::client_nonce` directly.
#[must_use]
pub fn client_nonce_log_hash(client_nonce: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(CLIENT_NONCE_LOG_DOMAIN);
    hasher.update(client_nonce);
    let digest = hasher.finalize();
    digest[..16].try_into().expect("sha256 digest is 32 bytes")
}

fn hash16(domain: &[u8], sig: &[u8; 64]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(sig);
    let digest = hasher.finalize();
    // SAFETY(panic): `Sha256::finalize()` always returns a 32-byte
    // output, so slicing to 16 and converting to `[u8; 16]` never fails.
    digest[..16].try_into().expect("sha256 digest is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::{client_nonce_log_hash, parent_ticket_id, ticket_id};

    #[test]
    fn client_nonce_log_hash_is_deterministic_for_same_nonce() {
        let nonce = [7u8; 16];

        assert_eq!(client_nonce_log_hash(&nonce), client_nonce_log_hash(&nonce));
    }

    #[test]
    fn client_nonce_log_hash_changes_for_different_nonces() {
        let first = [1u8; 16];
        let second = [2u8; 16];

        assert_ne!(
            client_nonce_log_hash(&first),
            client_nonce_log_hash(&second)
        );
    }

    #[test]
    fn client_nonce_log_hash_uses_distinct_domain_from_ticket_ids() {
        let sig = [3u8; 64];
        let nonce = [3u8; 16];

        assert_ne!(client_nonce_log_hash(&nonce), ticket_id(&sig));
        assert_ne!(client_nonce_log_hash(&nonce), parent_ticket_id(&sig));
    }
}

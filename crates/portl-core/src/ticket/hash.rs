//! Domain-separated ticket hash helpers.
//!
//! Both ids are truncated SHA-256 digests of the signature bytes, but
//! they deliberately use distinct ASCII domain tags so a collision in
//! one context cannot be replayed in the other.

use sha2::{Digest, Sha256};

const TICKET_ID_DOMAIN: &[u8] = b"portl/ticket-id/v1";
const PARENT_TICKET_ID_DOMAIN: &[u8] = b"portl/parent/v1";

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

fn hash16(domain: &[u8], sig: &[u8; 64]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(sig);
    let digest = hasher.finalize();
    // SAFETY(panic): `Sha256::finalize()` always returns a 32-byte
    // output, so slicing to 16 and converting to `[u8; 16]` never fails.
    digest[..16].try_into().expect("sha256 digest is 32 bytes")
}

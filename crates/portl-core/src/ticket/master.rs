use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use iroh_base::EndpointAddr;
use rand::random;

use crate::error::{PortlError, Result};
use crate::ticket::canonical::canonical_check_ticket;
use crate::ticket::schema::{Capabilities, PortlBody, PortlTicket};
use crate::ticket::sign::sign_body;

const MAX_MASTER_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Mint a root/master ticket carrying a non-empty bearer token.
pub fn mint_master(
    sk: &SigningKey,
    addr: EndpointAddr,
    caps: Capabilities,
    bearer: Vec<u8>,
    ttl_secs: u64,
    to: [u8; 32],
) -> Result<PortlTicket> {
    if bearer.is_empty() {
        return Err(PortlError::Ticket("master ticket bearer must be non-empty"));
    }
    if ttl_secs == 0 {
        return Err(PortlError::Ticket("master ticket ttl must be > 0"));
    }
    if ttl_secs > MAX_MASTER_TTL_SECS {
        return Err(PortlError::Ticket("master ticket ttl exceeds 30 days"));
    }

    let now = unix_now_secs()?;
    let not_after = now
        .checked_add(ttl_secs)
        .ok_or(PortlError::Ticket("master ticket ttl overflows u64"))?;
    let body = PortlBody {
        caps,
        target: *addr.id.as_bytes(),
        alpns_extra: vec![],
        not_before: now,
        not_after,
        issuer: issuer_for(sk, &addr),
        parent: None,
        nonce: fresh_nonce(),
        bearer: Some(bearer),
        to: Some(to),
    };
    let sig = sign_body(sk, &body)?;
    let ticket = PortlTicket {
        v: 1,
        addr,
        body,
        sig,
    };
    canonical_check_ticket(&ticket)?;
    Ok(ticket)
}

/// Return the bearer bytes carried by a master ticket, if present.
#[must_use]
pub fn extract_bearer(ticket: &PortlTicket) -> Option<&[u8]> {
    ticket.body.bearer.as_deref()
}

fn issuer_for(sk: &SigningKey, addr: &EndpointAddr) -> Option<[u8; 32]> {
    let signer = sk.verifying_key().to_bytes();
    if signer == *addr.id.as_bytes() {
        None
    } else {
        Some(signer)
    }
}

fn fresh_nonce() -> [u8; 8] {
    loop {
        let nonce = random::<[u8; 8]>();
        if nonce != [0u8; 8] {
            return nonce;
        }
    }
}

fn unix_now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PortlError::Clock("system clock is before unix epoch"))?
        .as_secs())
}

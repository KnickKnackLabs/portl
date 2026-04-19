//! Ticket minting helpers.

use rand::random;

use crate::caps::is_narrowing;
use crate::error::{PortlError, Result};
use crate::ticket::canonical::canonical_check_ticket;
use crate::ticket::hash::parent_ticket_id;
use crate::ticket::schema::{Capabilities, Delegation, PortlBody, PortlTicket};
use crate::ticket::sign::sign_body;
use crate::ticket::verify::MAX_DELEGATION_DEPTH;
use ed25519_dalek::SigningKey;
use iroh_base::EndpointAddr;

/// Mint a root ticket.
pub fn mint_root(
    sk: &SigningKey,
    addr: EndpointAddr,
    caps: Capabilities,
    not_before: u64,
    not_after: u64,
    to: Option<[u8; 32]>,
) -> Result<PortlTicket> {
    let body = PortlBody {
        caps,
        alpns_extra: vec![],
        not_before,
        not_after,
        issuer: issuer_for(sk, &addr),
        parent: None,
        nonce: fresh_nonce(),
        bearer: None,
        to,
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

/// Mint a delegated ticket that narrows an existing parent.
pub fn mint_delegated(
    parent_sk: &SigningKey,
    parent_ticket: &PortlTicket,
    child_caps: Capabilities,
    not_before: u64,
    not_after: u64,
    to: Option<[u8; 32]>,
) -> Result<PortlTicket> {
    canonical_check_ticket(parent_ticket)?;

    if !is_narrowing(&parent_ticket.body.caps, &child_caps) {
        return Err(PortlError::Ticket("child capabilities widen parent"));
    }
    if not_before < parent_ticket.body.not_before || not_after > parent_ticket.body.not_after {
        return Err(PortlError::Ticket("child validity window escapes parent"));
    }

    let depth_remaining = match parent_ticket.body.parent {
        Some(ref parent) => parent
            .depth_remaining
            .checked_sub(1)
            .ok_or(PortlError::Ticket("parent depth exhausted"))?,
        None => MAX_DELEGATION_DEPTH - 1,
    };

    let body = PortlBody {
        caps: child_caps,
        alpns_extra: vec![],
        not_before,
        not_after,
        issuer: issuer_for(parent_sk, &parent_ticket.addr),
        parent: Some(Delegation {
            parent_ticket_id: parent_ticket_id(&parent_ticket.sig),
            depth_remaining,
        }),
        nonce: fresh_nonce(),
        bearer: None,
        to,
    };
    let sig = sign_body(parent_sk, &body)?;
    let ticket = PortlTicket {
        v: 1,
        addr: parent_ticket.addr.clone(),
        body,
        sig,
    };
    canonical_check_ticket(&ticket)?;
    Ok(ticket)
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

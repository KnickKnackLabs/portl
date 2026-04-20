use portl_core::caps::is_narrowing;
use portl_core::ticket::canonical::{canonical_check_ticket, resolved_issuer};
use portl_core::ticket::hash::{parent_ticket_id, ticket_id};
use portl_core::ticket::offer::verify_pop;
use portl_core::ticket::schema::{Capabilities, PortlTicket};
use portl_core::ticket::sign::verify_body;
use portl_core::ticket::verify::{MAX_DELEGATION_DEPTH, TrustRoots};
use portl_proto::ticket_v1::{AckReason, TicketOffer};
use sha2::{Digest, Sha256};

use crate::revocations::RevocationSet;

const CLOCK_SKEW_SECS: u64 = 60;
const PEER_TOKEN_DOMAIN: &[u8] = b"portl/peer-token/v1";

pub trait RateLimitGate: Send + Sync {
    fn check(&self, source_id: [u8; 32]) -> bool;
}

pub struct AcceptanceInput<'a> {
    pub offer: &'a TicketOffer,
    pub source_id: [u8; 32],
    pub trust_roots: &'a TrustRoots,
    pub revocations: &'a RevocationSet,
    pub now: u64,
    pub rate_limit: &'a dyn RateLimitGate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceOutcome {
    Accepted {
        peer_token: [u8; 16],
        caps: Box<Capabilities>,
        ticket_id: [u8; 16],
        bearer: Option<Vec<u8>>,
    },
    Rejected {
        reason: AckReason,
    },
}

pub fn evaluate_offer(input: &AcceptanceInput<'_>) -> AcceptanceOutcome {
    if !input.rate_limit.check(input.source_id) {
        return reject(AckReason::RateLimited);
    }

    let terminal = match decode_offer_ticket(&input.offer.ticket) {
        Ok(ticket) => ticket,
        Err(reason) => return reject(reason),
    };

    let chain = match input
        .offer
        .chain
        .iter()
        .map(|bytes| decode_offer_ticket(bytes))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(chain) => chain,
        Err(reason) => return reject(reason),
    };

    let caps = match verify_chain_without_time(&terminal, &chain, input.trust_roots) {
        Ok(caps) => caps,
        Err(reason) => return reject(reason),
    };

    if chain
        .iter()
        .chain(std::iter::once(&terminal))
        .any(|ticket| input.revocations.contains(&ticket_id(&ticket.sig)))
    {
        return reject(AckReason::Revoked);
    }

    if let Some(reason) = check_validity_windows(&terminal, &chain, input.now) {
        return reject(reason);
    }

    if let Some(reason) = check_proof(&terminal, input.offer) {
        return reject(reason);
    }

    let terminal_ticket_id = ticket_id(&terminal.sig);
    AcceptanceOutcome::Accepted {
        peer_token: derive_peer_token(input.source_id, terminal_ticket_id),
        caps: Box::new(caps),
        ticket_id: terminal_ticket_id,
        bearer: terminal.body.bearer,
    }
}

fn decode_offer_ticket(bytes: &[u8]) -> Result<PortlTicket, AckReason> {
    let ticket: PortlTicket =
        postcard::from_bytes(bytes).map_err(|_| AckReason::InternalError {
            detail: Some("malformed offer".to_owned()),
        })?;
    canonical_check_ticket(&ticket).map_err(|_| AckReason::InternalError {
        detail: Some("non-canonical ticket".to_owned()),
    })?;
    let reencoded = postcard::to_stdvec(&ticket).map_err(|_| AckReason::InternalError {
        detail: Some("malformed offer".to_owned()),
    })?;
    if reencoded.as_slice() != bytes {
        return Err(AckReason::InternalError {
            detail: Some("non-canonical ticket".to_owned()),
        });
    }
    Ok(ticket)
}

fn verify_chain_without_time(
    terminal: &PortlTicket,
    chain: &[PortlTicket],
    roots: &TrustRoots,
) -> Result<Capabilities, AckReason> {
    let all_tickets: Vec<&PortlTicket> = chain.iter().chain(std::iter::once(terminal)).collect();
    if all_tickets.is_empty() {
        return Err(AckReason::BadChain);
    }
    if all_tickets.len() > usize::from(MAX_DELEGATION_DEPTH) + 1 {
        return Err(AckReason::BadChain);
    }

    let target = *all_tickets[0].addr.id.as_bytes();
    for ticket in &all_tickets {
        canonical_check_ticket(ticket).map_err(|_| AckReason::BadSignature)?;
        if ticket.v != 1 {
            return Err(AckReason::BadChain);
        }
        if *ticket.addr.id.as_bytes() != target {
            return Err(AckReason::BadChain);
        }
    }

    let root = all_tickets[0];
    if root.body.parent.is_some() {
        return Err(AckReason::BadChain);
    }
    let root_key = resolved_issuer(root);
    if !roots.0.contains(&root_key) {
        return Err(AckReason::BadChain);
    }
    verify_body(&root_key, &root.body, &root.sig).map_err(|_| AckReason::BadSignature)?;

    let mut parent = root;
    for child in all_tickets.iter().skip(1).copied() {
        let parent_ref = child.body.parent.as_ref().ok_or(AckReason::BadChain)?;

        let parent_key = resolved_issuer(parent);
        verify_body(&parent_key, &child.body, &child.sig).map_err(|_| AckReason::BadSignature)?;

        let child_resolved = resolved_issuer(child);
        if child_resolved != parent_key {
            return Err(AckReason::BadChain);
        }

        if parent_ref.parent_ticket_id != parent_ticket_id(&parent.sig) {
            return Err(AckReason::BadChain);
        }
        if !is_narrowing(&parent.body.caps, &child.body.caps) {
            return Err(AckReason::CapsExceedParent);
        }
        if child.body.not_before < parent.body.not_before
            || child.body.not_after > parent.body.not_after
        {
            return Err(AckReason::BadChain);
        }

        let expected_depth = match parent.body.parent {
            Some(ref delegation) => delegation
                .depth_remaining
                .checked_sub(1)
                .ok_or(AckReason::BadChain)?,
            None => MAX_DELEGATION_DEPTH - 1,
        };
        if parent_ref.depth_remaining != expected_depth {
            return Err(AckReason::BadChain);
        }

        parent = child;
    }

    Ok(terminal.body.caps.clone())
}

fn check_validity_windows(
    terminal: &PortlTicket,
    chain: &[PortlTicket],
    now: u64,
) -> Option<AckReason> {
    for ticket in chain.iter().chain(std::iter::once(terminal)) {
        if now.saturating_add(CLOCK_SKEW_SECS) < ticket.body.not_before {
            return Some(AckReason::NotYetValid);
        }
        if now >= ticket.body.not_after {
            return Some(AckReason::Expired);
        }
    }

    None
}

fn check_proof(terminal: &PortlTicket, offer: &TicketOffer) -> Option<AckReason> {
    let holder = terminal.body.to?;
    let Some(proof) = offer.proof.as_ref() else {
        return Some(AckReason::ProofMissing);
    };
    verify_pop(
        &holder,
        &ticket_id(&terminal.sig),
        &offer.client_nonce,
        proof,
    )
    .err()
    .map(|_| AckReason::ProofInvalid)
}

fn derive_peer_token(source_id: [u8; 32], ticket_id: [u8; 16]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(source_id);
    hasher.update(ticket_id);
    hasher.update(PEER_TOKEN_DOMAIN);
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("peer token length")
}

fn reject(reason: AckReason) -> AcceptanceOutcome {
    AcceptanceOutcome::Rejected { reason }
}

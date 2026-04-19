//! Delegation-chain verification.

use std::collections::HashSet;

use crate::caps::is_narrowing;
use crate::error::{PortlError, Result};
use crate::ticket::canonical::{canonical_check_ticket, resolved_issuer};
use crate::ticket::hash::parent_ticket_id;
use crate::ticket::schema::{Capabilities, PortlTicket};
use crate::ticket::sign::verify_body;

/// Maximum number of delegation hops below a root ticket.
pub const MAX_DELEGATION_DEPTH: u8 = 8;

/// Trust anchor set for root-ticket issuers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustRoots(pub HashSet<[u8; 32]>);

/// Verify a root or delegated ticket chain and return the terminal caps.
pub fn verify_chain(
    terminal: &PortlTicket,
    chain: &[PortlTicket],
    roots: &TrustRoots,
    now: u64,
) -> Result<Capabilities> {
    let all_tickets: Vec<&PortlTicket> = chain.iter().chain(std::iter::once(terminal)).collect();
    if all_tickets.is_empty() {
        return Err(PortlError::Chain("empty chain"));
    }
    if all_tickets.len() > usize::from(MAX_DELEGATION_DEPTH) + 1 {
        return Err(PortlError::Chain("delegation depth exceeded"));
    }

    let target = *all_tickets[0].addr.id.as_bytes();
    for ticket in &all_tickets {
        canonical_check_ticket(ticket)?;
        if ticket.v != 1 {
            return Err(PortlError::Ticket("unsupported ticket version"));
        }
        if *ticket.addr.id.as_bytes() != target {
            return Err(PortlError::Chain("mismatched endpoint_id in chain"));
        }
        check_time_window(ticket, now)?;
    }

    let root = all_tickets[0];
    if root.body.parent.is_some() {
        return Err(PortlError::Chain("root ticket must not have parent"));
    }
    let root_key = resolved_issuer(root);
    if !roots.0.contains(&root_key) {
        return Err(PortlError::Chain("unknown root"));
    }
    verify_body(&root_key, &root.body, &root.sig)?;

    let mut parent = root;
    for child in all_tickets.iter().skip(1).copied() {
        let parent_ref = child
            .body
            .parent
            .as_ref()
            .ok_or(PortlError::Chain("delegated ticket missing parent"))?;

        let parent_key = resolved_issuer(parent);
        verify_body(&parent_key, &child.body, &child.sig)?;

        if parent_ref.parent_ticket_id != parent_ticket_id(&parent.sig) {
            return Err(PortlError::Chain("parent ticket id mismatch"));
        }
        if !is_narrowing(&parent.body.caps, &child.body.caps) {
            return Err(PortlError::Chain("child caps widen parent"));
        }
        if child.body.not_before < parent.body.not_before
            || child.body.not_after > parent.body.not_after
        {
            return Err(PortlError::Chain("child validity window escapes parent"));
        }

        let expected_depth = match parent.body.parent {
            Some(ref delegation) => delegation
                .depth_remaining
                .checked_sub(1)
                .ok_or(PortlError::Chain("parent depth exhausted"))?,
            None => MAX_DELEGATION_DEPTH - 1,
        };
        if parent_ref.depth_remaining != expected_depth {
            return Err(PortlError::Chain("depth_remaining mismatch"));
        }

        parent = child;
    }

    Ok(terminal.body.caps.clone())
}

fn check_time_window(ticket: &PortlTicket, now: u64) -> Result<()> {
    if now.saturating_add(60) < ticket.body.not_before {
        return Err(PortlError::Clock("ticket not yet valid"));
    }
    if now >= ticket.body.not_after {
        return Err(PortlError::Clock("ticket expired"));
    }
    Ok(())
}

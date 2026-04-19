//! Postcard codec + `iroh_tickets::Ticket` impl.
//!
//! `encode` and `decode` both enforce canonical form — encode
//! refuses to emit a non-canonical ticket, decode refuses to
//! accept one. `decode` additionally enforces rule 6 from
//! `030-tickets.md §2.2`: `postcard::to_stdvec(decoded) ==
//! received_bytes`. This blocks malleability attacks where an
//! attacker replays a differently-encoded-but-semantically-
//! equivalent set of bytes.
//!
//! Implementing `iroh_tickets::Ticket` with `KIND = "portl"` buys
//! us the `portl<base32>` URI shape, parseability in
//! `ticket.iroh.computer`, and a common dialing-info layout
//! with every other iroh app.

use iroh_tickets::{ParseError, Ticket};
use n0_error::e;

use crate::error::{PortlError, Result};
use crate::ticket::canonical::canonical_check_ticket;
use crate::ticket::schema::PortlTicket;

/// Encode a ticket to canonical wire bytes.
///
/// Runs `canonical_check_ticket` first; callers can rely on the
/// output being decode-round-trippable without a second check.
pub fn encode(ticket: &PortlTicket) -> Result<Vec<u8>> {
    canonical_check_ticket(ticket)?;
    Ok(postcard::to_stdvec(ticket)?)
}

/// Decode wire bytes into a ticket, enforcing every canonical-form
/// rule including the re-encode invariant.
pub fn decode(bytes: &[u8]) -> Result<PortlTicket> {
    let ticket: PortlTicket = postcard::from_bytes(bytes)?;
    canonical_check_ticket(&ticket)?;
    // Rule 6: postcard(decoded) == received_bytes.
    let reencoded = postcard::to_stdvec(&ticket)?;
    if reencoded.as_slice() != bytes {
        return Err(PortlError::Canonical("re-encode mismatch"));
    }
    Ok(ticket)
}

impl Ticket for PortlTicket {
    const KIND: &'static str = "portl";

    fn to_bytes(&self) -> Vec<u8> {
        // iroh_tickets doesn't return Result here, so we fall back
        // to the non-canonical form on error. In practice a ticket
        // that passed canonical_check at mint time always encodes.
        postcard::to_stdvec(self).unwrap_or_default()
    }

    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, ParseError> {
        let ticket: Self = postcard::from_bytes(bytes)?;
        canonical_check_ticket(&ticket).map_err(|_| {
            e!(ParseError::Verify {
                message: "canonical form violated"
            })
        })?;
        let reencoded = postcard::to_stdvec(&ticket)?;
        if reencoded.as_slice() != bytes {
            return Err(e!(ParseError::Verify {
                message: "re-encode mismatch"
            }));
        }
        Ok(ticket)
    }
}

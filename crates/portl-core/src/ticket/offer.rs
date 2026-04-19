//! `TicketOffer` / `TicketAck` and proof-of-possession helpers.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{PortlError, Result};
use crate::ticket::hash::ticket_id;
use crate::ticket::schema::{Capabilities, PortlTicket};

const POP_DOMAIN: &[u8] = b"portl/ticket-pop/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketOffer {
    pub ticket: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    #[serde(with = "option_signature_bytes")]
    pub proof: Option<[u8; 64]>,
    pub client_nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketAck {
    pub ok: bool,
    pub reason: Option<AckReason>,
    pub peer_token: Option<[u8; 16]>,
    pub effective_caps: Option<Capabilities>,
    pub server_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckReason {
    InvalidTicket,
    Expired,
    Revoked,
    BadSignature,
    WrongRoot,
    DepthExceeded,
    WidenedCaps,
    BadProof,
    WrongTo,
    BadChain,
    ClockSkew,
    RateLimited,
}

/// Compute the proof-of-possession signature for a `to`-bound ticket.
#[must_use]
pub fn compute_pop_sig(
    op_sk: &SigningKey,
    ticket_id: &[u8; 16],
    client_nonce: &[u8; 16],
) -> [u8; 64] {
    let digest = pop_digest(ticket_id, client_nonce);
    op_sk.sign(&digest).to_bytes()
}

/// Verify a proof-of-possession signature with strict Ed25519 checks.
pub fn verify_pop(
    op_pk: &[u8; 32],
    ticket_id: &[u8; 16],
    client_nonce: &[u8; 16],
    proof: &[u8; 64],
) -> Result<()> {
    let digest = pop_digest(ticket_id, client_nonce);
    let verifying_key = VerifyingKey::from_bytes(op_pk)
        .map_err(|_| PortlError::Signature("invalid proof public key"))?;
    let signature = Signature::from_bytes(proof);
    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|_| PortlError::Signature("bad proof"))
}

/// Enforce the `to`-binding proof requirement for a terminal ticket.
pub fn validate_ticket_proof(
    ticket: &PortlTicket,
    client_nonce: &[u8; 16],
    proof: Option<&[u8; 64]>,
) -> Result<()> {
    match (ticket.body.to, proof) {
        (Some(holder), Some(sig)) => {
            verify_pop(&holder, &ticket_id(&ticket.sig), client_nonce, sig)
        }
        (None, None) => Ok(()),
        (None, Some(_)) => Err(PortlError::Ticket("proof not expected for bearer ticket")),
        (Some(_), None) => Err(PortlError::Ticket("proof required for to-bound ticket")),
    }
}

fn pop_digest(ticket_id: &[u8; 16], client_nonce: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POP_DOMAIN);
    hasher.update(ticket_id);
    hasher.update(client_nonce);
    hasher.finalize().into()
}

mod option_signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(value: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&bytes.as_slice()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let maybe = Option::<Vec<u8>>::deserialize(deserializer)?;
        maybe
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 64 proof bytes"))
            })
            .transpose()
    }
}

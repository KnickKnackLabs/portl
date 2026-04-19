//! Signing and strict verification helpers for ticket bodies.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{PortlError, Result};
use crate::ticket::canonical::canonical_check;
use crate::ticket::schema::PortlBody;

/// Canonical postcard bytes of a ticket body.
pub fn body_signing_bytes(body: &PortlBody) -> Result<Vec<u8>> {
    canonical_check(body)?;
    Ok(postcard::to_stdvec(body)?)
}

/// Sign a canonical ticket body with Ed25519.
pub fn sign_body(sk: &SigningKey, body: &PortlBody) -> Result<[u8; 64]> {
    let bytes = body_signing_bytes(body)?;
    Ok(sk.sign(&bytes).to_bytes())
}

/// Verify a body signature with Ed25519 strict verification.
pub fn verify_body(pk: &[u8; 32], body: &PortlBody, sig: &[u8; 64]) -> Result<()> {
    let bytes = body_signing_bytes(body)?;
    let verifying_key =
        VerifyingKey::from_bytes(pk).map_err(|_| PortlError::Signature("invalid public key"))?;
    let signature = Signature::from_bytes(sig);
    verifying_key
        .verify_strict(&bytes, &signature)
        .map_err(|_| PortlError::Signature("verify_strict failed"))
}

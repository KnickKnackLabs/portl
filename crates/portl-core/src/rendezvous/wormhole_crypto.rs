//! Wormhole-compatible SPAKE2 + secretbox crypto helpers (skeleton).

use crypto_secretbox::{
    aead::{Aead, KeyInit},
    Key as SecretboxKey, Nonce as SecretboxNonce, XSalsa20Poly1305,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use thiserror::Error;

/// Errors produced by the Wormhole-compatible crypto helpers.
#[derive(Debug, Error)]
pub enum WormholeCryptoError {
    /// The peer's PAKE body could not be decoded as JSON.
    #[error("invalid PAKE body JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// The `pake_v1` hex payload was not valid hex.
    #[error("invalid PAKE hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    /// SPAKE2 finishing failed (e.g. malformed peer share).
    #[error("SPAKE2 finish failed: {0}")]
    Spake(String),
    /// The shared key produced by SPAKE2 was not 32 bytes.
    #[error("derived key has unexpected length: {0}")]
    KeyLength(usize),
    /// Authenticated decryption failed.
    #[error("authenticated decryption failed")]
    Decrypt,
    /// The encrypted payload was shorter than the nonce.
    #[error("encrypted payload too short")]
    Truncated,
}

/// A 32-byte symmetric key derived from the Wormhole PAKE handshake.
#[derive(Clone, Debug)]
pub struct WormholeKey([u8; 32]);

impl WormholeKey {
    /// Construct a key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
struct PhaseMessage {
    pake_v1: String,
}

/// Begin a symmetric SPAKE2 handshake bound to `appid` and return the JSON
/// `pake_v1` body to send to the peer.
pub fn start_pake(password: &str, appid: &str) -> (Spake2<Ed25519Group>, Vec<u8>) {
    let (state, msg1) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(password.as_bytes()),
        &Identity::new(appid.as_bytes()),
    );
    let body = PhaseMessage {
        pake_v1: hex::encode(&msg1),
    };
    let serialized = serde_json::to_vec(&body).expect("PhaseMessage serialization is infallible");
    (state, serialized)
}

/// Finish the SPAKE2 handshake using the peer's JSON-encoded `pake_v1` body.
pub fn finish_pake(
    state: Spake2<Ed25519Group>,
    peer_body: &[u8],
) -> Result<WormholeKey, WormholeCryptoError> {
    let parsed: PhaseMessage = serde_json::from_slice(peer_body)?;
    let peer_msg = hex::decode(parsed.pake_v1)?;
    let shared = state
        .finish(&peer_msg)
        .map_err(|e| WormholeCryptoError::Spake(e.to_string()))?;
    let bytes: [u8; 32] = shared
        .as_slice()
        .try_into()
        .map_err(|_| WormholeCryptoError::KeyLength(shared.len()))?;
    Ok(WormholeKey(bytes))
}

/// HKDF-SHA256 derivation from a Wormhole key with the given purpose.
pub fn derive_key(key: &WormholeKey, purpose: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &key.0);
    let mut out = [0u8; 32];
    hk.expand(purpose, &mut out)
        .expect("HKDF-SHA256 expand of 32 bytes never fails");
    out
}

/// Derive a per-side, per-phase key bound to `wormhole:phase:` purposes.
pub fn derive_phase_key(key: &WormholeKey, side: &str, phase: &str) -> [u8; 32] {
    let side_digest = Sha256::digest(side.as_bytes());
    let phase_digest = Sha256::digest(phase.as_bytes());
    let mut purpose = b"wormhole:phase:".to_vec();
    purpose.extend_from_slice(&side_digest);
    purpose.extend_from_slice(&phase_digest);
    derive_key(key, &purpose)
}

/// Encrypt a phase payload with a freshly generated random 24-byte nonce.
pub fn encrypt_phase(key: &WormholeKey, side: &str, phase: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    encrypt_phase_with_nonce(key, side, phase, plaintext, nonce)
}

/// Encrypt a phase payload with the supplied 24-byte nonce, prepending it to
/// the `SecretBox` ciphertext.
pub fn encrypt_phase_with_nonce(
    key: &WormholeKey,
    side: &str,
    phase: &str,
    plaintext: &[u8],
    nonce: [u8; 24],
) -> Vec<u8> {
    let phase_key = derive_phase_key(key, side, phase);
    let cipher = XSalsa20Poly1305::new(SecretboxKey::from_slice(&phase_key));
    let nonce_ga = SecretboxNonce::from_slice(&nonce);
    let mut ciphertext = cipher
        .encrypt(nonce_ga, plaintext)
        .expect("XSalsa20Poly1305 encryption is infallible for in-memory plaintext");
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.append(&mut ciphertext);
    out
}

/// Decrypt a phase payload produced by [`encrypt_phase_with_nonce`].
pub fn decrypt_phase(
    key: &WormholeKey,
    side: &str,
    phase: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>, WormholeCryptoError> {
    if encrypted.len() < 24 {
        return Err(WormholeCryptoError::Truncated);
    }
    let (nonce, ciphertext) = encrypted.split_at(24);
    let phase_key = derive_phase_key(key, side, phase);
    let cipher = XSalsa20Poly1305::new(SecretboxKey::from_slice(&phase_key));
    cipher
        .decrypt(SecretboxNonce::from_slice(nonce), ciphertext)
        .map_err(|_| WormholeCryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_establishes_matching_keys() {
        let appid = "portl.exchange.v1";
        let password = "2-nebula-involve";

        let (left_state, left_msg) = start_pake(password, appid);
        let (right_state, right_msg) = start_pake(password, appid);

        let left_key = finish_pake(left_state, &right_msg).unwrap();
        let right_key = finish_pake(right_state, &left_msg).unwrap();

        assert_eq!(left_key.as_bytes(), right_key.as_bytes());
    }

    #[test]
    fn encrypted_phase_roundtrips() {
        let key = WormholeKey::from_bytes([7u8; 32]);
        let encrypted = encrypt_phase_with_nonce(&key, "side-a", "1", b"hello", [9u8; 24]);
        let plaintext = decrypt_phase(&key, "side-a", "1", &encrypted).unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn wrong_phase_fails_to_decrypt() {
        let key = WormholeKey::from_bytes([7u8; 32]);
        let encrypted = encrypt_phase_with_nonce(&key, "side-a", "1", b"hello", [9u8; 24]);
        assert!(decrypt_phase(&key, "side-a", "2", &encrypted).is_err());
    }
}

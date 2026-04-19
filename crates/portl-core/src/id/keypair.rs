//! Ed25519 operator identity wrapper.

use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

/// Operator identity.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Identity {
    sk: SigningKey,
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}

impl Identity {
    /// Generate a fresh identity from the OS RNG.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sk: SigningKey::generate(&mut OsRng),
        }
    }

    /// Wrap an existing signing key.
    #[must_use]
    pub fn from_signing_key(sk: SigningKey) -> Self {
        Self { sk }
    }

    /// Borrow the underlying signing key.
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.sk
    }

    /// Return the raw verifying key bytes.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    /// Convert the verifying key into an iroh endpoint id.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        EndpointId::from_bytes(&self.verifying_key())
            .expect("ed25519 verifying key is a valid endpoint id")
    }
}

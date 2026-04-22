//! Process-wide rustls crypto-provider installation.
//!
//! `reqwest` is configured with the `rustls-no-provider` feature so
//! that `aws-lc-rs` is not pulled into the dependency graph — on
//! macOS, having both `ring` and `aws-lc-rs` linked into the same
//! binary produces `malloc: pointer being freed was not allocated`
//! aborts on the first TLS handshake, because the two
//! `BoringSSL`-derived C libraries collide on internal allocator
//! symbols (see
//! `rustls/rustls#1877`).
//!
//! Every binary that performs any TLS must call
//! [`install_default_crypto_provider`] once at process start. The
//! call is idempotent — rustls returns `Err` if a provider has
//! already been installed, and we silently ignore that.
//!
//! For integration tests, the recommended pattern is a `#[ctor]` or
//! `OnceLock`-gated helper at the top of each test file.

use std::sync::OnceLock;

use rustls::crypto::ring;

static INSTALLED: OnceLock<()> = OnceLock::new();

/// Install the `ring` rustls crypto provider as the process-wide
/// default. Safe to call from anywhere; safe to call multiple times;
/// safe to call concurrently.
pub fn install_default_crypto_provider() {
    INSTALLED.get_or_init(|| {
        // Ignore the result: if another crate has already installed
        // a provider, we keep that one. Our call only needs to win
        // if nothing else has set a provider yet.
        let _ = ring::default_provider().install_default();
    });
}

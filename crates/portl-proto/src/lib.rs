//! portl-proto
//!
//! Wire protocols and ALPNs for portl. Each ALPN gets its own
//! module here once it lands (M1: ticket/v1; M2: meta/v1;
//! M3: shell/v1, tcp/v1; M6: udp/v1). Kept as one crate for v0.1;
//! split later if any single protocol exceeds roughly a thousand
//! lines.

/// Crate version at build time.
///
/// Stub exposed so M0's "all crates have `pub fn` stubs" exit
/// criterion is literally satisfied. Real items land as each ALPN
/// is implemented.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

//! portl-proto
//!
//! Wire protocols and ALPNs for portl. Each ALPN gets its own
//! module here once it lands (M1: ticket/v1; M2: meta/v1;
//! M3: shell/v1, tcp/v1; M6: udp/v1). Kept as one crate for v0.1;
//! split later if any single protocol exceeds roughly a thousand
//! lines.

pub mod error;
pub mod meta_v1;
pub mod shell_v1;
pub mod tcp_v1;
pub mod ticket_v1;
pub mod wire;

pub use portl_core::ticket::schema::Capabilities as Caps;

/// Crate version at build time.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

//! portl-proto
//!
//! Wire protocols and ALPNs for portl. Each ALPN gets its own
//! module here once it lands (M1: ticket/v1; M2: meta/v1;
//! M3: shell/v1, tcp/v1; M6: udp/v1). Kept as one crate for v0.1;
//! split later if any single protocol exceeds roughly a thousand
//! lines.

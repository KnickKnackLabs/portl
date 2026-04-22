//! `portl ticket issue` — mint a new ticket signed by the local
//! identity. The implementation is the former `commands::mint_root`
//! module, unchanged except for the re-export surface and help text.
//!
//! The parser helpers (`parse_caps`, `parse_ttl`, `parse_endpoint_bytes`)
//! are re-exported here so the docker and slicer adapters (which
//! mint their own tickets during `docker run` / `slicer run`) can
//! continue to reuse them without knowing about the old module
//! name.

// Re-export `run` publicly; the parser helpers stay `pub(crate)`
// (that's how the docker + slicer adapters already consume them
// via `mint_root::parse_*`, and there's no need to widen
// visibility just to satisfy `ticket::issue` callers).
pub use crate::commands::mint_root::run;

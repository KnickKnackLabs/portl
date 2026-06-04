//! portl-core
//!
//! Core types and primitives: tickets, sessions, the endpoint wrapper,
//! and in-process test helpers. This crate is the bedrock all other
//! portl crates build on.

pub mod attach_control;
pub mod bootstrap;
pub mod caps;
pub mod diagnostics;
pub mod endpoint;
pub mod error;
pub mod herdr_wire;
pub mod id;
pub mod io;
pub mod labels;
pub mod net;
pub mod pair_code;
pub mod pair_store;
pub mod paths;
pub mod peer_store;
pub mod query_response_filter;
pub mod query_stripper;
pub mod rendezvous;
pub mod runtime;
pub mod store_index;
pub mod terminal;
pub mod terminal_mode_tracker;
pub mod ticket;
pub mod ticket_store;
pub mod tls;
pub mod transport_telemetry;
pub mod wire;

pub use query_response_filter::{QueryResponseFilter, StdinResponseFilter};
pub use query_stripper::QueryStripper;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

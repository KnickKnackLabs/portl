//! portl-core
//!
//! Core types and primitives: tickets, sessions, the endpoint wrapper,
//! and in-process test helpers. This crate is the bedrock all other
//! portl crates build on.

pub mod bootstrap;
pub mod caps;
pub mod endpoint;
pub mod error;
pub mod id;
pub mod io;
pub mod net;
pub mod pair_code;
pub mod pair_store;
pub mod peer_store;
pub mod rendezvous;
pub mod runtime;
pub mod store_index;
pub mod ticket;
pub mod ticket_store;
pub mod tls;
pub mod wire;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

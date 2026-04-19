//! portl-core
//!
//! Core types and primitives: tickets, sessions, the endpoint wrapper,
//! and in-process test helpers. This crate is the bedrock all other
//! portl crates build on.

pub mod endpoint;
pub mod error;
pub mod ticket;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

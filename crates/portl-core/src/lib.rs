//! portl-core
//!
//! Core types and primitives: tickets, sessions, the endpoint wrapper,
//! and in-process test helpers. This crate is the bedrock all other
//! portl crates build on.

pub mod endpoint;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

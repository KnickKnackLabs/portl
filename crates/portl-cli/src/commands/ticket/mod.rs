//! `portl ticket` — manage outbound credentials (tickets we hold).
//!
//! v0.3.0 split peer-store (standing authority) from ticket-store
//! (bounded credentials). The `issue` verb is a straight rename of
//! the old top-level `portl mint` (help output and docs now say
//! "ticket issue"; `mint` has been deleted). `save` is new in
//! v0.3.0 and parses + binds a ticket string so the resolver can
//! use it by label.

pub mod caps;
pub mod issue;
pub mod ls;
pub mod prune;
pub mod revoke;
pub mod rm;
pub mod save;

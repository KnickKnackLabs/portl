//! `portl ticket revoke` — wrapper around the v0.2.x top-level
//! `revoke` command. No behavior change; the move into `ticket`
//! groups all credential-lifecycle verbs under one subcommand.

pub use crate::commands::revoke::run;

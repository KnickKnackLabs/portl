//! Generic `portl accept` router introduced in Task 10 of the
//! shortcode-rendezvous plan.
//!
//! Routes the user-supplied `<THING>` argument to the right
//! consumer based on its prefix:
//!
//! 1. `PORTLINV-*`     → existing peer invite accept implementation.
//! 2. `PORTL-S-*`      → short online exchange share (Task 12).
//! 3. `PORTL-SHARE1-*` → offline share token (not in this slice).
//! 4. `portl...`       → ticket string; suggest `portl ticket save`.
//! 5. unknown          → list supported forms.

use std::process::ExitCode;

use anyhow::{Result, bail};
use portl_core::rendezvous::ShortCode;

use crate::commands;

/// Dispatch entry point for the top-level `portl accept` command.
pub fn run(thing: &str, yes: bool) -> Result<ExitCode> {
    let trimmed = thing.trim();

    if trimmed.starts_with("PORTLINV-") {
        return commands::peer::pair::run(trimmed, yes);
    }

    if trimmed.starts_with("PORTL-S-") {
        return run_short_code(trimmed);
    }

    if trimmed.starts_with("PORTL-SHARE1-") {
        bail!(
            "offline share tokens are not implemented yet.\n       \
             `PORTL-SHARE1-*` will be supported in a future release."
        );
    }

    if trimmed.starts_with("PORTLTKT-") || trimmed.starts_with("portl") {
        bail!(
            "this looks like a ticket string, not an invite or share code.\n       \
             To save it for later use:\n         \
             portl ticket save <label> {trimmed}"
        );
    }

    bail!(
        "unrecognized accept input.\n       \
         Supported forms:\n         \
         PORTLINV-…    pairing invite from `portl invite`\n         \
         PORTL-S-…     short online session share\n         \
         PORTL-SHARE1-… offline share token (not yet implemented)\n         \
         portl…        ticket string — use `portl ticket save <label> <ticket>`"
    );
}

fn run_short_code(thing: &str) -> Result<ExitCode> {
    // Validate shape now so we surface clear `PORTL-S-` guidance for
    // malformed inputs even before the network path lands.
    let _code = ShortCode::parse(thing).map_err(|err| {
        anyhow::anyhow!(
            "invalid `PORTL-S-` short code: {err}.\n       \
             Expected `PORTL-S-<nameplate>-<word>-<word>[-…]`."
        )
    })?;
    bail!(
        "short online session shares are not implemented yet.\n       \
         A future release will import the share over the rendezvous mailbox."
    );
}

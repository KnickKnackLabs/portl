# Vendored crate forks

Published crates with local fixes, wired in through `[patch.crates-io]` in the root `Cargo.toml`. The workspace excludes this directory. Each tree is the crates.io release plus `patches/<crate>.patch`; drop a fork once upstream ships its fix.

| crate | upstream | fix | remove when |
|---|---|---|---|
| `netdev` 0.46.2 | [shellrow/netdev](https://github.com/shellrow/netdev) @ `3397811` | Darwin: take the interface index from the AF_LINK entry instead of `if_nametoindex` (a full `getifaddrs`) for every address | a release that has the fix and that netwatch accepts |
| `netwatch` 0.19.3 | [n0-computer/net-tools](https://github.com/n0-computer/net-tools) `netwatch/` @ `0030e57` | BSD/Darwin route monitor ignores `RTM_GET`/`RTM_GET2` lookups, so other processes' `route get` no longer triggers full rescans | a release with the fix that iroh accepts |

Both `src/lib.rs` files also carry `#![allow(warnings)]`. Path dependencies skip Cargo's `--cap-lints allow`, so CI's `-D warnings` would otherwise fail on upstream warnings.

## Monitoring

CI runs `scripts/check-vendored-crates.py`. For every shipped target it fails when the resolved graph contains a vendored crate from anywhere but `vendor/`, for example after iroh moves to a semver-incompatible netwatch. Don't rely on Cargo's "patch was not used" warning: portl depends on netwatch directly, so the patch stays in use while a second, unpatched copy is resolved.

## Updating to a new upstream release

```sh
v=0.20.0 crate=netwatch
curl -fsSL "https://static.crates.io/crates/$crate/$crate-$v.crate" | tar xz -C /tmp
rm -rf "vendor/$crate" && mv "/tmp/$crate-$v" "vendor/$crate"
patch -d "vendor/$crate" -p1 < "vendor/patches/$crate.patch"
cargo update -p "$crate" && python3 scripts/check-vendored-crates.py
```

Fix any rejected hunks, then regenerate the patch against the pristine crate with `diff -ruN` (`a/` = crates.io, `b/` = `vendor/<crate>`).

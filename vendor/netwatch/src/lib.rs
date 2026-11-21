//! Networking related utilities
// portl vendor: path dependencies skip Cargo's `--cap-lints allow`, so CI's
// `-D warnings` would fail on upstream warnings. Match registry builds.
#![allow(warnings)]

pub mod interfaces;
pub mod ip;
mod ip_family;
pub mod netmon;
#[cfg(not(wasm_browser))]
mod udp;

pub use self::ip_family::IpFamily;
#[cfg(not(wasm_browser))]
pub use self::udp::{UdpSender, UdpSocket};

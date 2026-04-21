//! Verifies the release profile's `panic = "abort"` actually aborts
//! the process with a non-zero exit status.
//!
//! Builds the `portl` binary in --release with the `test-panic-trigger`
//! feature enabled on `portl-agent`, invokes `portl agent run` with a
//! synthetic config, and expects the process to die non-zero once the
//! test-only panic fires at the top of `run`.
//!
//! Release-only: the test is `#[cfg]`d out in debug builds because
//! `panic = "abort"` applies to the release profile only.

#![cfg(all(unix, not(debug_assertions)))]

use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    manifest_dir()
        .parent()
        .expect("crates/ parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn release_build_panics_exit_nonzero() {
    let root = workspace_root();

    // Pin RUSTUP_TOOLCHAIN to the workspace's rust-toolchain.toml channel
    // so the nested cargo invocation uses the same rustc as the outer
    // test; a user-level rustup shim may otherwise point at a different
    // toolchain that can't link against the already-built artefacts.
    let toolchain = std::fs::read_to_string(root.join("rust-toolchain.toml"))
        .expect("read rust-toolchain.toml")
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("channel")
                .and_then(|rest| rest.trim().strip_prefix('='))
                .map(|rest| rest.trim().trim_matches('"').to_owned())
        })
        .expect("channel in rust-toolchain.toml");

    let status = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args([
            "build",
            "--release",
            "--bin",
            "portl",
            "--features",
            "portl-agent/test-panic-trigger",
        ])
        .env("RUSTUP_TOOLCHAIN", &toolchain)
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build failed: {status:?}");

    let bin = root.join("target").join("release").join("portl");
    assert!(bin.is_file(), "expected portl binary at {}", bin.display());

    let start = Instant::now();
    let mut child = Command::new(&bin)
        .args(["agent", "run"])
        .env("PORTL_TEST_PANIC_AT", "startup")
        .env("RUSTUP_TOOLCHAIN", &toolchain)
        .spawn()
        .expect("spawn portl agent run");

    // Poll for exit — cap at 10s so a misconfigured test can't hang CI.
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(10) {
                    let _ = child.kill();
                    panic!("portl agent did not exit within 10s of panic trigger");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => panic!("wait on portl agent failed: {err}"),
        }
    };

    assert!(
        !exit.success(),
        "panic=abort should exit non-zero, got {exit:?}"
    );
    // panic = abort on Unix terminates via SIGABRT. Depending on how
    // the shell / wrapper relays the signal, we observe either:
    //   - signal(SIGABRT)  (raw wait(2) exit status)
    //   - code(Some(134))  (128 + SIGABRT; shell-style wrapped exit)
    //   - code(None)       (signal-terminated, no exit code)
    // An unwinding panic followed by a clean non-zero Err exit would
    // give code(Some(1)), which is NOT abort semantics and must fail.
    assert!(
        exit.signal() == Some(nix::libc::SIGABRT)
            || exit.code() == Some(134)
            || exit.code().is_none(),
        "expected abort semantics (SIGABRT / 134 / no code), got {exit:?}"
    );
}

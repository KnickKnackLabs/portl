//! `agent_misc`: merged small portl-agent integration test files.
//! Merged per `TEST_BUILD_TUNING.md` to cut the number of nextest
//! binaries. Each former top-level file is preserved verbatim under
//! a `mod` with the same name so nextest test ids keep working
//! (e.g. `rate_limit::foo` -> `agent_misc::rate_limit::foo`).

#![allow(dead_code)]

#[allow(dead_code)]
mod common;

mod rate_limit {
    use portl_agent::{OfferRateLimiter, RateLimitConfig};

    #[test]
    fn keyed_limiter_allows_initial_burst_then_rejects() {
        let limiter = OfferRateLimiter::new(&RateLimitConfig::default()).expect("build limiter");
        let node_id = [9; 32];

        let results: Vec<_> = (0..20).map(|_| limiter.check(node_id)).collect();

        assert!(results.iter().take(10).all(|allowed| *allowed));
        assert!(results.iter().skip(10).all(|allowed| !allowed));
    }
}

mod discovery_local {
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use iroh::address_lookup::AddressLookupFailed;
    use n0_future::StreamExt;
    use portl_agent::{AgentConfig, DiscoveryConfig};
    use portl_core::id::Identity;

    #[tokio::test]
    #[ignore = "mDNS on localhost can be flaky in CI"]
    async fn local_discovery_resolves_endpoint_id_over_mdns() -> Result<()> {
        let discovery = DiscoveryConfig {
            dns: false,
            pkarr: false,
            local: true,
            relay: None,
        };
        let cfg = AgentConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("bind addr")),
            discovery,
            ..AgentConfig::default()
        };

        let first = portl_agent::endpoint::bind(&cfg, &Identity::new())
            .await
            .context("bind first endpoint")?;
        let second = portl_agent::endpoint::bind(&cfg, &Identity::new())
            .await
            .context("bind second endpoint")?;

        let lookup = second.address_lookup().context("access address lookup")?;
        let mut stream = lookup.resolve(first.id());
        let resolved = tokio::time::timeout(Duration::from_secs(10), async move {
            while let Some(item) = stream.next().await {
                match item {
                    Ok(Ok(item)) => return Ok(item.into_endpoint_addr()),
                    Ok(Err(_)) | Err(AddressLookupFailed::NoResults { .. }) => {}
                    Err(err) => return Err(anyhow::Error::from(err)),
                }
            }
            bail!("discovery returned no addresses")
        })
        .await
        .context("timed out waiting for local discovery")??;

        assert_eq!(resolved.id, first.id());

        first.close().await;
        second.close().await;
        Ok(())
    }
}

#[cfg(all(unix, not(debug_assertions)))]
mod panic_abort {
    use std::os::unix::{fs::symlink, process::ExitStatusExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use tempfile::tempdir;

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

        let temp = tempdir().expect("tempdir for portl-agent symlink");
        let portl_agent = temp.path().join("portl-agent");
        symlink(&bin, &portl_agent).expect("create portl-agent symlink");

        let start = Instant::now();
        let mut child = Command::new(&portl_agent)
            .env("PORTL_TEST_PANIC_AT", "startup")
            .env("RUSTUP_TOOLCHAIN", &toolchain)
            .spawn()
            .expect("spawn portl-agent");

        // Poll for exit — cap at 10s so a misconfigured test can't hang CI.
        let exit = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() > Duration::from_secs(10) {
                        let _ = child.kill();
                        panic!("portl-agent did not exit within 10s of panic trigger");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => panic!("wait on portl-agent failed: {err}"),
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
}

#[cfg(unix)]
mod pty_spawn {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::time::Duration;

    use nix::libc;
    use portl_agent::shell_handler::spawn_pty_for_test;

    #[tokio::test]
    async fn pty_spawn_has_controlling_terminal() {
        let (master, mut child) =
            spawn_pty_for_test("/bin/sh", &["-c", "tty; exit 0"]).expect("spawn pty");
        let output = read_until_eof(master).await;
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("child wait timeout")
            .expect("child wait");
        assert!(status.success(), "shell exited non-zero: {status:?}");
        assert!(
            output.contains("/dev/") && (output.contains("pts") || output.contains("ttys")),
            "tty(1) output should name a pseudo-terminal device, got: {output:?}"
        );
    }

    /// Regression for the review finding that the PTY master fd was not
    /// CLOEXEC: the forked child must not inherit the master. Probe via
    /// the live fd table (`/proc/self/fd` on Linux, `/dev/fd` on Darwin).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn pty_master_is_cloexec_in_child() {
        #[cfg(target_os = "linux")]
        let fd_dir = "/proc/self/fd";
        #[cfg(target_os = "macos")]
        let fd_dir = "/dev/fd";

        let script = format!("ls {fd_dir}; exit 0");
        let (master, mut child) =
            spawn_pty_for_test("/bin/sh", &["-c", &script]).expect("spawn pty");
        let master_fd = master.as_raw_fd();
        let output = read_until_eof(master).await;
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("child wait timeout")
            .expect("child wait");
        assert!(status.success(), "shell exited non-zero: {status:?}");
        let fd_str = master_fd.to_string();
        let inherited = output.split_whitespace().any(|token| token == fd_str);
        assert!(
            !inherited,
            "pty master fd {master_fd} leaked into child fd table: {output:?}"
        );
    }

    async fn read_until_eof(master: OwnedFd) -> String {
        #[rustfmt::skip]
    let handle = portl_core::runtime::slow_task("pty_spawn_read_until_eof", tokio::task::spawn_blocking(move || {
        let mut f = File::from(master);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match f.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                // Slave side close shows as EIO on Linux; treat as EOF.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => panic!("pty read failed: {e}"),
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }));
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("read timeout")
            .expect("join")
    }
}

#[cfg(unix)]
mod rlimits {
    use portl_agent::shell_handler::run_exec_capture;

    #[tokio::test]
    async fn exec_path_applies_nofile() {
        let out = run_exec_capture("/bin/sh", &["-c", "ulimit -n"], vec![])
            .await
            .expect("run exec");
        assert!(out.status.success(), "exec exited non-zero: {out:?}");
        assert_eq!(out.stdout.trim(), "4096");
    }

    #[tokio::test]
    async fn exec_path_applies_core_zero() {
        let out = run_exec_capture("/bin/sh", &["-c", "ulimit -c"], vec![])
            .await
            .expect("run exec");
        assert!(out.status.success(), "exec exited non-zero: {out:?}");
        assert_eq!(out.stdout.trim(), "0");
    }

    #[tokio::test]
    async fn exec_path_applies_fsize() {
        // RLIMIT_FSIZE is 10 GiB = 10 * 1024 * 1024 * 1024 bytes.
        // `ulimit -f` reports in block units, but the block size varies
        // between shells (dash uses POSIX 512-byte blocks; bash uses
        // 1024-byte blocks). Accept either, since both correspond to
        // 10 GiB.
        let out = run_exec_capture("/bin/sh", &["-c", "ulimit -f"], vec![])
            .await
            .expect("run exec");
        assert!(out.status.success(), "exec exited non-zero: {out:?}");
        let reported = out.stdout.trim();
        assert!(
            reported == "20971520" || reported == "10485760",
            "expected 10 GiB in 512-byte or 1024-byte blocks, got {reported:?}",
        );
    }

    #[tokio::test]
    async fn exec_path_applies_cpu() {
        let out = run_exec_capture("/bin/sh", &["-c", "ulimit -t"], vec![])
            .await
            .expect("run exec");
        assert!(out.status.success(), "exec exited non-zero: {out:?}");
        assert_eq!(out.stdout.trim(), "86400");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exec_path_applies_nproc_linux() {
        // `ulimit -u` is a bash-ism: dash (which is /bin/sh on Debian /
        // Ubuntu) rejects it with "Illegal option -u". Use bash explicitly
        // so this test runs on both Alpine-like and Debian-like distros.
        // bash is guaranteed available on every Linux target we ship to.
        let out = run_exec_capture("/bin/bash", &["-c", "ulimit -u"], vec![])
            .await
            .expect("run exec");
        assert!(out.status.success(), "exec exited non-zero: {out:?}");
        assert_eq!(out.stdout.trim(), "512");
    }

    // Inherently antisocial to parallel test execution: it intentionally
    // exhausts the agent's uid-wide NPROC budget with 512 sleeping
    // children, which blocks every other test in the same binary that
    // needs to fork. Marked #[ignore]; run manually with:
    //   cargo test -p portl-agent --test rlimits -- --ignored --test-threads=1
    //
    // The cheaper `exec_path_applies_nproc_linux` test (above) already
    // verifies `ulimit -u` reports 512, which is the real correctness
    // signal. This test only adds the live fork-bomb verification that
    // the cap is actually enforced at fork-time, which is an OS guarantee
    // we trust without CI signal.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "exhausts uid NPROC budget; run with --ignored --test-threads=1"]
    async fn fork_bomb_killed_by_nproc() {
        // Spawn a shell that forks 10k children; RLIMIT_NPROC=512 caps
        // the tree. Agent stays responsive.
        //
        // The `wait` at the end reaps children so we don't leak 512
        // sleeping processes into the test environment on manual runs.
        let _ = run_exec_capture(
            "/bin/sh",
            &[
                "-c",
                "i=0; while [ $i -lt 10000 ]; do (true) & i=$((i+1)); done; wait",
            ],
            vec![],
        )
        .await;
        // We don't assert on exit code — the shell hits NPROC cap and errors.
        // What we assert: this process's own fork budget is still healthy.
        assert!(std::process::Command::new("true").spawn().is_ok());
    }
}

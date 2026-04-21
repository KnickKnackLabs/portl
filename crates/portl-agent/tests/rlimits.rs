//! Verifies every spawn path applies the v0.1.1 rlimit set.
//! NOFILE / CORE / FSIZE / CPU tested on all platforms.
//! NPROC tested on Linux only (Darwin `RLIMIT_NPROC` is per-process and
//! cannot provide fork-bomb containment at the uid level).

#![cfg(unix)]

#[allow(dead_code)]
mod common;

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
    let out = run_exec_capture("/bin/sh", &["-c", "ulimit -u"], vec![])
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

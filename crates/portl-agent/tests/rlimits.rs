//! Verifies every spawn path applies the v0.1.1 rlimit set.
//! NOFILE / CORE / FSIZE / CPU tested on all platforms.
//! NPROC tested on Linux only (Darwin `RLIMIT_NPROC` is per-process and
//! cannot provide fork-bomb containment at the uid level).

#![cfg(unix)]

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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn fork_bomb_killed_by_nproc() {
    // Spawn a shell that forks 10k children; RLIMIT_NPROC=512 caps
    // the tree. Agent stays responsive.
    let _ = run_exec_capture(
        "/bin/sh",
        &[
            "-c",
            r#"i=0; while [ $i -lt 10000 ]; do sleep 60 & i=$((i+1)); done"#,
        ],
        vec![],
    )
    .await;
    // We don't assert on exit code — the shell hits NPROC cap and errors.
    // What we assert: this process's own fork budget is still healthy.
    assert!(std::process::Command::new("true").spawn().is_ok());
}

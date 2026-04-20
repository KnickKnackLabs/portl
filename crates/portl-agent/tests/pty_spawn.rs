//! Verifies the PTY path spawns with a controlling terminal via
//! direct `CommandExt::pre_exec` + `nix::pty::openpty`, no
//! `portable_pty` involved.

#![cfg(unix)]

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
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

async fn read_until_eof(master: OwnedFd) -> String {
    let handle = tokio::task::spawn_blocking(move || {
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
    });
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("read timeout")
        .expect("join")
}

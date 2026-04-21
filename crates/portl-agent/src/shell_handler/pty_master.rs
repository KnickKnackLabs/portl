#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::shell_registry::{PtyCommand, StdinMessage};

use super::IO_CHUNK;
use super::pumps::resize_pty;

#[cfg(unix)]
pub(super) async fn pty_master_task(
    master: OwnedFd,
    stdout_tx: mpsc::Sender<Vec<u8>>,
    mut stdin_rx: mpsc::Receiver<StdinMessage>,
    mut pty_rx: mpsc::UnboundedReceiver<PtyCommand>,
    drain_timeout: Duration,
) -> Result<()> {
    set_nonblocking(&master)?;
    let master = AsyncFd::new(master).context("register pty master fd")?;
    let mut stdin_open = true;
    let mut drain_deadline = None;
    let mut read_buf = vec![0_u8; IO_CHUNK];

    loop {
        let drain_sleep = async {
            if let Some(deadline) = drain_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            biased;
            Some(cmd) = pty_rx.recv() => {
                match cmd {
                    PtyCommand::Resize { rows, cols } => {
                        if drain_deadline.is_none() {
                            resize_pty(master.get_ref(), rows, cols).context("resize pty")?;
                        }
                    }
                    PtyCommand::Close { force } => {
                        if force {
                            return Ok(());
                        }
                        drain_deadline
                            .get_or_insert_with(|| tokio::time::Instant::now() + drain_timeout);
                    }
                }
            }
            Some(message) = stdin_rx.recv(), if stdin_open && drain_deadline.is_none() => {
                match message {
                    StdinMessage::Data(bytes) => write_pty_all(&master, &bytes).await.context("write pty stdin")?,
                    StdinMessage::Close => stdin_open = false,
                }
            }
            () = drain_sleep => {
                return Ok(());
            }
            chunk = read_pty_chunk(&master, &mut read_buf) => {
                match chunk.context("read pty output")? {
                    Some(chunk) => {
                        if stdout_tx.send(chunk).await.is_err() {
                            return Ok(());
                        }
                    }
                    None => return Ok(()),
                }
            }
            else => return Ok(()),
        }
    }
}

#[cfg(unix)]
pub(super) async fn read_pty_chunk(
    master: &AsyncFd<OwnedFd>,
    buf: &mut [u8],
) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        let mut guard = master.readable().await?;
        match nix::unistd::read(master.get_ref(), buf) {
            Ok(0) | Err(nix::errno::Errno::EIO) => return Ok(None),
            Ok(read) => return Ok(Some(buf[..read].to_vec())),
            Err(nix::errno::Errno::EAGAIN) => {
                guard.clear_ready();
            }
            Err(err) => return Err(std::io::Error::from(err)),
        }
    }
}

#[cfg(unix)]
pub(super) async fn write_pty_all(
    master: &AsyncFd<OwnedFd>,
    mut bytes: &[u8],
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let mut guard = master.writable().await?;
        match nix::unistd::write(master.get_ref(), bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "pty write returned zero bytes",
                ));
            }
            Ok(written) => {
                bytes = &bytes[written..];
            }
            Err(nix::errno::Errno::EAGAIN) => {
                guard.clear_ready();
            }
            Err(err) => return Err(std::io::Error::from(err)),
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn set_nonblocking(fd: &OwnedFd) -> std::io::Result<()> {
    let flags =
        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).map_err(std::io::Error::from)?;
    let flags = nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags)).map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::path::Path;
    #[cfg(unix)]
    use std::time::Duration;

    #[cfg(unix)]
    use nix::sys::signal::{Signal, kill};
    #[cfg(unix)]
    use nix::unistd::Pid;
    #[cfg(unix)]
    use tokio::sync::mpsc;

    #[cfg(unix)]
    use crate::shell_handler::spawn_pty_for_test;
    #[cfg(unix)]
    use crate::shell_registry::PtyCommand;

    #[cfg(unix)]
    use super::pty_master_task;

    #[cfg(unix)]
    #[tokio::test]
    async fn pty_drain_completes_on_normal_exit() {
        let mut harness = spawn_pty_task_harness(
            &["-c", "printf 'pty-drain-ok'; exit 0"],
            Duration::from_millis(200),
        );

        harness
            .pty_tx
            .send(PtyCommand::Close { force: false })
            .expect("queue pty close");

        let output = collect_output(&mut harness.stdout_rx).await;
        assert!(output.contains("pty-drain-ok"), "output was: {output:?}");
        harness
            .task
            .await
            .expect("pty task join")
            .expect("pty task result");
        let status = harness
            .child_wait
            .await
            .expect("child wait join")
            .expect("child wait status");
        assert!(status.success(), "child status was {status:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pty_drain_force_closes_at_30s() {
        let harness = spawn_pty_task_harness(
            &["-c", "printf 'held-open'; while :; do sleep 1; done"],
            Duration::from_millis(100),
        );

        harness
            .pty_tx
            .send(PtyCommand::Close { force: false })
            .expect("queue pty close");

        tokio::time::timeout(Duration::from_secs(1), harness.task)
            .await
            .expect("pty task timeout")
            .expect("pty task join")
            .expect("pty task result");

        let _ = kill(Pid::from_raw(harness.child_pid), Signal::SIGKILL);
        let _ = harness
            .child_wait
            .await
            .expect("child wait join")
            .expect("child wait status");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn pty_master_fd_closed_after_session_end() {
        let mut harness = spawn_pty_task_harness(
            &["-c", "printf 'fd-close'; exit 0"],
            Duration::from_millis(200),
        );
        let fd = harness.master_fd;

        harness
            .pty_tx
            .send(PtyCommand::Close { force: false })
            .expect("queue pty close");

        let _ = collect_output(&mut harness.stdout_rx).await;
        harness
            .task
            .await
            .expect("pty task join")
            .expect("pty task result");
        let _ = harness
            .child_wait
            .await
            .expect("child wait join")
            .expect("child wait status");

        assert!(!fd_path_exists(fd), "pty master fd {fd} should be closed");
    }

    #[cfg(unix)]
    struct PtyTaskHarness {
        child_pid: i32,
        master_fd: i32,
        pty_tx: mpsc::UnboundedSender<PtyCommand>,
        stdout_rx: mpsc::Receiver<Vec<u8>>,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
        child_wait: tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    }

    #[cfg(unix)]
    fn spawn_pty_task_harness(argv: &[&str], drain_timeout: Duration) -> PtyTaskHarness {
        let (master, mut child) =
            spawn_pty_for_test("/bin/sh", argv).expect("spawn pty task harness");
        let master_fd = master.as_raw_fd();
        let child_pid = i32::try_from(child.id().expect("child pid")).expect("pid fits in i32");
        let (stdin_tx, stdin_rx) = mpsc::channel(32);
        let (pty_tx, pty_rx) = mpsc::unbounded_channel();
        let (stdout_tx, stdout_rx) = mpsc::channel(32);
        let task = tokio::spawn(pty_master_task(
            master,
            stdout_tx,
            stdin_rx,
            pty_rx,
            drain_timeout,
        ));
        let child_wait = tokio::spawn(async move { child.wait().await });
        let _ = stdin_tx;
        PtyTaskHarness {
            child_pid,
            master_fd,
            pty_tx,
            stdout_rx,
            task,
            child_wait,
        }
    }

    #[cfg(unix)]
    async fn collect_output(stdout_rx: &mut mpsc::Receiver<Vec<u8>>) -> String {
        let mut output = Vec::new();
        while let Some(chunk) = stdout_rx.recv().await {
            output.extend_from_slice(&chunk);
        }
        String::from_utf8_lossy(&output).into_owned()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn fd_path_exists(fd: i32) -> bool {
        #[cfg(target_os = "linux")]
        let fd_dir = "/proc/self/fd";
        #[cfg(target_os = "macos")]
        let fd_dir = "/dev/fd";

        Path::new(fd_dir).join(fd.to_string()).exists()
    }
}

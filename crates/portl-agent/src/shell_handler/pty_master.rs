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
    let mut pending_input = PendingPtyWrite::new(DEFAULT_PTY_INPUT_QUEUE_BYTES);

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
                    PtyCommand::KickOthers => {}
                }
            }
            Some(message) = stdin_rx.recv(), if stdin_open && drain_deadline.is_none() => {
                match message {
                    StdinMessage::Data(bytes) => pending_input.push(bytes).context("queue pty stdin")?,
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
            writable_guard = master.writable(), if !pending_input.is_empty() && drain_deadline.is_none() => {
                let mut guard = writable_guard.context("wait pty writable")?;
                if let Some(bytes) = pending_input.front_chunk() {
                    match nix::unistd::write(master.get_ref(), bytes) {
                        Ok(0) => return Err(anyhow::anyhow!("pty write returned zero bytes")),
                        Ok(n) => { pending_input.consume(n); }
                        Err(nix::errno::Errno::EAGAIN) => { guard.clear_ready(); }
                        Err(e) => return Err(std::io::Error::from(e)).context("write pty stdin")?,
                    }
                }
            }
            else => return Ok(()),
        }
    }
}

#[cfg(unix)]
pub(crate) async fn read_pty_chunk(
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
pub(crate) async fn write_pty_all(
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
async fn wait_pty_writable(master: &AsyncFd<OwnedFd>) -> std::io::Result<()> {
    let mut guard = master.writable().await?;
    guard.clear_ready();
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn write_one_pending_pty_chunk(
    master: &AsyncFd<OwnedFd>,
    pending: &mut PendingPtyWrite,
) -> std::io::Result<()> {
    let Some(bytes) = pending.front_chunk() else {
        return Ok(());
    };
    let mut guard = master.writable().await?;
    match nix::unistd::write(master.get_ref(), bytes) {
        Ok(0) => Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "pty write returned zero bytes",
        )),
        Ok(written) => {
            pending.consume(written);
            Ok(())
        }
        Err(nix::errno::Errno::EAGAIN) => {
            guard.clear_ready();
            Ok(())
        }
        Err(err) => Err(std::io::Error::from(err)),
    }
}

#[cfg(unix)]
pub(crate) fn set_nonblocking(fd: &OwnedFd) -> std::io::Result<()> {
    let flags =
        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).map_err(std::io::Error::from)?;
    let flags = nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags)).map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) const DEFAULT_PTY_INPUT_QUEUE_BYTES: usize = 1024 * 1024;

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct PendingPtyWrite {
    chunks: std::collections::VecDeque<Vec<u8>>,
    front_offset: usize,
    pending_bytes: usize,
    max_bytes: usize,
}

#[cfg(unix)]
impl PendingPtyWrite {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            chunks: std::collections::VecDeque::new(),
            front_offset: 0,
            pending_bytes: 0,
            max_bytes,
        }
    }

    pub(crate) fn push(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.pending_bytes.saturating_add(bytes.len()) > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "pty input queue is full",
            ));
        }
        self.pending_bytes += bytes.len();
        self.chunks.push_back(bytes);
        Ok(())
    }

    pub(crate) fn front_chunk(&self) -> Option<&[u8]> {
        self.chunks
            .front()
            .map(|chunk| &chunk[self.front_offset..])
            .filter(|chunk| !chunk.is_empty())
    }

    pub(crate) fn consume(&mut self, written: usize) {
        debug_assert!(
            written <= self.pending_bytes,
            "consume({written}) exceeds pending_bytes({})",
            self.pending_bytes
        );
        let mut remaining = written.min(self.pending_bytes);
        while remaining > 0 {
            let Some(front) = self.chunks.front() else {
                self.front_offset = 0;
                break;
            };
            let available = front.len() - self.front_offset;
            if remaining < available {
                self.front_offset += remaining;
                self.pending_bytes -= remaining;
                return;
            }
            remaining -= available;
            self.pending_bytes -= available;
            self.chunks.pop_front();
            self.front_offset = 0;
        }
    }

    pub(crate) fn clear(&mut self) -> usize {
        let dropped = self.pending_bytes;
        self.chunks.clear();
        self.front_offset = 0;
        self.pending_bytes = 0;
        dropped
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending_bytes == 0
    }

    pub(crate) fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pty_master_echoes_large_input_without_deadlock() {
        // Use `stty raw; cat` so the PTY does not buffer lines and cat echoes
        // every byte as it arrives without waiting for a newline.
        let mut harness =
            spawn_pty_task_harness(&["-c", "stty raw -echo; cat"], Duration::from_secs(2));
        // Give stty a moment to configure the terminal
        tokio::time::sleep(Duration::from_millis(100)).await;
        let input = vec![b'x'; 256 * 1024];

        harness
            .stdin_tx
            .send(crate::shell_registry::StdinMessage::Data(input.clone()))
            .await
            .expect("send large input");

        let mut observed = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while observed.len() < input.len() {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .expect("timed out waiting for echoed input");
            let chunk = tokio::time::timeout(remaining, harness.stdout_rx.recv())
                .await
                .expect("wait for pty output")
                .expect("pty output channel open");
            observed.extend_from_slice(&chunk);
        }

        assert!(observed.windows(4096).any(|window| window == &input[..4096]));
        harness
            .pty_tx
            .send(PtyCommand::Close { force: true })
            .expect("queue pty close");
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(harness.child_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }

    #[cfg(unix)]
    struct PtyTaskHarness {
        child_pid: i32,
        master_fd: i32,
        stdin_tx: mpsc::Sender<crate::shell_registry::StdinMessage>,
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
        PtyTaskHarness {
            child_pid,
            master_fd,
            stdin_tx,
            pty_tx,
            stdout_rx,
            task,
            child_wait,
        }
    }

    #[cfg(unix)]
    #[test]
    fn pending_pty_write_tracks_bytes_and_partial_progress() {
        let mut pending = super::PendingPtyWrite::new(16);

        assert_eq!(pending.pending_bytes(), 0);
        assert!(pending.push(b"abcdef".to_vec()).is_ok());
        assert!(pending.push(b"gh".to_vec()).is_ok());
        assert_eq!(pending.pending_bytes(), 8);
        assert_eq!(pending.front_chunk(), Some(&b"abcdef"[..]));

        pending.consume(2);
        assert_eq!(pending.front_chunk(), Some(&b"cdef"[..]));
        assert_eq!(pending.pending_bytes(), 6);

        pending.consume(4);
        assert_eq!(pending.front_chunk(), Some(&b"gh"[..]));
        pending.consume(2);
        assert!(pending.is_empty());
        assert_eq!(pending.pending_bytes(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn pending_pty_write_rejects_over_capacity_and_clears() {
        let mut pending = super::PendingPtyWrite::new(8);

        assert!(pending.push(b"12345678".to_vec()).is_ok());
        let err = pending.push(b"9".to_vec()).expect_err("queue should be full");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(pending.clear(), 8);
        assert!(pending.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn pending_pty_write_consume_zero_is_noop() {
        let mut pending = super::PendingPtyWrite::new(16);
        pending.push(b"hello".to_vec()).unwrap();
        pending.consume(0);
        assert_eq!(pending.pending_bytes(), 5);
        assert_eq!(pending.front_chunk(), Some(&b"hello"[..]));
    }

    #[cfg(unix)]
    #[test]
    fn pending_pty_write_push_after_clear() {
        let mut pending = super::PendingPtyWrite::new(8);
        pending.push(b"12345678".to_vec()).unwrap();
        pending.clear();
        assert!(pending.push(b"abc".to_vec()).is_ok());
        assert_eq!(pending.pending_bytes(), 3);
        assert_eq!(pending.front_chunk(), Some(&b"abc"[..]));
    }

    #[cfg(unix)]
    #[test]
    fn pending_pty_write_push_empty_is_noop() {
        let mut pending = super::PendingPtyWrite::new(8);
        pending.push(vec![]).unwrap();
        assert!(pending.is_empty());
        assert_eq!(pending.pending_bytes(), 0);
        assert_eq!(pending.front_chunk(), None);
    }

    #[cfg(unix)]
    #[test]
    fn pending_pty_write_exact_boundary_fill() {
        let mut pending = super::PendingPtyWrite::new(8);
        assert!(pending.push(b"12345678".to_vec()).is_ok());
        assert_eq!(pending.pending_bytes(), 8);
        // One past the limit
        assert!(pending.push(b"9".to_vec()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pending_pty_write_consume_cross_chunk_boundary() {
        let mut pending = super::PendingPtyWrite::new(32);
        pending.push(b"abc".to_vec()).unwrap();
        pending.push(b"defg".to_vec()).unwrap();
        pending.push(b"hi".to_vec()).unwrap();
        // consume 1 byte into first chunk, then consume across chunk boundaries
        pending.consume(1);
        assert_eq!(pending.front_chunk(), Some(&b"bc"[..]));
        assert_eq!(pending.pending_bytes(), 8);
        // now consume 4: uses up "bc" (2) and "de" (2) from second chunk
        pending.consume(4);
        assert_eq!(pending.front_chunk(), Some(&b"fg"[..]));
        assert_eq!(pending.pending_bytes(), 4);
        // consume remainder
        pending.consume(4);
        assert!(pending.is_empty());
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

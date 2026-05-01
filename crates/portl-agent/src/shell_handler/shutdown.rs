use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::shell_registry::{PtyCommand, ShellProcess, ShellRegistry};

use super::SESSION_REAPER_GRACE;
use super::reject::SpawnReject;

pub(super) struct ShellSessionGuard<'a> {
    pub(super) registry: &'a ShellRegistry,
    pub(super) revocations: &'a std::sync::RwLock<crate::revocations::RevocationSet>,
    pub(super) session_id: [u8; 16],
    pub(super) ticket_chain_ids: Vec<[u8; 16]>,
}

impl Drop for ShellSessionGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut revocations) = self.revocations.write() {
            revocations.deregister_live_session(self.session_id, &self.ticket_chain_ids);
        }
        if let Some((_, process)) = self.registry.remove(&self.session_id) {
            begin_session_shutdown(process.as_ref(), false).spawn();
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct SessionReaper {
    pgid: Option<nix::unistd::Pid>,
    exit_rx: watch::Receiver<Option<i32>>,
    grace: Duration,
}

#[cfg(unix)]
impl SessionReaper {
    pub(crate) fn from_process(process: &ShellProcess) -> Self {
        Self {
            pgid: process
                .signal_target
                .and_then(i32::checked_abs)
                .map(nix::unistd::Pid::from_raw),
            exit_rx: process.exit_rx(),
            grace: SESSION_REAPER_GRACE,
        }
    }

    #[cfg(test)]
    fn new_for_test(
        pgid: nix::unistd::Pid,
        exit_rx: watch::Receiver<Option<i32>>,
        grace: Duration,
    ) -> Self {
        Self {
            pgid: Some(pgid),
            exit_rx,
            grace,
        }
    }

    pub(crate) fn spawn(self) {
        tokio::spawn(async move {
            let _ = self.reap().await;
        });
    }

    pub(crate) async fn reap(mut self) -> bool {
        let Some(pgid) = self.pgid else {
            return true;
        };
        if self.is_reaped() {
            return true;
        }

        for signal in [
            nix::sys::signal::Signal::SIGHUP,
            nix::sys::signal::Signal::SIGTERM,
        ] {
            match nix::sys::signal::killpg(pgid, signal) {
                Ok(()) => {}
                Err(nix::errno::Errno::ESRCH) => return true,
                Err(err) => {
                    warn!(
                        ?err,
                        pgid = pgid.as_raw(),
                        ?signal,
                        "session reaper failed to signal process group"
                    );
                    return false;
                }
            }
            if self.wait_for_reap().await {
                return true;
            }
        }

        match nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL) {
            Ok(()) => {}
            Err(nix::errno::Errno::ESRCH) => return true,
            Err(err) => {
                warn!(?err, pgid = pgid.as_raw(), signal = ?nix::sys::signal::Signal::SIGKILL, "session reaper failed to signal process group");
                return false;
            }
        }

        if std::env::var_os("PORTL_TEST_REAPER_SKIP_OBSERVATION").is_some() {
            return false;
        }

        self.wait_for_reap_with_timeout(Duration::from_millis(100))
            .await
    }

    fn is_reaped(&self) -> bool {
        self.exit_rx.borrow().is_some()
    }

    async fn wait_for_reap(&mut self) -> bool {
        self.wait_for_reap_with_timeout(self.grace).await
    }

    async fn wait_for_reap_with_timeout(&mut self, timeout: Duration) -> bool {
        if self.is_reaped() {
            return true;
        }
        tokio::select! {
            changed = self.exit_rx.changed() => changed.is_ok() && self.is_reaped(),
            () = tokio::time::sleep(timeout) => self.is_reaped(),
        }
    }
}

#[cfg(not(unix))]
#[derive(Debug)]
pub(crate) struct SessionReaper;

#[cfg(not(unix))]
impl SessionReaper {
    pub(crate) fn from_process(_process: &ShellProcess) -> Self {
        Self
    }

    pub(crate) fn spawn(self) {
        let _ = self;
    }
}

#[cfg(unix)]
pub(super) fn send_signal(target: Option<i32>, sig: u8) {
    let Some(target) = target else {
        return;
    };
    if let Ok(signal) = nix::sys::signal::Signal::try_from(i32::from(sig)) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(target), signal);
    }
}

#[cfg(not(unix))]
pub(super) fn send_signal(_target: Option<i32>, _sig: u8) {}

pub(super) fn request_pty_close(pty_tx: Option<&mpsc::UnboundedSender<PtyCommand>>, force: bool) {
    if let Some(pty_tx) = pty_tx {
        let _ = pty_tx.send(PtyCommand::Close { force });
    }
}

pub(crate) fn begin_session_shutdown(process: &ShellProcess, force_close: bool) -> SessionReaper {
    request_pty_close(process.pty_tx.as_ref(), force_close);
    SessionReaper::from_process(process)
}

pub(super) fn process_group_signal_target_from_pid(pid: u32) -> Result<i32, SpawnReject> {
    let pid =
        i32::try_from(pid).map_err(|_| SpawnReject::path_probe_failed("child pid out of range"))?;
    pid.checked_neg()
        .ok_or_else(|| SpawnReject::path_probe_failed("child pid out of range"))
}

pub(super) fn fresh_session_id() -> [u8; 16] {
    loop {
        let mut id = rand::random::<[u8; 16]>();
        id[0] |= 0b1000_0000;
        if id[0] >= 2 {
            return id;
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

    use crate::shell_registry::{ShellProcess, ShellRegistry};

    use super::{SessionReaper, ShellSessionGuard};

    #[tokio::test]
    async fn shell_registry_is_empty_after_control_stream_error() {
        let registry = ShellRegistry::default();
        let session_id = [9; 16];
        let (stdin_tx, _stdin_rx) = mpsc::channel(1);
        let (_stdout_tx, stdout_rx) = mpsc::channel(1);
        let (_stderr_tx, stderr_rx) = mpsc::channel(1);
        let exit_code = Arc::new(std::sync::Mutex::new(None));
        let (exit_tx, _) = watch::channel(None);

        registry.insert(
            session_id,
            Arc::new(ShellProcess {
                pid: 42,
                stdin_tx,
                stdout_rx: AsyncMutex::new(Some(stdout_rx)),
                stderr_rx: AsyncMutex::new(Some(stderr_rx)),
                exit_code,
                exit_tx,
                signal_target: None,
                pty_tx: None,
                started_at: Arc::new(std::sync::Mutex::new(None)),
            }),
        );
        let revocations = std::sync::RwLock::new(
            crate::revocations::RevocationSet::load(std::env::temp_dir().join(format!(
                "portl-shell-guard-revocations-{}.jsonl",
                uuid::Uuid::new_v4()
            )))
            .expect("load revocations set"),
        );

        {
            let _guard = ShellSessionGuard {
                registry: &registry,
                revocations: &revocations,
                session_id,
                ticket_chain_ids: vec![[0x11; 16]],
            };
        }

        assert!(registry.is_empty());
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        ))
    ))]
    #[tokio::test]
    async fn session_reaper_kills_interactive_shell_on_hup() {
        let (_master, pid, exit_rx, wait_task) = spawn_pty_reaper_target(&["-i"]);

        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;

        let status = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(nix::sys::signal::Signal::SIGHUP as i32)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_reaper_escalates_to_term_on_hup_ignored() {
        let (pid, exit_rx, wait_task) = spawn_exec_reaper_target("trap '' HUP; exec sleep 1000");

        tokio::time::sleep(Duration::from_millis(50)).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;

        let status = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(nix::sys::signal::Signal::SIGTERM as i32)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_reaper_escalates_to_kill_on_term_ignored() {
        let (pid, exit_rx, wait_task) =
            spawn_exec_reaper_target("trap '' HUP TERM; exec sleep 1000");

        tokio::time::sleep(Duration::from_millis(50)).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;

        let status = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(nix::sys::signal::Signal::SIGKILL as i32)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn background_jobs_in_pgroup_are_terminated() {
        let pid_file = temp_pid_file("session-reaper-background");
        let script = format!("sleep 1000 & echo $! > {}; wait", pid_file.display());
        let (pid, exit_rx, wait_task) = spawn_exec_reaper_target(&script);

        let background_pid = wait_for_pid_file(&pid_file).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;
        let _ = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");

        assert_process_gone(background_pid).await;
        let _ = std::fs::remove_file(pid_file);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn double_forked_daemons_survive_teardown() {
        let pid_file = temp_pid_file("session-reaper-daemon");
        let (pid, exit_rx, wait_task) = spawn_helper_reaper_target("double-fork-daemon", &pid_file);

        let daemon_pid = wait_for_pid_file(&pid_file).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;
        let _ = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");

        assert!(
            process_exists(daemon_pid),
            "double-forked daemon should survive session teardown"
        );
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(daemon_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = std::fs::remove_file(pid_file);
    }

    #[cfg(unix)]
    fn spawn_exec_reaper_target(
        script: &str,
    ) -> (
        nix::unistd::Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.arg("-c").arg(script);
        spawn_reaper_target(command)
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        ))
    ))]
    fn spawn_pty_reaper_target(
        argv: &[&str],
    ) -> (
        std::os::fd::OwnedFd,
        nix::unistd::Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        let (master, mut child) = crate::shell_handler::spawn_pty_for_test("/bin/sh", argv)
            .expect("spawn pty reaper target");
        let pid = nix::unistd::Pid::from_raw(
            i32::try_from(child.id().expect("child pid")).expect("pid fits in i32"),
        );
        let (exit_tx, exit_rx) = watch::channel(None);
        let wait_task = tokio::spawn(async move {
            let status = child.wait().await?;
            let _ = exit_tx.send(Some(exit_marker(status)));
            Ok(status)
        });
        (master, pid, exit_rx, wait_task)
    }

    #[cfg(unix)]
    fn spawn_helper_reaper_target(
        mode: &str,
        pid_file: &std::path::PathBuf,
    ) -> (
        nix::unistd::Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        let helper_name = "shell_handler::tests::session_reaper_helper_entrypoint";
        let mut command =
            tokio::process::Command::new(std::env::current_exe().expect("current exe"));
        command
            .env("PORTL_SESSION_REAPER_HELPER", mode)
            .env("PORTL_SESSION_REAPER_PID_FILE", pid_file)
            .arg("--exact")
            .arg(helper_name)
            .arg("--nocapture")
            .arg("--test-threads=1");
        spawn_reaper_target(command)
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn spawn_reaper_target(
        mut command: tokio::process::Command,
    ) -> (
        nix::unistd::Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        // SAFETY: post-fork hook only calls setpgid, which is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
                    .map_err(std::io::Error::from)
            });
        }
        let mut child = command.spawn().expect("spawn reaper target");
        let pid = nix::unistd::Pid::from_raw(
            i32::try_from(child.id().expect("child pid")).expect("pid fits in i32"),
        );
        let (exit_tx, exit_rx) = watch::channel(None);
        let wait_task = tokio::spawn(async move {
            let status = child.wait().await?;
            let _ = exit_tx.send(Some(exit_marker(status)));
            Ok(status)
        });
        (pid, exit_rx, wait_task)
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    pub(crate) fn run_double_fork_daemon_helper(pid_file: &std::path::PathBuf) {
        use nix::sys::wait::{WaitPidFlag, waitpid};
        use nix::unistd::{ForkResult, fork, setsid};
        use std::thread;

        // SAFETY: test-only helper process; each fork path either exits quickly
        // or enters a simple sleep loop, and no shared Rust state is touched
        // after the fork beyond process exit.
        match unsafe { fork() }.expect("first fork") {
            ForkResult::Parent { child } => {
                let _ = waitpid(child, Some(WaitPidFlag::empty()));
                loop {
                    thread::sleep(Duration::from_mins(1));
                }
            }
            ForkResult::Child => {
                setsid().expect("setsid");
                match unsafe { fork() }.expect("second fork") {
                    ForkResult::Parent { .. } => std::process::exit(0),
                    ForkResult::Child => {
                        std::fs::write(pid_file, std::process::id().to_string())
                            .expect("write daemon pid file");
                        loop {
                            thread::sleep(Duration::from_mins(1));
                        }
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    fn temp_pid_file(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{label}-{}-{}.pid",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    #[cfg(unix)]
    async fn wait_for_pid_file(path: &std::path::PathBuf) -> i32 {
        for _ in 0..100 {
            if let Ok(raw) = std::fs::read_to_string(path)
                && let Ok(pid) = raw.trim().parse::<i32>()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for pid file {}", path.display());
    }

    #[cfg(unix)]
    fn process_exists(pid: i32) -> bool {
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
            Ok(()) | Err(nix::errno::Errno::EPERM) => true,
            Err(nix::errno::Errno::ESRCH) => false,
            Err(err) => panic!("unexpected kill(0) error for pid {pid}: {err}"),
        }
    }

    #[cfg(unix)]
    async fn assert_process_gone(pid: i32) {
        for _ in 0..50 {
            if !process_exists(pid) || process_is_zombie(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!process_exists(pid), "pid {pid} should not be alive");
    }

    #[cfg(all(unix, target_os = "linux"))]
    fn process_is_zombie(pid: i32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit_once(") ").map(|(_, rest)| rest.to_owned()))
            .and_then(|rest| rest.split_whitespace().next().map(str::to_owned))
            .is_some_and(|state| state == "Z")
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn process_is_zombie(_pid: i32) -> bool {
        false
    }

    #[cfg(unix)]
    fn exit_marker(status: std::process::ExitStatus) -> i32 {
        use std::os::unix::process::ExitStatusExt as _;

        status
            .code()
            .unwrap_or_else(|| status.signal().unwrap_or(1))
    }
}

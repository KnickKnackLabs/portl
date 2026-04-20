use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

pub(crate) type ShellRegistry = DashMap<[u8; 16], Arc<ShellProcess>>;

pub(crate) struct ShellProcess {
    pub(crate) pid: u32,
    pub(crate) stdin_tx: mpsc::Sender<StdinMessage>,
    pub(crate) stdout_rx: AsyncMutex<Option<mpsc::Receiver<Vec<u8>>>>,
    pub(crate) stderr_rx: AsyncMutex<Option<mpsc::Receiver<Vec<u8>>>>,
    pub(crate) exit_code: Arc<Mutex<Option<i32>>>,
    pub(crate) exit_tx: watch::Sender<Option<i32>>,
    pub(crate) signal_target: Option<i32>,
    /// Master side of the pty pair; kept alive in the agent for
    /// TIOCSWINSZ resize. `None` for the non-PTY exec path.
    pub(crate) pty_master: Option<Arc<OwnedFd>>,
}

impl ShellProcess {
    pub(crate) fn exit_rx(&self) -> watch::Receiver<Option<i32>> {
        self.exit_tx.subscribe()
    }
}

#[derive(Debug)]
pub(crate) enum StdinMessage {
    Data(Vec<u8>),
    Close,
}

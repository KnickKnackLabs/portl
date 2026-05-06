use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context as _, Result};
use dashmap::DashMap;
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

pub(crate) type ShellRegistry = DashMap<[u8; 16], Arc<ShellProcess>>;

pub(crate) enum ShellOutput {
    Channel(AsyncMutex<Option<mpsc::Receiver<Vec<u8>>>>),
    EmptyUntilClosed(watch::Receiver<bool>),
}

impl ShellOutput {
    pub(crate) fn channel(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self::Channel(AsyncMutex::new(Some(rx)))
    }

    pub(crate) fn empty_until_closed(rx: watch::Receiver<bool>) -> Self {
        Self::EmptyUntilClosed(rx)
    }

    pub(crate) async fn take_channel(&self) -> Result<Option<mpsc::Receiver<Vec<u8>>>> {
        match self {
            Self::Channel(rx) => rx
                .lock()
                .await
                .take()
                .context("stream already attached")
                .map(Some),
            Self::EmptyUntilClosed(_) => Ok(None),
        }
    }

    pub(crate) fn empty_close_signal(&self) -> Option<watch::Receiver<bool>> {
        match self {
            Self::Channel(_) => None,
            Self::EmptyUntilClosed(rx) => Some(rx.clone()),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty_until_closed(&self) -> bool {
        matches!(self, Self::EmptyUntilClosed(_))
    }

    #[cfg(test)]
    pub(crate) fn empty_close_signal_for_test(&self) -> Option<watch::Receiver<bool>> {
        self.empty_close_signal()
    }
}

pub(crate) struct ShellProcess {
    pub(crate) pid: u32,
    pub(crate) stdin_tx: mpsc::Sender<StdinMessage>,
    pub(crate) stdout: ShellOutput,
    pub(crate) stderr: ShellOutput,
    pub(crate) exit_code: Arc<Mutex<Option<i32>>>,
    pub(crate) exit_tx: watch::Sender<Option<i32>>,
    pub(crate) signal_target: Option<i32>,
    /// Control channel for PTY-only operations handled by the single
    /// async PTY master task. `None` for the non-PTY exec path.
    pub(crate) pty_tx: Option<mpsc::UnboundedSender<PtyCommand>>,
    /// Wall-clock marker set when `audit.shell_start` is emitted.
    /// The wait-for-child task reads it to compute `duration_ms`
    /// for the `audit.shell_exit` record (spec 150 §3.2).
    pub(crate) started_at: Arc<Mutex<Option<Instant>>>,
}

impl ShellProcess {
    pub(crate) fn exit_rx(&self) -> watch::Receiver<Option<i32>> {
        self.exit_tx.subscribe()
    }

    /// Record the instant associated with the paired `shell_start`
    /// audit record so the exit path can emit `duration_ms`.
    pub(crate) fn set_started_at(&self, instant: Instant) {
        if let Ok(mut guard) = self.started_at.lock() {
            *guard = Some(instant);
        }
    }
}

#[derive(Debug)]
pub(crate) enum StdinMessage {
    Data(Vec<u8>),
    Close,
}

#[derive(Debug)]
pub(crate) enum PtyCommand {
    Resize { rows: u16, cols: u16 },
    Close { force: bool },
    KickOthers,
}

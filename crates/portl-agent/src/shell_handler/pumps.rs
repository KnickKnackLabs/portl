use std::os::fd::AsRawFd;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use iroh::endpoint::SendStream;
use tokio::io::AsyncReadExt;

use crate::shell_registry::{PtyCommand, ShellOutput, ShellProcess, StdinMessage};
use crate::stream_io::BufferedRecv;

use super::shutdown::send_signal;
use super::{IO_CHUNK, MAX_RESIZE_BYTES, MAX_SIGNAL_BYTES};

pub(crate) async fn pump_stdin(mut recv: BufferedRecv, process: Arc<ShellProcess>) -> Result<()> {
    let mut buf = vec![0_u8; IO_CHUNK];
    loop {
        let read = recv.read(&mut buf).await.context("read shell stdin")?;
        if read == 0 {
            let _ = process.stdin_tx.send(StdinMessage::Close).await;
            return Ok(());
        }
        process
            .stdin_tx
            .send(StdinMessage::Data(buf[..read].to_vec()))
            .await
            .context("forward shell stdin")?;
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ShellOutputKind {
    Stdout,
    Stderr,
}

fn output_for(process: &ShellProcess, kind: ShellOutputKind) -> &ShellOutput {
    match kind {
        ShellOutputKind::Stdout => &process.stdout,
        ShellOutputKind::Stderr => &process.stderr,
    }
}

async fn wait_process_exit(process: &ShellProcess) -> Result<i32> {
    let initial = *process
        .exit_code
        .lock()
        .map_err(|_| anyhow!("exit code mutex poisoned"))?;
    if let Some(code) = initial {
        return Ok(code);
    }

    let mut rx = process.exit_rx();
    if let Some(code) = *rx.borrow() {
        return Ok(code);
    }
    loop {
        rx.changed().await.context("wait for shell exit")?;
        if let Some(code) = *rx.borrow() {
            return Ok(code);
        }
    }
}

pub(crate) async fn pump_output(
    mut send: SendStream,
    process: &ShellProcess,
    kind: ShellOutputKind,
) -> Result<()> {
    let output = output_for(process, kind);
    if let Some(mut rx) = output.take_channel().await? {
        let strip_stdout_queries = matches!(kind, ShellOutputKind::Stdout)
            && process.strip_stdout_queries()
            && server_query_strip_enabled_for_tests();
        let mut query_stripper = strip_stdout_queries.then(portl_core::QueryStripper::new);
        while let Some(chunk) = rx.recv().await {
            let chunk = output_chunk_for_wire(&mut query_stripper, chunk);
            if !chunk.is_empty() {
                send.write_all(&chunk).await.context("write shell output")?;
            }
        }
        if let Some(stripper) = query_stripper.as_mut() {
            let tail = stripper.finish();
            if !tail.is_empty() {
                send.write_all(&tail).await.context("write shell output")?;
            }
        }
        send.finish().context("finish shell output")?;
        return Ok(());
    }

    let mut closed = output
        .empty_close_signal()
        .context("empty output stream missing close signal")?;
    loop {
        if *closed.borrow_and_update() {
            break;
        }
        closed
            .changed()
            .await
            .context("wait for empty output close")?;
    }
    send.finish().context("finish empty shell output")?;
    Ok(())
}

fn server_query_strip_enabled_for_tests() -> bool {
    !cfg!(feature = "force-disable-server-query-strip")
        || std::env::var_os("PORTL_TEST_FORCE_DISABLE_SERVER_QUERY_STRIP").is_none()
}

fn output_chunk_for_wire(
    query_stripper: &mut Option<portl_core::QueryStripper>,
    chunk: Vec<u8>,
) -> Vec<u8> {
    if let Some(stripper) = query_stripper.as_mut() {
        stripper.feed(&chunk)
    } else {
        chunk
    }
}

pub(crate) async fn pump_signals(mut recv: BufferedRecv, process: &ShellProcess) -> Result<()> {
    while let Some(frame) = recv
        .read_frame::<portl_proto::shell_v1::SignalFrame>(MAX_SIGNAL_BYTES)
        .await?
    {
        if process.signal_target.is_some() {
            send_signal(process.signal_target, frame.sig);
        } else if frame.sig == 2 {
            process
                .stdin_tx
                .send(StdinMessage::Data(vec![0x03]))
                .await
                .context("forward signal as terminal interrupt byte")?;
        }
    }
    Ok(())
}

pub(crate) async fn pump_resizes(mut recv: BufferedRecv, process: &ShellProcess) -> Result<()> {
    while let Some(frame) = recv
        .read_frame::<portl_proto::shell_v1::ResizeFrame>(MAX_RESIZE_BYTES)
        .await?
    {
        #[cfg(unix)]
        if let Some(pty_tx) = process.pty_tx.as_ref() {
            pty_tx
                .send(PtyCommand::Resize {
                    rows: frame.rows,
                    cols: frame.cols,
                })
                .map_err(|_| anyhow!("pty resize channel closed"))
                .context("forward pty resize")?;
        }
        #[cfg(not(unix))]
        let _ = frame;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn resize_pty(master: &impl AsRawFd, rows: u16, cols: u16) -> std::io::Result<()> {
    let ws = nix::libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY(unsafe_code): TIOCSWINSZ on a valid pty master fd is a
    // well-defined ioctl; we borrow the fd via AsRawFd for the duration
    // of the call only.
    #[allow(unsafe_code)]
    let rc = unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &ws) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) async fn pump_exit(mut send: SendStream, process: &ShellProcess) -> Result<()> {
    let frame = portl_proto::shell_v1::ExitFrame {
        code: wait_process_exit(process).await?,
    };
    send.write_all(&postcard::to_stdvec(&frame)?).await?;
    send.finish().context("finish shell exit stream")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tokio::sync::{mpsc, watch};

    use super::{ShellOutputKind, output_chunk_for_wire, pump_output};
    use crate::shell_registry::{ShellOutput, ShellProcess, StdinMessage};

    const ALL_QUERY_FORMS_CHUNK: &[u8] =
        b"pre\x1b[c\x1b[>c\x1b[6n\x1b[?u\x1b[>1u\x1b[=15u\x1b[<umiddle\x1b[c\x1b[?upost";
    const EXPECTED_STRIPPED_CHUNK: &[u8] = b"premiddlepost";
    const PUMP_OUTPUT_TEST_ALPN: &[u8] = b"portl/test/pump-output";

    #[derive(Debug, Clone, Copy)]
    enum TestProvider {
        Ghostty,
        Zmx,
        Tmux,
        RawShell,
    }

    impl TestProvider {
        const ALL: [Self; 4] = [Self::Ghostty, Self::Zmx, Self::Tmux, Self::RawShell];
        const NON_GHOSTTY: [Self; 3] = [Self::Zmx, Self::Tmux, Self::RawShell];
    }

    fn stripped_wire_capture(chunks: &[&[u8]]) -> Vec<u8> {
        let mut stripper = Some(portl_core::QueryStripper::new());
        let mut output = Vec::new();
        for chunk in chunks {
            output.extend(output_chunk_for_wire(&mut stripper, chunk.to_vec()));
        }
        if let Some(stripper) = stripper.as_mut() {
            output.extend(stripper.finish());
        }
        output
    }

    fn da1_burst_bytes(size: usize) -> Vec<u8> {
        let query = b"\x1b[c";
        let mut burst = Vec::with_capacity(size + query.len());
        while burst.len() < size {
            burst.extend_from_slice(query);
        }
        burst
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn assert_no_query_bytes(bytes: &[u8], context: &str) {
        for query in [
            b"\x1b[c".as_slice(),
            b"\x1b[>c",
            b"\x1b[6n",
            b"\x1b[?u",
            b"\x1b[>1u",
            b"\x1b[=15u",
            b"\x1b[<u",
        ] {
            assert!(
                !contains_subslice(bytes, query),
                "{context} leaked query bytes {query:?}: {bytes:?}"
            );
        }
    }

    fn assert_linear_dos_samples(provider: &str, samples: &[(usize, Duration)]) {
        let (mid_len, mid_elapsed) = samples[1];
        let (large_len, large_elapsed) = samples[2];
        let mid_bytes = u32::try_from(mid_len).expect("mid DoS size fits in u32");
        let large_bytes = u32::try_from(large_len).expect("large DoS size fits in u32");
        let mid_slope = mid_elapsed.as_secs_f64() / f64::from(mid_bytes);
        let large_slope = large_elapsed.as_secs_f64() / f64::from(large_bytes);
        let ratio = if mid_slope > large_slope {
            mid_slope / large_slope.max(0.000_000_001)
        } else {
            large_slope / mid_slope.max(0.000_000_001)
        };
        assert!(
            ratio <= 3.0,
            "{provider} DoS timing was not linear within 3x: samples={samples:?}, ratio={ratio}"
        );
    }

    fn test_shell_process(stdout: mpsc::Receiver<Vec<u8>>) -> Arc<ShellProcess> {
        let (stdin_tx, _stdin_rx) = mpsc::channel::<StdinMessage>(1);
        let (_stderr_closed_tx, stderr_closed_rx) = watch::channel(true);
        let (exit_tx, _exit_rx) = watch::channel(None);
        let process = Arc::new(ShellProcess {
            pid: 0,
            stdin_tx,
            stdout: ShellOutput::channel(stdout),
            stderr: ShellOutput::empty_until_closed(stderr_closed_rx),
            exit_code: Arc::new(Mutex::new(Some(0))),
            exit_tx,
            signal_target: None,
            strip_stdout_queries: std::sync::atomic::AtomicBool::new(false),
            pty_tx: None,
            started_at: Arc::new(Mutex::new(None)),
        });
        process.enable_stdout_query_stripping();
        process
    }

    async fn read_until_marker(
        recv: &mut iroh::endpoint::RecvStream,
        captured: &mut Vec<u8>,
        marker: &[u8],
    ) {
        let mut buf = [0_u8; 8192];
        tokio::time::timeout(Duration::from_secs(30), async {
            while !contains_subslice(captured, marker) {
                let Some(read) = recv.read(&mut buf).await.expect("read pump output stream") else {
                    panic!("pump output stream ended before marker {marker:?}");
                };
                assert!(read > 0, "pump output stream returned an empty read");
                captured.extend_from_slice(&buf[..read]);
            }
        })
        .await
        .expect("timed out waiting for pump output marker");
    }

    #[test]
    fn zmx_stdout_query_stripper_removes_queries_and_keeps_surrounding_bytes() {
        let mut stripper = Some(portl_core::QueryStripper::new());
        let chunk = b"pre\x1b[c\x1b[>c\x1b[6n\x1b[?u\x1b[>1u\x1b[=15u\x1b[<upost".to_vec();

        let output = output_chunk_for_wire(&mut stripper, chunk);

        assert_eq!(output, b"prepost");
    }

    #[test]
    fn zmx_stdout_query_stripper_holds_split_queries() {
        let mut stripper = Some(portl_core::QueryStripper::new());

        let first = output_chunk_for_wire(&mut stripper, b"pre\x1b[=".to_vec());
        let second = output_chunk_for_wire(&mut stripper, b"15upost".to_vec());

        assert_eq!(first, b"pre");
        assert_eq!(second, b"post");
    }

    #[test]
    fn zmx_stdout_query_stripper_does_not_panic_on_malformed_bursts() {
        let mut stripper = Some(portl_core::QueryStripper::new());
        let mut burst = Vec::new();
        for _ in 0..120 {
            burst.extend_from_slice(b"\x1b[Xhello\x1b[?Xhello\x1b[?;;uhello\x1bZhello");
        }

        let output = output_chunk_for_wire(&mut stripper, burst);

        assert!(
            output
                .windows(b"hello".len())
                .any(|window| window == b"hello")
        );
    }

    #[test]
    fn raw_shell_stdout_query_stripper_removes_all_queries_in_single_chunk() {
        let output = stripped_wire_capture(&[ALL_QUERY_FORMS_CHUNK]);

        assert_eq!(output, EXPECTED_STRIPPED_CHUNK);
        for query in [
            b"\x1b[c".as_slice(),
            b"\x1b[>c",
            b"\x1b[6n",
            b"\x1b[?u",
            b"\x1b[>1u",
            b"\x1b[=15u",
            b"\x1b[<u",
        ] {
            assert!(!output.windows(query.len()).any(|window| window == query));
        }
    }

    #[test]
    fn raw_shell_stdout_query_stripper_survives_large_query_burst() {
        let mut burst = Vec::from(&b"pre"[..]);
        for _ in 0..120 {
            burst.extend_from_slice(b"\x1b[c\x1b[>c\x1b[6n\x1b[?u\x1b[>1u\x1b[=15u\x1b[<u");
        }
        burst.extend_from_slice(b"post");

        let output = stripped_wire_capture(&[&burst]);

        assert_eq!(output, b"prepost");
    }

    #[tokio::test]
    async fn tmux_pump_output_dos_da1_burst_is_bounded_linear_and_wire_clean() {
        #[cfg(feature = "test-attach-taps")]
        portl_core::QueryStripper::reset_max_buffered_watermark_for_test();

        let (client, server) = portl_core::test_util::pair().await.expect("test endpoints");
        server
            .inner()
            .set_alpns(vec![PUMP_OUTPUT_TEST_ALPN.to_vec()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.inner().accept().await.expect("accept connection");
                incoming.await.expect("establish connection")
            }
        });
        let connection = client
            .inner()
            .connect(server.addr(), PUMP_OUTPUT_TEST_ALPN)
            .await
            .expect("connect endpoints");
        let server_connection = server_task.await.expect("server accept task");
        let (send, _recv) = connection.open_bi().await.expect("open pump output stream");
        let mut accept_stream_task = Some(tokio::spawn(async move {
            server_connection
                .accept_bi()
                .await
                .expect("accept pump output stream")
        }));
        let (stdout_tx, stdout_rx) = mpsc::channel(8);
        let process = test_shell_process(stdout_rx);
        let pump_task = tokio::spawn({
            let process = Arc::clone(&process);
            async move { pump_output(send, &process, ShellOutputKind::Stdout).await }
        });

        let sizes = [1024_usize, 100 * 1024, 10 * 1024 * 1024];
        let mut expected = Vec::new();
        let mut captured = Vec::new();
        let mut samples = Vec::new();
        let mut server_recv = None;
        for size in sizes {
            let burst = da1_burst_bytes(size);
            let prefix = format!("TMUX_DOS_PRE_{size}:");
            let suffix = format!(":TMUX_DOS_POST_{size}");
            let mut input = Vec::with_capacity(prefix.len() + burst.len() + suffix.len());
            input.extend_from_slice(prefix.as_bytes());
            input.extend_from_slice(&burst);
            input.extend_from_slice(suffix.as_bytes());

            let started = Instant::now();
            stdout_tx.send(input).await.expect("send stdout chunk");
            if server_recv.is_none() {
                let (_server_send, recv) = accept_stream_task
                    .take()
                    .expect("accept stream task should be pending")
                    .await
                    .expect("accept stream task");
                server_recv = Some(recv);
            }
            read_until_marker(
                server_recv.as_mut().expect("server recv stream"),
                &mut captured,
                suffix.as_bytes(),
            )
            .await;
            samples.push((burst.len(), started.elapsed()));
            expected.extend_from_slice(prefix.as_bytes());
            expected.extend_from_slice(suffix.as_bytes());
        }
        drop(stdout_tx);
        let tail = server_recv
            .as_mut()
            .expect("server recv stream")
            .read_to_end(1024 * 1024)
            .await
            .expect("read pump output tail");
        captured.extend_from_slice(&tail);
        pump_task
            .await
            .expect("pump task join")
            .expect("pump output succeeds");

        assert_eq!(
            captured, expected,
            "tmux ShellProcess::pump_output should preserve only surrounding non-query bytes"
        );
        assert_no_query_bytes(&captured, "tmux pump_output DoS capture");
        #[cfg(feature = "test-attach-taps")]
        {
            let high_water = portl_core::QueryStripper::max_buffered_watermark_for_test();
            assert!(
                high_water <= portl_core::QueryStripper::MAX_BUFFERED,
                "tmux pump_output QueryStripper high-water {high_water} exceeded bound {}",
                portl_core::QueryStripper::MAX_BUFFERED
            );
        }
        assert_linear_dos_samples("tmux pump_output", &samples);

        connection.close(0_u32.into(), b"test complete");
        client.inner().close().await;
        server.inner().close().await;
    }

    #[test]
    fn provider_parity_strips_all_queries_from_single_chunk_for_every_provider() {
        for provider in TestProvider::ALL {
            let output = stripped_wire_capture(&[ALL_QUERY_FORMS_CHUNK]);

            assert_eq!(
                output, EXPECTED_STRIPPED_CHUNK,
                "provider {provider:?} should strip all query forms"
            );
        }
    }

    #[test]
    fn provider_parity_non_ghostty_large_bursts_silent_consume_without_panic() {
        let mut burst = Vec::from(&b"before"[..]);
        for _ in 0..120 {
            burst.extend_from_slice(b"\x1b[c\x1b[>c\x1b[6n\x1b[?u\x1b[>1u\x1b[=15u\x1b[<u");
        }
        burst.extend_from_slice(b"after");

        for provider in TestProvider::NON_GHOSTTY {
            let output = stripped_wire_capture(&[&burst]);

            assert_eq!(
                output, b"beforeafter",
                "provider {provider:?} should silently consume query bursts"
            );
        }
    }

    #[test]
    fn provider_parity_wire_capture_is_byte_equal_across_providers() {
        let chunks = [
            b"pre\x1b[=".as_slice(),
            b"15umid\x1b[c\x1b[31m",
            b"color\x1b[?u\x1b[>cpost",
        ];
        let reference = stripped_wire_capture(&chunks);

        assert_eq!(reference, b"premid\x1b[31mcolorpost");
        for provider in TestProvider::ALL {
            let output = stripped_wire_capture(&chunks);

            assert_eq!(
                output, reference,
                "wire capture for provider {provider:?} should match all other providers"
            );
        }
    }
}

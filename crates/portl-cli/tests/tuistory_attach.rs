#![cfg(all(unix, feature = "ghostty-vt"))]

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::unistd::{dup, read, write};
use tempfile::tempdir;

const DETACH_KEY: &[u8] = b"\x1c";
const STANDIN_TUI: &str = "saved=$(stty -g); stty raw -echo; printf 'TUI-BEGIN\\r\\n'; printf '\\033[c\\033[>c\\033[?u'; printf '\\r\\nTUI-READY\\r\\n'; sleep 1; stty \"$saved\"";

#[test]
fn symptom1_startup_queries_do_not_leak_response_payloads() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = tempdir().expect("temp portl home");
    let init_status = Command::new(&portl)
        .env("PORTL_HOME", home.path())
        .args(["init", "--quiet", "--force"])
        .status()
        .expect("run portl init");
    assert!(init_status.success(), "portl init failed: {init_status}");
    let session = format!(
        "tuistory-symptom1-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix time")
            .as_nanos()
    );
    let host_script = r#"
set +e
"$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- /bin/sh -c "$STANDIN_TUI"
status=$?
printf '\nHOST_AFTER_DETACH status=%s\n' "$status"
IFS= read -r -t 1 leaked || leaked=''
printf 'HOST_STDIN:%s\n' "$leaked"
"$PORTL_BIN" kill "$PORTL_SESSION" --provider ghostty >/dev/null 2>&1 || true
exit "$status"
"#;

    let mut child = spawn_host_command(
        "/bin/bash",
        &["-lc", host_script],
        &[
            ("PORTL_BIN", portl.to_str().expect("portl path utf8")),
            ("PORTL_HOME", home.path().to_str().expect("home path utf8")),
            ("PORTL_SESSION", &session),
            ("STANDIN_TUI", STANDIN_TUI),
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");

    let mut transcript = Vec::new();
    if let Err(err) = wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"TUI-READY",
        Duration::from_secs(10),
    ) {
        panic!(
            "stand-in TUI reached startup marker: {err}; transcript:\n{}",
            escaped(&transcript)
        );
    }
    write(&child.input, DETACH_KEY).expect("send detach key");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"HOST_STDIN:",
        Duration::from_secs(10),
    )
    .expect("host shell reached post-detach stdin probe");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));

    let status = child.process.wait().expect("wait host shell");
    assert!(
        status.success(),
        "host shell exited with {status}; transcript:\n{}",
        escaped(&transcript)
    );

    assert_forbidden_response_payloads_absent(&transcript);
    let host_stdin = bytes_after_marker(&transcript, b"HOST_STDIN:").unwrap_or_default();
    assert_forbidden_response_payloads_absent(host_stdin);
}

struct HostCommand {
    process: Child,
    input: OwnedFd,
    rx: mpsc::Receiver<Vec<u8>>,
}

#[allow(unsafe_code)]
fn spawn_host_command(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> io::Result<HostCommand> {
    let size = nix::libc::winsize {
        ws_row: 24,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let nix::pty::OpenptyResult { master, slave } =
        nix::pty::openpty(Some(&size), None).map_err(io::Error::from)?;
    let input = dup(&master).map_err(io::Error::from)?;
    let slave_fd = slave.as_raw_fd();

    let mut command = Command::new(program);
    command.args(args).envs(env.iter().copied());
    command.env("COLUMNS", "100").env("LINES", "24");
    unsafe {
        command.pre_exec(move || {
            if nix::libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
            let req = nix::libc::TIOCSCTTY
                .try_into()
                .expect("TIOCSCTTY fits in ioctl request type");
            if nix::libc::ioctl(slave_fd, req, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            for target in [0, 1, 2] {
                if nix::libc::dup2(slave_fd, target) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            if slave_fd > 2 {
                let _ = nix::libc::close(slave_fd);
            }
            Ok(())
        });
    }

    let process = command.spawn()?;
    drop(slave);
    let rx = spawn_reader(master);
    Ok(HostCommand { process, input, rx })
}

fn spawn_reader(master: OwnedFd) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0_u8; 4096];
        loop {
            match read(&master, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

fn wait_for_bytes(
    rx: &mpsc::Receiver<Vec<u8>>,
    transcript: &mut Vec<u8>,
    needle: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(chunk) => {
                transcript.extend_from_slice(&chunk);
                if contains_subslice(transcript, needle) {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("timed out waiting for {}", escaped(needle)),
    ))
}

fn drain_for(rx: &mpsc::Receiver<Vec<u8>>, transcript: &mut Vec<u8>, duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(chunk) => transcript.extend_from_slice(&chunk),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn assert_forbidden_response_payloads_absent(bytes: &[u8]) {
    for forbidden in [
        b"0u62;52;c".as_slice(),
        b"62;52;c",
        b"62;1;6;22c",
        b"1;1;0c",
        b"?62;1;6;22c",
        b">1;1;0c",
        b"?0u",
        b";c",
        b";u",
        b";R",
        b"\x1b[?62;1;6;22c",
        b"\x1b[>1;1;0c",
        b"\x1b[?0u",
    ] {
        assert!(
            !contains_subslice(bytes, forbidden),
            "forbidden response payload {} leaked in transcript:\n{}",
            escaped(forbidden),
            escaped(bytes)
        );
    }
}

fn bytes_after_marker<'a>(bytes: &'a [u8], marker: &[u8]) -> Option<&'a [u8]> {
    bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|idx| &bytes[idx + marker.len()..])
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn escaped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

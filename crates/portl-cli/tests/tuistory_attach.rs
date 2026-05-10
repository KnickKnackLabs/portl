#![cfg(all(unix, feature = "ghostty-vt"))]

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use nix::unistd::{dup, read, write};
use tempfile::tempdir;

const DETACH_KEY: &[u8] = b"\x1c";
const STANDIN_TUI: &str = "saved=$(stty -g); stty raw -echo; printf 'TUI-BEGIN\\r\\n'; printf '\\033[c\\033[>c\\033[?u'; printf '\\r\\nTUI-READY\\r\\n'; sleep 1; stty \"$saved\"";
const SYMPTOM2_STANDIN_TUI: &[u8] = b"saved=$(stty -g); stty raw -echo; printf 'SYM2-TUI-BEGIN\\r\\n'; printf '\\033[>1u\\033[?1049h'; printf '\\033[?1049l'; stty \"$saved\"; printf '\\r\\nSYM2-TUI-DONE\\r\\n'\n";
const DEFENSIVE_KITTY_RESET: &[u8] = b"\x1b[<u\x1b[=0u\x1b[>4;0m";
const EXTENDED_CLEANUP: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\n";
const EMERGENCY_CLEANUP: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\n\x1bc";

#[test]
fn symptom1_startup_queries_do_not_leak_response_payloads() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let session = unique_session("tuistory-symptom1");
    let host_script = r#"
set +e
"$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- /bin/sh -c "$STANDIN_TUI"
status=$?
printf '\nHOST_AFTER_DETACH status=%s\n' "$status"
IFS= read -r -t 1 leaked
leaked=${leaked-}
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
    write(&child.input, DETACH_KEY).expect("enter attach control mode");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"detach",
        Duration::from_secs(5),
    )
    .expect("attach control mode displayed detach action");
    let detach_prompt = transcript.len();
    write(&child.input, b"d").expect("confirm detach");
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
    let post_detach_marker = find_subslice(&transcript, b"HOST_AFTER_DETACH status=0")
        .expect("normal detach status marker");
    assert!(
        post_detach_marker >= detach_prompt,
        "post-detach marker appeared before detach confirmation:\n{}",
        escaped(&transcript)
    );

    assert_forbidden_response_payloads_absent(&transcript);
    let host_stdin = bytes_after_marker(&transcript, b"HOST_STDIN:").unwrap_or_default();
    assert_forbidden_response_payloads_absent(host_stdin);
}

#[test]
fn symptom2_tui_exit_resets_kitty_before_next_ctrl_key() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let session = unique_session("tuistory-symptom2");
    let host_script = r#"
set +e
export PS1='SYM2-PROMPT> '
"$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- /bin/bash --noprofile --norc -i
status=$?
printf '\nHOST_AFTER_DETACH status=%s\n' "$status"
IFS= read -r -t 1 leaked
leaked=${leaked-}
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
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");

    let mut transcript = Vec::new();
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"SYM2-PROMPT>",
        Duration::from_secs(10),
    )
    .expect("inner shell reached prompt");

    write(&child.input, SYMPTOM2_STANDIN_TUI).expect("launch symptom2 stand-in TUI");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"SYM2-TUI-DONE",
        Duration::from_secs(10),
    )
    .expect("stand-in TUI exited back to shell");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));
    let before_ctrl_probe = transcript.len();

    let alt_leave =
        find_subslice(&transcript, b"\x1b[?1049l").expect("stand-in TUI emitted alt-screen leave");
    assert!(
        contains_subslice(
            &transcript[alt_leave..before_ctrl_probe],
            DEFENSIVE_KITTY_RESET
        ),
        "defensive Kitty reset was not emitted after alt-screen leave:\n{}",
        escaped(&transcript[alt_leave..before_ctrl_probe])
    );

    write(&child.input, b"TAIL").expect("type readline suffix");
    write(&child.input, b"\x01").expect("send Ctrl+A");
    write(&child.input, b"echo CTRL_A_OK ").expect("type readline prefix");
    write(&child.input, b"\n").expect("submit readline probe");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"CTRL_A_OK TAIL",
        Duration::from_secs(10),
    )
    .expect("Ctrl+A was interpreted as readline beginning-of-line");
    let after_ctrl_probe = &transcript[before_ctrl_probe..];
    assert!(
        !contains_kitty_csi_u_payload(after_ctrl_probe),
        "Kitty CSI-u payload leaked after TUI exit:\n{}",
        escaped(after_ctrl_probe)
    );

    write(&child.input, DETACH_KEY).expect("enter attach control mode");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"detach",
        Duration::from_secs(5),
    )
    .expect("attach control mode displayed detach action");
    write(&child.input, b"d").expect("confirm detach");
    wait_for_host_stdin(&child, &mut transcript);
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));

    let status = child.process.wait().expect("wait host shell");
    assert!(
        status.success(),
        "host shell exited with {status}; transcript:\n{}",
        escaped(&transcript)
    );

    let host_stdin = bytes_after_marker(&transcript, b"HOST_STDIN:").unwrap_or_default();
    assert!(
        !contains_kitty_csi_u_payload(host_stdin),
        "Kitty CSI-u payload leaked to host stdin:\n{}",
        escaped(host_stdin)
    );
}

#[test]
fn symptom3_signals_emit_emergency_cleanup_and_leave_host_usable() {
    for (signal, marker) in [
        (Signal::SIGHUP, b"status=1".as_slice()),
        (Signal::SIGTERM, b"status=1".as_slice()),
        (Signal::SIGINT, b"status=1".as_slice()),
    ] {
        let mut transcript = run_signal_terminated_attach(signal);
        let status = wait_for_bytes(
            &transcript.0.rx,
            &mut transcript.1,
            b"HOST_READY_PROBE",
            Duration::from_secs(10),
        );
        assert!(
            status.is_ok(),
            "host shell did not recover after {signal:?}: {status:?}; transcript:\n{}",
            escaped(&transcript.1)
        );
        drain_for(
            &transcript.0.rx,
            &mut transcript.1,
            Duration::from_millis(250),
        );
        let shell_status = transcript.0.process.wait().expect("wait host shell");
        assert!(
            shell_status.success(),
            "host shell failed after {signal:?}: {shell_status}; transcript:\n{}",
            escaped(&transcript.1)
        );
        assert!(
            contains_subslice(&transcript.1, marker),
            "portl status marker missing after {signal:?}:\n{}",
            escaped(&transcript.1)
        );
        assert_cleanup_before_marker(&transcript.1, b"HOST_AFTER_ATTACH", EMERGENCY_CLEANUP);
    }
}

#[test]
fn symptom3_panic_inject_attach_emits_cleanup_and_ris_on_stderr() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let session = unique_session("tuistory-symptom3-panic");
    let host_script = r#"
set +e
PORTL_PANIC_INJECT_ATTACH=1 "$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- /bin/sh -c "sleep 30"
status=$?
printf '\nHOST_AFTER_ATTACH status=%s\n' "$status"
printf 'HOST_READY_PROBE\n'
"$PORTL_BIN" kill "$PORTL_SESSION" --provider ghostty >/dev/null 2>&1 || true
exit 0
"#;

    let mut child = spawn_host_command(
        "/bin/bash",
        &["-lc", host_script],
        &[
            ("PORTL_BIN", portl.to_str().expect("portl path utf8")),
            ("PORTL_HOME", home.path().to_str().expect("home path utf8")),
            ("PORTL_SESSION", &session),
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");
    let mut transcript = Vec::new();
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"HOST_READY_PROBE",
        Duration::from_secs(10),
    )
    .expect("panic-injected attach returned to host shell");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));
    let status = child.process.wait().expect("wait host shell");
    assert!(
        status.success(),
        "host shell failed after panic injection: {status}; transcript:\n{}",
        escaped(&transcript)
    );
    assert_cleanup_before_marker(&transcript, b"HOST_AFTER_ATTACH", EMERGENCY_CLEANUP);
}

#[test]
fn symptom3_reattach_after_abnormal_exit_renders_cleanly() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let session = unique_session("tuistory-symptom3-reattach");
    let host_script = r#"
set +e
/bin/sh -c 'printf "ATTACH_PID=%s\n" "$$"; exec "$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- env PS1="REATTACH-PROMPT> " /bin/bash --noprofile --norc -i'
first_status=$?
printf '\nHOST_AFTER_FIRST status=%s\n' "$first_status"
"$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty
second_status=$?
printf '\nHOST_AFTER_SECOND status=%s\n' "$second_status"
"$PORTL_BIN" kill "$PORTL_SESSION" --provider ghostty >/dev/null 2>&1 || true
exit 0
"#;

    let mut child = spawn_host_command(
        "/bin/bash",
        &["-lc", host_script],
        &[
            ("PORTL_BIN", portl.to_str().expect("portl path utf8")),
            ("PORTL_HOME", home.path().to_str().expect("home path utf8")),
            ("PORTL_SESSION", &session),
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");
    let mut transcript = Vec::new();
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"REATTACH-PROMPT>",
        Duration::from_secs(10),
    )
    .expect("first attach became live");
    let pid = attach_pid_from_transcript(&transcript);
    kill(pid, Signal::SIGHUP).expect("send SIGHUP to first attach");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"HOST_AFTER_FIRST",
        Duration::from_secs(10),
    )
    .expect("first attach returned to host shell");
    let second_start = transcript.len();
    wait_for_new_bytes(
        &child.rx,
        &mut transcript,
        second_start,
        b"REATTACH-PROMPT>",
        Duration::from_secs(10),
    )
    .expect("second attach rendered cleanly");
    write(&child.input, DETACH_KEY).expect("enter attach control mode on second attach");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"detach",
        Duration::from_secs(5),
    )
    .expect("second attach control mode displayed detach action");
    write(&child.input, b"d").expect("confirm second detach");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"HOST_AFTER_SECOND",
        Duration::from_secs(10),
    )
    .expect("second attach exited");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));
    let status = child.process.wait().expect("wait host shell");
    assert!(
        status.success(),
        "host shell failed after reattach: {status}; transcript:\n{}",
        escaped(&transcript)
    );
    assert_cleanup_before_marker(&transcript, b"HOST_AFTER_FIRST", EMERGENCY_CLEANUP);
    let second_frame = &transcript[second_start..];
    let clean_idx =
        find_subslice(second_frame, b"REATTACH-PROMPT>").expect("second attach marker exists");
    let prefix = &second_frame[..clean_idx];
    assert!(
        !contains_subslice(prefix, b"\x1bc") && !contains_subslice(prefix, b"\x1b[!p"),
        "emergency cleanup leaked into second attach first frame:\n{}",
        escaped(prefix)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn symptom3_long_session_mixed_modes_and_kitty_detach_hotkey_stay_clean() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let session = unique_session("tuistory-symptom3-long");
    let host_script = r#"
set +e
export PS1='SYM3-PROMPT> '
"$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- /bin/bash --noprofile --norc -i
status=$?
printf '\nHOST_AFTER_DETACH status=%s\n' "$status"
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
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");
    let mut transcript = Vec::new();
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"SYM3-PROMPT>",
        Duration::from_secs(10),
    )
    .expect("inner shell reached prompt");
    write(&child.input, b"stty -echo\n").expect("disable shell echo for scripted TUIs");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));

    for (label, script) in [
        (
            "A",
            "printf '\\033[?1049hTUI_A\\033[?1049l\\r\\nPROBE_A:HELLO\\r\\n'\n",
        ),
        (
            "B",
            "printf '\\033[>1uTUI_B\\033[<u\\r\\nPROBE_B:HELLO\\r\\n'\n",
        ),
        (
            "C",
            "printf '\\033[?1000h\\033[?1006hTUI_C\\033[?1000l\\033[?1006l\\r\\nPROBE_C:HELLO\\r\\n'\n",
        ),
        (
            "D",
            "printf '\\033[>1u\\033[?1049h\\033[?1000h\\033[?1006h\\033[?2004h\\033[>4;2m\\033[?7l\\033[5;20rTUI_D\\r\\nPROBE_D:HELLO\\r\\n'\n",
        ),
    ] {
        let before = transcript.len();
        write(&child.input, script.as_bytes()).expect("send mixed-mode TUI script");
        let marker = format!("PROBE_{label}:HELLO");
        wait_for_bytes(
            &child.rx,
            &mut transcript,
            marker.as_bytes(),
            Duration::from_secs(10),
        )
        .expect("mixed-mode probe rendered");
        let slice = &transcript[before..];
        let probe = format!("PROBE_{label}:HELLO");
        let after_probe = bytes_after_marker(slice, probe.as_bytes()).unwrap_or_default();
        assert!(
            !contains_kitty_csi_u_payload(after_probe),
            "Kitty payload leaked after TUI {label} probe:\n{}",
            escaped(after_probe)
        );
    }

    write(&child.input, b"\x1b[92;5u").expect("send Kitty CSI-u detach hotkey");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"detach",
        Duration::from_secs(5),
    )
    .expect("attach control mode recognized Kitty detach hotkey");
    write(&child.input, b"d").expect("confirm detach");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"HOST_AFTER_DETACH",
        Duration::from_secs(10),
    )
    .expect("host shell reached post-detach marker");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));

    let status = child.process.wait().expect("wait host shell");
    assert!(
        status.success(),
        "host shell failed after mixed-mode detach: {status}; transcript:\n{}",
        escaped(&transcript)
    );
    assert_cleanup_before_marker(&transcript, b"HOST_AFTER_DETACH", EXTENDED_CLEANUP);
    let before_detach =
        bytes_before_marker(&transcript, b"HOST_AFTER_DETACH").unwrap_or(&transcript);
    assert!(
        !contains_subslice(before_detach, b"\x1bc"),
        "normal detach emitted emergency RIS:\n{}",
        escaped(before_detach)
    );
}

#[test]
fn symptom3_live_disconnect_window_has_no_cleanup_until_final_detach() {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let session = unique_session("tuistory-symptom3-live-window");
    let host_script = r#"
set +e
export PS1='SYM3-WINDOW> '
"$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- /bin/bash --noprofile --norc -i
status=$?
printf '\nHOST_AFTER_DETACH status=%s\n' "$status"
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
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");
    let mut transcript = Vec::new();
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"SYM3-WINDOW>",
        Duration::from_secs(10),
    )
    .expect("inner shell reached prompt");
    let live_start = transcript.len();
    write(&child.input, b"echo OK\n").expect("send live-window probe");
    wait_for_bytes(&child.rx, &mut transcript, b"OK", Duration::from_secs(10))
        .expect("live attach probe rendered");
    let live_window = &transcript[live_start..];
    for forbidden in [b"\x1b[?1049l".as_slice(), b"\x1b[<u", b"\x1b[!p", b"\x1bc"] {
        assert!(
            !contains_subslice(live_window, forbidden),
            "cleanup leaked during live attach window:\n{}",
            escaped(live_window)
        );
    }

    write(&child.input, DETACH_KEY).expect("enter attach control mode");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"detach",
        Duration::from_secs(5),
    )
    .expect("attach control mode displayed detach action");
    write(&child.input, b"d").expect("confirm detach");
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"HOST_AFTER_DETACH",
        Duration::from_secs(10),
    )
    .expect("host shell reached post-detach marker");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));
    let status = child.process.wait().expect("wait host shell");
    assert!(
        status.success(),
        "host shell failed after live-window detach: {status}; transcript:\n{}",
        escaped(&transcript)
    );
    assert_cleanup_before_marker(&transcript, b"HOST_AFTER_DETACH", EXTENDED_CLEANUP);
}

struct HostCommand {
    process: Child,
    input: OwnedFd,
    rx: mpsc::Receiver<Vec<u8>>,
}

fn initialized_portl_home(portl: &Path) -> tempfile::TempDir {
    let home = tempdir().expect("temp portl home");
    let init_status = Command::new(portl)
        .env("PORTL_HOME", home.path())
        .args(["init", "--quiet", "--force"])
        .status()
        .expect("run portl init");
    assert!(init_status.success(), "portl init failed: {init_status}");
    home
}

fn unique_session(prefix: &str) -> String {
    format!(
        "{}-{}",
        prefix,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix time")
            .as_nanos()
    )
}

fn wait_for_host_stdin(child: &HostCommand, transcript: &mut Vec<u8>) {
    if let Err(err) = wait_for_bytes(
        &child.rx,
        transcript,
        b"HOST_STDIN:",
        Duration::from_secs(10),
    ) {
        panic!(
            "host shell reached post-detach stdin probe: {err}; transcript:\n{}",
            escaped(transcript)
        );
    }
}

fn run_signal_terminated_attach(signal: Signal) -> (HostCommand, Vec<u8>) {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let session = unique_session("tuistory-symptom3-signal");
    let host_script = r#"
set +e
/bin/sh -c 'printf "ATTACH_PID=%s\n" "$$"; exec "$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty -- /bin/sh -c "printf SIGNAL_ATTACH_READY\\r\\n; sleep 30"'
status=$?
printf '\nHOST_AFTER_ATTACH status=%s\n' "$status"
printf 'HOST_READY_PROBE\n'
"$PORTL_BIN" kill "$PORTL_SESSION" --provider ghostty >/dev/null 2>&1 || true
exit 0
"#;
    let child = spawn_host_command(
        "/bin/bash",
        &["-lc", host_script],
        &[
            ("PORTL_BIN", portl.to_str().expect("portl path utf8")),
            ("PORTL_HOME", home.path().to_str().expect("home path utf8")),
            ("PORTL_SESSION", &session),
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");
    let mut transcript = Vec::new();
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"SIGNAL_ATTACH_READY",
        Duration::from_secs(10),
    )
    .expect("signal attach became live");
    let pid = attach_pid_from_transcript(&transcript);
    kill(pid, signal).expect("send signal to attach process");
    (child, transcript)
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

fn wait_for_new_bytes(
    rx: &mpsc::Receiver<Vec<u8>>,
    transcript: &mut Vec<u8>,
    start: usize,
    needle: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(chunk) => {
                transcript.extend_from_slice(&chunk);
                if contains_subslice(&transcript[start..], needle) {
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

fn bytes_before_marker<'a>(bytes: &'a [u8], marker: &[u8]) -> Option<&'a [u8]> {
    bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|idx| &bytes[..idx])
}

fn assert_cleanup_before_marker(bytes: &[u8], marker: &[u8], cleanup: &[u8]) {
    let before_marker = bytes_before_marker(bytes, marker).unwrap_or(bytes);
    assert!(
        before_marker.ends_with(cleanup)
            || contains_subslice(before_marker, cleanup)
            || cleanup_components_in_order(before_marker, cleanup),
        "expected cleanup {} before marker {} in transcript:\n{}",
        escaped(cleanup),
        escaped(marker),
        escaped(bytes)
    );
}

fn cleanup_components_in_order(bytes: &[u8], cleanup: &[u8]) -> bool {
    let mut search_from = 0;
    for component in [
        b"\x1b[0m".as_slice(),
        b"\x1b[?1049l",
        b"\x1b[r",
        b"\x1b[?7h",
        b"\x1b[!p",
        b"\x1b[?25h",
        b"\x1b[<u",
        b"\x1b[=0u",
        b"\x1b[>4;0m",
        b"\x1b[?2004l",
        b"\x1b[?1000l",
        b"\x1b[?1002l",
        b"\x1b[?1003l",
        b"\x1b[?1006l",
    ] {
        let Some(relative) = find_subslice(&bytes[search_from..], component) else {
            return false;
        };
        search_from += relative + component.len();
    }
    if cleanup.ends_with(b"\x1bc") {
        bytes[search_from..]
            .windows(b"\x1bc".len())
            .any(|window| window == b"\x1bc")
    } else {
        !bytes[search_from..]
            .windows(b"\x1bc".len())
            .any(|window| window == b"\x1bc")
    }
}

fn attach_pid_from_transcript(bytes: &[u8]) -> Pid {
    let text = String::from_utf8_lossy(bytes);
    let pid = text
        .lines()
        .find_map(|line| line.strip_prefix("ATTACH_PID="))
        .and_then(|pid| pid.trim().parse::<i32>().ok())
        .unwrap_or_else(|| {
            panic!(
                "ATTACH_PID marker missing from transcript:\n{}",
                escaped(bytes)
            )
        });
    Pid::from_raw(pid)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains_kitty_csi_u_payload(bytes: &[u8]) -> bool {
    contains_subslice(bytes, b"9;5:3u")
        || bytes
            .iter()
            .enumerate()
            .any(|(idx, byte)| byte.is_ascii_digit() && csi_u_payload_len(&bytes[idx..]).is_some())
}

fn csi_u_payload_len(bytes: &[u8]) -> Option<usize> {
    let mut idx = 0;
    if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
        return None;
    }
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    while idx < bytes.len() && bytes[idx] == b';' {
        idx += 1;
        if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
            return None;
        }
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    if idx < bytes.len() && bytes[idx] == b':' {
        idx += 1;
        if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
            return None;
        }
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    (idx < bytes.len() && bytes[idx] == b'u').then_some(idx + 1)
}

fn escaped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

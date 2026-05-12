#![cfg(all(unix, feature = "ghostty-vt"))]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, kill};
use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
use nix::unistd::Pid;
use nix::unistd::{dup, read, write};
use tempfile::tempdir;

use iroh_tickets::Ticket;
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};

const DETACH_KEY: &[u8] = b"\x1c";
const STANDIN_TUI: &str = "saved=$(stty -g); stty raw -echo; printf 'TUI-BEGIN\\r\\n'; printf '\\033[c\\033[>c\\033[?u'; printf '\\r\\nTUI-READY\\r\\n'; sleep 1; stty \"$saved\"";
const SYMPTOM2_STANDIN_TUI: &[u8] = b"saved=$(stty -g); stty raw -echo; printf 'SYM2-TUI-BEGIN\\r\\n'; printf '\\033[>1u\\033[?1049h'; printf '\\033[?1049l'; stty \"$saved\"; printf '\\r\\nSYM2-TUI-DONE\\r\\n'\n";
const DEFENSIVE_KITTY_RESET: &[u8] = b"\x1b[<u\x1b[=0u\x1b[>4;0m";
const EXTENDED_CLEANUP: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\r\n";
const EMERGENCY_CLEANUP: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\r\n\x1bc";
const PANIC_HOOK_EMERGENCY_CLEANUP: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[r\x1b[?7h\x1b[!p\x1b[?25h\x1b[<u\x1b[=0u\x1b[>4;0m\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\r\n\x1bc";
const REMOTE_TICKET_LABEL: &str = "remote-reconnect";

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
    let exit_window = &transcript[alt_leave..before_ctrl_probe];
    if !contains_subslice(exit_window, DEFENSIVE_KITTY_RESET) {
        assert!(
            !contains_subslice(&transcript[..before_ctrl_probe], b"\x1b[>1u"),
            "defensive Kitty reset was not emitted even though Kitty enable reached host:\n{}",
            escaped(exit_window)
        );
    }

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
        assert_cleanup_ends_before_marker(&transcript.1, b"HOST_AFTER_ATTACH", EMERGENCY_CLEANUP);
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
printf 'HOST_AFTER_ATTACH status=%s\n' "$status"
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
    assert_panic_cleanup_suffix_exact(&transcript, b"HOST_AFTER_ATTACH");
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
printf 'HOST_AFTER_FIRST status=%s\n' "$first_status"
"$PORTL_BIN" attach "$PORTL_SESSION" --provider ghostty
second_status=$?
printf 'HOST_AFTER_SECOND status=%s\n' "$second_status"
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
    assert_cleanup_ends_before_marker(&transcript, b"HOST_AFTER_FIRST", EMERGENCY_CLEANUP);
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
printf 'HOST_AFTER_DETACH status=%s\n' "$status"
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

    for (label, script, expected_cleanup) in [
        (
            "A",
            "printf '\\033[?1049hTUI_A\\033[?1049l\\r\\nPROBE_A:HELLO\\r\\n'\n",
            vec![b"\x1b[?1049l".as_slice()],
        ),
        (
            "B",
            "printf '\\033[>1uTUI_B\\033[<u\\r\\nPROBE_B:HELLO\\r\\n'\n",
            vec![b"\x1b[<u".as_slice()],
        ),
        (
            "C",
            "printf '\\033[?1000h\\033[?1002h\\033[?1003h\\033[?1006hTUI_C\\033[?1000l\\033[?1002l\\033[?1003l\\033[?1006l\\r\\nPROBE_C:HELLO\\r\\n'\n",
            vec![
                b"\x1b[?1000l".as_slice(),
                b"\x1b[?1002l",
                b"\x1b[?1003l",
                b"\x1b[?1006l",
            ],
        ),
        (
            "D",
            "printf '\\033[>1u\\033[?1049h\\033[?1000h\\033[?1002h\\033[?1003h\\033[?1006h\\033[?2004h\\033[>4;2m\\033[?7l\\033[5;20rTUI_D\\033[?1049l\\r\\nPROBE_D:HELLO\\r\\n'\n",
            vec![
                b"\x1b[<u".as_slice(),
                b"\x1b[=0u",
                b"\x1b[>4;0m",
                b"\x1b[?2004l",
                b"\x1b[?1000l",
                b"\x1b[?1002l",
                b"\x1b[?1003l",
                b"\x1b[?1006l",
                b"\x1b[?7h",
                b"\x1b[r",
            ],
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
        drain_for(&child.rx, &mut transcript, Duration::from_millis(250));
        let slice = &transcript[before..];
        let probe = format!("PROBE_{label}:HELLO");
        for cleanup in expected_cleanup {
            if !contains_subslice(slice, cleanup) {
                assert!(
                    is_server_stripped_kitty_stack_cleanup(cleanup, slice),
                    "expected targeted cleanup {} after TUI {label} exit:\n{}",
                    escaped(cleanup),
                    escaped(slice)
                );
            }
        }
        let after_probe = bytes_after_marker(slice, probe.as_bytes()).unwrap_or_default();
        assert!(
            !contains_subslice(after_probe, b"9;5:3u"),
            "Kitty keypress payload leaked after TUI {label} probe:\n{}",
            escaped(after_probe)
        );
        let echo_probe = format!("echo HELLO_{label}\n");
        let echo_marker = format!("HELLO_{label}");
        let echo_start = transcript.len();
        write(&child.input, echo_probe.as_bytes()).expect("send prompt usability probe");
        wait_for_bytes(
            &child.rx,
            &mut transcript,
            echo_marker.as_bytes(),
            Duration::from_secs(10),
        )
        .expect("prompt usability probe rendered");
        let echo_slice = &transcript[echo_start..];
        assert_eq!(
            echo_slice
                .windows(echo_marker.len())
                .filter(|window| *window == echo_marker.as_bytes())
                .count(),
            1,
            "prompt probe should echo cleanly once after TUI {label}:\n{}",
            escaped(echo_slice)
        );
        assert!(
            !contains_kitty_csi_u_payload(echo_slice),
            "Kitty payload leaked during prompt probe after TUI {label}:\n{}",
            escaped(echo_slice)
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
printf 'HOST_AFTER_DETACH status=%s\n' "$status"
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

#[test]
fn symptom3_sighup_during_reconnect_wait_emits_terminal_cleanup() {
    let transcript = run_reconnect_fixture("sighup-wait", Some(Signal::SIGHUP));

    assert!(
        contains_subslice(&transcript, b"HOST_READY_PROBE"),
        "host shell did not recover after reconnect-wait SIGHUP:\n{}",
        escaped(&transcript)
    );
    let after_wait_marker =
        bytes_after_marker(&transcript, b"RECONNECT_WAIT_READY").expect("reconnect wait marker");
    let cleanup_start = find_subslice(after_wait_marker, EMERGENCY_CLEANUP)
        .expect("emergency cleanup after reconnect wait");
    assert_no_cleanup_leaked(&after_wait_marker[..cleanup_start]);
    assert_cleanup_ends_before_marker(
        &transcript,
        b"HOST_AFTER_RECONNECT_FIXTURE",
        EMERGENCY_CLEANUP,
    );
}

#[test]
fn symptom3_sigterm_during_reconnect_connect_attempt_emits_terminal_cleanup() {
    let transcript = run_reconnect_fixture("signal-connect-attempt", Some(Signal::SIGTERM));

    assert!(
        contains_subslice(&transcript, b"HOST_READY_PROBE"),
        "host shell did not recover after reconnect-attempt SIGTERM:\n{}",
        escaped(&transcript)
    );
    let after_attempt_marker = bytes_after_marker(&transcript, b"RECONNECT_CONNECT_ATTEMPT_READY")
        .expect("reconnect connect-attempt marker");
    let cleanup_start = find_subslice(after_attempt_marker, EMERGENCY_CLEANUP)
        .expect("emergency cleanup after reconnect connect attempt");
    assert_no_cleanup_leaked(&after_attempt_marker[..cleanup_start]);
    assert_cleanup_ends_before_marker(
        &transcript,
        b"HOST_AFTER_RECONNECT_FIXTURE",
        EMERGENCY_CLEANUP,
    );
}

#[test]
fn symptom3_reconnect_budget_exhaustion_emits_cleanup_without_ris() {
    let transcript = run_reconnect_fixture("exhausted", None);

    assert!(
        contains_subslice(&transcript, b"HOST_AFTER_RECONNECT_FIXTURE status=1"),
        "fixture did not exit with reconnect exhaustion status:\n{}",
        escaped(&transcript)
    );
    assert_cleanup_ends_before_marker(
        &transcript,
        b"HOST_AFTER_RECONNECT_FIXTURE",
        EXTENDED_CLEANUP,
    );
    let before_marker =
        bytes_before_marker(&transcript, b"HOST_AFTER_RECONNECT_FIXTURE").unwrap_or(&transcript);
    assert!(
        !contains_subslice(before_marker, b"\x1bc"),
        "reconnect-budget exhaustion emitted emergency RIS:\n{}",
        escaped(before_marker)
    );
}

#[test]
fn symptom3_successful_reconnect_window_has_no_cleanup_leak() {
    let transcript = run_reconnect_fixture("transient", None);

    let reconnect_window = bytes_between_markers(
        &transcript,
        b"DISCONNECT_WINDOW_BEGIN",
        b"RECONNECT_SUCCESS",
    )
    .expect("transient reconnect window markers");
    assert_no_cleanup_leaked(reconnect_window);
    let live_after_reconnect = bytes_between_markers(
        &transcript,
        b"RECONNECT_SUCCESS",
        b"HOST_AFTER_RECONNECT_FIXTURE",
    )
    .expect("post-reconnect fixture markers");
    assert!(
        contains_subslice(live_after_reconnect, b"OK"),
        "post-reconnect prompt probe did not render cleanly:\n{}",
        escaped(live_after_reconnect)
    );
    assert_cleanup_ends_before_marker(
        &transcript,
        b"HOST_AFTER_RECONNECT_FIXTURE",
        EXTENDED_CLEANUP,
    );
}

struct HostCommand {
    process: Child,
    input: OwnedFd,
    rx: mpsc::Receiver<Vec<u8>>,
}

struct RemoteReconnectAgent {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
    _temp: tempfile::TempDir,
}

impl Drop for RemoteReconnectAgent {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

mod two_host_fixture {
    use super::*;

    static GHOSTTY_ROOT_ENV_LOCK: Mutex<()> = Mutex::new(());

    const DA1_QUERY: &[u8] = b"\x1b[c";
    const DA2_QUERY: &[u8] = b"\x1b[>c";
    const KITTY_QUERY: &[u8] = b"\x1b[?u";
    const KITTY_PUSH_QUERY: &[u8] = b"\x1b[>1u";
    const KITTY_SET_QUERY: &[u8] = b"\x1b[=2u";
    const KITTY_POP_QUERY: &[u8] = b"\x1b[<u";
    const CPR_QUERY: &[u8] = b"\x1b[6n";
    const SYMPTOM1_QUERIES: &[u8] = b"\x1b[c\x1b[>c\x1b[?u\x1b[>1u\x1b[=2u\x1b[<u\x1b[6n";
    const DROID_STARTUP_QUERIES: &[u8] = b"\x1b[c\x1b[>c\x1b[?u\x1b[6n";
    const GHOSTTY_DA1: &[u8] = b"\x1b[?62;52;c";
    const GHOSTTY_DA2: &[u8] = b"\x1b[>1;100;0c";
    const GHOSTTY_KITTY: &[u8] = b"\x1b[?0u";
    const GHOSTTY_CPR: &[u8] = b"\x1b[10;5R";
    const SAFE_STDIN_MARKER: &[u8] = b"SAFE_STDIN_MARKER\n";
    const BOX_DRAWING_DONE: &[u8] = b"E2E_BOX_DONE";

    #[derive(Debug, Clone, Copy)]
    enum E2eProvider {
        Ghostty,
        Zmx,
        Tmux,
        Raw,
    }

    impl E2eProvider {
        const ALL: [Self; 4] = [Self::Ghostty, Self::Zmx, Self::Tmux, Self::Raw];

        fn name(self) -> &'static str {
            match self {
                Self::Ghostty => "ghostty",
                Self::Zmx => "zmx",
                Self::Tmux => "tmux",
                Self::Raw => "raw",
            }
        }

        fn attach_provider(self) -> &'static str {
            match self {
                Self::Ghostty => "ghostty",
                Self::Raw => "raw",
                Self::Zmx => "zmx",
                Self::Tmux => "tmux",
            }
        }
    }

    #[test]
    fn fake_host_side_pty_answers_da1_like_ghostty() {
        let size = nix::libc::winsize {
            ws_row: 24,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let nix::pty::OpenptyResult { master, slave } =
            nix::pty::openpty(Some(&size), None).expect("open client-wrapper pty");
        set_raw(&slave);
        let input = dup(&master).expect("duplicate wrapper master for answer-back input");
        let slave_write = dup(&slave).expect("duplicate wrapper slave for host output stimulus");
        let host_rx = spawn_reader(master);
        let stdin_rx = spawn_reader(slave);
        let answer = spawn_fake_host_answerback(
            host_rx,
            input,
            vec![(DA1_QUERY.to_vec(), GHOSTTY_DA1.to_vec())],
        );

        write(&slave_write, DA1_QUERY).expect("write DA1 onto fake host-bound output");
        let mut answered = Vec::new();
        wait_for_bytes(
            &stdin_rx,
            &mut answered,
            GHOSTTY_DA1,
            Duration::from_millis(500),
        )
        .expect("fake Ghostty answer-back should reach wrapper stdin");
        assert!(
            contains_subslice(&answered, GHOSTTY_DA1),
            "DA1 answer-back missing from wrapper stdin tap:\n{}",
            escaped(&answered)
        );
        drop(slave_write);
        let _ = answer.join();
    }

    #[test]
    fn real_attach_fixture_roundtrips_payloads_and_keeps_taps_separate() {
        let mut fixture = TwoHostFixture::spawn("printf 'VIS'; sleep 30");
        wait_for_bytes(
            &fixture.child.rx,
            &mut fixture.host_bound,
            b"VIS",
            Duration::from_secs(10),
        )
        .expect("host-bound output tap sees guest payload");

        write(&fixture.child.input, b"INV").expect("write client-wrapper stdin payload");
        let wire = fixture.wait_for_wire_bytes(b"INV", Duration::from_secs(10));
        assert!(
            contains_subslice(&fixture.host_bound, b"VIS"),
            "host-bound tap missing VIS:\n{}",
            escaped(&fixture.host_bound)
        );
        assert!(
            !contains_subslice(&fixture.host_bound, b"INV"),
            "host-bound tap captured wire-bound input bytes:\n{}",
            escaped(&fixture.host_bound)
        );
        assert!(
            contains_subslice(&wire, b"INV"),
            "wire-bound tap missing INV:\n{}",
            escaped(&wire)
        );
        assert!(
            !contains_subslice(&wire, b"VIS"),
            "wire-bound tap captured host-bound output bytes:\n{}",
            escaped(&wire)
        );
        fixture.detach();
    }

    #[test]
    fn wire_bound_tap_records_arbitrary_stdin_bytes_in_order() {
        let mut fixture = TwoHostFixture::spawn("sleep 30");
        let payload = b"abc plain input def";
        write(&fixture.child.input, payload).expect("write client-wrapper stdin payload");
        let wire = fixture.wait_for_wire_bytes(payload, Duration::from_secs(10));
        assert!(
            contains_subslice(&wire, payload),
            "wire-bound tap did not preserve payload in order:\n{}",
            escaped(&wire)
        );
        fixture.detach();
    }

    #[test]
    fn e2e_symptom1_ghostty_provider_strips_host_answerbacks_from_wire() {
        assert_symptom1_provider_wire_clean(E2eProvider::Ghostty);
    }

    #[test]
    fn e2e_symptom1_zmx_provider_strips_host_answerbacks_from_wire() {
        assert_symptom1_provider_wire_clean(E2eProvider::Zmx);
    }

    #[test]
    fn e2e_symptom1_tmux_provider_strips_host_answerbacks_from_wire() {
        assert_symptom1_provider_wire_clean(E2eProvider::Tmux);
    }

    #[test]
    fn e2e_symptom1_raw_provider_strips_host_answerbacks_from_wire() {
        assert_symptom1_provider_wire_clean(E2eProvider::Raw);
    }

    #[test]
    fn e2e_symptom1_droid_startup_shape_is_clean_on_host_and_wire_for_all_providers() {
        for provider in E2eProvider::ALL {
            let mut fixture = TwoHostFixture::spawn_provider(provider, DROID_STARTUP_QUERIES);
            fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
            fixture.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY]);
            let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));

            assert_no_query_bytes(&fixture.host_bound, provider.name());
            assert_no_response_bytes(&wire, provider.name());
            fixture.detach();
        }
    }

    #[test]
    fn e2e_defense_in_depth_layers_are_independently_clean() {
        assert_m1_disabled_m2_catches_leak();
        assert_m2_disabled_m1_prevents_answerback();
    }

    #[test]
    fn e2e_m1_disabled_m2_catches_leak() {
        assert_m1_disabled_m2_catches_leak();
    }

    #[test]
    fn e2e_m2_disabled_m1_prevents_answerback() {
        assert_m2_disabled_m1_prevents_answerback();
    }

    #[test]
    fn e2e_defense_in_depth_multi_attach_detach_stays_wire_clean() {
        let shared = SharedTwoHostSession::spawn(E2eProvider::Zmx, DROID_STARTUP_QUERIES);
        let mut first = shared.attach_client("first");
        first.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
        let mut second = shared.attach_client("second");
        second.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
        first.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY, GHOSTTY_CPR]);
        second.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY, GHOSTTY_CPR]);

        let first_wire = first.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));
        let second_wire = second.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));
        assert_no_response_bytes(&first_wire, "multi-attach-first-before-detach");
        assert_no_response_bytes(&second_wire, "multi-attach-second-before-detach");

        second.detach();
        first.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_KITTY, GHOSTTY_CPR]);
        let first_wire_after_detach =
            first.wait_for_wire_occurrences(SAFE_STDIN_MARKER, 2, Duration::from_secs(10));
        assert_no_response_bytes(&first_wire_after_detach, "multi-attach-first-after-detach");
        first.detach();
    }

    #[test]
    fn e2e_dos_query_burst_is_bounded_linear_and_wire_clean() {
        for provider in [E2eProvider::Zmx, E2eProvider::Raw] {
            assert_dos_query_burst(provider);
        }
    }

    #[test]
    fn e2e_reload_utf8_box_drawing_grid_survives_reload() {
        let expected = full_box_drawing_block();
        let mut fixture =
            TwoHostFixture::spawn_ghostty_script(&box_drawing_reload_script(&expected));
        fixture.wait_for_host_marker_with_answerback(BOX_DRAWING_DONE, Duration::from_secs(10));

        fixture.trigger_reload();
        fixture.wait_for_host_occurrences_with_answerback(
            BOX_DRAWING_DONE,
            2,
            Duration::from_secs(10),
        );
        drain_for(
            &fixture.child.rx,
            &mut fixture.host_bound,
            Duration::from_millis(250),
        );

        let grid = TerminalGrid::parse(&fixture.host_bound);
        let actual: Vec<char> = grid
            .row_chars(0)
            .into_iter()
            .take(64)
            .chain(grid.row_chars(1))
            .take(expected.len())
            .collect();
        assert_eq!(
            actual,
            expected,
            "post-reload grid did not preserve the full box-drawing block:\n{}",
            grid.render_text()
        );
        let rendered = grid.render_text().into_bytes();
        assert_no_utf8_damage(&rendered, "box-drawing post-reload grid");
        assert_eq!(
            count_subslice(&fixture.host_bound, BOX_DRAWING_DONE),
            2,
            "reload should produce exactly one post-reload box-drawing screen:\n{}",
            escaped(&fixture.host_bound)
        );
        fixture.detach();
    }

    #[test]
    fn e2e_reload_during_live_stream() {
        let mut fixture = TwoHostFixture::spawn_ghostty_script(&live_streaming_reload_script());
        fixture.wait_for_host_marker_with_answerback(b"LIVE_READY:003", Duration::from_secs(10));
        let pre_reload_grid = TerminalGrid::parse(&fixture.host_bound);
        let pre_reload_frame = pre_reload_grid
            .line(0)
            .strip_prefix("FRAME:")
            .and_then(|line| line.get(..3))
            .expect("pre-reload grid contains frame header")
            .to_owned();
        let before_reload = fixture.host_bound.len();

        fixture.trigger_reload();
        let reload_command_done = fixture.host_bound.len();
        let reload_command_paints =
            live_full_screen_paints(&fixture.host_bound[before_reload..reload_command_done]);
        assert!(
            reload_command_paints.is_empty(),
            "LiveOutput frame painted during reload command window after pre-reload frame {pre_reload_frame}: {reload_command_paints:?}\n{}",
            escaped(&fixture.host_bound[before_reload..reload_command_done])
        );
        fixture.wait_for_host_marker_with_answerback(b"LIVE_READY:010", Duration::from_secs(10));
        drain_for(
            &fixture.child.rx,
            &mut fixture.host_bound,
            Duration::from_millis(250),
        );
        let paint_events = read_paint_events(&fixture.paint_event_tap);
        assert_true_reload_window_has_no_live_paints(&paint_events);
        assert_single_post_reload_viewport_without_dedup_overlap(&paint_events);

        let post_reload_paints =
            live_full_screen_paints(&fixture.host_bound[reload_command_done..]);
        assert!(
            !post_reload_paints.is_empty(),
            "expected paint-tracking tap to observe a post-reload full-screen paint:\n{}",
            escaped(&fixture.host_bound[reload_command_done..])
        );
        assert!(
            post_reload_paints.iter().all(|paint| paint.coherent),
            "paint-tracking tap observed torn post-reload paint(s): {post_reload_paints:?}\n{}",
            escaped(&fixture.host_bound[reload_command_done..])
        );
        let observations = live_frame_observations(&fixture.host_bound[before_reload..]);
        assert!(
            !observations.is_empty(),
            "expected at least one post-reload live frame observation:\n{}",
            escaped(&fixture.host_bound[before_reload..])
        );
        for observation in &observations {
            assert!(
                observation.coherent,
                "post-reload live TUI frame was torn/interleaved: {observation:?}\n{}",
                escaped(&fixture.host_bound[before_reload..])
            );
        }
        let final_grid = TerminalGrid::parse(&fixture.host_bound);
        let final_frame = final_grid
            .line(0)
            .strip_prefix("FRAME:")
            .and_then(|line| line.get(..3))
            .expect("final grid contains frame header")
            .to_owned();
        for prefix in ["ROWA:", "ROWB:", "LIVE_READY:"] {
            let line = final_grid
                .lines()
                .into_iter()
                .find(|line| line.starts_with(prefix))
                .unwrap_or_else(|| {
                    panic!(
                        "final grid missing {prefix} line:\n{}",
                        final_grid.render_text()
                    )
                });
            assert!(
                line.contains(&final_frame),
                "final grid line {line:?} did not match frame {final_frame}:\n{}",
                final_grid.render_text()
            );
        }
        assert_eq!(
            post_reload_paints.last().map(|paint| paint.frame.as_str()),
            Some(final_frame.as_str()),
            "post-reload grid was not byte-identical to the most recent tracked live paint: paints={post_reload_paints:?}\n{}",
            final_grid.render_text()
        );
        fixture.detach();
    }

    #[test]
    fn cross_area_da_da2_kitty_queries_produce_zero_wire_response_bytes_for_all_providers() {
        for provider in E2eProvider::ALL {
            let mut fixture = TwoHostFixture::spawn_provider(provider, DROID_STARTUP_QUERIES);
            fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
            fixture.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY]);
            let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));

            assert_no_response_bytes(&wire, provider.name());
            fixture.detach();
        }
    }

    #[test]
    fn cross_area_realistic_ghostty_62_52_answerback_never_leaks_to_wire() {
        let mut fixture =
            TwoHostFixture::spawn_provider(E2eProvider::Ghostty, DROID_STARTUP_QUERIES);
        fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
        fixture.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY]);
        let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));

        assert_no_response_bytes(&wire, "cross-realistic-ghostty-answerback");
        fixture.detach();
    }

    #[test]
    fn cross_area_sanitizer_and_responder_compose_across_startup_split_boundaries() {
        let chunks = startup_split_matrix_chunks();
        let mut fixture = TwoHostFixture::spawn_provider_chunks(E2eProvider::Zmx, &chunks);
        drain_for(
            &fixture.child.rx,
            &mut fixture.host_bound,
            Duration::from_secs(2),
        );
        fixture.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY, GHOSTTY_CPR]);
        let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));

        assert_no_response_bytes(&wire, "zmx split matrix");
        fixture.detach();
    }

    #[test]
    #[should_panic(expected = "bare ;52;c")]
    fn cross_area_assert_no_response_bytes_rejects_bare_ghostty_payload_tail() {
        assert_no_response_bytes(b"safe ;52;c unsafe", "bare-tail-regression");
    }

    #[test]
    fn cross_area_dsr_cpr_response_payloads_never_reach_wire_tap() {
        for provider in E2eProvider::ALL {
            let mut fixture = TwoHostFixture::spawn_provider(provider, CPR_QUERY);
            fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
            fixture.inject_ghostty_answers(&[GHOSTTY_CPR]);
            let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));

            assert_no_cpr_response_payloads(&wire, provider.name());
            assert_no_response_bytes(&wire, provider.name());
            fixture.detach();
        }
    }

    #[test]
    fn cross_area_droid_cli_shaped_attach_lifecycle_stays_wire_clean_through_detach() {
        let mut fixture = TwoHostFixture::spawn_provider_chunks(
            E2eProvider::Ghostty,
            &[
                b"\x1b[?1049h\x1b[2J\x1b[HDroid CLI\r\n> ".to_vec(),
                DROID_STARTUP_QUERIES.to_vec(),
                b"\r\nE2E_READY\r\n".to_vec(),
            ],
        );
        fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
        fixture.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY, GHOSTTY_CPR]);
        let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));
        assert_no_response_bytes(&wire, "ghostty droid lifecycle");

        fixture.detach();
        let final_wire = fs::read(&fixture.wire_tap).unwrap_or_default();
        assert_no_response_bytes(&final_wire, "ghostty droid lifecycle");
    }

    fn assert_symptom1_provider_wire_clean(provider: E2eProvider) {
        let mut fixture = TwoHostFixture::spawn_provider(provider, SYMPTOM1_QUERIES);
        fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
        fixture.inject_ghostty_answers(&[GHOSTTY_DA1, GHOSTTY_DA2, GHOSTTY_KITTY, GHOSTTY_CPR]);
        let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));

        assert_no_query_bytes(&fixture.host_bound, provider.name());
        assert_no_response_bytes(&wire, provider.name());
        fixture.detach();
    }

    fn assert_m1_disabled_m2_catches_leak() {
        let mut fixture = TwoHostFixture::spawn_provider_with_options(
            E2eProvider::Raw,
            SYMPTOM1_QUERIES,
            SpawnOptions {
                disable_server_query_strip: true,
                disable_client_query_strip: false,
            },
        );
        fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
        let host_raw = fs::read(&fixture.host_raw_output_tap).unwrap_or_default();
        for query in [
            DA1_QUERY,
            DA2_QUERY,
            CPR_QUERY,
            KITTY_QUERY,
            KITTY_PUSH_QUERY,
            KITTY_SET_QUERY,
            KITTY_POP_QUERY,
        ] {
            assert!(
                contains_subslice(&host_raw, query),
                "M1-disabled positive control did not observe host-bound query {} in raw real attach output:\n{}",
                escaped(query),
                escaped(&host_raw)
            );
        }
        fixture.inject_ghostty_answers(&[
            GHOSTTY_DA1,
            GHOSTTY_DA2,
            GHOSTTY_CPR,
            GHOSTTY_KITTY,
            GHOSTTY_KITTY,
            GHOSTTY_KITTY,
            GHOSTTY_KITTY,
        ]);
        let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));
        assert_no_response_bytes(&wire, "m1-disabled-m2-active");
        fixture.detach();
    }

    fn assert_m2_disabled_m1_prevents_answerback() {
        let mut fixture = TwoHostFixture::spawn_provider_with_options(
            E2eProvider::Ghostty,
            SYMPTOM1_QUERIES,
            SpawnOptions {
                disable_server_query_strip: false,
                disable_client_query_strip: true,
            },
        );
        fixture.wait_for_host_marker_with_answerback(b"E2E_READY", Duration::from_secs(10));
        assert_no_query_bytes(&fixture.host_bound, "m2-disabled-m1-active-host-bound");
        fixture.inject_safe_stdin_marker();
        let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));
        assert_no_response_bytes(&wire, "m2-disabled-m1-active-wire");
        fixture.detach();
    }

    #[derive(Clone, Copy, Default)]
    struct SpawnOptions {
        disable_server_query_strip: bool,
        disable_client_query_strip: bool,
    }

    struct TwoHostFixture {
        child: HostCommand,
        host_bound: Vec<u8>,
        wire_tap: std::path::PathBuf,
        host_raw_output_tap: std::path::PathBuf,
        paint_event_tap: std::path::PathBuf,
        _home: tempfile::TempDir,
        _agent: RemoteReconnectAgent,
        _provider_temp: tempfile::TempDir,
        _ghostty_roots: Option<GhosttyRootGuard>,
    }

    struct SharedTwoHostSession {
        portl: std::path::PathBuf,
        home: tempfile::TempDir,
        session: String,
        provider: E2eProvider,
        _agent: RemoteReconnectAgent,
        _provider_temp: tempfile::TempDir,
    }

    impl SharedTwoHostSession {
        fn spawn(provider: E2eProvider, guest_queries: &[u8]) -> Self {
            assert!(matches!(provider, E2eProvider::Zmx));
            let portl = assert_cmd::cargo::cargo_bin("portl");
            let home = initialized_portl_home(&portl);
            let provider_temp = tempdir().expect("temp shared provider");
            let provider_path = provider_temp.path().join("zmx");
            write_fake_zmx_shared_provider(&provider_path, guest_queries)
                .expect("write shared fake zmx provider");
            let agent = start_remote_reconnect_agent_with_temp(
                &portl,
                home.path(),
                Some(provider_path),
                provider_temp,
            );
            let session = unique_session("two-host-shared");
            let provider_temp = tempdir().expect("temp shared holder");
            Self {
                portl,
                home,
                session,
                provider,
                _agent: agent,
                _provider_temp: provider_temp,
            }
        }

        fn attach_client(&self, label: &str) -> SharedTwoHostClient {
            self.attach_client_with_command(label, None)
        }

        fn attach_client_with_command(
            &self,
            label: &str,
            command: Option<String>,
        ) -> SharedTwoHostClient {
            let wire_tap = self
                .home
                .path()
                .join(format!("wire-bound-input-{label}.tap"));
            let host_script = r#"
set +e
if [ -n "${PORTL_ATTACH_COMMAND:-}" ]; then
  eval "\"$PORTL_BIN\" attach \"$PORTL_SESSION\" --target \"$PORTL_TARGET_LABEL\" --provider \"$PORTL_PROVIDER\" -- $PORTL_ATTACH_COMMAND"
else
  "$PORTL_BIN" attach "$PORTL_SESSION" --target "$PORTL_TARGET_LABEL" --provider "$PORTL_PROVIDER"
fi
status=$?
printf 'HOST_AFTER_ATTACH status=%s\n' "$status"
exit 0
"#;
            let attach_command = command.unwrap_or_default();
            let child = spawn_host_command(
                "/bin/bash",
                &["-lc", host_script],
                &[
                    ("PORTL_BIN", self.portl.to_str().expect("portl path utf8")),
                    (
                        "PORTL_HOME",
                        self.home.path().to_str().expect("home path utf8"),
                    ),
                    ("PORTL_SESSION", &self.session),
                    ("PORTL_TARGET_LABEL", REMOTE_TICKET_LABEL),
                    ("PORTL_PROVIDER", self.provider.attach_provider()),
                    ("PORTL_ATTACH_COMMAND", &attach_command),
                    (
                        "PORTL_TEST_ATTACH_STDIN_TAP",
                        wire_tap.to_str().expect("tap path utf8"),
                    ),
                    ("TERM", "xterm-kitty"),
                    ("RUST_LOG", "off"),
                ],
            )
            .expect("spawn shared two-host attach wrapper");
            SharedTwoHostClient {
                child,
                host_bound: Vec::new(),
                wire_tap,
            }
        }
    }

    struct SharedTwoHostClient {
        child: HostCommand,
        host_bound: Vec<u8>,
        wire_tap: std::path::PathBuf,
    }

    impl SharedTwoHostClient {
        fn wait_for_host_marker_with_answerback(&mut self, marker: &[u8], timeout: Duration) {
            let deadline = Instant::now() + timeout;
            let mut answered = [false; 4];
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match self
                    .child
                    .rx
                    .recv_timeout(remaining.min(Duration::from_millis(100)))
                {
                    Ok(chunk) => {
                        self.host_bound.extend_from_slice(&chunk);
                        answer_queries_once(&self.host_bound, &self.child.input, &mut answered);
                        if contains_subslice(&self.host_bound, marker) {
                            return;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            panic!(
                "timed out waiting for shared host marker {}; host-bound:\n{}",
                escaped(marker),
                escaped(&self.host_bound)
            );
        }

        fn inject_ghostty_answers(&self, answers: &[&[u8]]) {
            for answer in answers {
                write(&self.child.input, answer).expect("inject fake Ghostty answer-back");
            }
            write(&self.child.input, SAFE_STDIN_MARKER).expect("inject safe stdin marker");
        }

        fn wait_for_wire_bytes(&self, needle: &[u8], timeout: Duration) -> Vec<u8> {
            self.wait_for_wire_occurrences(needle, 1, timeout)
        }

        fn wait_for_wire_occurrences(
            &self,
            needle: &[u8],
            occurrences: usize,
            timeout: Duration,
        ) -> Vec<u8> {
            let deadline = Instant::now() + timeout;
            loop {
                let bytes = fs::read(&self.wire_tap).unwrap_or_default();
                if count_subslice(&bytes, needle) >= occurrences {
                    return bytes;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for shared wire tap {}; tap:\n{}",
                    escaped(needle),
                    escaped(&bytes)
                );
                thread::sleep(Duration::from_millis(25));
            }
        }

        fn detach(&mut self) {
            drain_for(
                &self.child.rx,
                &mut self.host_bound,
                Duration::from_millis(250),
            );
            if let Some(status) = self.child.process.try_wait().expect("poll shared wrapper") {
                assert!(
                    status.success(),
                    "shared host wrapper failed: {status}; transcript:\n{}",
                    escaped(&self.host_bound)
                );
                return;
            }
            write(&self.child.input, DETACH_KEY).expect("enter attach control mode");
            wait_for_bytes(
                &self.child.rx,
                &mut self.host_bound,
                b"detach",
                Duration::from_secs(5),
            )
            .expect("shared attach control mode displayed detach action");
            write(&self.child.input, b"d").expect("confirm shared detach");
            wait_for_bytes(
                &self.child.rx,
                &mut self.host_bound,
                b"HOST_AFTER_ATTACH",
                Duration::from_secs(10),
            )
            .expect("shared host wrapper exited after detach");
            let status = self.child.process.wait().expect("wait shared wrapper");
            assert!(
                status.success(),
                "shared host wrapper failed: {status}; transcript:\n{}",
                escaped(&self.host_bound)
            );
        }
    }

    struct GhosttyRootGuard {
        _lock: MutexGuard<'static, ()>,
        previous_runtime: Option<OsString>,
        previous_state: Option<OsString>,
        previous_helper: Option<OsString>,
        previous_disable_server: Option<OsString>,
        _temp: tempfile::TempDir,
    }

    impl GhosttyRootGuard {
        #[allow(unsafe_code)]
        fn new_with_server_strip_disabled(helper_exe: &Path, disable_server_strip: bool) -> Self {
            let lock = GHOSTTY_ROOT_ENV_LOCK
                .lock()
                .expect("ghostty env lock poisoned");
            let temp = tempfile::Builder::new()
                .prefix("pgt-")
                .tempdir_in("/tmp")
                .expect("temp ghostty roots");
            let runtime = temp.path().join("r");
            let state = temp.path().join("s");
            fs::create_dir_all(&runtime).expect("create isolated ghostty runtime root");
            fs::create_dir_all(&state).expect("create isolated ghostty state root");
            let previous_runtime = std::env::var_os("PORTL_GHOSTTY_RUNTIME_DIR");
            let previous_state = std::env::var_os("PORTL_GHOSTTY_STATE_DIR");
            let previous_helper = std::env::var_os("PORTL_GHOSTTY_HELPER_EXE");
            let previous_disable_server =
                std::env::var_os("PORTL_TEST_FORCE_DISABLE_SERVER_QUERY_STRIP");
            unsafe {
                std::env::set_var("PORTL_GHOSTTY_RUNTIME_DIR", &runtime);
                std::env::set_var("PORTL_GHOSTTY_STATE_DIR", &state);
                std::env::set_var("PORTL_GHOSTTY_HELPER_EXE", helper_exe);
                if disable_server_strip {
                    std::env::set_var("PORTL_TEST_FORCE_DISABLE_SERVER_QUERY_STRIP", "1");
                } else {
                    std::env::remove_var("PORTL_TEST_FORCE_DISABLE_SERVER_QUERY_STRIP");
                }
            }
            Self {
                _lock: lock,
                previous_runtime,
                previous_state,
                previous_helper,
                previous_disable_server,
                _temp: temp,
            }
        }
    }

    impl Drop for GhosttyRootGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            unsafe {
                match &self.previous_runtime {
                    Some(value) => std::env::set_var("PORTL_GHOSTTY_RUNTIME_DIR", value),
                    None => std::env::remove_var("PORTL_GHOSTTY_RUNTIME_DIR"),
                }
                match &self.previous_state {
                    Some(value) => std::env::set_var("PORTL_GHOSTTY_STATE_DIR", value),
                    None => std::env::remove_var("PORTL_GHOSTTY_STATE_DIR"),
                }
                match &self.previous_helper {
                    Some(value) => std::env::set_var("PORTL_GHOSTTY_HELPER_EXE", value),
                    None => std::env::remove_var("PORTL_GHOSTTY_HELPER_EXE"),
                }
                match &self.previous_disable_server {
                    Some(value) => {
                        std::env::set_var("PORTL_TEST_FORCE_DISABLE_SERVER_QUERY_STRIP", value);
                    }
                    None => std::env::remove_var("PORTL_TEST_FORCE_DISABLE_SERVER_QUERY_STRIP"),
                }
            }
        }
    }

    impl TwoHostFixture {
        fn spawn(guest_script: &str) -> Self {
            Self::spawn_raw_script(guest_script)
        }

        fn spawn_ghostty_script(guest_script: &str) -> Self {
            Self::spawn_remote(
                E2eProvider::Ghostty,
                None,
                Some(guest_script.to_owned()),
                SpawnOptions::default(),
            )
        }

        fn spawn_provider(provider: E2eProvider, guest_queries: &[u8]) -> Self {
            Self::spawn_provider_with_options(provider, guest_queries, SpawnOptions::default())
        }

        fn spawn_provider_chunks(provider: E2eProvider, chunks: &[Vec<u8>]) -> Self {
            match provider {
                E2eProvider::Ghostty | E2eProvider::Raw => Self::spawn_remote(
                    provider,
                    None,
                    Some(format!(
                        "/bin/sh -c \"{}\"",
                        chunked_printf_shell(chunks, true)
                    )),
                    SpawnOptions::default(),
                ),
                E2eProvider::Zmx => {
                    let temp = tempdir().expect("temp zmx provider fixture");
                    let provider_path = temp.path().join("zmx");
                    write_fake_zmx_e2e_provider_chunks(&provider_path, chunks)
                        .expect("write fake zmx e2e provider");
                    Self::spawn_remote_with_temp(
                        provider,
                        Some(provider_path),
                        None,
                        temp,
                        SpawnOptions::default(),
                    )
                }
                E2eProvider::Tmux => {
                    let temp = tempdir().expect("temp tmux provider fixture");
                    let provider_path = temp.path().join("tmux");
                    write_fake_tmux_e2e_provider_chunks(&provider_path, chunks)
                        .expect("write fake tmux e2e provider");
                    Self::spawn_remote_with_temp(
                        provider,
                        Some(provider_path),
                        None,
                        temp,
                        SpawnOptions::default(),
                    )
                }
            }
        }

        fn spawn_provider_with_options(
            provider: E2eProvider,
            guest_queries: &[u8],
            options: SpawnOptions,
        ) -> Self {
            match provider {
                E2eProvider::Ghostty | E2eProvider::Raw => Self::spawn_remote(
                    provider,
                    None,
                    Some(format!(
                        "/bin/sh -c \"printf '{}E2E_READY\\r\\n'; sleep 30\"",
                        shell_escaped_printf(guest_queries)
                    )),
                    options,
                ),
                E2eProvider::Zmx => {
                    let temp = tempdir().expect("temp zmx provider fixture");
                    let provider_path = temp.path().join("zmx");
                    write_fake_zmx_e2e_provider(&provider_path, guest_queries)
                        .expect("write fake zmx e2e provider");
                    Self::spawn_remote_with_temp(provider, Some(provider_path), None, temp, options)
                }
                E2eProvider::Tmux => {
                    let temp = tempdir().expect("temp tmux provider fixture");
                    let provider_path = temp.path().join("tmux");
                    write_fake_tmux_e2e_provider(&provider_path, guest_queries)
                        .expect("write fake tmux e2e provider");
                    Self::spawn_remote_with_temp(provider, Some(provider_path), None, temp, options)
                }
            }
        }

        fn spawn_raw_script(guest_script: &str) -> Self {
            Self::spawn_remote(
                E2eProvider::Raw,
                None,
                Some(format!("/bin/sh -c {guest_script:?}")),
                SpawnOptions::default(),
            )
        }

        fn spawn_remote(
            provider: E2eProvider,
            provider_path: Option<std::path::PathBuf>,
            command: Option<String>,
            options: SpawnOptions,
        ) -> Self {
            let temp = tempdir().expect("temp provider fixture");
            Self::spawn_remote_with_temp(provider, provider_path, command, temp, options)
        }

        fn spawn_remote_with_temp(
            provider: E2eProvider,
            provider_path: Option<std::path::PathBuf>,
            command: Option<String>,
            provider_temp: tempfile::TempDir,
            options: SpawnOptions,
        ) -> Self {
            let portl = assert_cmd::cargo::cargo_bin("portl");
            let ghostty_roots = (matches!(provider, E2eProvider::Ghostty)
                || options.disable_server_query_strip)
                .then(|| {
                    GhosttyRootGuard::new_with_server_strip_disabled(
                        &portl,
                        options.disable_server_query_strip,
                    )
                });
            let home = initialized_portl_home(&portl);
            let agent =
                start_remote_reconnect_agent_with_provider_path(&portl, home.path(), provider_path);
            let session = unique_session("two-host-fixture");
            let wire_tap = home.path().join("wire-bound-input.tap");
            let host_raw_output_tap = home.path().join("host-raw-output.tap");
            let paint_event_tap = home.path().join("paint-events.tap");
            let host_script = r#"
set +e
if [ -n "${PORTL_ATTACH_COMMAND:-}" ]; then
  eval "\"$PORTL_BIN\" attach \"$PORTL_SESSION\" --target \"$PORTL_TARGET_LABEL\" --provider \"$PORTL_PROVIDER\" -- $PORTL_ATTACH_COMMAND"
else
  "$PORTL_BIN" attach "$PORTL_SESSION" --target "$PORTL_TARGET_LABEL" --provider "$PORTL_PROVIDER"
fi
status=$?
printf 'HOST_AFTER_ATTACH status=%s\n' "$status"
"$PORTL_BIN" kill "$PORTL_SESSION" --target "$PORTL_TARGET_LABEL" --provider "$PORTL_PROVIDER" >/dev/null 2>&1 || true
exit 0
"#;
            let attach_command = command.unwrap_or_default();
            let disable_client_query_strip = if options.disable_client_query_strip {
                "1"
            } else {
                ""
            };
            let child = spawn_host_command(
                "/bin/bash",
                &["-lc", host_script],
                &[
                    ("PORTL_BIN", portl.to_str().expect("portl path utf8")),
                    ("PORTL_HOME", home.path().to_str().expect("home path utf8")),
                    ("PORTL_SESSION", &session),
                    ("PORTL_TARGET_LABEL", REMOTE_TICKET_LABEL),
                    ("PORTL_PROVIDER", provider.attach_provider()),
                    ("PORTL_ATTACH_COMMAND", &attach_command),
                    (
                        "PORTL_TEST_ATTACH_STDIN_TAP",
                        wire_tap.to_str().expect("tap path utf8"),
                    ),
                    (
                        "PORTL_TEST_ATTACH_HOST_RAW_OUTPUT_TAP",
                        host_raw_output_tap
                            .to_str()
                            .expect("host raw tap path utf8"),
                    ),
                    (
                        "PORTL_TEST_ATTACH_PAINT_EVENT_TAP",
                        paint_event_tap.to_str().expect("paint tap path utf8"),
                    ),
                    (
                        "PORTL_TEST_FORCE_DISABLE_CLIENT_QUERY_STRIP",
                        disable_client_query_strip,
                    ),
                    ("TERM", "xterm-kitty"),
                    ("RUST_LOG", "off"),
                ],
            )
            .expect("spawn two-host attach wrapper");
            Self {
                child,
                host_bound: Vec::new(),
                wire_tap,
                host_raw_output_tap,
                paint_event_tap,
                _home: home,
                _agent: agent,
                _provider_temp: provider_temp,
                _ghostty_roots: ghostty_roots,
            }
        }

        fn wait_for_wire_bytes(&self, needle: &[u8], timeout: Duration) -> Vec<u8> {
            self.wait_for_wire_occurrences(needle, 1, timeout)
        }

        fn wait_for_wire_occurrences(
            &self,
            needle: &[u8],
            occurrences: usize,
            timeout: Duration,
        ) -> Vec<u8> {
            let deadline = Instant::now() + timeout;
            loop {
                let bytes = fs::read(&self.wire_tap).unwrap_or_default();
                if count_subslice(&bytes, needle) >= occurrences {
                    return bytes;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for wire tap {}; tap:\n{}",
                    escaped(needle),
                    escaped(&bytes)
                );
                thread::sleep(Duration::from_millis(25));
            }
        }

        fn wait_for_host_marker_with_answerback(&mut self, marker: &[u8], timeout: Duration) {
            let deadline = Instant::now() + timeout;
            let mut answered = [false; 4];
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match self
                    .child
                    .rx
                    .recv_timeout(remaining.min(Duration::from_millis(100)))
                {
                    Ok(chunk) => {
                        self.host_bound.extend_from_slice(&chunk);
                        answer_queries_once(&self.host_bound, &self.child.input, &mut answered);
                        if contains_subslice(&self.host_bound, marker) {
                            return;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            panic!(
                "timed out waiting for host marker {} with provider answer-back; host-bound:\n{}",
                escaped(marker),
                escaped(&self.host_bound)
            );
        }

        fn wait_for_host_occurrences_with_answerback(
            &mut self,
            marker: &[u8],
            occurrences: usize,
            timeout: Duration,
        ) {
            let deadline = Instant::now() + timeout;
            let mut answered = [false; 4];
            while Instant::now() < deadline {
                if count_subslice(&self.host_bound, marker) >= occurrences {
                    return;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                match self
                    .child
                    .rx
                    .recv_timeout(remaining.min(Duration::from_millis(100)))
                {
                    Ok(chunk) => {
                        self.host_bound.extend_from_slice(&chunk);
                        answer_queries_once(&self.host_bound, &self.child.input, &mut answered);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            panic!(
                "timed out waiting for {occurrences} occurrences of host marker {}; host-bound:\n{}",
                escaped(marker),
                escaped(&self.host_bound)
            );
        }

        fn trigger_reload(&mut self) {
            write(&self.child.input, DETACH_KEY).expect("enter attach control mode for reload");
            self.wait_for_host_marker_with_answerback(b"reload", Duration::from_secs(5));
            write(&self.child.input, b"r").expect("request attach reload");
            self.wait_for_host_marker_with_answerback(b"reload requested", Duration::from_secs(5));
        }

        fn inject_ghostty_answers(&self, answers: &[&[u8]]) {
            for answer in answers {
                write(&self.child.input, answer).expect("inject fake Ghostty answer-back");
            }
            self.inject_safe_stdin_marker();
        }

        fn inject_safe_stdin_marker(&self) {
            write(&self.child.input, SAFE_STDIN_MARKER).expect("inject safe stdin marker");
        }

        fn detach(&mut self) {
            drain_for(&self.child.rx, &mut self.host_bound, Duration::from_secs(2));
            if contains_subslice(&self.host_bound, b"HOST_AFTER_ATTACH") {
                let status = self.child.process.wait().expect("wait host wrapper");
                assert!(
                    status.success(),
                    "host wrapper failed: {status}; transcript:\n{}",
                    escaped(&self.host_bound)
                );
                return;
            }
            if let Some(status) = self.child.process.try_wait().expect("poll host wrapper") {
                assert!(
                    status.success(),
                    "host wrapper failed: {status}; transcript:\n{}",
                    escaped(&self.host_bound)
                );
                return;
            }
            write(&self.child.input, DETACH_KEY).expect("enter attach control mode");
            wait_for_bytes(
                &self.child.rx,
                &mut self.host_bound,
                b"detach",
                Duration::from_secs(5),
            )
            .expect("attach control mode displayed detach action");
            write(&self.child.input, b"d").expect("confirm detach");
            wait_for_bytes(
                &self.child.rx,
                &mut self.host_bound,
                b"HOST_AFTER_ATTACH",
                Duration::from_secs(10),
            )
            .expect("host wrapper exited after detach");
            let status = self.child.process.wait().expect("wait host wrapper");
            assert!(
                status.success(),
                "host wrapper failed: {status}; transcript:\n{}",
                escaped(&self.host_bound)
            );
        }
    }

    fn spawn_fake_host_answerback(
        rx: mpsc::Receiver<Vec<u8>>,
        input: OwnedFd,
        answers: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut seen = Vec::new();
            while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(500)) {
                seen.extend_from_slice(&chunk);
                for (query, answer) in &answers {
                    if contains_subslice(&seen, query) {
                        let _ = write(&input, answer);
                        return;
                    }
                }
            }
        })
    }

    fn answer_queries_once(seen: &[u8], input: &OwnedFd, answered: &mut [bool; 4]) {
        for (idx, (query, answer)) in [
            (DA1_QUERY, GHOSTTY_DA1),
            (DA2_QUERY, GHOSTTY_DA2),
            (KITTY_QUERY, GHOSTTY_KITTY),
            (CPR_QUERY, GHOSTTY_CPR),
        ]
        .into_iter()
        .enumerate()
        {
            if !answered[idx] && contains_subslice(seen, query) {
                write(input, answer).expect("write fake Ghostty answer-back");
                answered[idx] = true;
            }
        }
    }

    fn assert_no_query_bytes(bytes: &[u8], provider: &str) {
        for query in [
            DA1_QUERY,
            DA2_QUERY,
            KITTY_QUERY,
            KITTY_PUSH_QUERY,
            KITTY_SET_QUERY,
            KITTY_POP_QUERY,
            CPR_QUERY,
        ] {
            assert!(
                !contains_subslice(bytes, query),
                "provider {provider} leaked host-bound query {} in:\n{}",
                escaped(query),
                escaped(bytes)
            );
        }
    }

    fn assert_no_response_bytes(bytes: &[u8], provider: &str) {
        assert!(
            !contains_response_shape(bytes),
            "provider {provider} leaked response shape on wire-bound tap:\n{}",
            escaped(bytes)
        );
        assert!(
            !contains_subslice(bytes, b";52;c"),
            "provider {provider} leaked bare ;52;c payload tail on wire-bound tap:\n{}",
            escaped(bytes)
        );
        for forbidden in [
            b"0u62;52;c".as_slice(),
            b"62;52;c",
            b"?62;52;c",
            b">1;100;0c",
            b"?0u",
            b"10;5R",
            b"\x1b[?62;52;c",
            b"\x1b[>1;100;0c",
            b"\x1b[?0u",
            b"\x1b[10;5R",
        ] {
            assert!(
                !contains_subslice(bytes, forbidden),
                "provider {provider} leaked forbidden payload {} on wire-bound tap:\n{}",
                escaped(forbidden),
                escaped(bytes)
            );
        }
    }

    fn assert_no_cpr_response_payloads(bytes: &[u8], provider: &str) {
        assert!(
            !contains_cpr_payload_tail(bytes),
            "provider {provider} leaked CPR payload tail on wire-bound tap:\n{}",
            escaped(bytes)
        );
    }

    fn assert_dos_query_burst(provider: E2eProvider) {
        #[cfg(feature = "test-attach-taps")]
        portl_core::QueryStripper::reset_max_buffered_watermark_for_test();
        let sizes = [1024_usize, 100 * 1024, 10 * 1024 * 1024];
        let mut samples = Vec::new();
        let started = Instant::now();
        let mut fixture = spawn_provider_dos_fixture(provider, &sizes);
        let mut previous = started;
        for size in sizes {
            let marker = dos_marker(size);
            fixture.wait_for_host_marker_with_answerback(&marker, Duration::from_secs(30));
            let now = Instant::now();
            assert_no_query_bytes(&fixture.host_bound, provider.name());
            samples.push((size, now.saturating_duration_since(previous)));
            previous = now;
        }
        fixture.inject_safe_stdin_marker();
        let wire = fixture.wait_for_wire_bytes(SAFE_STDIN_MARKER, Duration::from_secs(10));
        assert_no_query_bytes(&wire, provider.name());
        #[cfg(feature = "test-attach-taps")]
        {
            let high_water = portl_core::QueryStripper::max_buffered_watermark_for_test();
            assert!(
                high_water <= portl_core::QueryStripper::MAX_BUFFERED,
                "provider {} actual QueryStripper high-water {high_water} exceeded bound {}",
                provider.name(),
                portl_core::QueryStripper::MAX_BUFFERED
            );
        }
        fixture.detach();

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
            "provider {} DoS timing was not linear within 3x: samples={samples:?}, ratio={ratio}",
            provider.name()
        );
    }

    fn startup_split_matrix_chunks() -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        for (shape, query) in [
            ("DA1", DA1_QUERY),
            ("DA2", DA2_QUERY),
            ("KITTY", KITTY_QUERY),
            ("KITTY_PUSH", KITTY_PUSH_QUERY),
            ("KITTY_SET", KITTY_SET_QUERY),
            ("KITTY_POP", KITTY_POP_QUERY),
            ("CPR", CPR_QUERY),
        ] {
            for split in 1..query.len() {
                chunks.push(format!("SPLIT:{shape}:{split}:").into_bytes());
                chunks.push(query[..split].to_vec());
                chunks.push(query[split..].to_vec());
                chunks.push(b"\r\n".to_vec());
            }
        }
        chunks.push(b"E2E_READY\r\n".to_vec());
        chunks
    }

    fn spawn_provider_dos_fixture(provider: E2eProvider, sizes: &[usize]) -> TwoHostFixture {
        match provider {
            E2eProvider::Ghostty | E2eProvider::Raw => TwoHostFixture::spawn_remote(
                provider,
                None,
                Some(dos_burst_shell_command(sizes)),
                SpawnOptions::default(),
            ),
            E2eProvider::Zmx => {
                let temp = tempdir().expect("temp zmx DoS provider fixture");
                let provider_path = temp.path().join("zmx");
                write_fake_zmx_dos_provider(&provider_path, sizes)
                    .expect("write fake zmx DoS provider");
                TwoHostFixture::spawn_remote_with_temp(
                    provider,
                    Some(provider_path),
                    None,
                    temp,
                    SpawnOptions::default(),
                )
            }
            E2eProvider::Tmux => {
                let temp = tempdir().expect("temp tmux DoS provider fixture");
                let provider_path = temp.path().join("tmux");
                write_fake_tmux_dos_provider(&provider_path, sizes)
                    .expect("write fake tmux DoS provider");
                TwoHostFixture::spawn_remote_with_temp(
                    provider,
                    Some(provider_path),
                    None,
                    temp,
                    SpawnOptions::default(),
                )
            }
        }
    }

    fn dos_marker(size: usize) -> Vec<u8> {
        format!("E2E_DOS_READY_{size}").into_bytes()
    }

    fn dos_burst_python(prefix: &[u8], sizes: &[usize]) -> String {
        let sizes = sizes
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut escaped_prefix = String::new();
        for byte in prefix {
            std::fmt::Write::write_fmt(&mut escaped_prefix, format_args!("\\x{byte:02x}"))
                .expect("write escaped prefix");
        }
        format!(
            "python3 -c 'import sys;sizes=[{sizes}];q=b\"\\x1b[c\";sys.stdout.buffer.write(b\"{escaped_prefix}\");[(sys.stdout.buffer.write(q*((s+len(q)-1)//len(q))),sys.stdout.buffer.write(f\"E2E_DOS_READY_{{s}}\\r\\n\".encode()),sys.stdout.buffer.flush()) for s in sizes]'"
        )
    }

    fn dos_burst_shell_command(sizes: &[usize]) -> String {
        format!(
            "/bin/sh -c {:?}",
            format!("{}; sleep 30", dos_burst_python(b"", sizes))
        )
    }

    fn full_box_drawing_block() -> Vec<char> {
        (0x2500..=0x257f)
            .filter_map(char::from_u32)
            .collect::<Vec<_>>()
    }

    fn box_drawing_reload_script(expected: &[char]) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"\x1b[?1049h\x1b[2J\x1b[H");
        for (idx, ch) in expected.iter().enumerate() {
            if idx == 64 {
                payload.extend_from_slice(b"\r\n");
            }
            let mut buf = [0_u8; 4];
            payload.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        payload.extend_from_slice(b"\r\nE2E_BOX_DONE\r\n");
        format!(
            "/bin/sh -c \"printf '{}'; sleep 30\"",
            shell_escaped_printf(&payload)
        )
    }

    fn live_streaming_reload_script() -> String {
        "/bin/sh -c \"i=0; while [ \\\"\\$i\\\" -lt 30 ]; do printf '\\033[?1049h\\033[2J\\033[HFRAME:%03d\\r\\nROWA:%03d\\r\\nROWB:%03d\\r\\nLIVE_READY:%03d\\r\\n' \\\"\\$i\\\" \\\"\\$i\\\" \\\"\\$i\\\" \\\"\\$i\\\"; i=\\$((i + 1)); sleep 0.05; done; sleep 30\"".to_owned()
    }

    #[derive(Debug)]
    struct LiveFrameObservation {
        frame: String,
        coherent: bool,
    }

    #[derive(Debug)]
    struct LiveFullScreenPaint {
        frame: String,
        coherent: bool,
    }

    #[derive(Debug)]
    struct PaintEvent {
        timestamp_nanos: u128,
        kind: String,
        fields: Vec<(String, String)>,
    }

    impl PaintEvent {
        fn field(&self, key: &str) -> Option<&str> {
            self.fields
                .iter()
                .find_map(|(field_key, value)| (field_key == key).then_some(value.as_str()))
        }

        fn overlaps_viewport(&self) -> bool {
            self.field("overlaps_viewport") == Some("true")
        }
    }

    fn read_paint_events(path: &Path) -> Vec<PaintEvent> {
        let contents = fs::read_to_string(path).unwrap_or_default();
        contents
            .lines()
            .map(|line| {
                let mut parts = line.split('|');
                let timestamp_nanos = parts
                    .next()
                    .and_then(|part| part.parse::<u128>().ok())
                    .unwrap_or_else(|| panic!("invalid paint-event timestamp in line {line:?}"));
                let kind = parts
                    .next()
                    .unwrap_or_else(|| panic!("missing paint-event kind in line {line:?}"))
                    .to_owned();
                let fields = parts
                    .filter_map(|part| {
                        let (key, value) = part.split_once('=')?;
                        Some((key.to_owned(), value.to_owned()))
                    })
                    .collect();
                PaintEvent {
                    timestamp_nanos,
                    kind,
                    fields,
                }
            })
            .collect()
    }

    fn assert_true_reload_window_has_no_live_paints(events: &[PaintEvent]) {
        let started = events
            .iter()
            .find(|event| event.kind == "ReloadStarted")
            .unwrap_or_else(|| panic!("missing ReloadStarted paint event: {events:?}"));
        let done = reload_done_or_first_post_start_viewport(events, started.timestamp_nanos);
        let interleaved_live: Vec<_> = events
            .iter()
            .filter(|event| {
                event.kind == "LiveOutput"
                    && event.timestamp_nanos >= started.timestamp_nanos
                    && event.timestamp_nanos <= done.timestamp_nanos
            })
            .collect();
        assert!(
            interleaved_live.is_empty(),
            "LiveOutput painted during true ReloadStarted→ReloadDone window: {interleaved_live:?}; all events={events:?}"
        );
    }

    fn reload_done_or_first_post_start_viewport(
        events: &[PaintEvent],
        started_nanos: u128,
    ) -> &PaintEvent {
        events
            .iter()
            .find(|event| event.kind == "ReloadDone")
            .or_else(|| {
                events.iter().find(|event| {
                    event.kind == "ViewportSnapshot" && event.timestamp_nanos >= started_nanos
                })
            })
            .unwrap_or_else(|| {
                panic!("missing ReloadDone/ViewportSnapshot paint event: {events:?}")
            })
    }

    fn assert_single_post_reload_viewport_without_dedup_overlap(events: &[PaintEvent]) {
        let started = events
            .iter()
            .find(|event| event.kind == "ReloadStarted")
            .unwrap_or_else(|| panic!("missing ReloadStarted paint event: {events:?}"));
        let done = reload_done_or_first_post_start_viewport(events, started.timestamp_nanos);
        let post_reload_viewports: Vec<_> = events
            .iter()
            .filter(|event| {
                event.kind == "ViewportSnapshot" && event.timestamp_nanos >= done.timestamp_nanos
            })
            .collect();
        assert_eq!(
            post_reload_viewports.len(),
            1,
            "expected exactly one ViewportSnapshot after ReloadDone; post-reload viewports={post_reload_viewports:?}; all events={events:?}"
        );
        let viewport_timestamp = post_reload_viewports[0].timestamp_nanos;
        let dedup_window_end = viewport_timestamp + 1_000_000_000;
        let overlapping_live: Vec<_> = events
            .iter()
            .filter(|event| {
                event.kind == "LiveOutput"
                    && event.field("queued") == Some("true")
                    && event.overlaps_viewport()
                    && event.timestamp_nanos >= viewport_timestamp
                    && event.timestamp_nanos <= dedup_window_end
            })
            .collect();
        assert!(
            overlapping_live.is_empty(),
            "LiveOutput overlapping the viewport painted within the 1s post-reload dedup window: {overlapping_live:?}; all events={events:?}"
        );
    }

    fn live_full_screen_paints(bytes: &[u8]) -> Vec<LiveFullScreenPaint> {
        let marker = b"\x1b[?1049h\x1b[2J\x1b[HFRAME:";
        let mut paints = Vec::new();
        let mut search = 0;
        while let Some(rel) = find_subslice(&bytes[search..], marker) {
            let start = search + rel + marker.len();
            let Some(frame_bytes) = bytes.get(start..start + 3) else {
                break;
            };
            let frame = String::from_utf8_lossy(frame_bytes).into_owned();
            let end = find_subslice(&bytes[start..], b"\r\nLIVE_READY:")
                .map_or(bytes.len(), |end_rel| {
                    start + end_rel + b"\r\nLIVE_READY:".len() + 3
                });
            let paint = &bytes[search + rel..end.min(bytes.len())];
            let coherent = [b"FRAME:" as &[u8], b"ROWA:", b"ROWB:", b"LIVE_READY:"]
                .into_iter()
                .all(|prefix| {
                    let mut expected = Vec::from(prefix);
                    expected.extend_from_slice(frame.as_bytes());
                    contains_subslice(paint, &expected)
                });
            paints.push(LiveFullScreenPaint { frame, coherent });
            search = end.min(bytes.len()).max(start);
        }
        paints
    }

    fn live_frame_observations(bytes: &[u8]) -> Vec<LiveFrameObservation> {
        let mut observations = Vec::new();
        let mut grid = TerminalGrid::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let before = grid.render_text();
            offset = grid.apply_one(bytes, offset);
            let after = grid.render_text();
            if before != after {
                let lines = grid.lines();
                if let Some(frame) = lines
                    .iter()
                    .find_map(|line| line.strip_prefix("LIVE_READY:"))
                    .and_then(|line| line.get(..3))
                {
                    let frame = frame.to_owned();
                    let coherent =
                        ["FRAME:", "ROWA:", "ROWB:", "LIVE_READY:"]
                            .into_iter()
                            .all(|prefix| {
                                lines
                                    .iter()
                                    .any(|line| line.starts_with(prefix) && line.contains(&frame))
                            });
                    if observations
                        .last()
                        .is_none_or(|last: &LiveFrameObservation| last.frame != frame)
                    {
                        observations.push(LiveFrameObservation { frame, coherent });
                    }
                }
            }
        }
        observations
    }

    #[derive(Clone, Debug)]
    struct TerminalGrid {
        cells: Vec<Vec<char>>,
        row: usize,
        col: usize,
    }

    impl TerminalGrid {
        const ROWS: usize = 24;
        const COLS: usize = 100;

        fn new() -> Self {
            Self {
                cells: vec![vec![' '; Self::COLS]; Self::ROWS],
                row: 0,
                col: 0,
            }
        }

        fn parse(bytes: &[u8]) -> Self {
            let mut grid = Self::new();
            let mut offset = 0;
            while offset < bytes.len() {
                offset = grid.apply_one(bytes, offset);
            }
            grid
        }

        fn apply_one(&mut self, bytes: &[u8], offset: usize) -> usize {
            match bytes[offset] {
                b'\x1b' => self.apply_escape(bytes, offset),
                b'\r' => {
                    self.col = 0;
                    offset + 1
                }
                b'\n' => {
                    self.row = (self.row + 1).min(Self::ROWS - 1);
                    offset + 1
                }
                b'\t' => {
                    self.col = (self.col + 8).min(Self::COLS - 1);
                    offset + 1
                }
                byte if byte.is_ascii_control() => offset + 1,
                _ => {
                    let text = std::str::from_utf8(&bytes[offset..]).unwrap_or("\u{fffd}");
                    let ch = text.chars().next().unwrap_or('\u{fffd}');
                    self.put(ch);
                    offset + ch.len_utf8().min(bytes.len() - offset)
                }
            }
        }

        fn apply_escape(&mut self, bytes: &[u8], offset: usize) -> usize {
            if offset + 1 >= bytes.len() {
                return offset + 1;
            }
            match bytes[offset + 1] {
                b'[' => self.apply_csi(bytes, offset),
                b']' | b'P' => skip_until_terminator(bytes, offset + 2),
                _ => (offset + 2).min(bytes.len()),
            }
        }

        fn apply_csi(&mut self, bytes: &[u8], offset: usize) -> usize {
            let params_start = offset + 2;
            let Some(final_rel) = bytes[params_start..]
                .iter()
                .position(|byte| (0x40..=0x7e).contains(byte))
            else {
                return bytes.len();
            };
            let final_idx = params_start + final_rel;
            let params = &bytes[params_start..final_idx];
            match bytes[final_idx] {
                b'H' | b'f' => {
                    let (row, col) = parse_cursor_position(params);
                    self.row = row.saturating_sub(1).min(Self::ROWS - 1);
                    self.col = col.saturating_sub(1).min(Self::COLS - 1);
                }
                b'J' if params == b"2" || params == b"3" => self.clear(),
                b'K' => {
                    for col in self.col..Self::COLS {
                        self.cells[self.row][col] = ' ';
                    }
                }
                b'h' if params == b"?1049" => {
                    self.clear();
                    self.row = 0;
                    self.col = 0;
                }
                b'A' => self.row = self.row.saturating_sub(csi_amount(params)),
                b'B' => self.row = (self.row + csi_amount(params)).min(Self::ROWS - 1),
                b'C' => self.col = (self.col + csi_amount(params)).min(Self::COLS - 1),
                b'D' => self.col = self.col.saturating_sub(csi_amount(params)),
                _ => {}
            }
            final_idx + 1
        }

        fn put(&mut self, ch: char) {
            if self.row < Self::ROWS && self.col < Self::COLS {
                self.cells[self.row][self.col] = ch;
            }
            self.col += 1;
            if self.col >= Self::COLS {
                self.col = 0;
                self.row = (self.row + 1).min(Self::ROWS - 1);
            }
        }

        fn clear(&mut self) {
            for row in &mut self.cells {
                row.fill(' ');
            }
        }

        fn row_chars(&self, row: usize) -> Vec<char> {
            self.cells[row].clone()
        }

        fn line(&self, row: usize) -> String {
            self.cells[row]
                .iter()
                .collect::<String>()
                .trim_end()
                .to_owned()
        }

        fn lines(&self) -> Vec<String> {
            (0..Self::ROWS).map(|row| self.line(row)).collect()
        }

        fn render_text(&self) -> String {
            self.lines().join("\n")
        }
    }

    fn skip_until_terminator(bytes: &[u8], mut offset: usize) -> usize {
        while offset < bytes.len() {
            if bytes[offset] == 0x07 {
                return offset + 1;
            }
            if bytes[offset] == b'\x1b' && bytes.get(offset + 1) == Some(&b'\\') {
                return offset + 2;
            }
            offset += 1;
        }
        bytes.len()
    }

    fn parse_cursor_position(params: &[u8]) -> (usize, usize) {
        let text = std::str::from_utf8(params).unwrap_or_default();
        let mut parts = text.split(';');
        let row = parts
            .next()
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse().ok())
            .unwrap_or(1);
        let col = parts
            .next()
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse().ok())
            .unwrap_or(1);
        (row, col)
    }

    fn csi_amount(params: &[u8]) -> usize {
        std::str::from_utf8(params)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1)
    }

    fn assert_no_utf8_damage(bytes: &[u8], context: &str) {
        assert!(
            !contains_subslice(bytes, "\u{fffd}".as_bytes()),
            "{context} contains U+FFFD replacement glyph bytes:\n{}",
            escaped(bytes)
        );
        for (idx, byte) in bytes.iter().enumerate() {
            if *byte == 0xe2 {
                assert!(
                    bytes
                        .get(idx + 1)
                        .is_some_and(|next| (0x80..=0xbf).contains(next))
                        && bytes
                            .get(idx + 2)
                            .is_some_and(|next| (0x80..=0xbf).contains(next)),
                    "{context} contains an unpaired E2 UTF-8 lead byte at offset {idx}:\n{}",
                    escaped(bytes)
                );
            }
        }
    }

    fn contains_response_shape(bytes: &[u8]) -> bool {
        let mut offset = 0;
        while offset + 2 < bytes.len() {
            if bytes[offset] != 0x1b || bytes[offset + 1] != b'[' {
                offset += 1;
                continue;
            }
            let body_start = offset + 2;
            let Some(final_rel) = bytes[body_start..]
                .iter()
                .position(|byte| (0x40..=0x7e).contains(byte))
            else {
                return false;
            };
            let final_byte = bytes[body_start + final_rel];
            let body = &bytes[body_start..body_start + final_rel];
            let response = match final_byte {
                b'c' => body
                    .strip_prefix(b"?")
                    .or_else(|| body.strip_prefix(b">"))
                    .is_some_and(semicolon_digits),
                b'u' => body.strip_prefix(b"?").is_some_and(colon_semicolon_digits),
                b'R' => body
                    .strip_prefix(b"?")
                    .unwrap_or(body)
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || *byte == b';'),
                _ => false,
            };
            if response {
                return true;
            }
            offset = body_start + final_rel + 1;
        }
        false
    }

    fn contains_cpr_payload_tail(bytes: &[u8]) -> bool {
        let mut offset = 0;
        while offset < bytes.len() {
            if !bytes[offset].is_ascii_digit() {
                offset += 1;
                continue;
            }
            let start = offset;
            while offset < bytes.len() && bytes[offset].is_ascii_digit() {
                offset += 1;
            }
            if bytes.get(offset) != Some(&b';') {
                offset = start + 1;
                continue;
            }
            offset += 1;
            let col_start = offset;
            while offset < bytes.len() && bytes[offset].is_ascii_digit() {
                offset += 1;
            }
            if offset > col_start && bytes.get(offset) == Some(&b'R') {
                return true;
            }
            offset = start + 1;
        }
        false
    }

    fn semicolon_digits(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b';')
    }

    fn colon_semicolon_digits(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && bytes
                .iter()
                .all(|byte| *byte == b':' || *byte == b';' || byte.is_ascii_digit())
    }

    fn shell_escaped_printf(bytes: &[u8]) -> String {
        let mut escaped = String::with_capacity(bytes.len() * 4);
        for byte in bytes {
            std::fmt::Write::write_fmt(&mut escaped, format_args!("\\{byte:03o}"))
                .expect("write to String");
        }
        escaped
    }

    fn chunked_printf_shell(chunks: &[Vec<u8>], keep_open: bool) -> String {
        let mut script = String::new();
        for (idx, chunk) in chunks.iter().enumerate() {
            std::fmt::Write::write_fmt(
                &mut script,
                format_args!("printf '{}'; ", shell_escaped_printf(chunk)),
            )
            .expect("write chunk script");
            if idx + 1 < chunks.len() {
                script.push_str("sleep 0.02; ");
            }
        }
        if keep_open {
            script.push_str("sleep 30");
        }
        script
    }

    fn write_fake_zmx_e2e_provider(path: &Path, guest_queries: &[u8]) -> io::Result<()> {
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.e2e" ;;
  list) printf 'dev\n' ;;
  attach)
    printf '{}E2E_READY\r\n'
    stty -echo -icanon min 0 time 100 2>/dev/null || true
    dd of=/dev/null bs=1024 count=1 2>/dev/null || true
    ;;
  kill) echo "killed:$2" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
                shell_escaped_printf(guest_queries)
            ),
        )?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn write_fake_zmx_shared_provider(path: &Path, guest_queries: &[u8]) -> io::Result<()> {
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.e2e" ;;
  list) printf 'dev\n' ;;
  attach)
    printf '{}E2E_READY\r\n'
    sleep 30
    ;;
  kill) echo "killed:$2" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
                shell_escaped_printf(guest_queries)
            ),
        )?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn write_fake_zmx_e2e_provider_chunks(path: &Path, chunks: &[Vec<u8>]) -> io::Result<()> {
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.e2e" ;;
  list) printf 'dev\n' ;;
  attach)
    {}
    stty -echo -icanon min 0 time 100 2>/dev/null || true
    dd of=/dev/null bs=1024 count=1 2>/dev/null || true
    ;;
  kill) echo "killed:$2" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
                chunked_printf_shell(chunks, false)
            ),
        )?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn write_fake_zmx_dos_provider(path: &Path, sizes: &[usize]) -> io::Result<()> {
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.e2e" ;;
  list) printf 'dev\n' ;;
  attach)
    {}
    stty -echo -icanon min 0 time 100 2>/dev/null || true
    dd of=/dev/null bs=1024 count=1 2>/dev/null || true
    ;;
  kill) echo "killed:$2" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
                dos_burst_python(b"", sizes)
            ),
        )?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn write_fake_tmux_dos_provider(path: &Path, sizes: &[usize]) -> io::Result<()> {
        let python = dos_burst_python(b"\x1bP1000p%output %1 ", sizes);
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'dev\n' ;;
  display-message) exit 1 ;;
  list-panes) exit 1 ;;
  kill-session) echo "killed:$3" ;;
  -CC)
    {python}
    stty -echo -icanon min 0 time 100 2>/dev/null || true
    dd of=/dev/null bs=1024 count=1 2>/dev/null || true
    ;;
  *) echo "not tmux e2e fixture" >&2; exit 64 ;;
esac
"#
            ),
        )?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn write_fake_tmux_e2e_provider(path: &Path, guest_queries: &[u8]) -> io::Result<()> {
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'dev\n' ;;
  display-message) exit 1 ;;
  list-panes) exit 1 ;;
  kill-session) echo "killed:$3" ;;
  -CC)
    stty -echo 2>/dev/null || true
    printf '\033P1000p%%output %%1 {}E2E_READY\\015\\012\r\n'
    stty -echo -icanon min 0 time 100 2>/dev/null || true
    dd of=/dev/null bs=1024 count=1 2>/dev/null || true
    ;;
  *) echo "not tmux e2e fixture" >&2; exit 64 ;;
esac
"#,
                shell_escaped_printf(guest_queries)
            ),
        )?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn write_fake_tmux_e2e_provider_chunks(path: &Path, chunks: &[Vec<u8>]) -> io::Result<()> {
        let mut output = String::new();
        for (idx, chunk) in chunks.iter().enumerate() {
            std::fmt::Write::write_fmt(
                &mut output,
                format_args!(
                    "    printf '\\033P1000p%%output %%1 {}\\r\\n'\n",
                    shell_escaped_printf(chunk)
                ),
            )
            .expect("write tmux chunk script");
            if idx + 1 < chunks.len() {
                output.push_str("    sleep 0.02\n");
            }
        }
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
case "$1" in
  -V) echo "tmux 3.6" ;;
  list-sessions) printf 'dev\n' ;;
  display-message) exit 1 ;;
  list-panes) exit 1 ;;
  kill-session) echo "killed:$3" ;;
  -CC)
    stty -echo 2>/dev/null || true
{output}
    stty -echo -icanon min 0 time 100 2>/dev/null || true
    dd of=/dev/null bs=1024 count=1 2>/dev/null || true
    ;;
  *) echo "not tmux e2e fixture" >&2; exit 64 ;;
esac
"#
            ),
        )?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn set_raw(fd: &OwnedFd) {
        let mut termios = tcgetattr(fd).expect("tcgetattr");
        cfmakeraw(&mut termios);
        tcsetattr(fd, SetArg::TCSANOW, &termios).expect("tcsetattr raw");
    }
}

fn start_remote_reconnect_agent(portl: &Path, home: &Path) -> RemoteReconnectAgent {
    let temp = tempdir().expect("temp remote agent fixture");
    let provider_path = temp.path().join("zmx");
    write_remote_reconnect_zmx(&provider_path).expect("write fake remote zmx provider");
    start_remote_reconnect_agent_with_temp(portl, home, Some(provider_path), temp)
}

fn start_remote_reconnect_agent_with_provider_path(
    portl: &Path,
    home: &Path,
    provider_path: Option<std::path::PathBuf>,
) -> RemoteReconnectAgent {
    let temp = tempdir().expect("temp remote agent fixture");
    start_remote_reconnect_agent_with_temp(portl, home, provider_path, temp)
}

fn start_remote_reconnect_agent_with_temp(
    portl: &Path,
    home: &Path,
    provider_path: Option<std::path::PathBuf>,
    temp: tempfile::TempDir,
) -> RemoteReconnectAgent {
    let agent_home = temp.path().join("agent-home");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("remote agent runtime");
        runtime.block_on(async move {
            if let Err(err) =
                start_remote_reconnect_agent_async(provider_path, agent_home, stop_rx, ready_tx)
                    .await
            {
                eprintln!("remote reconnect agent fixture failed: {err:#}");
            }
        });
    });
    let ticket = ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("remote agent fixture should report readiness")
        .expect("remote agent fixture should start");
    let save_status = Command::new(portl)
        .env("PORTL_HOME", home)
        .args(["ticket", "save", REMOTE_TICKET_LABEL, &ticket])
        .status()
        .expect("save remote reconnect ticket");
    assert!(
        save_status.success(),
        "saving reconnect ticket failed: {save_status}"
    );
    RemoteReconnectAgent {
        stop: Some(stop_tx),
        handle: Some(handle),
        _temp: temp,
    }
}

async fn start_remote_reconnect_agent_async(
    provider_path: Option<std::path::PathBuf>,
    agent_home: std::path::PathBuf,
    stop_rx: mpsc::Receiver<()>,
    ready_tx: mpsc::Sender<Result<String, String>>,
) -> anyhow::Result<()> {
    let server = portl_core::test_util::endpoint().await?;
    let operator = Identity::new();
    let paths = portl_core::paths::for_home(&agent_home);
    let agent = run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        peers_path: Some(paths.peers_path()),
        revocations_path: Some(paths.revocations_path()),
        endpoint: Some(server.clone()),
        session_provider_path: provider_path,
        ..AgentConfig::default()
    })
    .await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps(true)).serialize();
    let _ = ready_tx.send(Ok(ticket));
    tokio::task::spawn_blocking(move || {
        let _ = stop_rx.recv();
    })
    .await?;
    server.inner().close().await;
    let join = tokio::time::timeout(Duration::from_secs(5), agent).await?;
    join??;
    Ok(())
}

fn root_ticket(
    operator: &Identity,
    addr: iroh_base::EndpointAddr,
    caps: Capabilities,
) -> PortlTicket {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs();
    mint_root(operator.signing_key(), addr, caps, now, now + 300, None).expect("mint root ticket")
}

fn shell_caps(allow: bool) -> Capabilities {
    Capabilities {
        presence: u8::from(allow),
        shell: allow.then_some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Merge { allow: None },
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn write_remote_reconnect_zmx(path: &Path) -> io::Result<()> {
    fs::write(
        path,
        r#"#!/bin/sh
case "$1" in
  version) echo "zmx 0.0.reconnect" ;;
  list) printf 'dev\nfrontend\n' ;;
  attach) session="$2"; printf 'REMOTE_ATTACH:%s\nOK\n' "$session" ;;
  kill) echo "killed:$2" ;;
  *) echo "unknown:$1" >&2; exit 64 ;;
esac
"#,
    )?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
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
printf 'HOST_AFTER_ATTACH status=%s\n' "$status"
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

fn run_reconnect_fixture(scenario: &str, signal: Option<Signal>) -> Vec<u8> {
    let portl = assert_cmd::cargo::cargo_bin("portl");
    let home = initialized_portl_home(&portl);
    let _agent = start_remote_reconnect_agent(&portl, home.path());
    let session = "dev".to_owned();
    let host_script = r#"
set +e
/bin/sh -c 'printf "ATTACH_PID=%s\n" "$$"; PORTL_TEST_RECONNECT_SCENARIO="$PORTL_RECONNECT_SCENARIO" exec "$PORTL_BIN" attach "$PORTL_SESSION" --target "$PORTL_TARGET_LABEL" --provider zmx'
status=$?
printf 'HOST_AFTER_RECONNECT_FIXTURE status=%s\n' "$status"
printf 'HOST_READY_PROBE\n'
exit 0
"#;
    let child = spawn_host_command(
        "/bin/bash",
        &["-lc", host_script],
        &[
            ("PORTL_BIN", portl.to_str().expect("portl path utf8")),
            ("PORTL_HOME", home.path().to_str().expect("home path utf8")),
            ("PORTL_SESSION", &session),
            ("PORTL_TARGET_LABEL", REMOTE_TICKET_LABEL),
            ("PORTL_RECONNECT_SCENARIO", scenario),
            ("TERM", "xterm-kitty"),
            ("RUST_LOG", "off"),
        ],
    )
    .expect("spawn host command");
    let mut transcript = Vec::new();
    let ready = match scenario {
        "sighup-wait" => b"RECONNECT_WAIT_READY".as_slice(),
        "signal-connect-attempt" => b"RECONNECT_CONNECT_ATTEMPT_READY".as_slice(),
        "exhausted" => b"RECONNECT_BUDGET_EXHAUSTED".as_slice(),
        "transient" => b"RECONNECT_SUCCESS".as_slice(),
        other => panic!("unknown reconnect fixture scenario {other}"),
    };
    wait_for_bytes(&child.rx, &mut transcript, ready, Duration::from_secs(10))
        .expect("reconnect fixture reached ready marker");
    if let Some(signal) = signal {
        let pid = attach_pid_from_transcript(&transcript);
        kill(pid, signal).expect("send reconnect fixture signal");
    }
    wait_for_bytes(
        &child.rx,
        &mut transcript,
        b"HOST_READY_PROBE",
        Duration::from_secs(10),
    )
    .expect("host shell reached reconnect fixture post-attach probe");
    drain_for(&child.rx, &mut transcript, Duration::from_millis(250));
    let mut child = child;
    let status = child
        .process
        .wait()
        .expect("wait reconnect fixture host shell");
    assert!(
        status.success(),
        "host shell failed after reconnect fixture: {status}; transcript:\n{}",
        escaped(&transcript)
    );
    transcript
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
    command
        .args(args)
        .envs(env.iter().copied().filter(|(_, value)| !value.is_empty()));
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

fn bytes_between_markers<'a>(bytes: &'a [u8], start: &[u8], end: &[u8]) -> Option<&'a [u8]> {
    let after_start = bytes_after_marker(bytes, start)?;
    let end_idx = find_subslice(after_start, end)?;
    Some(&after_start[..end_idx])
}

fn assert_cleanup_ends_before_marker(bytes: &[u8], marker: &[u8], cleanup: &[u8]) {
    let before_marker = bytes_before_marker(bytes, marker).unwrap_or(bytes);
    assert!(
        before_marker.ends_with(cleanup),
        "expected stream before marker {} to end exactly with cleanup {}:\n{}",
        escaped(marker),
        escaped(cleanup),
        escaped(bytes)
    );
}

fn assert_cleanup_before_marker(bytes: &[u8], marker: &[u8], cleanup: &[u8]) {
    let before_marker = bytes_before_marker(bytes, marker).unwrap_or(bytes);
    assert!(
        contains_subslice(before_marker, cleanup),
        "expected cleanup {} before marker {} in transcript:\n{}",
        escaped(cleanup),
        escaped(marker),
        escaped(bytes)
    );
}

fn assert_panic_cleanup_suffix_exact(bytes: &[u8], marker: &[u8]) {
    let before_marker = bytes_before_marker(bytes, marker).unwrap_or(bytes);
    assert_eq!(
        before_marker.last().copied(),
        Some(b'c'),
        "panic cleanup stream must end with RIS final byte before marker {}:\n{}",
        escaped(marker),
        escaped(bytes)
    );
    assert!(
        before_marker.ends_with(PANIC_HOOK_EMERGENCY_CLEANUP),
        "panic cleanup suffix before marker {} was not byte-exact emergency cleanup:\n{}",
        escaped(marker),
        escaped(bytes)
    );
}

fn assert_no_cleanup_leaked(bytes: &[u8]) {
    for forbidden in [
        b"\x1b[?1049l".as_slice(),
        b"\x1b[<u",
        b"\x1b[=0u",
        b"\x1b[>4;0m",
        b"\x1b[?2004l",
        b"\x1b[?1000l",
        b"\x1b[?1002l",
        b"\x1b[?1003l",
        b"\x1b[?1006l",
        b"\x1b[?7h",
        b"\x1b[r",
        b"\x1b[!p",
        b"\x1bc",
    ] {
        assert!(
            !contains_subslice(bytes, forbidden),
            "cleanup byte sequence {} leaked in window:\n{}",
            escaped(forbidden),
            escaped(bytes)
        );
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

fn count_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn is_server_stripped_kitty_stack_cleanup(cleanup: &[u8], slice: &[u8]) -> bool {
    matches!(cleanup, b"\x1b[<u" | b"\x1b[=0u") && !contains_subslice(slice, b"\x1b[>1u")
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

use iroh::endpoint::SendStream;

use crate::wire::session::SessionStreamKind;
use crate::wire::shell::ShellStreamKind;

pub const CONTROL: i32 = 30;
pub const INTERACTIVE: i32 = 20;
pub const NORMAL: i32 = 0;
pub const BULK: i32 = -10;
pub const FORWARD: i32 = -20;

pub fn apply(stream: &SendStream, priority: i32) {
    if let Err(err) = stream.set_priority(priority) {
        tracing::debug!(?err, priority, "failed to set QUIC stream priority");
    }
}

pub const fn shell(kind: ShellStreamKind) -> i32 {
    match kind {
        ShellStreamKind::Signal | ShellStreamKind::Resize => CONTROL,
        ShellStreamKind::Stdin => INTERACTIVE,
        ShellStreamKind::Exit => NORMAL,
        ShellStreamKind::Stdout | ShellStreamKind::Stderr => BULK,
    }
}

pub const fn session(kind: SessionStreamKind) -> i32 {
    match kind {
        SessionStreamKind::HerdrClientControl | SessionStreamKind::HerdrServerControl => CONTROL,
        SessionStreamKind::HerdrClientInput
        | SessionStreamKind::HerdrClientResize
        | SessionStreamKind::AttachV2Input
        | SessionStreamKind::AttachV2Resize
        | SessionStreamKind::Stdin
        | SessionStreamKind::Signal
        | SessionStreamKind::Resize
        | SessionStreamKind::Control => INTERACTIVE,
        SessionStreamKind::HerdrServerRender
        | SessionStreamKind::AttachV2Viewport
        | SessionStreamKind::AttachV2Live
        | SessionStreamKind::Stdout
        | SessionStreamKind::Stderr
        | SessionStreamKind::Exit => NORMAL,
        SessionStreamKind::HerdrClientBulk
        | SessionStreamKind::HerdrServerBulk
        | SessionStreamKind::AttachV2History => BULK,
    }
}

pub const fn forward() -> i32 {
    FORWARD
}

#[cfg(test)]
mod tests {
    use crate::wire::session::SessionStreamKind;
    use crate::wire::shell::ShellStreamKind;

    #[test]
    fn shell_stream_priority_policy_prefers_control_and_input_over_output() {
        assert!(super::shell(ShellStreamKind::Signal) > super::shell(ShellStreamKind::Stdout));
        assert!(super::shell(ShellStreamKind::Resize) > super::shell(ShellStreamKind::Stdout));
        assert!(super::shell(ShellStreamKind::Stdin) > super::shell(ShellStreamKind::Stdout));
        assert_eq!(
            super::shell(ShellStreamKind::Stdout),
            super::shell(ShellStreamKind::Stderr)
        );
        assert!(super::shell(ShellStreamKind::Exit) >= super::shell(ShellStreamKind::Stdout));
    }

    #[test]
    fn session_priority_policy_covers_herdr_attach_v2_and_forwarders() {
        assert!(
            super::session(SessionStreamKind::HerdrClientControl)
                > super::session(SessionStreamKind::HerdrServerRender)
        );
        assert!(
            super::session(SessionStreamKind::HerdrClientInput)
                > super::session(SessionStreamKind::HerdrClientBulk)
        );
        assert!(
            super::session(SessionStreamKind::HerdrClientResize)
                > super::session(SessionStreamKind::HerdrClientBulk)
        );
        assert!(
            super::session(SessionStreamKind::AttachV2Input)
                > super::session(SessionStreamKind::AttachV2History)
        );
        assert!(super::forward() < super::session(SessionStreamKind::HerdrServerRender));
    }
}

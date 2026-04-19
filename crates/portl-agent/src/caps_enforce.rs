use portl_core::ticket::schema::{Capabilities, ShellCaps};
use portl_proto::shell_v1::{ShellMode, ShellReason, ShellReq};
use portl_proto::tcp_v1::TcpReq;

pub fn shell_permits(caps: &Capabilities, req: &ShellReq) -> Result<(), ShellReason> {
    let Some(shell_caps) = caps.shell.as_ref() else {
        return Err(ShellReason::CapDenied);
    };

    match req.mode {
        ShellMode::Shell if !shell_caps.pty_allowed => return Err(ShellReason::CapDenied),
        ShellMode::Exec if !shell_caps.exec_allowed => return Err(ShellReason::CapDenied),
        _ => {}
    }

    if req.mode == ShellMode::Shell && req.pty.is_none() {
        return Err(ShellReason::InvalidPty);
    }

    if let Some(allowlist) = shell_caps.user_allowlist.as_ref() {
        let requested_user = req.user.as_deref().unwrap_or_default();
        if !allowlist
            .iter()
            .any(|candidate| candidate == requested_user)
        {
            return Err(ShellReason::CapDenied);
        }
    }

    if req.mode == ShellMode::Exec
        && let Some(allowlist) = shell_caps.command_allowlist.as_ref()
    {
        let argv0 = req
            .argv
            .as_ref()
            .and_then(|argv| argv.first())
            .ok_or_else(|| ShellReason::SpawnFailed("exec mode requires argv".to_owned()))?;
        if !allowlist.iter().any(|candidate| candidate == argv0) {
            return Err(ShellReason::CapDenied);
        }
    }

    Ok(())
}

pub fn tcp_permits(caps: &Capabilities, req: &TcpReq) -> Result<(), &'static str> {
    let Some(rules) = caps.tcp.as_ref() else {
        return Err("tcp forwarding not allowed");
    };

    rules
        .iter()
        .any(|rule| {
            host_matches(&rule.host_glob, &req.host)
                && rule.port_min <= req.port
                && req.port <= rule.port_max
        })
        .then_some(())
        .ok_or("destination not permitted by ticket")
}

fn host_matches(pattern: &str, host: &str) -> bool {
    pattern == "*" || pattern == host
}

pub fn shell_caps(caps: &Capabilities) -> Option<&ShellCaps> {
    caps.shell.as_ref()
}

#[cfg(test)]
mod tests {
    use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortRule, ShellCaps};
    use portl_proto::shell_v1::{EnvValue, PtyCfg};
    use portl_proto::wire::StreamPreamble;

    use super::{shell_permits, tcp_permits};
    use portl_proto::shell_v1::{ShellMode, ShellReason, ShellReq};
    use portl_proto::tcp_v1::TcpReq;

    #[test]
    fn shell_permits_pty_session_when_caps_allow_it() {
        let caps = shell_caps(true, false, None, None);
        let req = ShellReq {
            mode: ShellMode::Shell,
            argv: None,
            env_patch: vec![("TERM".to_owned(), EnvValue::Set("xterm".to_owned()))],
            cwd: None,
            pty: Some(PtyCfg {
                term: "xterm-256color".to_owned(),
                cols: 80,
                rows: 24,
            }),
            user: None,
            preamble: preamble("portl/shell/v1"),
        };

        assert_eq!(shell_permits(&caps, &req), Ok(()));
    }

    #[test]
    fn shell_rejects_missing_shell_caps() {
        let caps = Capabilities {
            presence: 0,
            shell: None,
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
        };
        let req = shell_req(ShellMode::Shell, None);

        assert_eq!(shell_permits(&caps, &req), Err(ShellReason::CapDenied));
    }

    #[test]
    fn shell_rejects_exec_when_not_allowed() {
        let caps = shell_caps(true, false, None, None);
        let req = shell_req(ShellMode::Exec, Some(vec!["echo".to_owned()]));

        assert_eq!(shell_permits(&caps, &req), Err(ShellReason::CapDenied));
    }

    #[test]
    fn shell_rejects_disallowed_user() {
        let caps = shell_caps(true, true, Some(vec!["alice".to_owned()]), None);
        let mut req = shell_req(ShellMode::Shell, None);
        req.user = Some("bob".to_owned());

        assert_eq!(shell_permits(&caps, &req), Err(ShellReason::CapDenied));
    }

    #[test]
    fn shell_rejects_disallowed_command() {
        let caps = shell_caps(true, true, None, Some(vec!["/bin/echo".to_owned()]));
        let req = shell_req(ShellMode::Exec, Some(vec!["echo".to_owned()]));

        assert_eq!(shell_permits(&caps, &req), Err(ShellReason::CapDenied));
    }

    #[test]
    fn tcp_permits_exact_host_and_port_range() {
        let caps = tcp_caps(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: 20,
            port_max: 30,
        }]);
        let req = TcpReq {
            preamble: preamble("portl/tcp/v1"),
            host: "127.0.0.1".to_owned(),
            port: 22,
        };

        assert_eq!(tcp_permits(&caps, &req), Ok(()));
    }

    #[test]
    fn tcp_supports_wildcard_host_for_m3() {
        let caps = tcp_caps(vec![PortRule {
            host_glob: "*".to_owned(),
            port_min: 1,
            port_max: 65535,
        }]);
        let req = TcpReq {
            preamble: preamble("portl/tcp/v1"),
            host: "db.internal".to_owned(),
            port: 5432,
        };

        assert_eq!(tcp_permits(&caps, &req), Ok(()));
    }

    #[test]
    fn tcp_rejects_out_of_range_destination() {
        let caps = tcp_caps(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: 80,
            port_max: 81,
        }]);
        let req = TcpReq {
            preamble: preamble("portl/tcp/v1"),
            host: "127.0.0.1".to_owned(),
            port: 22,
        };

        assert_eq!(
            tcp_permits(&caps, &req),
            Err("destination not permitted by ticket")
        );
    }

    fn shell_caps(
        pty_allowed: bool,
        exec_allowed: bool,
        user_allowlist: Option<Vec<String>>,
        command_allowlist: Option<Vec<String>>,
    ) -> Capabilities {
        Capabilities {
            presence: 0b0000_0001,
            shell: Some(ShellCaps {
                user_allowlist,
                pty_allowed,
                exec_allowed,
                command_allowlist,
                env_policy: EnvPolicy::Merge { allow: None },
            }),
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
        }
    }

    fn tcp_caps(rules: Vec<PortRule>) -> Capabilities {
        Capabilities {
            presence: 0b0000_0010,
            shell: None,
            tcp: Some(rules),
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
        }
    }

    fn shell_req(mode: ShellMode, argv: Option<Vec<String>>) -> ShellReq {
        ShellReq {
            mode,
            argv,
            env_patch: Vec::new(),
            cwd: None,
            pty: Some(PtyCfg {
                term: "xterm-256color".to_owned(),
                cols: 80,
                rows: 24,
            }),
            user: None,
            preamble: preamble("portl/shell/v1"),
        }
    }

    fn preamble(alpn: &str) -> StreamPreamble {
        StreamPreamble {
            peer_token: [3; 16],
            alpn: alpn.to_owned(),
        }
    }
}

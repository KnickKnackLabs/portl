use portl_core::ticket::schema::{Capabilities, ShellCaps, TCP_LISTEN_CAP_BIT};
use portl_proto::shell_v1::{ShellMode, ShellReason, ShellReq};
use portl_proto::tcp_v1::TcpReq;
use portl_proto::udp_v1::UdpBind;
use portl_proto::unix_v1::UnixReq;

pub fn shell_permits(caps: &Capabilities, req: &ShellReq) -> Result<(), ShellReason> {
    let Some(shell_caps) = caps.shell.as_ref() else {
        return Err(ShellReason::CapDenied);
    };

    match req.mode {
        ShellMode::Shell if !shell_caps.pty_allowed => return Err(ShellReason::CapDenied),
        ShellMode::Exec if !shell_caps.exec_allowed => return Err(ShellReason::CapDenied),
        _ => {}
    }

    if req.pty.is_some() && !shell_caps.pty_allowed {
        return Err(ShellReason::CapDenied);
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

pub fn tcp_listen_permits(
    caps: &Capabilities,
    bind_host: &str,
    bind_port: u16,
) -> Result<(), &'static str> {
    if caps.presence & TCP_LISTEN_CAP_BIT == 0 {
        return Err("tcp listen forwarding not allowed");
    }
    let Some(rules) = caps.tcp.as_ref() else {
        return Err("tcp listen forwarding not allowed");
    };

    rules
        .iter()
        .any(|rule| {
            listen_host_matches(&rule.host_glob, bind_host)
                && rule.port_min <= bind_port
                && bind_port <= rule.port_max
        })
        .then_some(())
        .ok_or("listen address not permitted by ticket")
}

pub fn unix_permits(caps: &Capabilities, req: &UnixReq) -> Result<(), &'static str> {
    let Some(unix_caps) = caps.unix.as_ref() else {
        return Err("unix forwarding not allowed");
    };

    let (rules, path) = match &req.op {
        portl_proto::unix_v1::UnixOp::Connect { path } => (&unix_caps.connect, path),
        portl_proto::unix_v1::UnixOp::Listen { path, .. } => (&unix_caps.listen, path),
    };

    rules
        .iter()
        .any(|rule| rule.matches_path(path))
        .then_some(())
        .ok_or("unix path not permitted by ticket")
}

pub fn udp_permits(caps: &Capabilities, bind: &UdpBind) -> Result<(), &'static str> {
    let Some(rules) = caps.udp.as_ref() else {
        return Err("udp forwarding not allowed");
    };

    rules
        .iter()
        .any(|rule| {
            host_matches(&rule.host_glob, &bind.target_host)
                && rule.port_min <= bind.target_port_range.0
                && bind.target_port_range.1 <= rule.port_max
        })
        .then_some(())
        .ok_or("destination not permitted by ticket")
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.ends_with(&format!(".{suffix}")) || host == suffix;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return host.starts_with(&format!("{prefix}."));
    }
    pattern == host
}

fn listen_host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return matches!(host, "localhost" | "127.0.0.1" | "::1");
    }
    host_matches(pattern, host)
}

pub fn shell_caps(caps: &Capabilities) -> Option<&ShellCaps> {
    caps.shell.as_ref()
}

#[cfg(test)]
mod tests {
    use portl_core::ticket::schema::{
        Capabilities, EnvPolicy, PortRule, ShellCaps, TCP_LISTEN_CAP_BIT, UnixCaps, UnixPathRule,
    };
    use portl_proto::shell_v1::{EnvValue, PtyCfg};
    use portl_proto::wire::StreamPreamble;

    use super::{shell_permits, tcp_listen_permits, tcp_permits, udp_permits, unix_permits};
    use portl_proto::shell_v1::{ShellMode, ShellReason, ShellReq};
    use portl_proto::tcp_v1::TcpReq;
    use portl_proto::udp_v1::UdpBind;
    use portl_proto::unix_v1::{UnixOp, UnixReq};

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
    fn shell_permits_raw_session_when_shell_caps_allow_shell() {
        let caps = shell_caps(true, false, None, None);
        let req = shell_req(ShellMode::Shell, None);

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
            unix: None,
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
    fn shell_rejects_exec_with_pty_when_pty_not_allowed() {
        let caps = shell_caps(false, true, None, None);
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
    fn tcp_supports_suffix_host_globs() {
        let caps = tcp_caps(vec![PortRule {
            host_glob: "*.example.com".to_owned(),
            port_min: 1,
            port_max: 65535,
        }]);

        assert_eq!(
            tcp_permits(
                &caps,
                &TcpReq {
                    preamble: preamble("portl/tcp/v1"),
                    host: "a.example.com".to_owned(),
                    port: 443,
                }
            ),
            Ok(())
        );
        assert_eq!(
            tcp_permits(
                &caps,
                &TcpReq {
                    preamble: preamble("portl/tcp/v1"),
                    host: "example.com".to_owned(),
                    port: 443,
                }
            ),
            Ok(())
        );
        assert_eq!(
            tcp_permits(
                &caps,
                &TcpReq {
                    preamble: preamble("portl/tcp/v1"),
                    host: "evil.com".to_owned(),
                    port: 443,
                }
            ),
            Err("destination not permitted by ticket")
        );
    }

    #[test]
    fn tcp_supports_prefix_host_globs() {
        let caps = tcp_caps(vec![PortRule {
            host_glob: "10.0.0.*".to_owned(),
            port_min: 1,
            port_max: 65535,
        }]);

        assert_eq!(
            tcp_permits(
                &caps,
                &TcpReq {
                    preamble: preamble("portl/tcp/v1"),
                    host: "10.0.0.5".to_owned(),
                    port: 22,
                }
            ),
            Ok(())
        );
        assert_eq!(
            tcp_permits(
                &caps,
                &TcpReq {
                    preamble: preamble("portl/tcp/v1"),
                    host: "10.1.0.5".to_owned(),
                    port: 22,
                }
            ),
            Err("destination not permitted by ticket")
        );
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

    #[test]
    fn tcp_listen_requires_explicit_listen_cap_bit() {
        let caps = tcp_caps(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: 1,
            port_max: 65535,
        }]);

        assert_eq!(
            tcp_listen_permits(&caps, "127.0.0.1", 2222),
            Err("tcp listen forwarding not allowed")
        );
    }

    #[test]
    fn tcp_listen_uses_existing_tcp_port_rules_when_flagged() {
        let mut caps = tcp_caps(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: 2000,
            port_max: 3000,
        }]);
        caps.presence |= TCP_LISTEN_CAP_BIT;

        assert_eq!(tcp_listen_permits(&caps, "127.0.0.1", 2222), Ok(()));
        assert_eq!(
            tcp_listen_permits(&caps, "0.0.0.0", 2222),
            Err("listen address not permitted by ticket")
        );
        assert_eq!(
            tcp_listen_permits(&caps, "127.0.0.1", 4000),
            Err("listen address not permitted by ticket")
        );
    }

    #[test]
    fn tcp_listen_wildcard_rule_only_allows_loopback_binds() {
        let mut caps = tcp_caps(vec![PortRule {
            host_glob: "*".to_owned(),
            port_min: 0,
            port_max: 65535,
        }]);
        caps.presence |= TCP_LISTEN_CAP_BIT;

        assert_eq!(tcp_listen_permits(&caps, "127.0.0.1", 0), Ok(()));
        assert_eq!(tcp_listen_permits(&caps, "localhost", 2222), Ok(()));
        assert_eq!(tcp_listen_permits(&caps, "::1", 2222), Ok(()));
        assert_eq!(
            tcp_listen_permits(&caps, "0.0.0.0", 2222),
            Err("listen address not permitted by ticket")
        );
    }

    #[test]
    fn unix_permits_exact_connect_path() {
        let caps = unix_caps(
            vec![UnixPathRule {
                path: "/run/user/1000/agent.sock".to_owned(),
            }],
            vec![],
        );
        let req = UnixReq {
            preamble: preamble("portl/unix/v1"),
            op: UnixOp::Connect {
                path: "/run/user/1000/agent.sock".to_owned(),
            },
        };

        assert_eq!(unix_permits(&caps, &req), Ok(()));
    }

    #[test]
    fn unix_rejects_connect_path_outside_caps() {
        let caps = unix_caps(
            vec![UnixPathRule {
                path: "/run/user/1000/agent.sock".to_owned(),
            }],
            vec![],
        );
        let req = UnixReq {
            preamble: preamble("portl/unix/v1"),
            op: UnixOp::Connect {
                path: "/tmp/other.sock".to_owned(),
            },
        };

        assert_eq!(
            unix_permits(&caps, &req),
            Err("unix path not permitted by ticket")
        );
    }

    #[test]
    fn unix_rejects_parent_dir_escape_under_glob() {
        let caps = unix_caps(
            vec![UnixPathRule {
                path: "/tmp/portl-*".to_owned(),
            }],
            vec![],
        );
        let req = UnixReq {
            preamble: preamble("portl/unix/v1"),
            op: UnixOp::Connect {
                path: "/tmp/portl-foo/../other.sock".to_owned(),
            },
        };

        assert_eq!(
            unix_permits(&caps, &req),
            Err("unix path not permitted by ticket")
        );
    }

    #[test]
    fn unix_permits_narrow_listen_glob() {
        let caps = unix_caps(
            vec![],
            vec![UnixPathRule {
                path: "/tmp/portl-*".to_owned(),
            }],
        );
        let req = UnixReq {
            preamble: preamble("portl/unix/v1"),
            op: UnixOp::Listen {
                path: "/tmp/portl-agent.sock".to_owned(),
                cleanup: true,
                ssh_agent: false,
            },
        };

        assert_eq!(unix_permits(&caps, &req), Ok(()));
    }

    #[test]
    fn udp_permits_exact_host_and_port_range() {
        let caps = udp_caps(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: 5300,
            port_max: 5301,
        }]);
        let bind = UdpBind {
            local_port_range: (5300, 5300),
            target_host: "127.0.0.1".to_owned(),
            target_port_range: (5301, 5301),
        };

        assert_eq!(udp_permits(&caps, &bind), Ok(()));
    }

    #[test]
    fn udp_rejects_destination_outside_allowed_range() {
        let caps = udp_caps(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: 53,
            port_max: 53,
        }]);
        let bind = UdpBind {
            local_port_range: (5300, 5300),
            target_host: "127.0.0.1".to_owned(),
            target_port_range: (5353, 5353),
        };

        assert_eq!(
            udp_permits(&caps, &bind),
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
            unix: None,
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
            unix: None,
        }
    }

    fn udp_caps(rules: Vec<PortRule>) -> Capabilities {
        Capabilities {
            presence: 0b0000_0100,
            shell: None,
            tcp: None,
            udp: Some(rules),
            fs: None,
            vpn: None,
            meta: None,
            unix: None,
        }
    }

    fn unix_caps(connect: Vec<UnixPathRule>, listen: Vec<UnixPathRule>) -> Capabilities {
        Capabilities {
            presence: 0b0100_0000,
            shell: None,
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
            unix: Some(UnixCaps { connect, listen }),
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

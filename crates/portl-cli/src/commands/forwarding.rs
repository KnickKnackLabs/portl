use std::time::Instant;

use anyhow::{Context, Result, bail};
use portl_core::net::{
    LocalUdpForwardHandle, UnixListenControl, open_udp, open_unix_listen,
    run_local_forward as run_local_tcp_forward, run_local_unix_forward, run_unix_reverse_forwards,
};
use portl_core::ticket::schema::{Capabilities, PortRule};
use portl_proto::udp_v1::UdpBind;

use crate::commands::peer_resolve::ConnectedPeer;
use crate::commands::{socket, tcp, udp};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ForwardingArgs {
    pub(crate) local: Vec<String>,
    pub(crate) remote: Vec<String>,
}

impl ForwardingArgs {
    pub(crate) fn is_empty(&self) -> bool {
        self.local.is_empty() && self.remote.is_empty()
    }

    pub(crate) fn parse(&self, peer: &str, source_label: &str) -> Result<ForwardPlan> {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        let mut unix_l = Vec::new();
        let mut unix_r = Vec::new();

        for spec in &self.local {
            if looks_like_unix_socket_spec(spec) {
                unix_l.push(spec.clone());
            } else if spec.ends_with("/udp") {
                udp.push(udp::parse_local_spec(spec)?);
            } else {
                tcp.push(tcp::parse_local_spec(spec)?);
            }
        }

        for spec in &self.remote {
            if looks_like_unix_socket_spec(spec) {
                unix_r.push(spec.clone());
            } else {
                bail!(
                    "TCP/UDP -R forwarding is not supported yet; use Unix socket -R or an explicit portl socket command"
                );
            }
        }

        let unix = if unix_l.is_empty() && unix_r.is_empty() {
            Vec::new()
        } else {
            socket::parse_new_socket_modes(peer, source_label, &unix_l, &unix_r, false)?
        };

        Ok(ForwardPlan { tcp, udp, unix })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardPlan {
    tcp: Vec<tcp::LocalForwardSpec>,
    udp: Vec<udp::LocalForwardSpec>,
    unix: Vec<socket::SocketMode>,
}

impl ForwardPlan {
    pub(crate) fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty() && self.unix.is_empty()
    }

    pub(crate) fn augment_caps(&self, caps: &mut Capabilities) {
        if !self.tcp.is_empty() {
            caps.presence |= 0b0000_0010;
            let rules = caps.tcp.get_or_insert_with(Vec::new);
            rules.push(PortRule {
                host_glob: "*".to_owned(),
                port_min: 1,
                port_max: u16::MAX,
            });
            sort_dedup_port_rules(rules);
        }
        if !self.udp.is_empty() {
            caps.presence |= 0b0000_0100;
            let rules = caps.udp.get_or_insert_with(Vec::new);
            rules.push(PortRule {
                host_glob: "*".to_owned(),
                port_min: 1,
                port_max: u16::MAX,
            });
            sort_dedup_port_rules(rules);
        }
        if !self.unix.is_empty() {
            let unix_caps = socket::socket_caps_for_modes(&self.unix)
                .unix
                .expect("socket caps contain unix caps");
            caps.presence |= 0b0100_0000;
            let target = caps
                .unix
                .get_or_insert_with(|| portl_core::ticket::schema::UnixCaps {
                    connect: Vec::new(),
                    listen: Vec::new(),
                });
            target.connect.extend(unix_caps.connect);
            target.listen.extend(unix_caps.listen);
            target.connect.sort_by(|a, b| a.path.cmp(&b.path));
            target.connect.dedup_by(|a, b| a.path == b.path);
            target.listen.sort_by(|a, b| a.path.cmp(&b.path));
            target.listen.dedup_by(|a, b| a.path == b.path);
        }
    }

    #[allow(clippy::format_push_string)]
    pub(crate) fn render_summary(&self, peer: &str, source_label: &str) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut out = format!("Forwarding through {peer}\n");
        if !self.tcp.is_empty() {
            out.push_str("\nTCP ports:\n");
            let width = self
                .tcp
                .iter()
                .map(|spec| spec.local_addr().len())
                .max()
                .unwrap_or(0);
            for spec in &self.tcp {
                out.push_str(&format!(
                    "  -L  {local:<width$} -> {peer}:{}:{}\n",
                    spec.remote_host,
                    spec.remote_port,
                    local = spec.local_addr(),
                ));
            }
        }
        if !self.udp.is_empty() {
            out.push_str("\nUDP ports:\n");
            let width = self
                .udp
                .iter()
                .map(|spec| spec.local_addr().len())
                .max()
                .unwrap_or(0);
            for spec in &self.udp {
                out.push_str(&format!(
                    "  -L  {local:<width$} -> {peer}:{}:{}\n",
                    spec.remote_host,
                    spec.remote_port,
                    local = spec.local_addr(),
                ));
            }
        }
        if !self.unix.is_empty() {
            out.push_str("\nUnix sockets:\n");
            for (index, mode) in self.unix.iter().enumerate() {
                if index > 0 {
                    out.push('\n');
                }
                match mode {
                    socket::SocketMode::Connect {
                        local,
                        remote,
                        generated,
                        ..
                    } => {
                        let label = if *generated {
                            "generated local socket"
                        } else {
                            "explicit local socket"
                        };
                        out.push_str(&format!(
                            "  -L  {source_label}:{local}\n      -> {peer}:{remote}\n      {label}\n"
                        ));
                    }
                    socket::SocketMode::Listen {
                        remote,
                        local,
                        generated,
                        ..
                    } => {
                        let label = if *generated {
                            "generated remote socket"
                        } else {
                            "explicit remote socket"
                        };
                        out.push_str(&format!(
                            "  -R  {peer}:{remote}\n      -> {source_label}:{local}\n      {label}\n"
                        ));
                    }
                }
            }
        }
        out.push_str("\nWaiting for forwarded connections. Press Ctrl-C to stop.\n");
        out
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) async fn start(&self, connected: &ConnectedPeer) -> Result<ForwardRuntime> {
        let mut tasks = Vec::new();
        let mut listen_controls = Vec::new();
        let mut reverse_forwards = Vec::new();

        for spec in &self.tcp {
            let local_addr = spec.local_addr();
            let connection = connected.connection.clone();
            let session = connected.session.clone();
            let remote_host = spec.remote_host.clone();
            let remote_port = spec.remote_port;
            tasks.push(tokio::spawn(async move {
                run_local_tcp_forward(connection, session, &local_addr, remote_host, remote_port)
                    .await
            }));
        }

        for spec in &self.udp {
            let forward = LocalUdpForwardHandle::bind(&spec.local_addr())?;
            let control = open_udp(
                &connected.connection,
                &connected.session,
                forward.session_id(),
                vec![UdpBind {
                    local_port_range: (spec.local_port, spec.local_port),
                    target_host: spec.remote_host.clone(),
                    target_port_range: (spec.remote_port, spec.remote_port),
                }],
            )
            .await?;
            let connection = connected.connection.clone();
            let remote_port = spec.remote_port;
            let spec = spec.clone();
            tasks.push(tokio::spawn(async move {
                let opened_at = Instant::now();
                let start_stats = forward.stats_snapshot();
                eprintln!("{}", udp::format_open_line(&spec));
                let result = forward
                    .run_with_control(connection, control, remote_port)
                    .await;
                let stats = forward.stats_snapshot().delta_since(start_stats);
                match &result {
                    Ok(()) => eprintln!(
                        "{}",
                        udp::format_close_line(&spec, opened_at.elapsed(), stats)
                    ),
                    Err(err) => eprintln!(
                        "[udp -L {}] closed after {}, error={err}",
                        spec.local_addr(),
                        udp::format_duration(opened_at.elapsed())
                    ),
                }
                result
            }));
        }

        for mode in &self.unix {
            match mode {
                socket::SocketMode::Connect {
                    local,
                    remote,
                    cleanup,
                    generated,
                } => {
                    if *generated {
                        socket::ensure_generated_socket_parent(local, "portl-to-")?;
                    }
                    tasks.push(tokio::spawn(run_local_unix_forward(
                        connected.connection.clone(),
                        connected.session.clone(),
                        local.clone(),
                        remote.clone(),
                        *cleanup,
                    )));
                }
                socket::SocketMode::Listen {
                    remote,
                    local,
                    cleanup,
                    ..
                } => {
                    let control = open_unix_listen(
                        &connected.connection,
                        &connected.session,
                        remote,
                        *cleanup,
                    )
                    .await?;
                    listen_controls.push(control);
                    reverse_forwards.push((remote.clone(), local.clone()));
                }
            }
        }

        if !reverse_forwards.is_empty() {
            tasks.push(tokio::spawn(run_unix_reverse_forwards(
                connected.connection.clone(),
                connected.session.clone(),
                reverse_forwards,
            )));
        }

        Ok(ForwardRuntime {
            tasks,
            listen_controls,
        })
    }
}

pub(crate) struct ForwardRuntime {
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    listen_controls: Vec<UnixListenControl>,
}

impl ForwardRuntime {
    pub(crate) fn abort(&mut self) {
        for control in self.listen_controls.drain(..) {
            let _ = control.close();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for ForwardRuntime {
    fn drop(&mut self) {
        self.abort();
    }
}

fn sort_dedup_port_rules(rules: &mut Vec<PortRule>) {
    rules.sort_by(|a, b| {
        a.host_glob
            .cmp(&b.host_glob)
            .then(a.port_min.cmp(&b.port_min))
            .then(a.port_max.cmp(&b.port_max))
    });
    rules.dedup_by(|a, b| {
        a.host_glob == b.host_glob && a.port_min == b.port_min && a.port_max == b.port_max
    });
}

fn looks_like_unix_socket_spec(spec: &str) -> bool {
    spec.starts_with('/')
        || spec.starts_with(':')
        || spec
            .split_once(':')
            .is_some_and(|(left, right)| left.starts_with('/') || right.starts_with('/'))
}

pub(crate) fn source_label() -> Result<String> {
    socket::local_socket_source_label()
}

pub(crate) fn parse_for_target(peer: &str, args: &ForwardingArgs) -> Result<(String, ForwardPlan)> {
    let source_label = source_label().context("resolve local forwarding label")?;
    let plan = args.parse(peer, &source_label)?;
    Ok((source_label, plan))
}

#[cfg(test)]
mod tests {
    use super::ForwardingArgs;
    use portl_core::ticket::schema::{Capabilities, ShellCaps};

    #[test]
    fn parses_mixed_local_and_remote_forwarding_flags() {
        let args = ForwardingArgs {
            local: vec![
                "8080:3000".to_owned(),
                "5353/udp".to_owned(),
                "/run/herdr.sock".to_owned(),
            ],
            remote: vec!["/tmp/local-agent.sock".to_owned()],
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();
        assert_eq!(plan.tcp.len(), 1);
        assert_eq!(plan.udp.len(), 1);
        assert_eq!(plan.unix.len(), 2);
    }

    #[test]
    fn rejects_remote_port_forwarding_until_protocol_exists() {
        let args = ForwardingArgs {
            local: Vec::new(),
            remote: vec!["9000:localhost:9000".to_owned()],
        };
        let err = args
            .parse("remote-dev", "local-dev")
            .expect_err("remote TCP -R should fail");
        assert!(
            err.to_string()
                .contains("TCP/UDP -R forwarding is not supported yet")
        );
    }

    #[test]
    fn renders_mixed_forwarding_summary_once() {
        let args = ForwardingArgs {
            local: vec!["8080:3000".to_owned(), "/run/herdr.sock".to_owned()],
            remote: Vec::new(),
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();
        let summary = plan.render_summary("remote-dev", "local-dev");
        assert_eq!(summary.matches("Forwarding through remote-dev").count(), 1);
        assert!(summary.contains("TCP ports:"));
        assert!(summary.contains("Unix sockets:"));
    }

    #[test]
    fn forwarding_plan_augments_existing_shell_caps() {
        let args = ForwardingArgs {
            local: vec!["8080".to_owned(), "5353/udp".to_owned()],
            remote: vec!["/tmp/local-agent.sock".to_owned()],
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();
        let mut caps = Capabilities {
            presence: 0b0000_0001,
            shell: Some(ShellCaps {
                user_allowlist: None,
                pty_allowed: true,
                exec_allowed: true,
                command_allowlist: None,
                env_policy: portl_core::ticket::schema::EnvPolicy::Merge { allow: None },
            }),
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
            unix: None,
        };
        plan.augment_caps(&mut caps);
        assert_eq!(caps.presence & 0b0000_0001, 0b0000_0001);
        assert!(caps.tcp.is_some());
        assert!(caps.udp.is_some());
        assert!(
            caps.unix
                .as_ref()
                .is_some_and(|unix| !unix.listen.is_empty())
        );
    }
}

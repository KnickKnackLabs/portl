use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use portl_core::net::run_local_forward;
use portl_core::ticket::schema::{Capabilities, PortRule};

use crate::commands::peer_resolve::connect_peer;

pub fn run(peer: &str, specs: &[String]) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        if specs.is_empty() {
            bail!("at least one -L spec is required")
        }
        let parsed_specs = specs
            .iter()
            .map(|spec| parse_local_spec(spec))
            .collect::<Result<Vec<_>>>()?;
        let connected = connect_peer(peer, tcp_caps()).await?;
        eprint!("{}", render_startup_summary(peer, &parsed_specs));

        let mut tasks = Vec::new();
        for parsed in parsed_specs {
            let connection = connected.connection.clone();
            let session = connected.session.clone();
            tasks.push(tokio::spawn(async move {
                run_local_forward(
                    connection,
                    session,
                    &parsed.local_addr(),
                    parsed.remote_host,
                    parsed.remote_port,
                )
                .await
            }));
        }

        tokio::signal::ctrl_c().await.context("wait for ctrl-c")?;
        connected.connection.close(0u32.into(), b"tcp complete");
        connected.endpoint.close().await;
        for task in tasks {
            task.abort();
        }
        Ok(ExitCode::SUCCESS)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalForwardSpec {
    pub bind: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl LocalForwardSpec {
    pub(crate) fn local_addr(&self) -> String {
        format!("{}:{}", self.bind, self.local_port)
    }

    fn remote_addr(&self) -> String {
        format!("{}:{}", self.remote_host, self.remote_port)
    }
}

#[allow(clippy::format_push_string)]
fn render_startup_summary(peer: &str, specs: &[LocalForwardSpec]) -> String {
    let local_width = specs
        .iter()
        .map(|spec| spec.local_addr().len())
        .max()
        .unwrap_or(0);
    let mut summary = format!("Forwarding through {peer}\n\nTCP ports:\n");
    for spec in specs {
        summary.push_str(&format!(
            "  -L  {local:<local_width$} -> {peer}:{}\n",
            spec.remote_addr(),
            local = spec.local_addr(),
        ));
    }
    summary.push_str("\nWaiting for connections. Press Ctrl-C to stop.\n");
    summary
}

pub(crate) fn parse_local_spec(spec: &str) -> Result<LocalForwardSpec> {
    let spec = strip_protocol_suffix(spec)?;
    let parts = spec.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [local_port] => {
            let local_port = local_port.parse().context("parse local port")?;
            Ok(LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port,
                remote_host: "localhost".to_owned(),
                remote_port: local_port,
            })
        }
        [local_port, remote_port] => Ok(LocalForwardSpec {
            bind: "127.0.0.1".to_owned(),
            local_port: local_port.parse().context("parse local port")?,
            remote_host: "localhost".to_owned(),
            remote_port: remote_port.parse().context("parse remote port")?,
        }),
        [local_port, remote_host, remote_port] => Ok(LocalForwardSpec {
            bind: "127.0.0.1".to_owned(),
            local_port: local_port.parse().context("parse local port")?,
            remote_host: (*remote_host).to_owned(),
            remote_port: remote_port.parse().context("parse remote port")?,
        }),
        [bind, local_port, remote_host, remote_port] => Ok(LocalForwardSpec {
            bind: (*bind).to_owned(),
            local_port: local_port.parse().context("parse local port")?,
            remote_host: (*remote_host).to_owned(),
            remote_port: remote_port.parse().context("parse remote port")?,
        }),
        _ => bail!("invalid -L spec: {spec}"),
    }
}

fn strip_protocol_suffix(spec: &str) -> Result<&str> {
    let Some((base, proto)) = spec.rsplit_once('/') else {
        return Ok(spec);
    };
    match proto {
        "tcp" => Ok(base),
        "udp" | "both" => bail!("protocol /{proto} is not supported by portl tcp"),
        _ => Ok(spec),
    }
}

fn tcp_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0010,
        shell: None,
        tcp: Some(vec![PortRule {
            host_glob: "*".to_owned(),
            port_min: 1,
            port_max: u16::MAX,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalForwardSpec, parse_local_spec, render_startup_summary};

    #[test]
    fn renders_grouped_tcp_startup_summary() {
        let specs = vec![
            parse_local_spec("8080:3000").unwrap(),
            parse_local_spec("15432:db.internal:5432").unwrap(),
        ];
        assert_eq!(
            render_startup_summary("remote-dev", &specs),
            "Forwarding through remote-dev\n\nTCP ports:\n  -L  127.0.0.1:8080  -> remote-dev:localhost:3000\n  -L  127.0.0.1:15432 -> remote-dev:db.internal:5432\n\nWaiting for connections. Press Ctrl-C to stop.\n"
        );
    }

    #[test]
    fn parses_bare_port_as_loopback_same_port_tcp() {
        assert_eq!(
            parse_local_spec("8080").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 8080,
                remote_host: "localhost".to_owned(),
                remote_port: 8080,
            }
        );
    }

    #[test]
    fn parses_docker_style_port_suffix_for_tcp() {
        assert_eq!(
            parse_local_spec("127.0.0.1:8080:db.internal:5432/tcp").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 8080,
                remote_host: "db.internal".to_owned(),
                remote_port: 5432,
            }
        );
    }

    #[test]
    fn parses_two_port_form_as_loopback_remote_host() {
        assert_eq!(
            parse_local_spec("8080:8888").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 8080,
                remote_host: "localhost".to_owned(),
                remote_port: 8888,
            }
        );
    }

    #[test]
    fn rejects_udp_suffix_for_tcp_command() {
        let err = parse_local_spec("5353/udp").expect_err("udp suffix should be rejected");
        assert!(err.to_string().contains("portl tcp"));
    }

    #[test]
    fn parses_short_forward_spec() {
        assert_eq!(
            parse_local_spec("3000:host:22").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 3000,
                remote_host: "host".to_owned(),
                remote_port: 22,
            }
        );
    }

    #[test]
    fn parses_long_forward_spec() {
        assert_eq!(
            parse_local_spec("127.0.0.1:3000:host:22").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 3000,
                remote_host: "host".to_owned(),
                remote_port: 22,
            }
        );
    }
}

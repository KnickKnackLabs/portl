use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use portl_core::net::{open_udp, run_local_udp_forward};
use portl_core::ticket::schema::{Capabilities, PortRule};
use portl_proto::udp_v1::UdpBind;

use crate::commands::peer::connect_peer;

pub fn run(peer: &str, specs: &[String]) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        if specs.is_empty() {
            bail!("at least one -L spec is required")
        }

        let mut tasks = Vec::new();
        let mut connections = Vec::new();
        let mut endpoints = Vec::new();
        for spec in specs {
            let parsed = parse_local_spec(spec)?;
            let connected = connect_peer(peer, udp_caps()).await?;
            let control = open_udp(
                &connected.connection,
                &connected.session,
                None,
                vec![UdpBind {
                    local_port_range: (parsed.local_port, parsed.local_port),
                    target_host: parsed.remote_host.clone(),
                    target_port_range: (parsed.remote_port, parsed.remote_port),
                }],
            )
            .await?;
            let connection = connected.connection.clone();
            connections.push(connected.connection);
            endpoints.push(connected.endpoint);
            tasks.push(tokio::spawn(async move {
                run_local_udp_forward(
                    connection,
                    control,
                    &parsed.local_addr(),
                    parsed.remote_port,
                )
                .await
            }));
        }

        tokio::signal::ctrl_c().await.context("wait for ctrl-c")?;
        for connection in &connections {
            connection.close(0u32.into(), b"udp complete");
        }
        for endpoint in endpoints {
            endpoint.close().await;
        }
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
}

pub(crate) fn parse_local_spec(spec: &str) -> Result<LocalForwardSpec> {
    let parts = spec.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
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

fn udp_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0100,
        shell: None,
        tcp: None,
        udp: Some(vec![PortRule {
            host_glob: "*".to_owned(),
            port_min: 1,
            port_max: u16::MAX,
        }]),
        fs: None,
        vpn: None,
        meta: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalForwardSpec, parse_local_spec};

    #[test]
    fn parses_short_forward_spec() {
        assert_eq!(
            parse_local_spec("3000:host:53").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 3000,
                remote_host: "host".to_owned(),
                remote_port: 53,
            }
        );
    }

    #[test]
    fn parses_long_forward_spec() {
        assert_eq!(
            parse_local_spec("127.0.0.1:3000:host:53").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 3000,
                remote_host: "host".to_owned(),
                remote_port: 53,
            }
        );
    }
}

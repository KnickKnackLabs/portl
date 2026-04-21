use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use portl_core::id::store;
use portl_core::net::{LocalUdpForwardHandle, open_udp};
use portl_core::ticket::schema::{Capabilities, PortRule};
use portl_proto::udp_v1::UdpBind;
use tokio::sync::watch;

use crate::commands::peer::{
    bind_client_endpoint, connect_peer_with_endpoint, resolve_identity_path,
};

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
        let identity_path = resolve_identity_path(None);
        let identity = store::load(&identity_path).context("load local identity")?;
        let (shutdown_tx, _) = watch::channel(false);
        let mut tasks = Vec::new();

        for parsed in parsed_specs {
            let peer = peer.to_owned();
            let identity = identity.clone();
            let endpoint = bind_client_endpoint(&identity).await?;
            let mut shutdown_rx = shutdown_tx.subscribe();
    let forward = LocalUdpForwardHandle::bind(&parsed.local_addr())?;
            tasks.push(tokio::spawn(async move {
                let mut backoff = Duration::from_millis(100);
                loop {
                    if *shutdown_rx.borrow() {
                        return Ok::<_, anyhow::Error>(());
                    }

                    let connected = match connect_peer_with_endpoint(
                        &peer,
                        udp_caps(),
                        &identity,
                        &endpoint,
                    )
                    .await {
                        Ok(connected) => connected,
                        Err(err) => {
                            tracing::debug!(%err, spec = %parsed.local_addr(), "udp reconnect failed during ticket handshake");
                            wait_backoff(&mut shutdown_rx, backoff).await;
                            backoff = next_backoff(backoff);
                            continue;
                        }
                    };

                    let requested_session_id = forward.session_id();
                    let control = match open_udp(
                        &connected.connection,
                        &connected.session,
                        requested_session_id,
                        vec![UdpBind {
                            local_port_range: (parsed.local_port, parsed.local_port),
                            target_host: parsed.remote_host.clone(),
                            target_port_range: (parsed.remote_port, parsed.remote_port),
                        }],
                    )
                    .await
                    {
                        Ok(control) => control,
                        Err(err) => {
                            tracing::debug!(%err, spec = %parsed.local_addr(), "udp reconnect failed while opening control stream");
                            connected.connection.close(0u32.into(), b"udp reconnect retry");
                            wait_backoff(&mut shutdown_rx, backoff).await;
                            backoff = next_backoff(backoff);
                            continue;
                        }
                    };

                    backoff = Duration::from_millis(100);
                    let result = tokio::select! {
                        result = forward.run_with_control(
                            connected.connection.clone(),
                            control,
                            parsed.remote_port,
                        ) => result,
                        changed = shutdown_rx.changed() => {
                            let _ = changed;
                            connected.connection.close(0u32.into(), b"udp shutdown");
                            return Ok(());
                        }
                    };

                    connected.connection.close(0u32.into(), b"udp reconnect retry");

                    if *shutdown_rx.borrow() {
                        return Ok(());
                    }

                    if let Err(err) = result {
                        tracing::debug!(%err, spec = %parsed.local_addr(), "udp forward loop stopped; reconnecting");
                    }
                    wait_backoff(&mut shutdown_rx, backoff).await;
                    backoff = next_backoff(backoff);
                }
            }));
        }

        tokio::signal::ctrl_c().await.context("wait for ctrl-c")?;
        let _ = shutdown_tx.send(true);
        for task in tasks {
            let _ = task.await;
        }
        Ok(ExitCode::SUCCESS)
    })
}

async fn wait_backoff(shutdown_rx: &mut watch::Receiver<bool>, backoff: Duration) {
    tokio::select! {
        () = tokio::time::sleep(backoff) => {}
        changed = shutdown_rx.changed() => {
            let _ = changed;
        }
    }
}

fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(Duration::from_secs(5))
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
    use super::{LocalForwardSpec, next_backoff, parse_local_spec};
    use std::time::Duration;

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

    #[test]
    fn udp_reconnect_backoff_caps_at_five_seconds() {
        assert_eq!(
            next_backoff(Duration::from_millis(100)),
            Duration::from_millis(200)
        );
        assert_eq!(next_backoff(Duration::from_secs(4)), Duration::from_secs(5));
        assert_eq!(next_backoff(Duration::from_secs(5)), Duration::from_secs(5));
    }
}

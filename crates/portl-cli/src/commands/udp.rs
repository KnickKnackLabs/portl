use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use portl_core::id::store;
use portl_core::net::{LocalUdpForwardHandle, open_udp};
use portl_core::ticket::schema::{Capabilities, PortRule};
use portl_proto::udp_v1::UdpBind;
use tokio::sync::watch;

use crate::commands::peer_resolve::{
    bind_client_endpoint, close_client_endpoint, connect_peer_with_endpoint, resolve_identity_path,
};

#[allow(clippy::too_many_lines)]
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
        eprint!("{}", render_startup_summary(peer, &parsed_specs));
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
                        close_client_endpoint(endpoint, "udp command").await;
                        return Ok::<_, anyhow::Error>(());
                    }

                    let quiet = false;
                    let connected = match connect_peer_with_endpoint(
                        &peer,
                        udp_caps(),
                        &identity,
                        &endpoint,
                        quiet,
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
                    let opened_at = Instant::now();
                    let start_stats = forward.stats_snapshot();
                    eprintln!("{}", format_open_line(&parsed));
                    let mut shutdown_during_run = false;
                    let result = tokio::select! {
                        result = forward.run_with_control(
                            connected.connection.clone(),
                            control,
                            parsed.remote_port,
                        ) => result,
                        changed = shutdown_rx.changed() => {
                            let _ = changed;
                            shutdown_during_run = true;
                            Ok(())
                        }
                    };

                    connected.connection.close(0u32.into(), b"udp reconnect retry");
                    let stats = forward.stats_snapshot().delta_since(start_stats);
                    match &result {
                        Ok(()) => eprintln!("{}", format_close_line(&parsed, opened_at.elapsed(), stats)),
                        Err(err) => eprintln!(
                            "[udp -L {}] closed after {}, error={err}",
                            parsed.local_addr(),
                            format_duration(opened_at.elapsed())
                        ),
                    }

                    if shutdown_during_run || *shutdown_rx.borrow() {
                        close_client_endpoint(endpoint, "udp command").await;
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
    let mut summary = format!("Forwarding through {peer}\n\nUDP ports:\n");
    for spec in specs {
        summary.push_str(&format!(
            "  -L  {local:<local_width$} -> {peer}:{}\n",
            spec.remote_addr(),
            local = spec.local_addr(),
        ));
    }
    summary.push_str("\nWaiting for datagrams. Press Ctrl-C to stop.\n");
    summary
}

pub(crate) fn format_open_line(spec: &LocalForwardSpec) -> String {
    format!(
        "[udp -L {}] opened -> remote {}",
        spec.local_addr(),
        spec.remote_addr()
    )
}

pub(crate) fn format_close_line(
    spec: &LocalForwardSpec,
    elapsed: Duration,
    stats: portl_core::net::UdpForwardStatsSnapshot,
) -> String {
    format!(
        "[udp -L {}] closed after {}, up={}/{} datagrams down={}/{} datagrams",
        spec.local_addr(),
        format_duration(elapsed),
        format_bytes(stats.upstream_bytes),
        stats.upstream_datagrams,
        format_bytes(stats.downstream_bytes),
        stats.downstream_datagrams
    )
}

pub(crate) fn format_duration(elapsed: Duration) -> String {
    if elapsed.as_secs() >= 1 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else {
        format!("{}ms", elapsed.as_millis())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if bytes >= MIB {
        format_decimal_unit(bytes, MIB, "MiB")
    } else if bytes >= KIB {
        format_decimal_unit(bytes, KIB, "KiB")
    } else {
        format!("{bytes} B")
    }
}

fn format_decimal_unit(bytes: u64, unit: u64, suffix: &str) -> String {
    let whole = bytes / unit;
    let mut tenths = ((bytes % unit) * 10 + unit / 2) / unit;
    let whole = if tenths == 10 {
        tenths = 0;
        whole + 1
    } else {
        whole
    };
    format!("{whole}.{tenths} {suffix}")
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
        "udp" => Ok(base),
        "tcp" | "both" => bail!("protocol /{proto} is not supported by portl udp"),
        _ => Ok(spec),
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
        unix: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LocalForwardSpec, format_close_line, next_backoff, parse_local_spec, render_startup_summary,
    };
    use std::time::Duration;

    #[test]
    fn renders_grouped_udp_startup_summary() {
        let specs = vec![
            parse_local_spec("5353/udp").unwrap(),
            parse_local_spec("1053:dns.internal:53/udp").unwrap(),
        ];
        assert_eq!(
            render_startup_summary("remote-dev", &specs),
            "Forwarding through remote-dev\n\nUDP ports:\n  -L  127.0.0.1:5353 -> remote-dev:localhost:5353\n  -L  127.0.0.1:1053 -> remote-dev:dns.internal:53\n\nWaiting for datagrams. Press Ctrl-C to stop.\n"
        );
    }

    #[test]
    fn parses_bare_port_as_loopback_same_port_udp() {
        assert_eq!(
            parse_local_spec("5353").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 5353,
                remote_host: "localhost".to_owned(),
                remote_port: 5353,
            }
        );
    }

    #[test]
    fn parses_docker_style_port_suffix_for_udp() {
        assert_eq!(
            parse_local_spec("127.0.0.1:1053:dns.internal:53/udp").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 1053,
                remote_host: "dns.internal".to_owned(),
                remote_port: 53,
            }
        );
    }

    #[test]
    fn parses_two_port_form_as_loopback_remote_host() {
        assert_eq!(
            parse_local_spec("1053:53").unwrap(),
            LocalForwardSpec {
                bind: "127.0.0.1".to_owned(),
                local_port: 1053,
                remote_host: "localhost".to_owned(),
                remote_port: 53,
            }
        );
    }

    #[test]
    fn rejects_tcp_suffix_for_udp_command() {
        let err = parse_local_spec("8080/tcp").expect_err("tcp suffix should be rejected");
        assert!(err.to_string().contains("portl udp"));
    }

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
    fn udp_close_line_includes_elapsed_and_byte_totals() {
        let spec = parse_local_spec("1053:dns.internal:53/udp").unwrap();
        assert_eq!(
            format_close_line(
                &spec,
                Duration::from_millis(1200),
                portl_core::net::UdpForwardStatsSnapshot {
                    upstream_bytes: 2048,
                    downstream_bytes: 4096,
                    upstream_datagrams: 3,
                    downstream_datagrams: 4,
                },
            ),
            "[udp -L 127.0.0.1:1053] closed after 1.2s, up=2.0 KiB/3 datagrams down=4.0 KiB/4 datagrams"
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

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use portl_core::ticket::schema::{Capabilities, PortRule};

use crate::commands::forwarding::ForwardPlan;
use crate::commands::persistent_forward;

pub fn run(peer: &str, specs: &[String]) -> Result<ExitCode> {
    if specs.is_empty() {
        bail!("at least one -L spec is required")
    }
    let parsed_specs = specs
        .iter()
        .map(|spec| parse_local_spec(spec))
        .collect::<Result<Vec<_>>>()?;
    eprint!("{}", render_startup_summary(peer, &parsed_specs));
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(persistent_forward::run(
        peer,
        ForwardPlan {
            udp: parsed_specs,
            ..ForwardPlan::default()
        },
        udp_caps(),
    ));
    runtime.shutdown_background();
    result
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
    use super::{LocalForwardSpec, format_close_line, parse_local_spec, render_startup_summary};
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
    fn udp_control_rejection_is_not_retried_forever() {
        let error = portl_core::net::udp_client::UdpRequestRejected("capability denied".to_owned());
        assert!(!crate::commands::network_lifecycle::retryable(
            &error.into()
        ));
    }
}

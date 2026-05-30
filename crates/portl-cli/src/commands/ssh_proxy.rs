use std::fmt::Write as _;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use portl_core::net::open_tcp;
use portl_core::ticket::schema::{Capabilities, PortRule};
use tokio::io::{AsyncWriteExt, copy};

use crate::SshConfigMode;
use crate::commands::peer_resolve::{close_connected, connect_peer_quiet};

pub fn run(peer: &str, host: &str, port: u16) -> Result<ExitCode> {
    validate_exact_tcp_target(host, port)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let connected = connect_peer_quiet(peer, ssh_proxy_caps(host, port)).await?;
        ensure_effective_tcp_cap_is_exact(&connected.session.effective_caps, host, port)?;
        let result = run_stdio_proxy(&connected.connection, &connected.session, host, port).await;
        close_connected(connected, b"ssh proxy complete").await;
        result
    });
    runtime.shutdown_background();
    result
}

pub fn print_config(
    mode: SshConfigMode,
    target: &str,
    host_alias: Option<&str>,
    remote_host: &str,
    remote_port: u16,
    portl_bin: &str,
) -> Result<ExitCode> {
    print!(
        "{}",
        render_config(
            mode,
            target,
            host_alias,
            remote_host,
            remote_port,
            portl_bin
        )?
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_stdio_proxy(
    connection: &iroh::endpoint::Connection,
    session: &portl_core::net::PeerSession,
    host: &str,
    port: u16,
) -> Result<ExitCode> {
    let (mut send, mut recv) = open_tcp(connection, session, host, port).await?;
    let mut upstream = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        copy(&mut stdin, &mut send)
            .await
            .context("copy ssh proxy stdin")?;
        send.finish().context("finish ssh proxy tcp send")?;
        Ok::<_, anyhow::Error>(())
    });
    let mut downstream = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        copy(&mut recv, &mut stdout)
            .await
            .context("copy ssh proxy stdout")?;
        stdout.flush().await.context("flush ssh proxy stdout")?;
        Ok::<_, anyhow::Error>(())
    });

    tokio::select! {
        upstream_join = &mut upstream => {
            if let Err(err) = upstream_join.context("join ssh proxy stdin task").and_then(|inner| inner) {
                downstream.abort();
                let _ = downstream.await;
                return Err(err);
            }
            downstream.await.context("join ssh proxy stdout task")??;
        }
        downstream_join = &mut downstream => {
            let result = downstream_join.context("join ssh proxy stdout task").and_then(|inner| inner);
            upstream.abort();
            let _ = upstream.await;
            result?;
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn render_config(
    mode: SshConfigMode,
    target: &str,
    host_alias: Option<&str>,
    remote_host: &str,
    remote_port: u16,
    portl_bin: &str,
) -> Result<String> {
    match mode {
        SshConfigMode::SshdProxy => render_sshd_proxy_config(
            target,
            host_alias.unwrap_or(target),
            remote_host,
            remote_port,
            portl_bin,
        ),
    }
}

fn render_sshd_proxy_config(
    target: &str,
    host_alias: &str,
    remote_host: &str,
    remote_port: u16,
    portl_bin: &str,
) -> Result<String> {
    validate_ssh_config_token("target", target)?;
    validate_ssh_config_token("host alias", host_alias)?;
    validate_ssh_config_token("remote host", remote_host)?;
    validate_ssh_config_token("portl binary", portl_bin)?;
    validate_exact_tcp_target(remote_host, remote_port)?;

    let mut output = String::new();
    writeln!(&mut output, "Host {host_alias}")?;
    writeln!(&mut output, "  HostName {target}")?;
    writeln!(&mut output, "  Port {remote_port}")?;
    writeln!(
        &mut output,
        "  ProxyCommand {portl_bin} ssh-proxy %h --host {remote_host} --port %p"
    )?;
    Ok(output)
}

fn ensure_effective_tcp_cap_is_exact(caps: &Capabilities, host: &str, port: u16) -> Result<()> {
    let exact_count = caps
        .tcp
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|rule| rule.host_glob == host && rule.port_min == port && rule.port_max == port)
        .count();
    if caps.presence == 0b0000_0010
        && caps.tcp.as_ref().is_some_and(|rules| rules.len() == 1)
        && exact_count == 1
    {
        return Ok(());
    }
    bail!("ssh-proxy requires an exact TCP ticket for {host}:{port}")
}

pub(crate) fn ssh_proxy_caps(host: &str, port: u16) -> Capabilities {
    Capabilities {
        presence: 0b0000_0010,
        shell: None,
        tcp: Some(vec![PortRule {
            host_glob: host.to_owned(),
            port_min: port,
            port_max: port,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix: None,
    }
}

fn validate_exact_tcp_target(host: &str, port: u16) -> Result<()> {
    if host.is_empty() {
        bail!("ssh-proxy --host must not be empty");
    }
    if host.contains('*') {
        bail!("ssh-proxy --host must be exact and must not contain wildcards");
    }
    validate_port(port)
}

fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        bail!("ssh-proxy --port must be between 1 and 65535");
    }
    Ok(())
}

fn validate_ssh_config_token(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("ssh-config {name} must not be empty");
    }
    if value.bytes().any(is_unsafe_ssh_config_byte) {
        bail!("ssh-config {name} contains unsafe characters");
    }
    Ok(())
}

fn is_unsafe_ssh_config_byte(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'\''
                | b'"'
                | b'`'
                | b'$'
                | b'\\'
                | b';'
                | b'&'
                | b'|'
                | b'<'
                | b'>'
                | b'('
                | b')'
                | b'%'
                | b'?'
                | b'['
                | b']'
        )
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_effective_tcp_cap_is_exact, render_config, ssh_proxy_caps, validate_exact_tcp_target,
    };
    use crate::SshConfigMode;

    #[test]
    fn ssh_proxy_caps_are_exact_to_host_and_port() {
        let caps = ssh_proxy_caps("127.0.0.1", 2222);
        assert_eq!(caps.presence, 0b0000_0010);
        let rule = &caps.tcp.expect("tcp cap")[0];
        assert_eq!(rule.host_glob, "127.0.0.1");
        assert_eq!(rule.port_min, 2222);
        assert_eq!(rule.port_max, 2222);
    }

    #[test]
    fn ssh_proxy_rejects_effective_caps_that_are_broader_than_exact_target() {
        let broad = portl_core::ticket::schema::Capabilities {
            presence: 0b0000_0010,
            shell: None,
            tcp: Some(vec![portl_core::ticket::schema::PortRule {
                host_glob: "*".to_owned(),
                port_min: 1,
                port_max: u16::MAX,
            }]),
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
            unix: None,
        };
        let err = ensure_effective_tcp_cap_is_exact(&broad, "127.0.0.1", 22)
            .expect_err("broad effective caps must fail");
        assert!(err.to_string().contains("exact TCP ticket"));
    }

    #[test]
    fn ssh_proxy_accepts_exact_effective_caps() {
        let caps = ssh_proxy_caps("127.0.0.1", 22);
        ensure_effective_tcp_cap_is_exact(&caps, "127.0.0.1", 22)
            .expect("exact effective caps should pass");
    }

    #[test]
    fn ssh_proxy_rejects_wildcard_host_caps() {
        let err = validate_exact_tcp_target("*", 22).expect_err("wildcard host must fail");
        assert!(err.to_string().contains("wildcards"));
    }

    #[test]
    fn ssh_proxy_config_uses_percent_host_and_port() {
        let config = render_config(
            SshConfigMode::SshdProxy,
            "vn3",
            Some("vn3-sshd"),
            "127.0.0.1",
            2222,
            "portl",
        )
        .expect("render config");
        assert_eq!(
            config,
            "Host vn3-sshd\n  HostName vn3\n  Port 2222\n  ProxyCommand portl ssh-proxy %h --host 127.0.0.1 --port %p\n"
        );
    }

    #[test]
    fn ssh_proxy_config_rejects_wildcard_remote_host() {
        let err = render_config(SshConfigMode::SshdProxy, "vn3", None, "*", 22, "portl")
            .expect_err("wildcard remote host must fail");
        assert!(err.to_string().contains("wildcards"));
    }

    #[test]
    fn ssh_proxy_config_rejects_openssh_percent_tokens() {
        let err = render_config(SshConfigMode::SshdProxy, "vn3", None, "%n", 22, "portl")
            .expect_err("percent tokens must fail");
        assert!(err.to_string().contains("unsafe"));
    }

    #[test]
    fn ssh_proxy_config_rejects_shell_globs() {
        for value in ["portl?", "portl[0]"] {
            let err = render_config(
                SshConfigMode::SshdProxy,
                "vn3",
                None,
                "127.0.0.1",
                22,
                value,
            )
            .expect_err("glob metacharacters must fail");
            assert!(err.to_string().contains("unsafe"));
        }
    }

    #[test]
    fn ssh_proxy_config_rejects_shell_metacharacters() {
        let err = render_config(
            SshConfigMode::SshdProxy,
            "vn3;rm",
            None,
            "127.0.0.1",
            22,
            "portl",
        )
        .expect_err("unsafe target must fail");
        assert!(err.to_string().contains("unsafe"));
    }
}

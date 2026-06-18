use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Result, bail};

use crate::SshConfigMode;
use crate::commands::ssh_proxy::validate_exact_tcp_target;

pub fn print_config(
    mode: SshConfigMode,
    target: &str,
    host_alias: Option<&str>,
    remote_host: &str,
    remote_port: u16,
    portl_bin: &str,
    ssh_user: Option<&str>,
) -> Result<ExitCode> {
    print!(
        "{}",
        render_config(
            mode,
            target,
            host_alias,
            remote_host,
            remote_port,
            portl_bin,
            ssh_user,
        )?
    );
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn render_config(
    mode: SshConfigMode,
    target: &str,
    host_alias: Option<&str>,
    remote_host: &str,
    remote_port: u16,
    portl_bin: &str,
    ssh_user: Option<&str>,
) -> Result<String> {
    match mode {
        SshConfigMode::NativeProxycommand => render_native_proxycommand_config(
            target,
            host_alias.unwrap_or(target),
            portl_bin,
            ssh_user,
        ),
        SshConfigMode::SshdProxy => render_sshd_proxy_config(
            target,
            host_alias.unwrap_or(target),
            remote_host,
            remote_port,
            portl_bin,
            ssh_user,
        ),
    }
}

fn render_native_proxycommand_config(
    target: &str,
    host_alias: &str,
    portl_bin: &str,
    ssh_user: Option<&str>,
) -> Result<String> {
    validate_ssh_config_token("target", target)?;
    validate_ssh_config_token("host alias", host_alias)?;
    validate_ssh_config_token("portl binary", portl_bin)?;
    if let Some(user) = ssh_user {
        validate_ssh_config_token("user", user)?;
    }

    let mut output = String::new();
    writeln!(&mut output, "Host {host_alias}")?;
    if let Some(user) = ssh_user {
        writeln!(&mut output, "  User {user}")?;
    }
    writeln!(&mut output, "  HostName {target}")?;
    writeln!(
        &mut output,
        "  ProxyCommand {}",
        native_proxy_command(portl_bin, ssh_user.is_some())
    )?;
    writeln!(&mut output, "  ForwardAgent yes")?;
    writeln!(&mut output, "  ServerAliveInterval 30")?;
    writeln!(&mut output, "  ServerAliveCountMax 3")?;
    writeln!(&mut output, "  HostKeyAlias portl-{target}")?;
    writeln!(&mut output, "  UserKnownHostsFile ~/.portl/ssh/known_hosts")?;
    Ok(output)
}

fn render_sshd_proxy_config(
    target: &str,
    host_alias: &str,
    remote_host: &str,
    remote_port: u16,
    portl_bin: &str,
    ssh_user: Option<&str>,
) -> Result<String> {
    validate_exact_tcp_target(remote_host, remote_port)?;
    validate_ssh_config_token("target", target)?;
    validate_ssh_config_token("host alias", host_alias)?;
    validate_ssh_config_token("remote host", remote_host)?;
    validate_ssh_config_token("portl binary", portl_bin)?;
    if let Some(user) = ssh_user {
        validate_ssh_config_token("user", user)?;
    }

    let mut output = String::new();
    writeln!(&mut output, "Host {host_alias}")?;
    if let Some(user) = ssh_user {
        writeln!(&mut output, "  User {user}")?;
    }
    writeln!(&mut output, "  HostName {target}")?;
    writeln!(&mut output, "  Port {remote_port}")?;
    writeln!(
        &mut output,
        "  ProxyCommand {portl_bin} ssh-proxy %h --host {remote_host} --port %p"
    )?;
    Ok(output)
}

fn native_proxy_command(portl_bin: &str, map_ssh_user: bool) -> String {
    let map_user_arg = if map_ssh_user { " --map-ssh-user" } else { "" };
    if Path::new(portl_bin)
        .file_name()
        .and_then(|name| name.to_str())
        == Some("portl-ssh")
    {
        format!("{portl_bin} --stdio{map_user_arg} %h")
    } else {
        format!("{portl_bin} ssh --stdio{map_user_arg} %h")
    }
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
                | b'*'
                | b'?'
                | b'['
                | b']'
        )
}

#[cfg(test)]
mod tests {
    use super::{native_proxy_command, render_config};
    use crate::SshConfigMode;

    #[test]
    fn ssh_config_native_proxycommand_is_default_shape() {
        let config = render_config(
            SshConfigMode::NativeProxycommand,
            "vn3",
            None,
            "ignored",
            22,
            "portl",
            None,
        )
        .expect("render native config");
        assert_eq!(
            config,
            "Host vn3\n  HostName vn3\n  ProxyCommand portl ssh --stdio %h\n  ForwardAgent yes\n  ServerAliveInterval 30\n  ServerAliveCountMax 3\n  HostKeyAlias portl-vn3\n  UserKnownHostsFile ~/.portl/ssh/known_hosts\n"
        );
    }

    #[test]
    fn ssh_config_native_proxycommand_can_pin_target_user() {
        let config = render_config(
            SshConfigMode::NativeProxycommand,
            "onyx",
            None,
            "ignored",
            22,
            "portl",
            Some("thinh_nguyen"),
        )
        .expect("render native config");
        assert_eq!(
            config,
            "Host onyx\n  User thinh_nguyen\n  HostName onyx\n  ProxyCommand portl ssh --stdio --map-ssh-user %h\n  ForwardAgent yes\n  ServerAliveInterval 30\n  ServerAliveCountMax 3\n  HostKeyAlias portl-onyx\n  UserKnownHostsFile ~/.portl/ssh/known_hosts\n"
        );
    }

    #[test]
    fn ssh_config_native_proxycommand_uses_host_alias_but_stable_target_host_key_alias() {
        let config = render_config(
            SshConfigMode::NativeProxycommand,
            "vn3",
            Some("prod-shell"),
            "ignored",
            22,
            "portl",
            None,
        )
        .expect("render native config");
        assert!(config.starts_with("Host prod-shell\n  HostName vn3\n"));
        assert!(config.contains("  HostKeyAlias portl-vn3\n"));
    }

    #[test]
    fn ssh_config_native_proxycommand_accepts_portl_ssh_shim() {
        assert_eq!(
            native_proxy_command("portl-ssh", false),
            "portl-ssh --stdio %h"
        );
        assert_eq!(
            native_proxy_command("/usr/local/bin/portl-ssh", false),
            "/usr/local/bin/portl-ssh --stdio %h"
        );
        assert_eq!(native_proxy_command("portl", false), "portl ssh --stdio %h");
        assert_eq!(
            native_proxy_command("portl", true),
            "portl ssh --stdio --map-ssh-user %h"
        );
    }

    #[test]
    fn ssh_config_sshd_proxy_uses_percent_host_and_port() {
        let config = render_config(
            SshConfigMode::SshdProxy,
            "vn3",
            Some("vn3-sshd"),
            "127.0.0.1",
            2222,
            "portl",
            None,
        )
        .expect("render config");
        assert_eq!(
            config,
            "Host vn3-sshd\n  HostName vn3\n  Port 2222\n  ProxyCommand portl ssh-proxy %h --host 127.0.0.1 --port %p\n"
        );
    }

    #[test]
    fn ssh_config_rejects_wildcard_remote_host() {
        let err = render_config(
            SshConfigMode::SshdProxy,
            "vn3",
            None,
            "*",
            22,
            "portl",
            None,
        )
        .expect_err("wildcard remote host must fail");
        assert!(err.to_string().contains("wildcards"));
    }

    #[test]
    fn ssh_config_rejects_openssh_percent_tokens() {
        let err = render_config(
            SshConfigMode::SshdProxy,
            "vn3",
            None,
            "%n",
            22,
            "portl",
            None,
        )
        .expect_err("percent tokens must fail");
        assert!(err.to_string().contains("unsafe"));
    }

    #[test]
    fn ssh_config_rejects_shell_globs() {
        for value in ["portl?", "portl[0]", "portl*"] {
            let err = render_config(
                SshConfigMode::SshdProxy,
                "vn3",
                None,
                "127.0.0.1",
                22,
                value,
                None,
            )
            .expect_err("glob metacharacters must fail");
            assert!(err.to_string().contains("unsafe"));
        }
    }

    #[test]
    fn ssh_config_rejects_wildcard_host_patterns() {
        let target_err = render_config(
            SshConfigMode::NativeProxycommand,
            "*",
            None,
            "ignored",
            22,
            "portl",
            None,
        )
        .expect_err("wildcard target must fail");
        assert!(target_err.to_string().contains("unsafe"));

        let alias_err = render_config(
            SshConfigMode::NativeProxycommand,
            "vn3",
            Some("*"),
            "ignored",
            22,
            "portl",
            None,
        )
        .expect_err("wildcard host alias must fail");
        assert!(alias_err.to_string().contains("unsafe"));
    }

    #[test]
    fn ssh_config_rejects_shell_metacharacters() {
        let err = render_config(
            SshConfigMode::SshdProxy,
            "vn3;rm",
            None,
            "127.0.0.1",
            22,
            "portl",
            None,
        )
        .expect_err("unsafe target must fail");
        assert!(err.to_string().contains("unsafe"));
    }
}

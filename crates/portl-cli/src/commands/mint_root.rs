use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::Ticket;
use portl_core::id::{Identity, store};
use portl_core::ticket::mint::{mint_delegated, mint_root};
use portl_core::ticket::schema::{
    Capabilities, EnvPolicy, MetaCaps, PortRule, ShellCaps, UnixCaps, UnixPathRule,
    validate_unix_path_rule,
};
use qrcode::QrCode;
use qrcode::render::unicode;

use crate::MintRootPrint;

const TICKET_EXPLORER_URL: &str = "https://ticket.iroh.computer/#";
const ONE_YEAR_SECONDS: u64 = 365 * 24 * 60 * 60;

pub fn run(
    caps: Option<&str>,
    ttl: &str,
    to: Option<&str>,
    from: Option<&str>,
    print: MintRootPrint,
    endpoint: Option<&str>,
    list_caps: bool,
) -> Result<ExitCode> {
    if list_caps {
        print!("{}", caps_reference());
        return Ok(ExitCode::SUCCESS);
    }
    let caps = caps.context(
        "missing <CAPS> argument; run `portl ticket caps` \
         for the capability reference",
    )?;
    let identity = store::load(&store::default_path())?;
    let caps = parse_caps(caps).with_context(|| {
        format!(
            "parse capability spec '{caps}'\n\n{}",
            caps_reference_short()
        )
    })?;
    let ttl_secs = parse_ttl(ttl)?;
    let to = to.map(parse_endpoint_bytes).transpose()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let not_after = now.checked_add(ttl_secs).context("ttl overflows u64")?;

    let ticket = if let Some(parent) = from {
        let parent = parse_ticket(parent)?;
        mint_delegated(identity.signing_key(), &parent, caps, now, not_after, to)?
    } else {
        let addr = endpoint
            .map(parse_endpoint_addr)
            .transpose()?
            .unwrap_or_else(|| local_endpoint_addr(&identity));
        mint_root(identity.signing_key(), addr, caps, now, not_after, to)?
    };
    let ticket_uri = ticket.serialize();

    match print {
        MintRootPrint::String => println!("{ticket_uri}"),
        MintRootPrint::Qr => {
            let qr = QrCode::new(ticket_uri.as_bytes()).context("encode QR")?;
            let rendered = qr.render::<unicode::Dense1x2>().build();
            println!("{rendered}");
        }
        MintRootPrint::Url => println!("{TICKET_EXPLORER_URL}{ticket_uri}"),
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn parse_caps(spec: &str) -> Result<Capabilities> {
    if spec == "all" {
        return Ok(all_caps());
    }

    let mut shell = None;
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    let mut unix_connect = Vec::new();
    let mut unix_listen = Vec::new();
    let mut meta = None::<MetaCaps>;

    for entry in spec.split(',').filter(|entry| !entry.is_empty()) {
        match entry {
            "shell" | "session" => {
                shell = Some(default_shell_caps());
            }
            "exec" => {
                shell = Some(exec_shell_caps());
            }
            "dev" => return Ok(all_caps()),
            "meta:ping" => {
                meta.get_or_insert(MetaCaps {
                    ping: false,
                    info: false,
                })
                .ping = true;
            }
            "meta:info" => {
                meta.get_or_insert(MetaCaps {
                    ping: false,
                    info: false,
                })
                .info = true;
            }
            _ if entry.starts_with("tcp:") => tcp.push(parse_port_rule(&entry[4..])?),
            _ if entry.starts_with("udp:") => udp.push(parse_port_rule(&entry[4..])?),
            _ if entry.starts_with("unix:connect:") => {
                unix_connect.push(parse_unix_path_rule(&entry[13..])?);
            }
            _ if entry.starts_with("unix:listen:") => {
                unix_listen.push(parse_unix_path_rule(&entry[12..])?);
            }
            _ => bail!(
                "unsupported cap '{entry}'\n\
                 valid caps: shell, exec, session, dev, meta:ping, meta:info, \
                 tcp:<host>:<port>[-<port>], udp:<host>:<port>[-<port>], \
                 unix:connect:<path>, unix:listen:<path>, all\n\
                 run `portl ticket caps` for the full reference"
            ),
        }
    }

    sort_and_validate_rules(&mut tcp)?;
    sort_and_validate_rules(&mut udp)?;
    sort_and_validate_unix_rules(&mut unix_connect, "unix:connect")?;
    sort_and_validate_unix_rules(&mut unix_listen, "unix:listen")?;

    let tcp = (!tcp.is_empty()).then_some(tcp);
    let udp = (!udp.is_empty()).then_some(udp);
    let unix = (!unix_connect.is_empty() || !unix_listen.is_empty()).then_some(UnixCaps {
        connect: unix_connect,
        listen: unix_listen,
    });
    let presence = u8::from(shell.is_some())
        | (u8::from(tcp.is_some()) << 1)
        | (u8::from(udp.is_some()) << 2)
        | (u8::from(meta.is_some()) << 5)
        | (u8::from(unix.is_some()) << 6);

    if presence == 0 {
        bail!("at least one capability is required");
    }

    Ok(Capabilities {
        presence,
        shell,
        tcp,
        udp,
        fs: None,
        vpn: None,
        meta,
        unix,
    })
}

/// Full human-readable reference dumped by `portl ticket caps`.
pub(crate) fn caps_reference() -> String {
    "\
Capability reference for `portl ticket issue`

Caps are comma-separated. Any combination can be granted in one
ticket. Use `all` as a wildcard only for dev / self-trust.

  shell
      Full shell access — PTY allowed, exec allowed, no env filter.
      Grants `portl shell <target>` and `portl exec <target> <cmd>`.

  exec
      Non-PTY exec access only. Grants `portl exec <target> -- <cmd>`;
      does not grant `portl shell` or persistent sessions.

  session
      Persistent-session access for v0.4.0. Encoded as shell PTY/exec
      caps today; user-facing denials use session vocabulary. Dedicated
      SessionCaps are deferred.

  dev
      Alias for `all`: shell + exec + session plus TCP/UDP/Unix/meta conveniences.

  meta:ping
      Respond to liveness pings. Pairs well with uptime monitoring;
      does NOT expose identity or version.

  meta:info
      Expose agent metadata (version, uptime, feature flags).
      Use with `portl status <ticket>`.

  tcp:<host_glob>:<port>
  tcp:<host_glob>:<port_min>-<port_max>
      TCP port forward. `<host_glob>` is matched against target
      hostnames; `*` matches everything. `<port>` or range is
      matched against destination port.
      Grants `portl tcp <target> -L <local>:<host>:<port>`.

  udp:<host_glob>:<port>
  udp:<host_glob>:<port_min>-<port_max>
      UDP port forward. Same semantics as tcp:… but for UDP.
      Grants `portl udp <target> -L <local>:<host>:<port>`.

  unix:connect:<path>
      Permit connecting to a target-side Unix-domain socket path.
      Grants `portl socket --local <path> --connect <path> <target>`.

  unix:listen:<path>
      Permit binding a target-side Unix-domain socket path and reverse-forwarding
      connections back to a local Unix socket.
      Grants `portl socket --local <path> --listen <path> <target>`.

  all
      Wildcard — grants every cap above with `*:1-65535` for
      tcp/udp and `*` Unix paths. Intended for self-trust / dev,
      not production.

Examples:

  portl ticket issue shell --ttl 10m
  portl ticket issue session --ttl 1d
  portl ticket issue exec --ttl 10m
  portl ticket issue 'shell,tcp:*:8080' --ttl 1h
  portl ticket issue 'tcp:127.0.0.1:6000-6100' --ttl 30m
  portl ticket issue 'unix:listen:/tmp/portl-*' --ttl 10m
  portl ticket issue 'meta:ping,meta:info' --ttl 30d
  portl ticket issue all --ttl 1h       # dev only
"
    .to_owned()
}

/// Abbreviated reference for error messages (keeps the failure
/// output narrow).
pub(crate) fn caps_reference_short() -> String {
    "valid caps: shell | exec | session | dev | meta:ping | meta:info | tcp:<host>:<range> | udp:<host>:<range> | unix:connect:<path> | unix:listen:<path> | all\n\
     full reference: portl ticket caps"
        .to_owned()
}

fn all_caps() -> Capabilities {
    Capabilities {
        presence: 0b0110_0111,
        shell: Some(default_shell_caps()),
        tcp: Some(vec![PortRule {
            host_glob: "*".to_owned(),
            port_min: 1,
            port_max: u16::MAX,
        }]),
        udp: Some(vec![PortRule {
            host_glob: "*".to_owned(),
            port_min: 1,
            port_max: u16::MAX,
        }]),
        fs: None,
        vpn: None,
        meta: Some(MetaCaps {
            ping: true,
            info: true,
        }),
        unix: Some(UnixCaps {
            connect: vec![UnixPathRule {
                path: "*".to_owned(),
            }],
            listen: vec![UnixPathRule {
                path: "*".to_owned(),
            }],
        }),
    }
}

fn default_shell_caps() -> ShellCaps {
    ShellCaps {
        pty_allowed: true,
        exec_allowed: true,
        user_allowlist: None,
        command_allowlist: None,
        env_policy: EnvPolicy::Deny,
    }
}

fn exec_shell_caps() -> ShellCaps {
    ShellCaps {
        pty_allowed: false,
        exec_allowed: true,
        user_allowlist: None,
        command_allowlist: None,
        env_policy: EnvPolicy::Deny,
    }
}

fn parse_port_rule(spec: &str) -> Result<PortRule> {
    let (host_glob, ports) = spec
        .rsplit_once(':')
        .context("port rule must look like host:min-max")?;
    let (port_min, port_max) = ports
        .split_once('-')
        .context("port range must look like min-max")?;
    let port_min = port_min.parse::<u16>().context("invalid port_min")?;
    let port_max = port_max.parse::<u16>().context("invalid port_max")?;
    if port_min > port_max {
        bail!("port_min must be <= port_max");
    }

    Ok(PortRule {
        host_glob: host_glob.to_owned(),
        port_min,
        port_max,
    })
}

fn parse_unix_path_rule(spec: &str) -> Result<UnixPathRule> {
    validate_unix_path_rule(spec, false).map_err(anyhow::Error::msg)?;
    Ok(UnixPathRule {
        path: spec.to_owned(),
    })
}

fn sort_and_validate_unix_rules(rules: &mut [UnixPathRule], name: &str) -> Result<()> {
    rules.sort_by(|left, right| left.path.cmp(&right.path));
    for window in rules.windows(2) {
        let [left, right] = window else { continue };
        if left.path == right.path {
            bail!("duplicate {name} rule");
        }
    }
    Ok(())
}

fn sort_and_validate_rules(rules: &mut [PortRule]) -> Result<()> {
    rules.sort_by(|left, right| {
        left.host_glob
            .cmp(&right.host_glob)
            .then(left.port_min.cmp(&right.port_min))
            .then(left.port_max.cmp(&right.port_max))
    });

    for window in rules.windows(2) {
        let [left, right] = window else { continue };
        if left.host_glob == right.host_glob
            && left.port_min == right.port_min
            && left.port_max == right.port_max
        {
            bail!("duplicate port rule");
        }
    }

    Ok(())
}

pub(crate) fn parse_ttl(spec: &str) -> Result<u64> {
    let (value, unit) = spec.split_at(spec.len().checked_sub(1).context("ttl is empty")?);
    let value = value
        .parse::<u64>()
        .context("ttl value must be an integer")?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "y" => ONE_YEAR_SECONDS,
        _ => bail!("ttl unit must be one of s, m, h, d, y"),
    };
    value.checked_mul(multiplier).context("ttl overflows u64")
}

fn parse_ticket(spec: &str) -> Result<portl_core::ticket::schema::PortlTicket> {
    <portl_core::ticket::schema::PortlTicket as Ticket>::deserialize(spec)
        .map_err(|err| anyhow!("parse parent ticket: {err}"))
}

fn local_endpoint_addr(identity: &Identity) -> EndpointAddr {
    EndpointAddr::new(
        EndpointId::from_bytes(&identity.verifying_key())
            .expect("identity pubkey is a valid endpoint id"),
    )
}

fn parse_endpoint_addr(spec: &str) -> Result<EndpointAddr> {
    let bytes = parse_endpoint_bytes(spec)?;
    let endpoint_id = EndpointId::from_bytes(&bytes).context("invalid endpoint id")?;
    Ok(EndpointAddr::new(endpoint_id))
}

pub(crate) fn parse_endpoint_bytes(spec: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(spec).context("endpoint id must be hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("endpoint id must be exactly 32 bytes"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::parse_caps;

    #[test]
    fn parse_caps_accepts_unix_connect_and_listen_rules() {
        let caps = parse_caps("unix:connect:/run/agent.sock,unix:listen:/tmp/portl-*").unwrap();
        assert_eq!(caps.presence, 0b0100_0000);
        let unix = caps.unix.expect("unix caps");
        assert_eq!(unix.connect[0].path, "/run/agent.sock");
        assert_eq!(unix.listen[0].path, "/tmp/portl-*");
    }

    #[test]
    fn parse_caps_rejects_broad_unix_wildcard() {
        let err = parse_caps("unix:connect:*").expect_err("broad unix wildcard should fail");
        assert!(err.to_string().contains("broad unix wildcard"));
    }
}

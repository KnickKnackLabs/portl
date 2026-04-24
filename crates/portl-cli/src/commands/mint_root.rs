use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::Ticket;
use portl_core::id::{Identity, store};
use portl_core::ticket::mint::{mint_delegated, mint_root};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, MetaCaps, PortRule, ShellCaps};
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
    let mut meta = None::<MetaCaps>;

    for entry in spec.split(',').filter(|entry| !entry.is_empty()) {
        match entry {
            "shell" => {
                shell = Some(default_shell_caps());
            }
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
            _ => bail!(
                "unsupported cap '{entry}'\n\
                 valid caps: shell, meta:ping, meta:info, \
                 tcp:<host>:<port>[-<port>], udp:<host>:<port>[-<port>], all\n\
                 run `portl ticket caps` for the full reference"
            ),
        }
    }

    sort_and_validate_rules(&mut tcp)?;
    sort_and_validate_rules(&mut udp)?;

    let tcp = (!tcp.is_empty()).then_some(tcp);
    let udp = (!udp.is_empty()).then_some(udp);
    let presence = u8::from(shell.is_some())
        | (u8::from(tcp.is_some()) << 1)
        | (u8::from(udp.is_some()) << 2)
        | (u8::from(meta.is_some()) << 5);

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

  all
      Wildcard — grants every cap above with `*:1-65535` for
      tcp/udp. Intended for self-trust / dev, not production.

Examples:

  portl ticket issue shell --ttl 10m
  portl ticket issue 'shell,tcp:*:8080' --ttl 1h
  portl ticket issue 'tcp:127.0.0.1:6000-6100' --ttl 30m
  portl ticket issue 'meta:ping,meta:info' --ttl 30d
  portl ticket issue all --ttl 1h       # dev only
"
    .to_owned()
}

/// Abbreviated reference for error messages (keeps the failure
/// output narrow).
pub(crate) fn caps_reference_short() -> String {
    "valid caps: shell | meta:ping | meta:info | tcp:<host>:<range> | udp:<host>:<range> | all\n\
     full reference: portl ticket caps"
        .to_owned()
}

fn all_caps() -> Capabilities {
    Capabilities {
        presence: 0b0010_0111,
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

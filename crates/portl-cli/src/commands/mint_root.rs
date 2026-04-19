use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::Ticket;
use portl_core::id::store;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, MetaCaps, PortRule, ShellCaps};
use qrcode::QrCode;
use qrcode::render::unicode;

use crate::MintRootPrint;

const TICKET_EXPLORER_URL: &str = "https://ticket.iroh.computer/#";
const ONE_YEAR_SECONDS: u64 = 365 * 24 * 60 * 60;

pub fn run(
    endpoint: &str,
    caps: &str,
    ttl: &str,
    to: Option<&str>,
    depth: Option<u8>,
    print: MintRootPrint,
) -> Result<ExitCode> {
    let identity = store::load(&store::default_path())?;
    let addr = parse_endpoint_addr(endpoint)?;
    let caps = parse_caps(caps)?;
    let ttl_secs = parse_ttl(ttl)?;
    let to = to.map(parse_endpoint_bytes).transpose()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let not_after = now.checked_add(ttl_secs).context("ttl overflows u64")?;

    if let Some(depth) = depth {
        eprintln!("warning: ignoring --depth={depth} for root tickets in M1");
    }

    let ticket = mint_root(identity.signing_key(), addr, caps, now, not_after, to)?;
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

fn parse_caps(spec: &str) -> Result<Capabilities> {
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
            _ => bail!("unsupported cap {entry}"),
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

fn parse_ttl(spec: &str) -> Result<u64> {
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

fn parse_endpoint_addr(spec: &str) -> Result<EndpointAddr> {
    let bytes = parse_endpoint_bytes(spec)?;
    let endpoint_id = EndpointId::from_bytes(&bytes).context("invalid endpoint id")?;
    Ok(EndpointAddr::new(endpoint_id))
}

fn parse_endpoint_bytes(spec: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(spec).context("endpoint id must be hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("endpoint id must be exactly 32 bytes"))?;
    Ok(bytes)
}

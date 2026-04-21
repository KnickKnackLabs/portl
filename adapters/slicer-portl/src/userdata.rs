use std::ffi::OsString;
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result, anyhow, bail};

const TEMPLATE: &str = include_str!("userdata/install.sh.tmpl");
const ENV_HEREDOC_START: &str = "cat > /etc/portl/agent.env <<'ENV'\n";
const ENV_HEREDOC_END: &str = "\nENV";
static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
const AGENT_ENV_VARS: &[&str] = &[
    "PORTL_HOME",
    "PORTL_IDENTITY_SECRET_HEX",
    "PORTL_TRUST_ROOTS",
    "PORTL_LISTEN_ADDR",
    "PORTL_DISCOVERY",
    "PORTL_METRICS",
    "PORTL_REVOCATIONS_PATH",
    "PORTL_RATE_LIMIT",
    "PORTL_UDP_SESSION_LINGER_SECS",
    "PORTL_MODE",
];

pub struct UserdataContext<'a> {
    pub secret_name: &'a str,
    pub portl_release_url: &'a str,
    pub relay_list: &'a [String],
    pub operator_pubkey: &'a str,
}

pub fn render(context: &UserdataContext<'_>) -> Result<String> {
    validate_safe("secret_name", context.secret_name)?;
    validate_safe("portl_release_url", context.portl_release_url)?;
    validate_safe("operator_pubkey", context.operator_pubkey)?;
    if let Some(relay) = context.relay_list.first() {
        validate_safe("relay", relay)?;
    }

    let mut rendered = TEMPLATE.to_owned();
    for (needle, replacement) in [
        ("{{SECRET_NAME}}", context.secret_name.to_owned()),
        (
            "{{PORTL_RELEASE_URL}}",
            context.portl_release_url.to_owned(),
        ),
        ("{{DISCOVERY}}", discovery_value(context.relay_list)),
        ("{{OPERATOR_PUBKEY}}", context.operator_pubkey.to_owned()),
    ] {
        rendered = rendered.replace(needle, &replacement);
    }
    if rendered.contains("{{") {
        bail!("userdata template contains unsubstituted placeholders");
    }

    let agent_env = extract_agent_env(&rendered)?;
    validate_agent_env(agent_env).context("validate rendered agent env")?;

    Ok(rendered)
}

fn validate_safe(name: &str, value: &str) -> Result<()> {
    for c in value.chars() {
        if !c.is_ascii_alphanumeric() && !matches!(c, '_' | '-' | '.' | '/' | ':' | '=') {
            bail!("unsafe character {c:?} in {name} value {value:?}");
        }
    }
    Ok(())
}

fn discovery_value(_relay_list: &[String]) -> String {
    "dns,pkarr,local,relay".to_owned()
}

fn extract_agent_env(rendered: &str) -> Result<&str> {
    let start = rendered
        .find(ENV_HEREDOC_START)
        .map(|index| index + ENV_HEREDOC_START.len())
        .ok_or_else(|| anyhow!("userdata template missing agent env heredoc start"))?;
    let end = rendered[start..]
        .find(ENV_HEREDOC_END)
        .map(|index| start + index)
        .ok_or_else(|| anyhow!("userdata template missing agent env heredoc end"))?;
    Ok(&rendered[start..end])
}

fn validate_agent_env(agent_env: &str) -> Result<()> {
    config_from_agent_env(agent_env).map(|_| ())
}

fn config_from_agent_env(agent_env: &str) -> Result<portl_agent::AgentConfig> {
    let vars = agent_env
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid agent env line: {line}"))?;
            Ok((key.to_owned(), OsString::from(value)))
        })
        .collect::<Result<Vec<_>>>()?;

    with_agent_env(&vars, portl_agent::AgentConfig::from_env)
}

#[allow(unsafe_code)]
fn with_agent_env<T>(vars: &[(String, OsString)], f: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let saved = AGENT_ENV_VARS
        .iter()
        .map(|name| (*name, std::env::var_os(name)))
        .collect::<Vec<_>>();
    for name in AGENT_ENV_VARS {
        // SAFETY: the validator serializes process env mutation with ENV_LOCK.
        unsafe { std::env::remove_var(name) };
    }
    for (name, value) in vars {
        // SAFETY: the validator serializes process env mutation with ENV_LOCK.
        unsafe { std::env::set_var(name, value) };
    }

    let result = f();

    for (name, value) in saved {
        match value {
            Some(value) => {
                // SAFETY: the validator serializes process env mutation with ENV_LOCK.
                unsafe { std::env::set_var(name, value) };
            }
            None => {
                // SAFETY: the validator serializes process env mutation with ENV_LOCK.
                unsafe { std::env::remove_var(name) };
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::{UserdataContext, config_from_agent_env, extract_agent_env, render};

    #[test]
    fn render_substitutes_every_placeholder() {
        let rendered = render(&UserdataContext {
            secret_name: "portl-demo",
            portl_release_url: "example.invalid/releases",
            relay_list: &["https://relay.example.invalid".to_owned()],
            operator_pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        })
        .expect("render userdata");

        assert!(rendered.contains("/run/slicer/secrets/portl-demo"));
        assert!(rendered.contains("example.invalid/releases"));
        assert!(rendered.contains("PORTL_DISCOVERY=dns,pkarr,local,relay"));
        assert!(rendered.contains("0123456789abcdef0123456789abcdef"));
        assert!(!rendered.contains("{{"));
    }

    #[test]
    fn render_rejects_unsafe_shell_substitutions() {
        let err = render(&UserdataContext {
            secret_name: "portl-demo$(whoami)",
            portl_release_url: "example.invalid/releases",
            relay_list: &[],
            operator_pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        })
        .expect_err("unsafe shell substitution must be rejected");
        assert!(err.to_string().contains("unsafe character"));
    }

    #[test]
    fn renders_valid_agent_env() {
        let rendered = render(&UserdataContext {
            secret_name: "portl-demo",
            portl_release_url: "example.invalid/releases",
            relay_list: &[],
            operator_pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        })
        .expect("render userdata");
        let agent_env = extract_agent_env(&rendered).expect("extract agent env");

        let config = config_from_agent_env(agent_env).expect("parse rendered env");
        assert_eq!(config.trust_roots.len(), 1);
        assert_eq!(
            config.identity_path.as_deref(),
            Some(std::path::Path::new("/var/lib/portl/identity.bin"))
        );
    }
}

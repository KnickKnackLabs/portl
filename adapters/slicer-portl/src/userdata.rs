use anyhow::{Context, Result, anyhow, bail};

const TEMPLATE: &str = include_str!("userdata/install.sh.tmpl");
const TOML_HEREDOC_START: &str = "cat > /etc/portl/agent.toml <<'TOML'\n";
const TOML_HEREDOC_END: &str = "\nTOML";

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
        ("{{RELAY_LINE}}", relay_line(context.relay_list)),
        ("{{OPERATOR_PUBKEY}}", context.operator_pubkey.to_owned()),
    ] {
        rendered = rendered.replace(needle, &replacement);
    }
    if rendered.contains("{{") {
        bail!("userdata template contains unsubstituted placeholders");
    }

    let agent_toml = extract_agent_toml(&rendered)?;
    portl_agent::AgentConfig::from_toml_str(agent_toml)
        .context("validate rendered agent config TOML")?;

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

fn relay_line(relay_list: &[String]) -> String {
    match relay_list.first() {
        Some(relay) => format!("relay = \"{relay}\""),
        None => String::from("# relay omitted"),
    }
}

fn extract_agent_toml(rendered: &str) -> Result<&str> {
    let start = rendered
        .find(TOML_HEREDOC_START)
        .map(|index| index + TOML_HEREDOC_START.len())
        .ok_or_else(|| anyhow!("userdata template missing agent TOML heredoc start"))?;
    let end = rendered[start..]
        .find(TOML_HEREDOC_END)
        .map(|index| start + index)
        .ok_or_else(|| anyhow!("userdata template missing agent TOML heredoc end"))?;
    Ok(&rendered[start..end])
}

#[cfg(test)]
mod tests {
    use super::{UserdataContext, extract_agent_toml, render};

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
        assert!(rendered.contains("relay = \"https://relay.example.invalid\""));
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
    fn renders_valid_agent_toml() {
        let rendered = render(&UserdataContext {
            secret_name: "portl-demo",
            portl_release_url: "example.invalid/releases",
            relay_list: &[],
            operator_pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        })
        .expect("render userdata");
        let agent_toml = extract_agent_toml(&rendered).expect("extract agent toml");

        let config =
            portl_agent::AgentConfig::from_toml_str(agent_toml).expect("parse rendered TOML");
        assert!(!agent_toml.contains("relay = ["));
        assert_eq!(config.trust_roots.len(), 1);
    }
}

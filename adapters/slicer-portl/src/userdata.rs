use anyhow::{Result, bail};

const TEMPLATE: &str = include_str!("userdata/install.sh.tmpl");

pub struct UserdataContext<'a> {
    pub secret_name: &'a str,
    pub portl_release_url: &'a str,
    pub relay_list: &'a [String],
    pub operator_pubkey: &'a str,
}

pub fn render(context: &UserdataContext<'_>) -> Result<String> {
    let mut rendered = TEMPLATE.to_owned();
    for (needle, replacement) in [
        ("{{SECRET_NAME}}", context.secret_name.to_owned()),
        (
            "{{PORTL_RELEASE_URL}}",
            context.portl_release_url.to_owned(),
        ),
        ("{{RELAY_LIST}}", serde_json::to_string(context.relay_list)?),
        ("{{OPERATOR_PUBKEY}}", context.operator_pubkey.to_owned()),
    ] {
        rendered = rendered.replace(needle, &replacement);
    }
    if rendered.contains("{{") {
        bail!("userdata template contains unsubstituted placeholders");
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::{UserdataContext, render};

    #[test]
    fn render_substitutes_every_placeholder() {
        let rendered = render(&UserdataContext {
            secret_name: "portl-demo",
            portl_release_url: "example.invalid/releases",
            relay_list: &["https://relay.example.invalid".to_owned()],
            operator_pubkey: "deadbeef",
        })
        .expect("render userdata");

        assert!(rendered.contains("/run/slicer/secrets/portl-demo"));
        assert!(rendered.contains("example.invalid/releases"));
        assert!(rendered.contains("https://relay.example.invalid"));
        assert!(rendered.contains("deadbeef"));
        assert!(!rendered.contains("{{"));
    }
}

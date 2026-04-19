use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use portl_agent::run_task;
use portl_core::id::{Identity, store};
use portl_core::net::open_ticket_v1;
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, MetaCaps};
use tempfile::tempdir;

#[tokio::test]
async fn agent_run_loads_toml_config_and_accepts_configured_root() -> Result<()> {
    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    let revocations_path = home.path().join("revocations.json");
    let operator = Identity::new();
    let agent_identity = Identity::new();
    store::save(&agent_identity, &identity_path)?;

    let config_path = home.path().join("agent.toml");
    std::fs::write(
        &config_path,
        format!(
            "identity_path = \"{}\"\nrevocations_path = \"{}\"\ntrust_roots = [\"{}\"]\n\n[discovery]\ndns = false\npkarr = false\nlocal = true\n\n[rate_limit]\nperiod_secs = 5\nburst = 10\n",
            identity_path.display(),
            revocations_path.display(),
            hex::encode(operator.verifying_key()),
        ),
    )?;

    let (client, server) = pair().await?;
    let mut cfg = portl_cli::load_agent_config(Some(config_path.as_path()))?;
    assert_eq!(cfg.identity_path.as_deref(), Some(identity_path.as_path()));
    assert_eq!(
        cfg.revocations_path.as_deref(),
        Some(revocations_path.as_path())
    );
    assert_eq!(cfg.trust_roots, vec![operator.verifying_key()]);
    cfg.endpoint = Some(server.clone());

    let agent = run_task(cfg).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let ticket = mint_root(
        operator.signing_key(),
        server.addr(),
        meta_caps(),
        now,
        now + 300,
        None,
    )?;

    let (_connection, session) = open_ticket_v1(&client, &ticket, &[], &Identity::new()).await?;
    assert_eq!(session.effective_caps, meta_caps());

    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

#[test]
fn agent_run_rejects_invalid_trust_root_hex() {
    let home = tempdir().expect("tempdir");
    let config_path = home.path().join("agent.toml");
    std::fs::write(&config_path, "trust_roots = [\"xyz\"]\n").expect("write config");

    let err = portl_cli::load_agent_config(Some(config_path.as_path()))
        .expect_err("invalid trust root hex should fail");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("invalid trust root hex"),
        "unexpected error: {rendered}"
    );
}

fn meta_caps() -> Capabilities {
    Capabilities {
        presence: 0b0010_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: Some(MetaCaps {
            ping: true,
            info: true,
        }),
    }
}

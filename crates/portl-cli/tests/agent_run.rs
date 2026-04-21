use std::ffi::OsString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use portl_agent::run_task;
use portl_core::id::{Identity, store};
use portl_core::net::open_ticket_v1;
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, MetaCaps};
use std::sync::{LazyLock, Mutex};
use tempfile::tempdir;

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

#[tokio::test]
async fn agent_run_loads_env_config_and_accepts_configured_root() -> Result<()> {
    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    let revocations_path = home.path().join("revocations.jsonl");
    let operator = Identity::new();
    let agent_identity = Identity::new();
    store::save(&agent_identity, &identity_path)?;

    let (client, server) = pair().await?;
    let mut cfg = with_env(
        &[
            ("PORTL_HOME", Some(home.path().as_os_str().to_os_string())),
            (
                "PORTL_TRUST_ROOTS",
                Some(OsString::from(hex::encode(operator.verifying_key()))),
            ),
            ("PORTL_DISCOVERY", Some(OsString::from("local"))),
        ],
        portl_cli::load_agent_config,
    )?;
    assert_eq!(cfg.identity_path.as_deref(), Some(identity_path.as_path()));
    assert_eq!(
        cfg.revocations_path.as_deref(),
        Some(revocations_path.as_path())
    );
    assert_eq!(cfg.trust_roots, vec![operator.verifying_key()]);
    assert!(cfg.discovery.local);
    assert!(!cfg.discovery.dns);
    assert!(!cfg.discovery.pkarr);
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
    let err = with_env(
        &[("PORTL_TRUST_ROOTS", Some(OsString::from("xyz")))],
        portl_cli::load_agent_config,
    )
    .expect_err("invalid trust root hex should fail");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("invalid trust root hex"),
        "unexpected error: {rendered}"
    );
}

#[allow(unsafe_code)]
fn with_env<T>(vars: &[(&str, Option<OsString>)], f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let saved = AGENT_ENV_VARS
        .iter()
        .map(|name| (*name, std::env::var_os(name)))
        .collect::<Vec<_>>();
    for name in AGENT_ENV_VARS {
        // SAFETY: tests serialize environment mutation with ENV_LOCK.
        unsafe { std::env::remove_var(name) };
    }
    for (name, value) in vars {
        match value {
            Some(value) => {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                unsafe { std::env::set_var(name, value) };
            }
            None => {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                unsafe { std::env::remove_var(name) };
            }
        }
    }

    let result = f();

    for (name, value) in saved {
        match value {
            Some(value) => {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                unsafe { std::env::set_var(name, value) };
            }
            None => {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                unsafe { std::env::remove_var(name) };
            }
        }
    }

    result
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

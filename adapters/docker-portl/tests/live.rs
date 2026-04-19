use anyhow::Result;
use docker_portl::DockerBootstrapper;
use portl_core::bootstrap::{Bootstrapper, TargetSpec, TargetStatus};
use portl_core::ticket::schema::Capabilities;

fn empty_caps() -> Capabilities {
    Capabilities {
        presence: 0,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

#[tokio::test]
#[ignore = "requires a live docker daemon and test image"]
async fn provision_cycle_smoke_test() -> Result<()> {
    let bootstrapper = DockerBootstrapper::connect_with_local_defaults(vec![[1; 32]])?;
    let handle = bootstrapper
        .provision(&TargetSpec {
            name: format!("portl-live-{}", std::process::id()),
            image: "portl-agent:local".to_owned(),
            network: "bridge".to_owned(),
            caps: empty_caps(),
            ttl_secs: 60,
            to: None,
            labels: vec![],
        })
        .await?;

    let status = bootstrapper.resolve(&handle).await?;
    assert!(matches!(status, TargetStatus::Running));
    bootstrapper.teardown(&handle).await?;
    Ok(())
}

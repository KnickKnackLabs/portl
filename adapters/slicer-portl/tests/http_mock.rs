use anyhow::Result;
use portl_core::bootstrap::{Bootstrapper, ProvisionSpec, TargetStatus};
use slicer_portl::http::SlicerClient;
use slicer_portl::{SlicerBootstrapper, SlicerHandle};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn provision_resolve_teardown_roundtrip() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/secret"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/vm/add"))
        .and(body_string_contains("demo-group"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "demo-1",
            "group": "demo-group",
            "status": "Provisioning"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/vm/list"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
                "name": "demo-1",
                "group": "demo-group",
                "status": "Running"
            })]),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/vm/demo-1"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let bootstrapper = SlicerBootstrapper::new(SlicerClient::new(&server.uri(), None)?);
    let handle = bootstrapper
        .provision(&ProvisionSpec {
            name: "demo".to_owned(),
            adapter_params: serde_json::json!({
                "base_url": server.uri(),
                "group": "demo-group",
                "cpus": 2,
                "ram_gb": 4,
                "tags": [["agent", "claude"]],
                "relay_list": ["https://relay.example.invalid"],
                "operator_pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "portl_release_url": "example.invalid/releases"
            }),
            labels: vec![("managed_by".to_owned(), "test".to_owned())],
        })
        .await?;

    let inner = SlicerHandle::from_handle(&handle)?;
    assert_eq!(inner.name, "demo-1");
    assert_eq!(inner.group, "demo-group");

    assert_eq!(bootstrapper.resolve(&handle).await?, TargetStatus::Running);
    bootstrapper.teardown(&handle).await?;
    Ok(())
}

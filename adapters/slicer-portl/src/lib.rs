use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::Engine;
use portl_core::bootstrap::{Bootstrapper, Handle, ProvisionSpec, TargetStatus};
use portl_core::id::Identity;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub mod http;
pub mod userdata;

pub const ADAPTER_NAME: &str = "slicer-portl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlicerProvisionParams {
    pub base_url: String,
    pub group: String,
    #[serde(default)]
    pub cpus: Option<u8>,
    #[serde(default)]
    pub ram_gb: Option<u16>,
    #[serde(default)]
    pub tags: Vec<(String, String)>,
    #[serde(default)]
    pub relay_list: Vec<String>,
    pub operator_pubkey: String,
    pub portl_release_url: String,
    #[serde(default)]
    pub session_provider: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlicerHandle {
    pub group: String,
    pub name: String,
    pub endpoint_id: String,
    pub base_url: String,
}

impl SlicerHandle {
    pub fn from_handle(handle: &Handle) -> Result<Self> {
        if handle.adapter != ADAPTER_NAME {
            bail!(
                "expected adapter handle for {ADAPTER_NAME}, found {}",
                handle.adapter
            );
        }
        serde_json::from_value(handle.inner.clone()).context("decode slicer handle")
    }
}

#[derive(Clone)]
pub struct SlicerBootstrapper {
    client: http::SlicerClient,
}

impl SlicerBootstrapper {
    pub fn new(client: http::SlicerClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Bootstrapper for SlicerBootstrapper {
    async fn provision(&self, spec: &ProvisionSpec) -> Result<Handle> {
        let params: SlicerProvisionParams = serde_json::from_value(spec.adapter_params.clone())
            .context("decode slicer adapter_params")?;
        validate_spec(spec, &params)?;

        let identity = Identity::new();
        let endpoint_id = hex::encode(identity.endpoint_id().as_bytes());
        let secret_name = format!("portl-{endpoint_id}");
        let secret_body_b64 =
            base64::engine::general_purpose::STANDARD.encode(identity.signing_key().to_bytes());
        self.client
            .create_secret(&secret_name, &secret_body_b64)
            .await
            .context("upload slicer secret")?;

        let mut tags = params.tags.clone();
        tags.extend(spec.labels.clone());
        tags.push(("portl_endpoint_id".to_owned(), endpoint_id.clone()));
        let userdata = userdata::render(&userdata::UserdataContext {
            secret_name: &secret_name,
            portl_release_url: &params.portl_release_url,
            relay_list: &params.relay_list,
            operator_pubkey: &params.operator_pubkey,
            session_provider: params.session_provider.as_deref(),
        })?;
        let vm = self
            .client
            .add_vm(&http::AddVmRequest {
                group: params.group.clone(),
                cpus: params.cpus,
                ram_gb: params.ram_gb,
                tags,
                userdata,
                secrets: vec![secret_name],
            })
            .await
            .context("create slicer vm")?;

        Ok(Handle {
            adapter: ADAPTER_NAME.to_owned(),
            inner: json!(SlicerHandle {
                group: params.group,
                name: vm.name,
                endpoint_id,
                base_url: params.base_url,
            }),
        })
    }

    async fn register(&self, _handle: &Handle, _endpoint_id: iroh_base::EndpointId) -> Result<()> {
        Ok(())
    }

    async fn resolve(&self, handle: &Handle) -> Result<TargetStatus> {
        let handle = SlicerHandle::from_handle(handle)?;
        let vm = self.client.get_vm(&handle.group, &handle.name).await?;
        Ok(map_status(vm.as_ref().map(|vm| vm.status.as_str())))
    }

    async fn teardown(&self, handle: &Handle) -> Result<()> {
        let handle = SlicerHandle::from_handle(handle)?;
        self.client.delete_vm(&handle.group, &handle.name).await
    }
}

fn validate_spec(spec: &ProvisionSpec, params: &SlicerProvisionParams) -> Result<()> {
    if spec.name.trim().is_empty() {
        bail!("vm alias must not be empty");
    }
    if params.group.trim().is_empty() {
        bail!("slicer group must not be empty");
    }
    if params.base_url.trim().is_empty() {
        bail!("slicer base_url must not be empty");
    }
    if params.operator_pubkey.trim().is_empty() {
        bail!("slicer operator_pubkey must not be empty");
    }
    if params.portl_release_url.trim().is_empty() {
        bail!("slicer portl_release_url must not be empty");
    }
    if let Some(provider) = params.session_provider.as_deref()
        && provider != "zmx"
    {
        bail!("unsupported slicer session_provider '{provider}' (supported: zmx)");
    }
    Ok(())
}

fn map_status(status: Option<&str>) -> TargetStatus {
    match status {
        None => TargetStatus::NotFound,
        Some("running" | "Running") => TargetStatus::Running,
        Some("provisioning" | "Provisioning" | "Created") => TargetStatus::Provisioning,
        Some("stopped" | "Stopped") => TargetStatus::Exited { code: 0 },
        Some(other) => TargetStatus::Unknown(other.to_owned()),
    }
}

pub fn parse_tag(spec: &str) -> Result<(String, String)> {
    let (key, value) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("tag must look like KEY=VALUE: {spec}"))?;
    Ok((key.to_owned(), value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{map_status, parse_tag};
    use portl_core::bootstrap::TargetStatus;

    #[test]
    fn parse_tag_requires_equals() {
        let err = parse_tag("broken").expect_err("tag must fail");
        assert!(err.to_string().contains("KEY=VALUE"));
    }

    #[test]
    fn maps_running_status() {
        assert_eq!(map_status(Some("Running")), TargetStatus::Running);
    }
}

use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct SlicerClient {
    base_url: reqwest::Url,
    http: reqwest::Client,
    auth_token: Option<String>,
}

impl SlicerClient {
    pub fn new(base_url: &str, auth_token: Option<String>) -> Result<Self> {
        portl_core::tls::install_default_crypto_provider();
        Ok(Self {
            base_url: reqwest::Url::parse(base_url)
                .with_context(|| format!("parse slicer base url {base_url}"))?,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(5))
                .build()
                .context("build reqwest client")?,
            auth_token,
        })
    }

    pub async fn create_secret(&self, name: &str, body_b64: &str) -> Result<()> {
        let request = SecretRequest {
            name: name.to_owned(),
            body_b64: body_b64.to_owned(),
        };
        let response = self
            .request(reqwest::Method::POST, "secret")
            .json(&request)
            .send()
            .await
            .context("call slicer POST /secret")?;
        if response.status().is_success() {
            return Ok(());
        }
        bail!("slicer secret upload failed: {}", response.status())
    }

    pub async fn add_vm(&self, req: &AddVmRequest) -> Result<VmRecord> {
        let response = self
            .request(reqwest::Method::POST, "vm/add")
            .json(req)
            .send()
            .await
            .context("call slicer POST /vm/add")?;
        if response.status() != StatusCode::NOT_FOUND {
            return decode_json(response).await;
        }

        let response = self
            .request(
                reqwest::Method::POST,
                &format!("hostgroup/{}/nodes", req.group),
            )
            .json(&HostGroupAddRequest {
                cpus: req.cpus,
                ram_gb: req.ram_gb,
                tags: flatten_tags(&req.tags),
                userdata: req.userdata.clone(),
            })
            .send()
            .await
            .with_context(|| format!("call slicer POST /hostgroup/{}/nodes", req.group))?;
        decode_json(response).await
    }

    pub async fn list_vms(&self) -> Result<Vec<VmRecord>> {
        let response = self
            .request(reqwest::Method::GET, "vm/list")
            .send()
            .await
            .context("call slicer GET /vm/list")?;
        if response.status() != StatusCode::NOT_FOUND {
            return decode_json(response).await;
        }

        let groups: Vec<HostGroupRecord> = decode_json(
            self.request(reqwest::Method::GET, "hostgroup")
                .send()
                .await
                .context("call slicer GET /hostgroup")?,
        )
        .await?;
        let mut vms = Vec::new();
        for group in groups {
            let listed: Vec<VmRecord> = decode_json(
                self.request(
                    reqwest::Method::GET,
                    &format!("hostgroup/{}/nodes", group.name),
                )
                .send()
                .await
                .with_context(|| format!("call slicer GET /hostgroup/{}/nodes", group.name))?,
            )
            .await?;
            vms.extend(listed);
        }
        Ok(vms)
    }

    pub async fn get_vm(&self, group: &str, name: &str) -> Result<Option<VmRecord>> {
        let vms = self.list_vms().await?;
        Ok(vms
            .into_iter()
            .find(|vm| vm.group == group && vm.name == name))
    }

    pub async fn delete_vm(&self, group: &str, name: &str) -> Result<()> {
        let response = self
            .request(reqwest::Method::DELETE, &format!("vm/{name}"))
            .send()
            .await
            .with_context(|| format!("call slicer DELETE /vm/{name}"))?;
        if response.status() == StatusCode::NOT_FOUND {
            let response = self
                .request(
                    reqwest::Method::DELETE,
                    &format!("hostgroup/{group}/nodes/{name}"),
                )
                .send()
                .await
                .with_context(|| format!("call slicer DELETE /hostgroup/{group}/nodes/{name}"))?;
            expect_success(&response, "delete slicer vm")?;
            return Ok(());
        }
        expect_success(&response, "delete slicer vm")?;
        Ok(())
    }

    pub async fn vm_logs(&self, group: &str, name: &str, tail: usize) -> Result<String> {
        let response = self
            .request(reqwest::Method::GET, &format!("vm/{name}/logs"))
            .query(&[("tail", tail)])
            .send()
            .await
            .with_context(|| format!("call slicer GET /vm/{name}/logs"))?;
        if response.status() != StatusCode::NOT_FOUND {
            let body: VmLogsResponse = decode_json(response).await?;
            return Ok(body.content);
        }

        let body: VmLogsResponse = decode_json(
            self.request(
                reqwest::Method::GET,
                &format!("hostgroup/{group}/nodes/{name}/logs"),
            )
            .query(&[("tail", tail)])
            .send()
            .await
            .with_context(|| format!("call slicer GET /hostgroup/{group}/nodes/{name}/logs"))?,
        )
        .await?;
        Ok(body.content)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = self
            .base_url
            .join(path)
            .expect("slicer path joins base url");
        let builder = self.http.request(method, url);
        if let Some(token) = &self.auth_token {
            builder.bearer_auth(token)
        } else {
            builder
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddVmRequest {
    pub group: String,
    pub cpus: Option<u8>,
    pub ram_gb: Option<u16>,
    pub tags: Vec<(String, String)>,
    pub userdata: String,
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmRecord {
    #[serde(alias = "hostname", alias = "vm_id")]
    pub name: String,
    #[serde(default, alias = "hostgroup")]
    pub group: String,
    #[serde(default, alias = "boot_state")]
    pub status: String,
    #[serde(default)]
    pub ip: Option<String>,
}

#[derive(Debug, Serialize)]
struct SecretRequest {
    name: String,
    body_b64: String,
}

#[derive(Debug, Serialize)]
struct HostGroupAddRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    cpus: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ram_gb: Option<u16>,
    tags: Vec<String>,
    userdata: String,
}

#[derive(Debug, Deserialize)]
struct HostGroupRecord {
    name: String,
}

#[derive(Debug, Deserialize)]
struct VmLogsResponse {
    content: String,
}

async fn decode_json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("slicer request failed with {status}: {body}");
    }
    response.json().await.context("decode slicer json response")
}

fn expect_success(response: &reqwest::Response, context: &str) -> Result<()> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        bail!("{context} failed with {status}")
    }
}

fn flatten_tags(tags: &[(String, String)]) -> Vec<String> {
    tags.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

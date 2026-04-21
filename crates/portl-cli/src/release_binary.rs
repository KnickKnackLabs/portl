use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};

const RELEASE_BASE_URL: &str = "https://github.com/KnickKnackLabs/portl/releases/download";

pub fn download_release_binary(tag: &str, target_os: &str, target_arch: &str) -> Result<PathBuf> {
    let triple = release_target_triple(target_os, target_arch)?;
    let cache_dir = std::env::temp_dir()
        .join("portl-release-cache")
        .join(tag)
        .join(triple);
    let extracted = cache_dir
        .join(format!("portl-{tag}-{triple}"))
        .join("portl");
    if extracted.exists() {
        return Ok(extracted);
    }

    fs::create_dir_all(&cache_dir)
        .with_context(|| format!("create release cache {}", cache_dir.display()))?;
    let archive_name = format!("portl-{tag}-{triple}.tar.zst");
    let archive_url = format!("{RELEASE_BASE_URL}/{tag}/{archive_name}");
    let sha_url = format!("{archive_url}.sha256");
    let client = Client::builder()
        .build()
        .context("build release downloader")?;
    let archive = download_bytes(&client, &archive_url)?;
    let sha = download_text(&client, &sha_url)?;
    verify_sha256(&archive, &sha, &archive_name)?;

    let decoder = zstd::stream::read::Decoder::new(Cursor::new(archive))
        .context("open release tar.zst decoder")?;
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(&cache_dir)
        .with_context(|| format!("extract release archive into {}", cache_dir.display()))?;
    if extracted.exists() {
        Ok(extracted)
    } else {
        bail!(
            "release archive {} did not contain {}",
            archive_name,
            extracted.display()
        )
    }
}

pub fn release_target_triple(target_os: &str, target_arch: &str) -> Result<&'static str> {
    match (target_os, target_arch) {
        ("linux", "amd64") => Ok("x86_64-unknown-linux-musl"),
        ("linux", "arm64") => Ok("aarch64-unknown-linux-musl"),
        ("darwin", "amd64") => Ok("x86_64-apple-darwin"),
        ("darwin", "arm64") => Ok("aarch64-apple-darwin"),
        _ => bail!("unsupported release target {target_os}/{target_arch}"),
    }
}

fn download_bytes(client: &Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("download {url}"))?
        .error_for_status()
        .with_context(|| format!("download {url}"))?;
    response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .context("read release bytes")
}

fn download_text(client: &Client, url: &str) -> Result<String> {
    client
        .get(url)
        .send()
        .with_context(|| format!("download {url}"))?
        .error_for_status()
        .with_context(|| format!("download {url}"))?
        .text()
        .context("read release checksum")
}

fn verify_sha256(bytes: &[u8], sidecar: &str, archive_name: &str) -> Result<()> {
    let expected = sidecar
        .split_whitespace()
        .next()
        .context("parse sha256 sidecar")?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual == expected {
        Ok(())
    } else {
        bail!("sha256 mismatch for {archive_name}: expected {expected}, got {actual}")
    }
}

#[cfg(test)]
mod tests {
    use super::release_target_triple;

    #[test]
    fn release_triples_cover_supported_targets() {
        assert_eq!(
            release_target_triple("linux", "amd64").expect("linux amd64"),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            release_target_triple("linux", "arm64").expect("linux arm64"),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            release_target_triple("darwin", "amd64").expect("darwin amd64"),
            "x86_64-apple-darwin"
        );
    }
}

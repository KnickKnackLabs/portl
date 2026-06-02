use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::json;
use zip::write::SimpleFileOptions;

pub(crate) struct BundleInput<'a> {
    pub doctor_json: serde_json::Value,
    pub output: Option<&'a Path>,
}

pub(crate) fn collect(input: &BundleInput<'_>) -> Result<PathBuf> {
    let path = resolve_bundle_path(input.output)?;
    if path.exists() {
        bail!("bundle output already exists: {}", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create bundle output directory {}", parent.display()))?;
    }

    let file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    add_json(&mut zip, options, "manifest.json", &manifest())?;
    add_json(&mut zip, options, "doctor.json", &input.doctor_json)?;
    add_status(&mut zip, options)?;
    add_metrics(&mut zip, options)?;
    add_logs(&mut zip, options)?;
    add_config_summary(&mut zip, options)?;

    zip.finish().context("finish doctor bundle zip")?;
    Ok(path)
}

fn resolve_bundle_path(output: Option<&Path>) -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("resolve current directory for doctor bundle")?;
    Ok(resolve_bundle_path_for_test(
        output,
        &cwd,
        &portl_core::diagnostics::doctor_bundle_filename_now(),
    ))
}

pub(crate) fn resolve_bundle_path_for_test(
    output: Option<&Path>,
    cwd: &Path,
    filename: &str,
) -> PathBuf {
    match output {
        None => cwd.join(filename),
        Some(path) if path.exists() && !path.is_dir() => path.to_path_buf(),
        Some(path) if path.exists() && path.is_dir() => path.join(filename),
        Some(path) if path.extension().is_none() => path.join(filename),
        Some(path) => path.to_path_buf(),
    }
}

fn manifest() -> serde_json::Value {
    json!({
        "schema": 1,
        "kind": "portl.doctor.bundle",
        "portl_version": env!("CARGO_PKG_VERSION"),
        "redaction": "tickets_secrets_tokens_redacted",
    })
}

fn add_json(
    zip: &mut zip::ZipWriter<File>,
    options: SimpleFileOptions,
    name: &str,
    value: &serde_json::Value,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("serialize bundle JSON")?;
    add_bytes(zip, options, name, &bytes)
}

fn add_bytes(
    zip: &mut zip::ZipWriter<File>,
    options: SimpleFileOptions,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    zip.start_file(name, options)
        .with_context(|| format!("start bundle entry {name}"))?;
    zip.write_all(bytes)
        .with_context(|| format!("write bundle entry {name}"))?;
    Ok(())
}

fn add_status(zip: &mut zip::ZipWriter<File>, options: SimpleFileOptions) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("create runtime for status snapshot")?;
    let socket = crate::agent_ipc::default_socket_path();
    let status = runtime.block_on(async { crate::agent_ipc::fetch_status(&socket).await });
    match status {
        Ok(status) => add_json(zip, options, "status.json", &serde_json::to_value(status)?)?,
        Err(err) => add_bytes(
            zip,
            options,
            "status-error.txt",
            format!("{err:#}\n").as_bytes(),
        )?,
    }
    runtime.shutdown_background();
    Ok(())
}

fn add_metrics(zip: &mut zip::ZipWriter<File>, options: SimpleFileOptions) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("create runtime for metrics snapshot")?;
    let socket = crate::agent_ipc::default_socket_path();
    let metrics =
        runtime.block_on(async { crate::agent_ipc::fetch_raw(&socket, "/metrics").await });
    match metrics {
        Ok(metrics) => add_bytes(zip, options, "metrics.openmetrics", metrics.as_bytes())?,
        Err(err) => add_bytes(
            zip,
            options,
            "metrics-error.txt",
            format!("{err:#}\n").as_bytes(),
        )?,
    }
    runtime.shutdown_background();
    Ok(())
}

fn add_logs(zip: &mut zip::ZipWriter<File>, options: SimpleFileOptions) -> Result<()> {
    for (name, kind) in [
        ("logs/agent.ndjson", portl_core::diagnostics::LogKind::Agent),
        ("logs/cli.ndjson", portl_core::diagnostics::LogKind::Cli),
    ] {
        let path = portl_core::diagnostics::log_path(kind);
        match portl_core::diagnostics::read_tail(
            &path,
            portl_core::diagnostics::BUNDLE_LOG_TAIL_BYTES,
        )? {
            Some(bytes) => add_bytes(zip, options, name, &bytes)?,
            None => add_bytes(
                zip,
                options,
                &format!("{name}.missing.txt"),
                b"log file not found\n",
            )?,
        }
    }
    Ok(())
}

fn add_config_summary(zip: &mut zip::ZipWriter<File>, options: SimpleFileOptions) -> Result<()> {
    let env = std::env::vars()
        .filter(|(key, _)| key.starts_with("PORTL_") || key == "RUST_LOG")
        .map(|(key, value)| {
            let value = portl_core::diagnostics::redact_env_value(&key, &value);
            json!({ "name": key, "value": value })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "schema": 1,
        "kind": "config-summary",
        "portl_home": portl_core::paths::home_dir(),
        "env": env,
        "agent_run_marker": portl_core::paths::agent_run_marker_path(),
    });
    add_json(zip, options, "config-summary.json", &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundle_path_uses_cwd_and_timestamped_zip() {
        let cwd = Path::new("/tmp/example");
        let path =
            resolve_bundle_path_for_test(None, cwd, "portl-doctor-bundle-20240101-000000Z.zip");
        assert_eq!(path, cwd.join("portl-doctor-bundle-20240101-000000Z.zip"));
    }

    #[test]
    fn directory_output_gets_timestamped_filename() {
        let cwd = Path::new("/tmp/example");
        let output = Path::new("/tmp/outdir");
        let path = resolve_bundle_path_for_test(
            Some(output),
            cwd,
            "portl-doctor-bundle-20240101-000000Z.zip",
        );
        assert_eq!(
            path,
            output.join("portl-doctor-bundle-20240101-000000Z.zip")
        );
    }

    #[test]
    fn file_output_is_exact() {
        let cwd = Path::new("/tmp/example");
        let output = Path::new("/tmp/debug.zip");
        let path = resolve_bundle_path_for_test(Some(output), cwd, "ignored.zip");
        assert_eq!(path, output);
    }

    #[test]
    fn existing_no_extension_file_output_is_exact() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("debug");
        std::fs::write(&output, b"already here").expect("write output placeholder");

        let path = resolve_bundle_path_for_test(Some(&output), temp.path(), "ignored.zip");

        assert_eq!(path, output);
    }
}

//! Local diagnostics helpers shared by the CLI and agent.
//!
//! This module intentionally stays local-only: it manages Portl's structured
//! log file paths, startup rotation, redaction helpers, bundle filenames, and
//! byte-limited log tail reads. It must not emit telemetry or contact remote
//! services.

use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

pub const LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;
pub const LOG_ROTATE_KEEP: usize = 10;
pub const BUNDLE_LOG_TAIL_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Agent,
    Cli,
}

impl LogKind {
    #[must_use]
    pub const fn filename(self) -> &'static str {
        match self {
            Self::Agent => "agent.ndjson",
            Self::Cli => "cli.ndjson",
        }
    }
}

#[must_use]
pub fn logs_dir() -> PathBuf {
    crate::paths::logs_dir()
}

#[must_use]
pub fn log_path(kind: LogKind) -> PathBuf {
    logs_dir().join(kind.filename())
}

#[must_use]
pub fn file_logs_enabled() -> bool {
    std::env::var("PORTL_LOG_FILES").map_or(true, |value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        )
    })
}

pub fn ensure_log_file_ready(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    rotate_if_needed(path, LOG_ROTATE_BYTES, LOG_ROTATE_KEEP)
}

pub fn rotate_if_needed(path: &Path, max_bytes: u64, keep: usize) -> Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if metadata.len() <= max_bytes {
        return Ok(());
    }

    for idx in (1..=keep).rev() {
        let src = rotated_path(path, idx);
        let dst = rotated_path(path, idx + 1);
        if !src.exists() {
            continue;
        }
        if idx == keep {
            let _ = fs::remove_file(&src);
        } else {
            let _ = fs::rename(&src, &dst);
        }
    }
    fs::rename(path, rotated_path(path, 1))
        .with_context(|| format!("rotate {}", path.display()))?;
    Ok(())
}

fn rotated_path(path: &Path, idx: usize) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("portl.ndjson");
    path.with_file_name(format!("{file_name}.{idx}"))
}

#[must_use]
pub fn redact_argv(args: &[String]) -> Vec<String> {
    let mut redact_next = false;
    args.iter()
        .map(|arg| {
            if redact_next && !arg.starts_with('-') {
                redact_next = false;
                return "<redacted>".to_owned();
            }
            redact_next = false;
            let redacted = redact_arg(arg);
            if redacted == *arg && is_sensitive_bare_flag(arg) {
                redact_next = true;
            }
            redacted
        })
        .collect()
}

#[must_use]
pub fn redact_arg(arg: &str) -> String {
    if looks_like_portl_ticket(arg) {
        return "<redacted:ticket>".to_owned();
    }
    if let Some((key, value)) = arg.split_once('=')
        && is_sensitive_key(key)
        && !value.is_empty()
    {
        return format!("{key}=<redacted>");
    }
    arg.to_owned()
}

#[must_use]
pub fn redact_text(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut token_start = None;

    for (idx, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                redacted.push_str(&redact_text_token(&text[start..idx]));
            }
            redacted.push(ch);
        } else if token_start.is_none() {
            token_start = Some(idx);
        }
    }

    if let Some(start) = token_start {
        redacted.push_str(&redact_text_token(&text[start..]));
    }

    redacted
}

fn redact_text_token(token: &str) -> String {
    if let Some((key, value)) = token.split_once('=')
        && is_sensitive_key(key)
        && !value.is_empty()
    {
        return format!("{key}=<redacted>");
    }

    let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-');
    if trimmed.is_empty() || !looks_like_portl_ticket(trimmed) {
        return token.to_owned();
    }

    let start = token.find(trimmed).unwrap_or(0);
    let end = start + trimmed.len();
    format!("{}<redacted:ticket>{}", &token[..start], &token[end..])
}

#[must_use]
pub fn redact_env_value(name: &str, value: &str) -> String {
    if is_sensitive_key(name) || looks_like_portl_ticket(value) {
        "<redacted>".to_owned()
    } else {
        value.to_owned()
    }
}

fn looks_like_portl_ticket(value: &str) -> bool {
    let normalized = value.trim().to_ascii_uppercase();
    normalized.starts_with("PORTLINV-")
        || normalized.starts_with("PORTL-SHARE1-")
        || normalized.starts_with("PORTL-S-")
        || normalized.starts_with("PORTLTKT-")
        || (normalized.starts_with("PORTL") && normalized.len() >= 16)
}

fn is_sensitive_bare_flag(key: &str) -> bool {
    key.starts_with('-') && !key.contains('=') && is_sensitive_key(key)
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .trim_start_matches('-')
        .replace('-', "_")
        .to_ascii_uppercase();
    normalized.contains("SECRET")
        || normalized.contains("TOKEN")
        || normalized.contains("BEARER")
        || normalized.contains("PASSWORD")
        || normalized == "PORTL_IDENTITY_SECRET_HEX"
        || normalized == "IROH_SERVICES_API_SECRET"
}

#[must_use]
pub fn doctor_bundle_filename_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    doctor_bundle_filename_for_unix(secs)
}

#[must_use]
pub fn doctor_bundle_filename_for_unix(secs: u64) -> String {
    let (year, month, day, hh, mm, ss) = unix_to_ymdhms(secs);
    format!("portl-doctor-bundle-{year:04}{month:02}{day:02}-{hh:02}{mm:02}{ss:02}Z.zip")
}

pub fn read_tail(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>> {
    let Ok(mut file) = fs::File::open(path) else {
        return Ok(None);
    };
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(Some(out))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::similar_names
)]
fn unix_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = (secs % 86_400) as u32;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let seconds_of_minute = rem % 60;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y_i64 = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y_i64 + 1 } else { y_i64 };
    (year as u32, month, day, hours, minutes, seconds_of_minute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_ticket_like_arguments_and_sensitive_key_values() {
        let args = vec![
            "portl".to_owned(),
            "ticket".to_owned(),
            "save".to_owned(),
            "dev".to_owned(),
            "portl1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890".to_owned(),
            "--token=abc123".to_owned(),
            "--cwd".to_owned(),
            "/tmp/work".to_owned(),
        ];

        let redacted = redact_argv(&args);

        assert_eq!(redacted[0], "portl");
        assert_eq!(redacted[4], "<redacted:ticket>");
        assert_eq!(redacted[5], "--token=<redacted>");
        assert_eq!(redacted[7], "/tmp/work");
    }

    #[test]
    fn redacts_sensitive_bare_flag_value() {
        let args = vec!["portl".into(), "--password".into(), "secret".into()];
        assert_eq!(redact_argv(&args), ["portl", "--password", "<redacted>"]);
    }

    #[test]
    fn redacts_short_portl_invite_and_share_codes() {
        let args = vec![
            "portl".to_owned(),
            "accept".to_owned(),
            "PORTLINV-AAAA".to_owned(),
            "PORTL-S-2-nebula-involve".to_owned(),
            "PORTL-SHARE1-offline".to_owned(),
            "PORTLTKT-short".to_owned(),
        ];

        let redacted = redact_argv(&args);

        assert_eq!(redacted[0], "portl");
        assert_eq!(redacted[2], "<redacted:ticket>");
        assert_eq!(redacted[3], "<redacted:ticket>");
        assert_eq!(redacted[4], "<redacted:ticket>");
        assert_eq!(redacted[5], "<redacted:ticket>");
    }

    #[test]
    fn redacts_ticket_like_text_without_reformatting_errors() {
        let text = "unknown peer or ticket name 'PORTLINV-AAAA'.\nTry token=abc123";
        let redacted = redact_text(text);

        assert_eq!(
            redacted,
            "unknown peer or ticket name '<redacted:ticket>'.\nTry token=<redacted>"
        );
    }

    #[test]
    fn timestamped_doctor_bundle_name_is_stable_shape() {
        let name = doctor_bundle_filename_for_unix(1_704_067_200);
        assert_eq!(name, "portl-doctor-bundle-20240101-000000Z.zip");
    }
}

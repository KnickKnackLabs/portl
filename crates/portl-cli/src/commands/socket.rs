use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use portl_core::id::store;
use portl_core::net::{open_unix_listen, run_local_unix_forward, run_unix_reverse_forwards};
use portl_core::ticket::schema::{Capabilities, UnixCaps, UnixPathRule, validate_unix_path_rule};
use sha2::{Digest, Sha256};

use crate::commands::peer_resolve::{close_connected, connect_peer, resolve_identity_path};

pub fn run(
    peer: &str,
    local: Option<&str>,
    connect: Option<&str>,
    listen: Option<&str>,
    local_forwards: &[String],
    remote_forwards: &[String],
    cleanup: bool,
) -> Result<ExitCode> {
    let source_label = local_socket_source_label()?;
    let modes = parse_socket_modes(
        peer,
        &source_label,
        local,
        connect,
        listen,
        local_forwards,
        remote_forwards,
        cleanup,
    )?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let connected = connect_peer(peer, socket_caps_for_modes(&modes)).await?;
        eprint!("{}", render_startup_summary(peer, &source_label, &modes));
        let mut tasks = Vec::new();
        let mut listen_controls = Vec::new();
        let mut reverse_forwards = Vec::new();

        for mode in &modes {
            match mode {
                SocketMode::Connect {
                    local,
                    remote,
                    cleanup,
                    generated,
                } => {
                    if *generated {
                        ensure_generated_socket_parent(local, "portl-to-")?;
                    }
                    tasks.push(tokio::spawn(run_local_unix_forward(
                        connected.connection.clone(),
                        connected.session.clone(),
                        local.clone(),
                        remote.clone(),
                        *cleanup,
                    )));
                }
                SocketMode::Listen {
                    remote,
                    local,
                    cleanup,
                    ..
                } => {
                    let control = open_unix_listen(
                        &connected.connection,
                        &connected.session,
                        remote,
                        *cleanup,
                    )
                    .await?;
                    listen_controls.push(control);
                    reverse_forwards.push((remote.clone(), local.clone()));
                }
            }
        }

        if !reverse_forwards.is_empty() {
            tasks.push(tokio::spawn(run_unix_reverse_forwards(
                connected.connection.clone(),
                connected.session.clone(),
                reverse_forwards,
            )));
        }

        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("wait for ctrl-c")?;
            }
            result = wait_for_forward_task(&mut tasks) => {
                result?;
            }
        }

        for control in listen_controls {
            control.close()?;
        }
        for task in tasks {
            task.abort();
        }
        close_connected(connected, b"socket complete").await;
        Ok(ExitCode::SUCCESS)
    })
}

async fn wait_for_forward_task(tasks: &mut [tokio::task::JoinHandle<Result<()>>]) -> Result<()> {
    if tasks.is_empty() {
        return Ok(());
    }
    let (result, _index, _remaining) = futures_util::future::select_all(tasks.iter_mut()).await;
    result.context("join unix forward task")?
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SocketMode {
    Connect {
        local: String,
        remote: String,
        cleanup: bool,
        generated: bool,
    },
    Listen {
        remote: String,
        local: String,
        cleanup: bool,
        generated: bool,
    },
}

#[allow(clippy::too_many_arguments)]
fn parse_socket_modes(
    peer: &str,
    source_label: &str,
    local: Option<&str>,
    connect: Option<&str>,
    listen: Option<&str>,
    local_forwards: &[String],
    remote_forwards: &[String],
    cleanup: bool,
) -> Result<Vec<SocketMode>> {
    if local.is_some() || connect.is_some() || listen.is_some() {
        if !local_forwards.is_empty() || !remote_forwards.is_empty() {
            bail!("legacy --local/--connect/--listen options cannot be combined with -L/-R");
        }
        let local = local.context("--local is required with --connect or --listen")?;
        return Ok(vec![SocketMode::from_legacy_args(
            local, connect, listen, cleanup,
        )?]);
    }

    parse_new_socket_modes(peer, source_label, local_forwards, remote_forwards, cleanup)
}

pub(crate) fn parse_new_socket_modes(
    peer: &str,
    source_label: &str,
    local_forwards: &[String],
    remote_forwards: &[String],
    cleanup: bool,
) -> Result<Vec<SocketMode>> {
    let local_name_counts = generated_name_counts(local_forwards);
    let remote_name_counts = generated_name_counts(remote_forwards);
    let mut modes = Vec::new();
    for spec in local_forwards {
        modes.push(parse_local_socket_forward(
            peer,
            spec,
            cleanup,
            &local_name_counts,
        )?);
    }
    for spec in remote_forwards {
        modes.push(parse_remote_socket_forward(
            source_label,
            spec,
            cleanup,
            &remote_name_counts,
        )?);
    }
    reject_duplicate_generated_paths(&modes)?;
    if modes.is_empty() {
        bail!("at least one --connect/--listen, -L, or -R socket forward is required");
    }
    Ok(modes)
}

fn parse_local_socket_forward(
    peer: &str,
    spec: &str,
    cleanup: bool,
    generated_name_counts: &HashMap<String, usize>,
) -> Result<SocketMode> {
    let (local, remote, generated) = if let Some(remote) = spec.strip_prefix(':') {
        if remote.is_empty() {
            bail!("-L socket spec with generated local path requires a remote socket path");
        }
        (
            generated_local_socket_path(peer, remote, generated_name_counts)?,
            remote.to_owned(),
            true,
        )
    } else if let Some((local, remote)) = spec.split_once(':') {
        if local.is_empty() || remote.is_empty() {
            bail!("-L socket spec must be LOCAL_SOCKET:REMOTE_SOCKET or :REMOTE_SOCKET");
        }
        (local.to_owned(), remote.to_owned(), false)
    } else {
        (
            generated_local_socket_path(peer, spec, generated_name_counts)?,
            spec.to_owned(),
            true,
        )
    };
    validate_socket_remote_path(&remote)?;
    Ok(SocketMode::Connect {
        local,
        remote,
        cleanup: cleanup || generated,
        generated,
    })
}

fn parse_remote_socket_forward(
    source_label: &str,
    spec: &str,
    cleanup: bool,
    generated_name_counts: &HashMap<String, usize>,
) -> Result<SocketMode> {
    let (remote, local, generated) = if let Some(local) = spec.strip_prefix(':') {
        if local.is_empty() {
            bail!("-R socket spec with generated remote path requires a local socket path");
        }
        (
            generated_remote_socket_path(source_label, local, generated_name_counts)?,
            local.to_owned(),
            true,
        )
    } else if let Some((remote, local)) = spec.split_once(':') {
        if remote.is_empty() || local.is_empty() {
            bail!("-R socket spec must be REMOTE_SOCKET:LOCAL_SOCKET or :LOCAL_SOCKET");
        }
        (remote.to_owned(), local.to_owned(), false)
    } else {
        (
            generated_remote_socket_path(source_label, spec, generated_name_counts)?,
            spec.to_owned(),
            true,
        )
    };
    validate_socket_remote_path(&remote)?;
    Ok(SocketMode::Listen {
        remote,
        local,
        cleanup: cleanup || generated,
        generated,
    })
}

fn generated_local_socket_path(
    peer: &str,
    remote: &str,
    generated_name_counts: &HashMap<String, usize>,
) -> Result<String> {
    generated_socket_path("to", peer, "L", remote, generated_name_counts)
}

fn generated_remote_socket_path(
    source_label: &str,
    local: &str,
    generated_name_counts: &HashMap<String, usize>,
) -> Result<String> {
    generated_socket_path("from", source_label, "R", local, generated_name_counts)
}

fn generated_socket_path(
    direction: &str,
    label: &str,
    hash_direction: &str,
    target: &str,
    generated_name_counts: &HashMap<String, usize>,
) -> Result<String> {
    let base = sanitized_basename(target);
    let hash = short_hash(["portl-socket-v1", hash_direction, label, target]);
    let filename = generated_socket_filename(
        &base,
        &hash,
        generated_name_counts.get(&base).copied().unwrap_or(0) > 1,
    );
    let path = PathBuf::from("/tmp")
        .join(format!("portl-{direction}-{}", sanitize_component(label)))
        .join(filename)
        .display()
        .to_string();
    validate_generated_socket_path(&path)?;
    Ok(path)
}

fn generated_socket_filename(base: &str, hash: &str, needs_hash: bool) -> String {
    if !needs_hash {
        return base.to_owned();
    }
    let hash = &hash[..6];
    if let Some(stem) = base.strip_suffix(".sock")
        && !stem.is_empty()
    {
        format!("{stem}-{hash}.sock")
    } else {
        format!("{base}-{hash}")
    }
}

fn sanitized_basename(path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("socket.sock");
    let sanitized = sanitize_component(name);
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "socket.sock".to_owned()
    } else {
        sanitized
    }
}

fn sanitize_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if sanitized.is_empty() {
        "default".to_owned()
    } else {
        sanitized
    }
}

fn generated_name_counts(specs: &[String]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for spec in specs {
        let Some(target) = generated_target_from_spec(spec) else {
            continue;
        };
        *counts.entry(sanitized_basename(target)).or_insert(0) += 1;
    }
    counts
}

fn generated_target_from_spec(spec: &str) -> Option<&str> {
    if let Some(target) = spec.strip_prefix(':') {
        Some(target)
    } else if spec.split_once(':').is_some() {
        None
    } else {
        Some(spec)
    }
}

fn reject_duplicate_generated_paths(modes: &[SocketMode]) -> Result<()> {
    let mut paths = HashSet::new();
    for mode in modes {
        let Some(path) = mode.generated_listener_path() else {
            continue;
        };
        if !paths.insert(path.to_owned()) {
            bail!("duplicate generated socket path {path}");
        }
    }
    Ok(())
}

fn short_hash<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())[..10].to_owned()
}

fn validate_generated_socket_path(path: &str) -> Result<()> {
    const MAX_UNIX_SOCKET_PATH_LEN: usize = 104;
    if path.len() >= MAX_UNIX_SOCKET_PATH_LEN {
        bail!(
            "generated socket path is too long for this platform: {path}. Use an explicit shorter socket path, for example -L /tmp/app.sock:REMOTE_SOCKET"
        );
    }
    Ok(())
}

pub(crate) fn ensure_generated_socket_parent(path: &str, prefix: &str) -> Result<()> {
    let path = Path::new(path);
    let parent = path.parent().with_context(|| {
        format!(
            "generated socket path must include a parent: {}",
            path.display()
        )
    })?;
    validate_generated_tmp_parent(parent, prefix)?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create generated socket directory {}", parent.display()))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod generated socket directory {}", parent.display()))?;
    Ok(())
}

fn validate_generated_tmp_parent(parent: &Path, prefix: &str) -> Result<()> {
    let Some(name) = parent.file_name().and_then(|name| name.to_str()) else {
        bail!("generated socket parent must have a utf-8 name");
    };
    if parent.parent() != Some(Path::new("/tmp")) || !name.starts_with(prefix) {
        bail!(
            "generated socket parent must be /tmp/{prefix}*: {}",
            parent.display()
        );
    }
    Ok(())
}

pub(crate) fn local_socket_source_label() -> Result<String> {
    let identity_path = resolve_identity_path(None);
    let identity = store::load(&identity_path).context("load local identity")?;
    Ok(crate::commands::local_machine_label(&hex::encode(
        identity.verifying_key(),
    )))
}

impl SocketMode {
    fn from_legacy_args(
        local: &str,
        connect: Option<&str>,
        listen: Option<&str>,
        cleanup: bool,
    ) -> Result<Self> {
        match (connect, listen) {
            (Some(remote), None) => {
                validate_socket_remote_path(remote)?;
                Ok(Self::Connect {
                    local: local.to_owned(),
                    remote: remote.to_owned(),
                    cleanup,
                    generated: false,
                })
            }
            (None, Some(remote)) => {
                validate_socket_remote_path(remote)?;
                Ok(Self::Listen {
                    remote: remote.to_owned(),
                    local: local.to_owned(),
                    cleanup,
                    generated: false,
                })
            }
            (None, None) => bail!("one of --connect, --listen, -L, or -R is required"),
            (Some(_), Some(_)) => bail!("--connect and --listen are mutually exclusive"),
        }
    }
}

#[allow(clippy::format_push_string)]
pub(crate) fn render_startup_summary(
    peer: &str,
    source_label: &str,
    modes: &[SocketMode],
) -> String {
    let mut summary = format!("Forwarding through {peer}\n\nUnix sockets:\n");
    for (index, mode) in modes.iter().enumerate() {
        if index > 0 {
            summary.push('\n');
        }
        match mode {
            SocketMode::Connect {
                local,
                remote,
                generated,
                ..
            } => {
                let label = if *generated {
                    "generated local socket"
                } else {
                    "explicit local socket"
                };
                summary.push_str(&format!(
                    "  -L  {source_label}:{local}\n      -> {peer}:{remote}\n      {label}\n"
                ));
            }
            SocketMode::Listen {
                remote,
                local,
                generated,
                ..
            } => {
                let label = if *generated {
                    "generated remote socket"
                } else {
                    "explicit remote socket"
                };
                summary.push_str(&format!(
                    "  -R  {peer}:{remote}\n      -> {source_label}:{local}\n      {label}\n"
                ));
            }
        }
    }
    summary.push_str("\nWaiting for socket connections. Press Ctrl-C to stop.\n");
    summary
}

impl SocketMode {
    fn generated_listener_path(&self) -> Option<&str> {
        match self {
            SocketMode::Connect {
                local,
                generated: true,
                ..
            } => Some(local),
            SocketMode::Listen {
                remote,
                generated: true,
                ..
            } => Some(remote),
            SocketMode::Connect { .. } | SocketMode::Listen { .. } => None,
        }
    }
}

pub(crate) fn socket_caps_for_modes(modes: &[SocketMode]) -> Capabilities {
    let mut connect = Vec::new();
    let mut listen = Vec::new();
    for mode in modes {
        match mode {
            SocketMode::Connect { remote, .. } => connect.push(path_rule(remote)),
            SocketMode::Listen { remote, .. } => listen.push(path_rule(remote)),
        }
    }
    connect.sort_by(|a, b| a.path.cmp(&b.path));
    connect.dedup_by(|a, b| a.path == b.path);
    listen.sort_by(|a, b| a.path.cmp(&b.path));
    listen.dedup_by(|a, b| a.path == b.path);
    socket_caps_from_rules(connect, listen)
}

#[cfg(test)]
fn socket_caps(mode: &SocketMode) -> Capabilities {
    socket_caps_for_modes(std::slice::from_ref(mode))
}

fn socket_caps_from_rules(connect: Vec<UnixPathRule>, listen: Vec<UnixPathRule>) -> Capabilities {
    Capabilities {
        presence: 0b0100_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix: Some(UnixCaps { connect, listen }),
    }
}

fn path_rule(path: &str) -> UnixPathRule {
    UnixPathRule {
        path: path.to_owned(),
    }
}

fn validate_socket_remote_path(path: &str) -> Result<()> {
    validate_unix_path_rule(path, false).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{SocketMode, parse_new_socket_modes, render_startup_summary, socket_caps};

    #[test]
    fn renders_grouped_socket_startup_summary() {
        let modes = parse_new_socket_modes(
            "remote-dev",
            "local-dev",
            &["/run/herdr.sock".to_owned()],
            &["/tmp/local-agent.sock".to_owned()],
            false,
        )
        .unwrap();
        assert_eq!(
            render_startup_summary("remote-dev", "local-dev", &modes),
            "Forwarding through remote-dev\n\nUnix sockets:\n  -L  local-dev:/tmp/portl-to-remote-dev/herdr.sock\n      -> remote-dev:/run/herdr.sock\n      generated local socket\n\n  -R  remote-dev:/tmp/portl-from-local-dev/local-agent.sock\n      -> local-dev:/tmp/local-agent.sock\n      generated remote socket\n\nWaiting for socket connections. Press Ctrl-C to stop.\n"
        );
    }

    #[test]
    fn parses_local_forward_bare_remote_socket_to_stable_tmp_path() {
        let modes = parse_new_socket_modes(
            "remote-dev",
            "local-dev",
            &["/run/herdr.sock".to_owned()],
            &[],
            false,
        )
        .unwrap();
        assert_eq!(modes.len(), 1);
        let SocketMode::Connect {
            local,
            remote,
            cleanup,
            generated,
        } = &modes[0]
        else {
            panic!("expected connect mode");
        };
        assert_eq!(remote, "/run/herdr.sock");
        assert_eq!(local, "/tmp/portl-to-remote-dev/herdr.sock");
        assert!(*cleanup, "generated local sockets should be cleaned up");
        assert!(
            *generated,
            "bare -L should mark the local socket as generated"
        );
    }

    #[test]
    fn parses_local_forward_explicit_local_and_remote_socket() {
        let modes = parse_new_socket_modes(
            "remote-dev",
            "local-dev",
            &["/tmp/local.sock:/run/herdr.sock".to_owned()],
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            modes,
            vec![SocketMode::Connect {
                local: "/tmp/local.sock".to_owned(),
                remote: "/run/herdr.sock".to_owned(),
                cleanup: false,
                generated: false,
            }]
        );
    }

    #[test]
    fn parses_remote_forward_bare_local_socket_to_stable_tmp_path() {
        let modes = parse_new_socket_modes(
            "remote-dev",
            "local-dev",
            &[],
            &["/tmp/local-agent.sock".to_owned()],
            false,
        )
        .unwrap();
        assert_eq!(modes.len(), 1);
        let SocketMode::Listen {
            remote,
            local,
            cleanup,
            generated,
        } = &modes[0]
        else {
            panic!("expected listen mode");
        };
        assert_eq!(local, "/tmp/local-agent.sock");
        assert_eq!(remote, "/tmp/portl-from-local-dev/local-agent.sock");
        assert!(*cleanup, "generated remote sockets should be cleaned up");
        assert!(
            *generated,
            "bare -R should mark the remote socket as generated"
        );
        assert_eq!(
            Path::new(&remote).parent().unwrap(),
            Path::new("/tmp/portl-from-local-dev")
        );
    }

    #[test]
    fn parses_remote_forward_explicit_remote_and_local_socket() {
        let modes = parse_new_socket_modes(
            "remote-dev",
            "local-dev",
            &[],
            &["/tmp/remote.sock:/tmp/local.sock".to_owned()],
            false,
        )
        .unwrap();
        assert_eq!(
            modes,
            vec![SocketMode::Listen {
                remote: "/tmp/remote.sock".to_owned(),
                local: "/tmp/local.sock".to_owned(),
                cleanup: false,
                generated: false,
            }]
        );
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn generated_same_basename_collisions_get_hash_suffixes() {
        let modes = parse_new_socket_modes(
            "remote-dev",
            "local-dev",
            &[
                "/run/app/api.sock".to_owned(),
                "/run/other/api.sock".to_owned(),
            ],
            &[],
            false,
        )
        .unwrap();
        let locals = modes
            .iter()
            .map(|mode| match mode {
                SocketMode::Connect { local, .. } => local.as_str(),
                SocketMode::Listen { .. } => panic!("expected connect mode"),
            })
            .collect::<Vec<_>>();
        assert!(
            locals[0].starts_with("/tmp/portl-to-remote-dev/api-"),
            "{}",
            locals[0]
        );
        assert!(locals[0].ends_with(".sock"), "{}", locals[0]);
        assert!(
            locals[1].starts_with("/tmp/portl-to-remote-dev/api-"),
            "{}",
            locals[1]
        );
        assert!(locals[1].ends_with(".sock"), "{}", locals[1]);
        assert_ne!(locals[0], locals[1]);
    }

    #[test]
    fn socket_caps_grant_exact_connect_path() {
        let caps = socket_caps(&SocketMode::Connect {
            local: "/tmp/local.sock".to_owned(),
            remote: "/run/agent.sock".to_owned(),
            cleanup: false,
            generated: false,
        });
        assert_eq!(caps.presence, 0b0100_0000);
        let unix = caps.unix.expect("unix caps");
        assert_eq!(unix.connect[0].path, "/run/agent.sock");
        assert!(unix.listen.is_empty());
    }

    #[test]
    fn socket_mode_rejects_unsafe_remote_path() {
        let err = SocketMode::from_legacy_args(
            "/tmp/local.sock",
            Some("/tmp/portl-a/../b.sock"),
            None,
            false,
        )
        .expect_err("unsafe remote path should fail");
        assert!(err.to_string().contains("unix path"));
    }

    #[test]
    fn socket_caps_grant_exact_listen_path() {
        let caps = socket_caps(&SocketMode::Listen {
            remote: "/tmp/portl-agent.sock".to_owned(),
            local: "/tmp/local.sock".to_owned(),
            cleanup: false,
            generated: false,
        });
        let unix = caps.unix.expect("unix caps");
        assert!(unix.connect.is_empty());
        assert_eq!(unix.listen[0].path, "/tmp/portl-agent.sock");
    }
}

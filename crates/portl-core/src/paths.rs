//! Canonical on-disk layout for Portl.
//!
//! Portl intentionally uses a CLI-friendly single root on every OS:
//! `$PORTL_HOME` when set, otherwise `$HOME/.portl`. Within that root
//! we keep XDG-like lifecycle boundaries so config, durable data,
//! operational state, and runtime sockets remain easy to reason about.

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use directories::{BaseDirs, ProjectDirs};

const ENV_PORTL_HOME: &str = "PORTL_HOME";
static MIGRATION_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortlPaths {
    root: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub root: PathBuf,
    pub moved: Vec<(PathBuf, PathBuf)>,
}

impl MigrationReport {
    #[must_use]
    pub fn moved_count(&self) -> usize {
        self.moved.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.moved.is_empty()
    }
}

impl PortlPaths {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    #[must_use]
    pub fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.config_dir().join("portl.toml")
    }

    #[must_use]
    pub fn identity_path(&self) -> PathBuf {
        self.data_dir().join("identity.bin")
    }

    #[must_use]
    pub fn peers_path(&self) -> PathBuf {
        self.data_dir().join("peers.json")
    }

    #[must_use]
    pub fn tickets_path(&self) -> PathBuf {
        self.data_dir().join("tickets.json")
    }

    #[must_use]
    pub fn aliases_path(&self) -> PathBuf {
        self.data_dir().join("aliases.json")
    }

    #[must_use]
    pub fn revocations_path(&self) -> PathBuf {
        self.state_dir().join("revocations.jsonl")
    }

    #[must_use]
    pub fn pending_invites_path(&self) -> PathBuf {
        self.state_dir().join("pending_invites.json")
    }

    #[must_use]
    pub fn metrics_socket_path(&self) -> PathBuf {
        self.run_dir().join("metrics.sock")
    }

    #[must_use]
    pub fn ghostty_state_dir(&self) -> PathBuf {
        self.state_dir().join("ghostty")
    }

    #[must_use]
    pub fn ghostty_runtime_dir(&self) -> PathBuf {
        self.run_dir().join("ghostty")
    }
}

#[must_use]
pub fn default_home_dir() -> PathBuf {
    BaseDirs::new().map_or_else(
        || PathBuf::from(".portl"),
        |dirs| dirs.home_dir().join(".portl"),
    )
}

#[must_use]
pub fn home_dir() -> PathBuf {
    std::env::var_os(ENV_PORTL_HOME).map_or_else(default_home_dir, PathBuf::from)
}

#[must_use]
pub fn current() -> PortlPaths {
    PortlPaths::new(home_dir())
}

#[must_use]
pub fn for_home(home: impl Into<PathBuf>) -> PortlPaths {
    PortlPaths::new(home)
}

#[must_use]
pub fn config_path() -> PathBuf {
    current().config_path()
}

#[must_use]
pub fn identity_path() -> PathBuf {
    current().identity_path()
}

#[must_use]
pub fn peers_path() -> PathBuf {
    current().peers_path()
}

#[must_use]
pub fn tickets_path() -> PathBuf {
    current().tickets_path()
}

#[must_use]
pub fn aliases_path() -> PathBuf {
    current().aliases_path()
}

#[must_use]
pub fn pending_invites_path() -> PathBuf {
    current().pending_invites_path()
}

#[must_use]
pub fn revocations_path() -> PathBuf {
    current().revocations_path()
}

#[must_use]
pub fn metrics_socket_path() -> PathBuf {
    current().metrics_socket_path()
}

#[must_use]
pub fn ghostty_state_dir() -> PathBuf {
    current().ghostty_state_dir()
}

#[must_use]
pub fn ghostty_runtime_dir() -> PathBuf {
    current().ghostty_runtime_dir()
}

pub fn ensure_layout_migrated() -> Result<MigrationReport> {
    let paths = current();
    ensure_layout_dirs(&paths)?;
    migrate_legacy_layouts(&paths)
}

fn ensure_layout_dirs(paths: &PortlPaths) -> Result<()> {
    for dir in [
        paths.config_dir(),
        paths.data_dir(),
        paths.state_dir(),
        paths.run_dir(),
    ] {
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    }
    set_private_dir_permissions(paths.root());
    set_private_dir_permissions(&paths.run_dir());
    Ok(())
}

fn migrate_legacy_layouts(paths: &PortlPaths) -> Result<MigrationReport> {
    let mut report = MigrationReport {
        root: paths.root().to_path_buf(),
        moved: Vec::new(),
    };
    for legacy_home in legacy_home_dirs(paths.root()) {
        migrate_legacy_home(&legacy_home, paths, &mut report)
            .with_context(|| format!("migrate legacy Portl home {}", legacy_home.display()))?;
    }
    Ok(report)
}

fn legacy_home_dirs(new_root: &Path) -> Vec<PathBuf> {
    legacy_home_dirs_for(new_root, std::env::var_os(ENV_PORTL_HOME).is_none())
}

fn legacy_home_dirs_for(new_root: &Path, include_platform_default: bool) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut dirs = Vec::new();
    let candidates = [
        Some(new_root.to_path_buf()),
        include_platform_default
            .then(legacy_project_dirs_home)
            .flatten(),
    ];
    for dir in candidates {
        let Some(dir) = dir else {
            continue;
        };
        if seen.insert(dir.clone()) {
            dirs.push(dir);
        }
    }
    dirs
}

#[must_use]
pub fn previous_project_dirs_home() -> Option<PathBuf> {
    legacy_project_dirs_home()
}

fn legacy_project_dirs_home() -> Option<PathBuf> {
    ProjectDirs::from("computer", "KnickKnackLabs", "portl")
        .map(|dirs| dirs.data_dir().to_path_buf())
}

fn migrate_legacy_home(
    legacy_home: &Path,
    paths: &PortlPaths,
    report: &mut MigrationReport,
) -> Result<()> {
    migrate_file(
        &legacy_home.join("portl.toml"),
        &paths.config_path(),
        report,
    )?;
    migrate_file(
        &legacy_home.join("identity.bin"),
        &paths.identity_path(),
        report,
    )?;
    migrate_file(&legacy_home.join("peers.json"), &paths.peers_path(), report)?;
    migrate_file(
        &legacy_home.join("tickets.json"),
        &paths.tickets_path(),
        report,
    )?;
    migrate_file(
        &legacy_home.join("aliases.json"),
        &paths.aliases_path(),
        report,
    )?;
    migrate_file(
        &legacy_home.join("revocations.jsonl"),
        &paths.revocations_path(),
        report,
    )?;
    migrate_file(
        &legacy_home.join("pending_invites.json"),
        &paths.pending_invites_path(),
        report,
    )?;
    migrate_dir_contents(
        &legacy_home.join("ghostty/sessions"),
        &paths.ghostty_state_dir().join("sessions"),
        report,
    )?;
    Ok(())
}

fn migrate_file(source: &Path, dest: &Path, report: &mut MigrationReport) -> Result<()> {
    if source == dest || !source.exists() || dest.exists() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if move_path_if_still_needed(source, dest)
        .with_context(|| format!("move {} -> {}", source.display(), dest.display()))?
    {
        report
            .moved
            .push((source.to_path_buf(), dest.to_path_buf()));
    }
    Ok(())
}

fn migrate_dir_contents(
    source_dir: &Path,
    dest_dir: &Path,
    report: &mut MigrationReport,
) -> Result<()> {
    let entries = match fs::read_dir(source_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("read {}", source_dir.display())),
    };
    fs::create_dir_all(dest_dir).with_context(|| format!("create {}", dest_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", source_dir.display()))?;
        let source = entry.path();
        let dest = dest_dir.join(entry.file_name());
        if move_path_if_still_needed(&source, &dest)
            .with_context(|| format!("move {} -> {}", source.display(), dest.display()))?
        {
            report.moved.push((source, dest));
        }
    }
    Ok(())
}

fn move_path_if_still_needed(source: &Path, dest: &Path) -> std::io::Result<bool> {
    if dest.exists() || !source.exists() || source.is_dir() {
        return Ok(false);
    }
    match fs::hard_link(source, dest) {
        Ok(()) => {
            remove_source_file(source)?;
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) if err.kind() == ErrorKind::CrossesDevices => copy_file_no_clobber(source, dest),
        Err(err) => Err(err),
    }
}

fn copy_file_no_clobber(source: &Path, dest: &Path) -> std::io::Result<bool> {
    let parent = dest
        .parent()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "destination has no parent"))?;
    let tmp = migration_tmp_path(parent, dest);
    let copy_result = fs::copy(source, &tmp);
    match copy_result {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    }

    match fs::hard_link(&tmp, dest) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp);
            remove_source_file(source)?;
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            Ok(false)
        }
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            Err(err)
        }
    }
}

fn migration_tmp_path(parent: &Path, dest: &Path) -> PathBuf {
    let counter = MIGRATION_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    parent.join(format!(
        ".portl-migrate-{}-{counter}-{file_name}.tmp",
        std::process::id()
    ))
}

fn remove_source_file(source: &Path) -> std::io::Result<()> {
    match fs::remove_file(source) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_paths_live_under_single_root() {
        let paths = PortlPaths::new("/home/alice/.portl");

        assert_eq!(
            paths.config_path(),
            PathBuf::from("/home/alice/.portl/config/portl.toml")
        );
        assert_eq!(
            paths.identity_path(),
            PathBuf::from("/home/alice/.portl/data/identity.bin")
        );
        assert_eq!(
            paths.peers_path(),
            PathBuf::from("/home/alice/.portl/data/peers.json")
        );
        assert_eq!(
            paths.tickets_path(),
            PathBuf::from("/home/alice/.portl/data/tickets.json")
        );
        assert_eq!(
            paths.aliases_path(),
            PathBuf::from("/home/alice/.portl/data/aliases.json")
        );
        assert_eq!(
            paths.revocations_path(),
            PathBuf::from("/home/alice/.portl/state/revocations.jsonl")
        );
        assert_eq!(
            paths.pending_invites_path(),
            PathBuf::from("/home/alice/.portl/state/pending_invites.json")
        );
        assert_eq!(
            paths.metrics_socket_path(),
            PathBuf::from("/home/alice/.portl/run/metrics.sock")
        );
        assert_eq!(
            paths.ghostty_state_dir(),
            PathBuf::from("/home/alice/.portl/state/ghostty")
        );
        assert_eq!(
            paths.ghostty_runtime_dir(),
            PathBuf::from("/home/alice/.portl/run/ghostty")
        );
    }

    #[test]
    fn explicit_home_migration_does_not_import_platform_default() {
        let explicit = PathBuf::from("/tmp/explicit-portl-home");
        let candidates = legacy_home_dirs_for(&explicit, false);

        assert_eq!(candidates, vec![explicit]);
    }

    #[test]
    fn default_home_migration_includes_platform_default() {
        let default = PathBuf::from("/tmp/default-portl-home");
        let candidates = legacy_home_dirs_for(&default, true);

        assert_eq!(candidates.first(), Some(&default));
        if let Some(platform_default) = legacy_project_dirs_home() {
            assert!(candidates.contains(&platform_default));
        }
    }

    #[test]
    fn migration_moves_flat_home_files_into_structured_layout() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let legacy = temp.path().join("legacy");
        let root = temp.path().join(".portl");
        fs::create_dir_all(legacy.join("ghostty/sessions"))?;
        fs::write(legacy.join("portl.toml"), "schema = 1\n")?;
        fs::write(legacy.join("identity.bin"), b"id")?;
        fs::write(legacy.join("peers.json"), b"{}")?;
        fs::write(legacy.join("tickets.json"), b"{}")?;
        fs::write(legacy.join("aliases.json"), b"{}")?;
        fs::write(legacy.join("revocations.jsonl"), b"rev")?;
        fs::write(legacy.join("pending_invites.json"), b"[]")?;
        fs::write(legacy.join("ghostty/sessions/dev.json"), b"{}")?;

        let paths = PortlPaths::new(root);
        ensure_layout_dirs(&paths)?;
        let mut report = MigrationReport {
            root: paths.root().to_path_buf(),
            moved: Vec::new(),
        };
        migrate_legacy_home(&legacy, &paths, &mut report)?;

        assert_eq!(report.moved_count(), 8);
        assert_eq!(fs::read_to_string(paths.config_path())?, "schema = 1\n");
        assert_eq!(fs::read(paths.identity_path())?, b"id");
        assert_eq!(fs::read(paths.peers_path())?, b"{}");
        assert_eq!(fs::read(paths.tickets_path())?, b"{}");
        assert_eq!(fs::read(paths.aliases_path())?, b"{}");
        assert_eq!(fs::read(paths.revocations_path())?, b"rev");
        assert_eq!(fs::read(paths.pending_invites_path())?, b"[]");
        assert_eq!(
            fs::read(paths.ghostty_state_dir().join("sessions/dev.json"))?,
            b"{}"
        );
        assert!(!legacy.join("identity.bin").exists());
        Ok(())
    }

    #[test]
    fn migration_move_helper_does_not_replace_existing_dest() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source.json");
        let dest = temp.path().join("dest.json");
        fs::write(&source, b"old")?;
        fs::write(&dest, b"new")?;

        assert!(!move_path_if_still_needed(&source, &dest)?);
        assert_eq!(fs::read(&source)?, b"old");
        assert_eq!(fs::read(&dest)?, b"new");
        Ok(())
    }

    #[test]
    fn migration_does_not_overwrite_existing_structured_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let legacy = temp.path().join("legacy");
        let paths = PortlPaths::new(temp.path().join(".portl"));
        fs::create_dir_all(&legacy)?;
        fs::create_dir_all(paths.data_dir())?;
        fs::write(legacy.join("identity.bin"), b"old")?;
        fs::write(paths.identity_path(), b"new")?;

        let mut report = MigrationReport {
            root: paths.root().to_path_buf(),
            moved: Vec::new(),
        };
        migrate_legacy_home(&legacy, &paths, &mut report)?;

        assert!(report.is_empty());
        assert_eq!(fs::read(paths.identity_path())?, b"new");
        assert_eq!(fs::read(legacy.join("identity.bin"))?, b"old");
        Ok(())
    }
}

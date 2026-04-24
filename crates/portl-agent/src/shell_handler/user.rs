use std::process::Command as StdCommand;

#[cfg(unix)]
use nix::unistd::{Gid, Uid, User, geteuid};

use super::reject::SpawnReject;

#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct RequestedUser {
    pub(crate) uid: Uid,
    pub(crate) gid: Gid,
    pub(crate) name: String,
    pub(crate) home_dir: String,
    pub(crate) shell: String,
    pub(crate) switch_required: bool,
}

#[cfg(not(unix))]
#[derive(Debug, Clone)]
pub(crate) struct RequestedUser;

pub(crate) fn resolve_requested_user(
    user: Option<&str>,
) -> Result<Option<RequestedUser>, SpawnReject> {
    #[cfg(unix)]
    {
        let current = geteuid();
        let current_user = User::from_uid(current)
            .map_err(|err| SpawnReject::uid_lookup_failed(err.to_string()))?
            .ok_or_else(|| {
                SpawnReject::uid_lookup_failed(format!(
                    "unknown current user: {}",
                    current.as_raw()
                ))
            })?;
        let requested = match user {
            Some(user) => User::from_name(user)
                .map_err(|err| SpawnReject::user_switch_refused(err.to_string()))?
                .ok_or_else(|| SpawnReject::user_switch_refused(format!("unknown user: {user}")))?,
            None => current_user,
        };
        if !current.is_root() && requested.uid != current {
            return Err(SpawnReject::user_switch_refused(
                "cannot drop uid as non-root",
            ));
        }
        let shell = requested.shell.to_string_lossy().into_owned();
        Ok(Some(RequestedUser {
            uid: requested.uid,
            gid: requested.gid,
            name: requested.name,
            home_dir: requested.dir.to_string_lossy().into_owned(),
            shell: if shell.is_empty() {
                "/bin/sh".to_owned()
            } else {
                shell
            },
            switch_required: current.is_root() && requested.uid != current,
        }))
    }

    #[cfg(not(unix))]
    {
        match user {
            Some(_) => Err(SpawnReject::user_switch_refused(
                "user switching is unsupported on this platform",
            )),
            None => Ok(None),
        }
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
#[allow(unsafe_code)]
pub(super) fn install_exec_user_switch(command: &mut StdCommand, user: &RequestedUser) -> bool {
    use std::os::unix::process::CommandExt;
    if !user.switch_required {
        return false;
    }

    let gid_raw = user.gid.as_raw();
    let uid_raw = user.uid.as_raw();
    // SAFETY: pre_exec runs in the child process between fork(2) and
    // execve(2). The closure only calls async-signal-safe syscalls
    // (setgroups/setgid/setuid) and returns an io::Result, which is
    // the documented contract.
    unsafe {
        command.pre_exec(move || {
            // Drop supplementary groups BEFORE setgid/setuid. Order matters:
            // setgroups requires uid 0.
            nix::unistd::setgroups(&[]).map_err(nix_to_io_error)?;
            // Set the primary gid before uid.
            nix::unistd::setgid(Gid::from_raw(gid_raw)).map_err(nix_to_io_error)?;
            nix::unistd::setuid(Uid::from_raw(uid_raw)).map_err(nix_to_io_error)?;
            Ok(())
        });
    }

    true
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn nix_to_io_error(err: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(err as i32)
}

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )
))]
pub(super) fn install_exec_user_switch(command: &mut StdCommand, user: &RequestedUser) -> bool {
    use std::os::unix::process::CommandExt;

    if !user.switch_required {
        return false;
    }

    command.uid(user.uid.as_raw());
    command.gid(user.gid.as_raw());
    true
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::process::Command as StdCommand;

    #[cfg(unix)]
    use nix::unistd::{Gid, Uid};

    #[cfg(unix)]
    use super::{RequestedUser, install_exec_user_switch};

    #[cfg(unix)]
    #[test]
    fn exec_user_switch_hook_only_installs_when_switch_is_required() {
        let base_user = RequestedUser {
            uid: Uid::from_raw(1000),
            gid: Gid::from_raw(1000),
            name: "demo".to_owned(),
            home_dir: "/home/demo".to_owned(),
            shell: "/bin/sh".to_owned(),
            switch_required: false,
        };

        let mut unchanged = StdCommand::new("/bin/echo");
        assert!(!install_exec_user_switch(&mut unchanged, &base_user));

        let mut switched = StdCommand::new("/bin/echo");
        let mut target_user = base_user;
        target_user.switch_required = true;
        assert!(install_exec_user_switch(&mut switched, &target_user));
    }
}

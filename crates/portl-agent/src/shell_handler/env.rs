use std::collections::BTreeMap;
use std::process::Command as StdCommand;

use super::user::RequestedUser;

pub(super) fn apply_env_to_command(command: &mut StdCommand, envs: Vec<(String, String)>) {
    command.env_clear();
    command.envs(envs);
}

pub(super) fn effective_env(
    shell_caps: Option<&portl_core::ticket::schema::ShellCaps>,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
) -> Vec<(String, String)> {
    // v0.1 uses a minimal sanitized env; v0.2 may add PAM login-env
    // synthesis for Merge policy.
    let deny_base = sanitized_env_base(requested_user, req);

    let env = match shell_caps.map(|caps| &caps.env_policy) {
        Some(portl_core::ticket::schema::EnvPolicy::Deny) | None => deny_base,
        Some(portl_core::ticket::schema::EnvPolicy::Merge { allow: Some(keys) }) => {
            let mut env = deny_base;
            merge_env_patch(&mut env, &req.env_patch, Some(keys));
            env
        }
        Some(portl_core::ticket::schema::EnvPolicy::Merge { allow: None }) => {
            let mut env = deny_base;
            merge_env_patch(&mut env, &req.env_patch, None);
            env
        }
        Some(portl_core::ticket::schema::EnvPolicy::Replace { base }) => {
            base.iter().cloned().collect::<BTreeMap<_, _>>()
        }
    };

    env.into_iter().collect()
}

pub(super) fn merge_env_patch(
    env: &mut BTreeMap<String, String>,
    env_patch: &[(String, portl_proto::shell_v1::EnvValue)],
    allow: Option<&Vec<String>>,
) {
    for (key, value) in env_patch {
        if allow
            .as_ref()
            .is_some_and(|allow| !allow.iter().any(|candidate| candidate == key))
        {
            continue;
        }
        match value {
            portl_proto::shell_v1::EnvValue::Set(value) => {
                env.insert(key.clone(), value.clone());
            }
            portl_proto::shell_v1::EnvValue::Unset => {
                env.remove(key);
            }
        }
    }
}

pub(super) fn sanitized_env_base(
    requested_user: Option<&RequestedUser>,
    req: &portl_proto::shell_v1::ShellReq,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    #[cfg(unix)]
    if let Some(user) = requested_user {
        env.insert("HOME".to_owned(), user.home_dir.clone());
        env.insert("USER".to_owned(), user.name.clone());
        env.insert("LOGNAME".to_owned(), user.name.clone());
        env.insert("SHELL".to_owned(), user.shell.clone());
    }

    #[cfg(not(unix))]
    {
        let _ = requested_user;
    }

    env.insert("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned());

    if let Some(pty) = req.pty.as_ref() {
        env.insert("TERM".to_owned(), pty.term.clone());
    }

    env
}

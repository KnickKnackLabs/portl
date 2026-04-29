use std::collections::BTreeMap;

use crate::shell_handler::user::RequestedUser;

#[derive(Debug, Clone)]
pub(crate) struct TargetProcessContext {
    pub(crate) cwd: Option<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) shell_program: String,
}

impl TargetProcessContext {
    pub(crate) fn new(
        shell_caps: Option<&portl_core::ticket::schema::ShellCaps>,
        req: &portl_proto::shell_v1::ShellReq,
        requested_user: Option<&RequestedUser>,
    ) -> Self {
        Self {
            cwd: requested_cwd(req, requested_user),
            env: effective_env(shell_caps, req, requested_user),
            shell_program: target_shell(requested_user),
        }
    }

    #[cfg(test)]
    fn env_map(&self) -> BTreeMap<String, String> {
        self.env.iter().cloned().collect()
    }
}

fn requested_cwd(
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
) -> Option<String> {
    req.cwd
        .clone()
        .or_else(|| requested_user.map(|user| user.home_dir.clone()))
}

fn target_shell(requested_user: Option<&RequestedUser>) -> String {
    requested_user.map_or_else(
        || std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned()),
        |user| user.shell.clone(),
    )
}

pub(crate) fn effective_env(
    shell_caps: Option<&portl_core::ticket::schema::ShellCaps>,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
) -> Vec<(String, String)> {
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

fn merge_env_patch(
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

fn sanitized_env_base(
    requested_user: Option<&RequestedUser>,
    req: &portl_proto::shell_v1::ShellReq,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    if let Some(user) = requested_user {
        env.insert("HOME".to_owned(), user.home_dir.clone());
        env.insert("USER".to_owned(), user.name.clone());
        env.insert("LOGNAME".to_owned(), user.name.clone());
        env.insert("SHELL".to_owned(), user.shell.clone());
    }

    env.insert("PATH".to_owned(), default_target_path());

    if let Some(pty) = req.pty.as_ref() {
        env.insert("TERM".to_owned(), normalize_term(&pty.term));
    }

    env
}

pub(crate) fn default_target_path() -> String {
    [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/bin",
    ]
    .join(":")
}

fn normalize_term(term: &str) -> String {
    let trimmed = term.trim();
    if trimmed.is_empty() || trimmed == "unknown" {
        "xterm-256color".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use nix::unistd::{Gid, Uid};

    #[cfg(unix)]
    use crate::shell_handler::user::RequestedUser;

    #[cfg(unix)]
    fn demo_user() -> RequestedUser {
        RequestedUser {
            uid: Uid::from_raw(501),
            gid: Gid::from_raw(20),
            name: "demo".to_owned(),
            home_dir: "/Users/demo".to_owned(),
            shell: "/opt/homebrew/bin/zsh".to_owned(),
            switch_required: false,
        }
    }

    #[cfg(unix)]
    fn shell_req(
        cwd: Option<&str>,
        pty: Option<portl_proto::shell_v1::PtyCfg>,
    ) -> portl_proto::shell_v1::ShellReq {
        portl_proto::shell_v1::ShellReq {
            preamble: portl_proto::wire::StreamPreamble {
                peer_token: [0; 16],
                alpn: String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1).into_owned(),
            },
            mode: portl_proto::shell_v1::ShellMode::Shell,
            argv: None,
            env_patch: Vec::new(),
            cwd: cwd.map(ToOwned::to_owned),
            pty,
            user: None,
        }
    }

    #[cfg(unix)]
    fn shell_caps() -> portl_core::ticket::schema::ShellCaps {
        portl_core::ticket::schema::ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: portl_core::ticket::schema::EnvPolicy::Merge { allow: None },
        }
    }

    #[cfg(unix)]
    #[test]
    fn defaults_cwd_to_target_user_home() {
        let req = shell_req(None, None);
        let user = demo_user();

        let context = super::TargetProcessContext::new(Some(&shell_caps()), &req, Some(&user));

        assert_eq!(context.cwd.as_deref(), Some("/Users/demo"));
        assert_eq!(context.shell_program, "/opt/homebrew/bin/zsh");
    }

    #[cfg(unix)]
    #[test]
    fn requested_cwd_overrides_target_user_home() {
        let req = shell_req(Some("/tmp/work"), None);
        let user = demo_user();

        let context = super::TargetProcessContext::new(Some(&shell_caps()), &req, Some(&user));

        assert_eq!(context.cwd.as_deref(), Some("/tmp/work"));
    }

    #[cfg(unix)]
    #[test]
    fn pty_context_includes_normalized_term_and_user_env() {
        let req = shell_req(
            None,
            Some(portl_proto::shell_v1::PtyCfg {
                term: "unknown".to_owned(),
                cols: 80,
                rows: 24,
            }),
        );
        let user = demo_user();

        let context = super::TargetProcessContext::new(Some(&shell_caps()), &req, Some(&user));
        let env = context.env_map();

        assert_eq!(env.get("HOME").map(String::as_str), Some("/Users/demo"));
        assert_eq!(env.get("USER").map(String::as_str), Some("demo"));
        assert_eq!(env.get("LOGNAME").map(String::as_str), Some("demo"));
        assert_eq!(
            env.get("SHELL").map(String::as_str),
            Some("/opt/homebrew/bin/zsh")
        );
        assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color"));
    }

    #[cfg(unix)]
    #[test]
    fn non_pty_context_omits_term() {
        let req = shell_req(None, None);
        let user = demo_user();

        let context = super::TargetProcessContext::new(Some(&shell_caps()), &req, Some(&user));
        let env = context.env_map();

        assert!(!env.contains_key("TERM"));
    }
}

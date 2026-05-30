//! Capability narrowing helpers.
//!
//! Delegated tickets must be monotone: they can only reduce the scope
//! of a parent capability set, never add new capability families or
//! broaden any existing family.
//!
//! Ticket-chain verification enforces additional non-capability monotonicity
//! rules, including bearer-token inheritance, in `ticket::verify`.

use crate::ticket::schema::{
    Capabilities, EnvPolicy, FsCaps, MetaCaps, PortRule, ShellCaps, UnixCaps, VpnCaps,
};

/// Return true iff `child` is a monotone narrowing of `parent`.
#[must_use]
pub fn is_narrowing(parent: &Capabilities, child: &Capabilities) -> bool {
    if child.presence & !parent.presence != 0 {
        return false;
    }

    option_narrows(parent.shell.as_ref(), child.shell.as_ref(), shell_narrows)
        && option_narrows(
            parent.tcp.as_deref(),
            child.tcp.as_deref(),
            port_rules_narrow,
        )
        && option_narrows(
            parent.udp.as_deref(),
            child.udp.as_deref(),
            port_rules_narrow,
        )
        && option_narrows(parent.fs.as_ref(), child.fs.as_ref(), fs_narrows)
        && option_narrows(parent.vpn.as_ref(), child.vpn.as_ref(), vpn_narrows)
        && option_narrows(parent.meta.as_ref(), child.meta.as_ref(), meta_narrows)
        && option_narrows(parent.unix.as_ref(), child.unix.as_ref(), unix_narrows)
}

fn option_narrows<T: ?Sized>(
    parent: Option<&T>,
    child: Option<&T>,
    cmp: impl FnOnce(&T, &T) -> bool,
) -> bool {
    match (parent, child) {
        (_, None) => true,
        (Some(parent), Some(child)) => cmp(parent, child),
        (None, Some(_)) => false,
    }
}

fn shell_narrows(parent: &ShellCaps, child: &ShellCaps) -> bool {
    allowlist_narrows(
        parent.user_allowlist.as_deref(),
        child.user_allowlist.as_deref(),
    ) && allowlist_narrows(
        parent.command_allowlist.as_deref(),
        child.command_allowlist.as_deref(),
    ) && bool_narrows(parent.pty_allowed, child.pty_allowed)
        && bool_narrows(parent.exec_allowed, child.exec_allowed)
        && env_policy_narrows(&parent.env_policy, &child.env_policy)
}

fn allowlist_narrows(parent: Option<&[String]>, child: Option<&[String]>) -> bool {
    match (parent, child) {
        (_, None) => parent.is_none(),
        (None, Some(_)) => true,
        (Some(parent), Some(child)) => child.iter().all(|entry| parent.contains(entry)),
    }
}

fn env_policy_narrows(parent: &EnvPolicy, child: &EnvPolicy) -> bool {
    match (parent, child) {
        (_, EnvPolicy::Deny) | (EnvPolicy::Merge { allow: None }, EnvPolicy::Merge { .. }) => true,
        (EnvPolicy::Deny, _) => matches!(child, EnvPolicy::Deny),
        (
            EnvPolicy::Merge {
                allow: Some(parent),
            },
            EnvPolicy::Merge { allow: Some(child) },
        ) => child.iter().all(|entry| parent.contains(entry)),
        (EnvPolicy::Replace { base: parent }, EnvPolicy::Replace { base: child }) => {
            parent == child
        }
        _ => false,
    }
}

fn bool_narrows(parent: bool, child: bool) -> bool {
    !child || parent
}

fn port_rules_narrow(parent: &[PortRule], child: &[PortRule]) -> bool {
    child.iter().all(|child_rule| {
        parent
            .iter()
            .any(|parent_rule| port_rule_covers(parent_rule, child_rule))
    })
}

fn port_rule_covers(parent: &PortRule, child: &PortRule) -> bool {
    host_glob_covers(&parent.host_glob, &child.host_glob)
        && parent.port_min <= child.port_min
        && parent.port_max >= child.port_max
}

fn host_glob_covers(parent: &str, child: &str) -> bool {
    parent == "*" || parent == child
}

fn fs_narrows(parent: &FsCaps, child: &FsCaps) -> bool {
    child.roots.iter().all(|child_root| {
        parent
            .roots
            .iter()
            .any(|parent_root| path_root_covers(parent_root, child_root))
    }) && (!parent.readonly || child.readonly)
        && match (parent.max_size, child.max_size) {
            (_, None) => parent.max_size.is_none(),
            (None, Some(_)) => true,
            (Some(parent), Some(child)) => child <= parent,
        }
}

fn path_root_covers(parent: &str, child: &str) -> bool {
    child == parent
        || parent == "/"
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn vpn_narrows(parent: &VpnCaps, child: &VpnCaps) -> bool {
    parent.my_ula == child.my_ula && parent.peer_ula == child.peer_ula && child.mtu <= parent.mtu
}

fn meta_narrows(parent: &MetaCaps, child: &MetaCaps) -> bool {
    bool_narrows(parent.ping, child.ping) && bool_narrows(parent.info, child.info)
}

fn unix_narrows(parent: &UnixCaps, child: &UnixCaps) -> bool {
    unix_rules_narrow(&parent.connect, &child.connect)
        && unix_rules_narrow(&parent.listen, &child.listen)
}

fn unix_rules_narrow(
    parent: &[crate::ticket::schema::UnixPathRule],
    child: &[crate::ticket::schema::UnixPathRule],
) -> bool {
    child.iter().all(|child_rule| {
        parent
            .iter()
            .any(|parent_rule| parent_rule.covers(child_rule))
    })
}

#[cfg(test)]
mod tests {
    use super::is_narrowing;
    use crate::ticket::schema::{Capabilities, UnixCaps, UnixPathRule};

    #[test]
    fn unix_connect_child_must_stay_within_parent_rules() {
        let parent = unix_caps(vec!["/tmp/portl-*"], vec![]);
        let allowed = unix_caps(vec!["/tmp/portl-agent.sock"], vec![]);
        let widened = unix_caps(vec!["/tmp/other.sock"], vec![]);

        assert!(is_narrowing(&parent, &allowed));
        assert!(!is_narrowing(&parent, &widened));
    }

    #[test]
    fn unix_listen_child_cannot_add_connect_capability() {
        let parent = unix_caps(vec![], vec!["/tmp/portl-*"]);
        let child = unix_caps(vec!["/tmp/portl-agent.sock"], vec!["/tmp/portl-agent.sock"]);

        assert!(!is_narrowing(&parent, &child));
    }

    fn unix_caps(connect: Vec<&str>, listen: Vec<&str>) -> Capabilities {
        Capabilities {
            presence: 0b0100_0000,
            shell: None,
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
            unix: Some(UnixCaps {
                connect: connect.into_iter().map(rule).collect(),
                listen: listen.into_iter().map(rule).collect(),
            }),
        }
    }

    fn rule(path: &str) -> UnixPathRule {
        UnixPathRule {
            path: path.to_owned(),
        }
    }
}

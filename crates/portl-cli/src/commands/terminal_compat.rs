use std::io::{self, IsTerminal, Write as _};
use std::process::Command as StdCommand;

use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;
use portl_core::io::BufferedRecv;
use portl_core::net::{PeerSession, ShellClient, open_exec_with_env};
use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::commands::peer_resolve::ConnectedPeer;

pub(crate) const FALLBACK_TERM: &str = "xterm-256color";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TermRequest {
    Auto,
    AutoCandidate(String),
    Explicit(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TermInstallPrompt {
    AllowIfInteractive,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TermDecision {
    Use {
        term: String,
        warning: Option<String>,
    },
    OfferInstall {
        term: String,
    },
    Fail {
        message: String,
    },
}

impl TermRequest {
    fn candidate_term(&self, local_term: &str) -> String {
        match self {
            Self::Auto => local_term.to_owned(),
            Self::AutoCandidate(term) => normalize_local_term(Some(term)),
            Self::Explicit(term) => term.to_owned(),
        }
    }

    fn is_auto(&self) -> bool {
        matches!(self, Self::Auto | Self::AutoCandidate(_))
    }
}

pub(crate) fn term_request(requested_term: Option<&str>) -> Result<TermRequest> {
    let Some(term) = requested_term else {
        return Ok(TermRequest::Auto);
    };
    let trimmed = term.trim();
    if trimmed.is_empty() {
        bail!("--term must not be empty");
    }
    Ok(TermRequest::Explicit(trimmed.to_owned()))
}

pub(crate) fn auto_candidate_term_request(term: &str) -> TermRequest {
    TermRequest::AutoCandidate(normalize_local_term(Some(term)))
}

pub(crate) async fn resolve_pty_term(
    connected: &ConnectedPeer,
    target_label: &str,
    user: Option<&str>,
    request: TermRequest,
    install_prompt: TermInstallPrompt,
    install_hint: Option<&str>,
) -> Result<String> {
    resolve_pty_term_on_session(
        &connected.connection,
        &connected.session,
        target_label,
        user,
        request,
        install_prompt,
        install_hint,
    )
    .await
}

pub(crate) async fn resolve_pty_term_on_session(
    connection: &Connection,
    session: &PeerSession,
    target_label: &str,
    user: Option<&str>,
    request: TermRequest,
    install_prompt: TermInstallPrompt,
    install_hint: Option<&str>,
) -> Result<String> {
    let local_term = normalize_local_term(std::env::var("TERM").ok().as_deref());
    let candidate = request.candidate_term(&local_term);
    let remote_has = if request.is_auto() && candidate == FALLBACK_TERM {
        true
    } else {
        remote_has_terminfo(connection, session, user, &candidate).await?
    };
    let local_export = if matches!(request, TermRequest::Explicit(_)) && !remote_has {
        export_local_terminfo(&candidate).ok()
    } else {
        None
    };
    let can_prompt_install =
        install_prompt == TermInstallPrompt::AllowIfInteractive && io::stdin().is_terminal();
    let decision = choose_term_after_probe(
        request,
        &candidate,
        target_label,
        remote_has,
        local_export.is_some(),
        can_prompt_install,
        install_hint,
    );

    match decision {
        TermDecision::Use { term, warning } => {
            if let Some(warning) = warning {
                eprint!("{warning}");
            }
            Ok(term)
        }
        TermDecision::OfferInstall { term } => {
            let source = local_export.context("local terminfo export missing")?;
            if !prompt_install_terminfo(target_label, &term)? {
                bail!(
                    "target {target_label} does not know TERM={term}; install declined, so no shell was started"
                );
            }
            install_remote_terminfo(connection, session, user, &term, &source).await?;
            Ok(term)
        }
        TermDecision::Fail { message } => bail!(message),
    }
}

fn normalize_local_term(term: Option<&str>) -> String {
    let Some(term) = term.map(str::trim).filter(|term| !term.is_empty()) else {
        return FALLBACK_TERM.to_owned();
    };
    if term == "unknown" {
        FALLBACK_TERM.to_owned()
    } else {
        term.to_owned()
    }
}

fn choose_term_after_probe(
    request: TermRequest,
    candidate_term: &str,
    target_label: &str,
    remote_has_term: bool,
    local_can_export: bool,
    can_prompt_install: bool,
    install_hint: Option<&str>,
) -> TermDecision {
    match request {
        TermRequest::Auto | TermRequest::AutoCandidate(_) => {
            if remote_has_term || candidate_term == FALLBACK_TERM {
                TermDecision::Use {
                    term: candidate_term.to_owned(),
                    warning: None,
                }
            } else {
                TermDecision::Use {
                    term: FALLBACK_TERM.to_owned(),
                    warning: Some(fallback_warning(target_label, candidate_term, install_hint)),
                }
            }
        }
        TermRequest::Explicit(term) => {
            if remote_has_term {
                return TermDecision::Use {
                    term,
                    warning: None,
                };
            }
            if !local_can_export {
                return TermDecision::Fail {
                    message: terminfo_install_unavailable_message(&term, target_label),
                };
            }
            if can_prompt_install {
                TermDecision::OfferInstall { term }
            } else {
                TermDecision::Fail {
                    message: format!(
                        "target {target_label} does not know TERM={term}; rerun interactively with --term {term} to install user-scoped terminfo, or omit --term to fall back automatically"
                    ),
                }
            }
        }
    }
}

fn fallback_warning(target_label: &str, term: &str, install_hint: Option<&str>) -> String {
    let mut warning = format!(
        "warning: target {target_label} does not know TERM={term}; using {FALLBACK_TERM}.\n"
    );
    if let Some(hint) = install_hint {
        warning.push_str("         To install and use it next time: ");
        warning.push_str(hint);
        warning.push('\n');
    }
    warning
}

fn terminfo_install_unavailable_message(term: &str, target_label: &str) -> String {
    format!(
        "target {target_label} does not know TERM={term}, and local terminfo for {term} could not be exported"
    )
}

async fn remote_has_terminfo(
    connection: &Connection,
    session: &PeerSession,
    user: Option<&str>,
    term: &str,
) -> Result<bool> {
    let argv = vec![
        "sh".to_owned(),
        "-lc".to_owned(),
        "command -v infocmp >/dev/null 2>&1 && infocmp \"$1\" >/dev/null 2>&1".to_owned(),
        "sh".to_owned(),
        term.to_owned(),
    ];
    let code = run_remote_exec_for_status(connection, session, user, argv, None)
        .await
        .with_context(|| format!("check remote terminfo for {term}"))?;
    Ok(code == 0)
}

fn export_local_terminfo(term: &str) -> Result<Vec<u8>> {
    let output = StdCommand::new("infocmp")
        .arg("-x")
        .arg(term)
        .output()
        .with_context(|| format!("run local infocmp for {term}"))?;
    if !output.status.success() || output.stdout.is_empty() {
        bail!("local infocmp could not export {term}");
    }
    Ok(output.stdout)
}

fn prompt_install_terminfo(target_label: &str, term: &str) -> Result<bool> {
    let mut stderr = io::stderr();
    write!(
        stderr,
        "target {target_label} does not know TERM={term}. Install user-scoped terminfo into ~/.terminfo on {target_label}? [y/N] "
    )
    .context("write terminfo install prompt")?;
    stderr.flush().context("flush terminfo install prompt")?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("read terminfo install prompt")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

async fn install_remote_terminfo(
    connection: &Connection,
    session: &PeerSession,
    user: Option<&str>,
    term: &str,
    source: &[u8],
) -> Result<()> {
    let argv = vec![
        "sh".to_owned(),
        "-lc".to_owned(),
        "mkdir -p ~/.terminfo && tic -x -o ~/.terminfo -".to_owned(),
    ];
    let code = run_remote_exec_for_status(connection, session, user, argv, Some(source))
        .await
        .with_context(|| format!("install remote terminfo for {term}"))?;
    if code != 0 {
        bail!("remote tic failed while installing TERM={term}");
    }
    Ok(())
}

async fn run_remote_exec_for_status(
    connection: &Connection,
    session: &PeerSession,
    user: Option<&str>,
    argv: Vec<String>,
    stdin_bytes: Option<&[u8]>,
) -> Result<i32> {
    let mut shell = open_exec_with_env(
        connection,
        session,
        user.map(ToOwned::to_owned),
        None,
        argv,
        Vec::new(),
    )
    .await?;

    if let Some(bytes) = stdin_bytes {
        shell
            .stdin
            .write_all(bytes)
            .await
            .context("write remote exec stdin")?;
    }
    shell.close_stdin()?;

    let ShellClient {
        control_send: _control_send,
        control_recv: _control_recv,
        stdin: _stdin,
        mut stdout,
        mut stderr,
        mut exit,
        signal: _signal,
        resize: _resize,
    } = shell;

    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stdout
            .read_to_end(&mut buf)
            .await
            .context("read remote exec stdout")?;
        Ok::<_, anyhow::Error>(buf)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stderr
            .read_to_end(&mut buf)
            .await
            .context("read remote exec stderr")?;
        Ok::<_, anyhow::Error>(buf)
    });

    let code = read_exit(&mut exit).await?;
    let _stdout = stdout_task.await.context("join remote exec stdout")??;
    let stderr = stderr_task.await.context("join remote exec stderr")??;
    if code != 0 && !stderr.is_empty() {
        debug!(
            stderr = %String::from_utf8_lossy(&stderr),
            "remote helper command failed"
        );
    }
    Ok(code)
}

async fn read_exit(recv: &mut BufferedRecv) -> Result<i32> {
    let frame = recv
        .read_frame::<portl_proto::shell_v1::ExitFrame>(128)
        .await?
        .context("missing exit frame")?;
    Ok(frame.code)
}

#[cfg(test)]
mod tests {
    use super::{
        FALLBACK_TERM, TermDecision, TermInstallPrompt, TermRequest, auto_candidate_term_request,
        choose_term_after_probe, normalize_local_term, term_request,
        terminfo_install_unavailable_message,
    };

    #[test]
    fn shell_term_auto_uses_local_term_when_target_knows_it() {
        let decision = choose_term_after_probe(
            TermRequest::Auto,
            "xterm-kitty",
            "onyx",
            true,
            false,
            false,
            Some("portl shell --term xterm-kitty onyx"),
        );

        assert_eq!(
            decision,
            TermDecision::Use {
                term: "xterm-kitty".to_owned(),
                warning: None,
            }
        );
    }

    #[test]
    fn shell_term_auto_falls_back_when_target_lacks_local_term() {
        let decision = choose_term_after_probe(
            TermRequest::Auto,
            "xterm-kitty",
            "onyx",
            false,
            true,
            true,
            Some("portl shell --term xterm-kitty onyx"),
        );

        assert_eq!(
            decision,
            TermDecision::Use {
                term: FALLBACK_TERM.to_owned(),
                warning: Some(
                    "warning: target onyx does not know TERM=xterm-kitty; using xterm-256color.\n         To install and use it next time: portl shell --term xterm-kitty onyx\n"
                        .to_owned()
                ),
            }
        );
    }

    #[test]
    fn ssh_stdio_term_auto_candidate_falls_back_when_target_lacks_requested_term() {
        let decision = choose_term_after_probe(
            TermRequest::AutoCandidate("xterm-kitty".to_owned()),
            "xterm-kitty",
            "onyx",
            false,
            false,
            false,
            None,
        );

        assert_eq!(
            decision,
            TermDecision::Use {
                term: FALLBACK_TERM.to_owned(),
                warning: Some(
                    "warning: target onyx does not know TERM=xterm-kitty; using xterm-256color.\n"
                        .to_owned()
                ),
            }
        );
    }

    #[test]
    fn shell_term_explicit_missing_offers_interactive_install_when_exportable() {
        let decision = choose_term_after_probe(
            TermRequest::Explicit("xterm-kitty".to_owned()),
            "xterm-kitty",
            "onyx",
            false,
            true,
            true,
            None,
        );

        assert_eq!(
            decision,
            TermDecision::OfferInstall {
                term: "xterm-kitty".to_owned()
            }
        );
    }

    #[test]
    fn shell_term_explicit_missing_fails_without_interactive_prompt() {
        let decision = choose_term_after_probe(
            TermRequest::Explicit("xterm-kitty".to_owned()),
            "xterm-kitty",
            "onyx",
            false,
            true,
            false,
            None,
        );

        assert_eq!(
            decision,
            TermDecision::Fail {
                message: "target onyx does not know TERM=xterm-kitty; rerun interactively with --term xterm-kitty to install user-scoped terminfo, or omit --term to fall back automatically"
                    .to_owned()
            }
        );
    }

    #[test]
    fn shell_term_explicit_missing_fails_when_local_export_is_unavailable() {
        assert_eq!(
            terminfo_install_unavailable_message("xterm-kitty", "onyx"),
            "target onyx does not know TERM=xterm-kitty, and local terminfo for xterm-kitty could not be exported"
        );
    }

    #[test]
    fn shell_term_auto_normalizes_empty_local_term_to_fallback() {
        assert_eq!(normalize_local_term(None), FALLBACK_TERM);
        assert_eq!(normalize_local_term(Some("")), FALLBACK_TERM);
        assert_eq!(normalize_local_term(Some("unknown")), FALLBACK_TERM);
        assert_eq!(
            auto_candidate_term_request(" "),
            TermRequest::AutoCandidate(FALLBACK_TERM.to_owned())
        );
    }

    #[test]
    fn explicit_term_request_rejects_empty_values() {
        assert!(term_request(Some(" ")).is_err());
        assert_eq!(
            term_request(Some("xterm-kitty")).expect("term request"),
            TermRequest::Explicit("xterm-kitty".to_owned())
        );
        assert_eq!(term_request(None).expect("term request"), TermRequest::Auto);
    }

    #[test]
    fn term_install_prompt_modes_are_distinct() {
        assert_ne!(
            TermInstallPrompt::AllowIfInteractive,
            TermInstallPrompt::Never
        );
    }
}

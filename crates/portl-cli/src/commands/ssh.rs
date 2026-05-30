use std::process::ExitCode;

use anyhow::{Result, bail};

use crate::commands::{exec, shell};

fn validate_phase1_options(
    tty: Option<bool>,
    _forward_agent: bool,
    remote_command: &[String],
) -> Result<()> {
    if tty == Some(true) && !remote_command.is_empty() {
        bail!("portl ssh: -t with a remote command is not supported yet");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    peer: &str,
    user: Option<&str>,
    tty: Option<bool>,
    forward_agent: bool,
    stdin_null: bool,
    _quiet: bool,
    _verbose: u8,
    remote_command: &[String],
) -> Result<ExitCode> {
    validate_phase1_options(tty, forward_agent, remote_command)?;

    if remote_command.is_empty() {
        return shell::run_with_options(
            peer,
            None,
            user,
            shell::ShellRunOptions {
                quiet_resolve: true,
                close_stdin: stdin_null,
            },
        );
    }

    let command = remote_command.join(" ");
    let argv = vec!["/bin/sh".to_owned(), "-lc".to_owned(), command];
    exec::run_with_options(
        peer,
        None,
        user,
        &argv,
        exec::ExecRunOptions {
            quiet_resolve: true,
            close_stdin: stdin_null,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::validate_phase1_options;

    #[test]
    fn phase1_accepts_agent_forwarding_flag_without_enabling_it_yet() {
        validate_phase1_options(None, true, &["git-upload-pack".to_owned()]).unwrap();
    }

    #[test]
    fn phase1_rejects_forced_tty_with_remote_command() {
        let err = validate_phase1_options(Some(true), false, &["top".to_owned()])
            .expect_err("forced tty remote command should be rejected for now");
        assert!(err.to_string().contains("-t with a remote command"));
    }
}

pub mod agent;
pub mod config;
pub mod docker;
pub mod doctor;
pub mod exec;
pub mod init;
pub mod install;
pub mod mint_root;
pub mod peer;
pub mod peer_resolve;
pub mod revocations;
pub mod revoke;
pub mod shell;
pub mod slicer;
pub mod status;
pub mod tcp;
pub mod ticket;
pub mod udp;
pub mod whoami;

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Command, CommandFactory};
use clap_complete::Shell;

pub fn completions(shell: Shell) -> ExitCode {
    let mut cmd = crate::Cli::command();
    let name = cmd.get_name().to_owned();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
    ExitCode::SUCCESS
}

pub fn man(out_dir: Option<&Path>, section: &str) -> Result<ExitCode> {
    let cmd = crate::Cli::command();
    if let Some(out_dir) = out_dir {
        fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
        write_man_tree(out_dir, &cmd, &[], section)?;
    } else {
        let mut buffer = Vec::new();
        clap_mangen::Man::new(cmd)
            .section(section)
            .render(&mut buffer)?;
        print!("{}", String::from_utf8_lossy(&buffer));
    }
    Ok(ExitCode::SUCCESS)
}

fn write_man_tree(out_dir: &Path, cmd: &Command, path: &[String], section: &str) -> Result<()> {
    if cmd.is_hide_set() {
        return Ok(());
    }
    let name = if path.is_empty() {
        "portl".to_owned()
    } else {
        format!("portl-{}", path.join("-"))
    };
    let file = out_dir.join(format!("{name}.{section}"));
    let mut buffer = Vec::new();
    clap_mangen::Man::new(cmd.clone())
        .section(section)
        .render(&mut buffer)?;
    fs::write(&file, buffer).with_context(|| format!("write {}", file.display()))?;

    for sub in cmd.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        let mut child_path = path.to_owned();
        child_path.push(sub.get_name().to_owned());
        write_man_tree(out_dir, sub, &child_path, section)?;
    }
    Ok(())
}

use std::process::ExitCode;

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct CapsEnvelope<'a> {
    schema: u8,
    kind: &'static str,
    caps: Vec<CapEntry<'a>>,
}

#[derive(Clone, Debug, Serialize)]
struct CapEntry<'a> {
    name: &'a str,
    summary: &'a str,
    argument_grammar: Option<&'a str>,
    examples: Vec<&'a str>,
}

pub fn run(cap: Option<&str>, json: bool) -> Result<ExitCode> {
    let entries = filtered_entries(cap)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&CapsEnvelope {
                schema: 1,
                kind: "ticket.caps",
                caps: entries,
            })?
        );
    } else if cap.is_none() {
        print!("{}", crate::commands::mint_root::caps_reference());
    } else {
        print_human_entries(&entries);
    }
    Ok(ExitCode::SUCCESS)
}

fn filtered_entries(cap: Option<&str>) -> Result<Vec<CapEntry<'static>>> {
    let entries = entries();
    if let Some(name) = cap {
        let found: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.name == name)
            .collect();
        if found.is_empty() {
            anyhow::bail!("unknown cap '{name}'. Run `portl ticket caps` for the full reference.");
        }
        Ok(found)
    } else {
        Ok(entries)
    }
}

fn entries() -> Vec<CapEntry<'static>> {
    vec![
        CapEntry {
            name: "shell",
            summary: "Full shell access — PTY allowed, exec allowed, no env filter.",
            argument_grammar: None,
            examples: vec!["portl ticket issue shell --ttl 10m"],
        },
        CapEntry {
            name: "meta:ping",
            summary: "Respond to liveness pings.",
            argument_grammar: None,
            examples: vec!["portl ticket issue meta:ping --ttl 30d"],
        },
        CapEntry {
            name: "meta:info",
            summary: "Expose agent metadata (version, uptime, feature flags).",
            argument_grammar: None,
            examples: vec!["portl ticket issue meta:info --ttl 30d"],
        },
        CapEntry {
            name: "tcp",
            summary: "TCP port forward.",
            argument_grammar: Some("tcp:<host_glob>:<port>[-<port_max>]"),
            examples: vec![
                "portl ticket issue 'tcp:*:8080' --ttl 1h",
                "portl ticket issue 'tcp:127.0.0.1:6000-6100' --ttl 30m",
            ],
        },
        CapEntry {
            name: "udp",
            summary: "UDP port forward.",
            argument_grammar: Some("udp:<host_glob>:<port>[-<port_max>]"),
            examples: vec!["portl ticket issue 'udp:*:5353' --ttl 1h"],
        },
        CapEntry {
            name: "all",
            summary: "Wildcard for development and self-trust.",
            argument_grammar: None,
            examples: vec!["portl ticket issue all --ttl 1h"],
        },
    ]
}

fn print_human_entries(entries: &[CapEntry<'_>]) {
    for entry in entries {
        println!("{}", entry.name);
        println!("    {}", entry.summary);
        if let Some(grammar) = entry.argument_grammar {
            println!("    grammar: {grammar}");
        }
        for example in &entry.examples {
            println!("    example: {example}");
        }
    }
}

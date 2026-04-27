use std::path::PathBuf;
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use nix::unistd::Uid;
use serde::Serialize;

use crate::AgentAction;

const LABEL: &str = "com.portl.agent";
const UNIT: &str = "portl-agent.service";

#[derive(Debug, Clone, Serialize)]
struct AgentServiceReport {
    schema: &'static str,
    service: ServiceInfo,
    process: ProcessInfo,
    ipc: IpcInfo,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceInfo {
    manager: String,
    scope: String,
    installed: bool,
    loaded: bool,
    enabled: bool,
    state: String,
    path: Option<String>,
    program: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ProcessInfo {
    running: bool,
    pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct IpcInfo {
    ok: bool,
    socket: String,
    pid: Option<u32>,
    version: Option<String>,
    uptime_secs: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AgentActionReport {
    schema: &'static str,
    action: String,
    ok: bool,
    changed: bool,
    message: String,
    status: AgentServiceReport,
}

pub fn run(action: AgentAction, json: bool) -> Result<ExitCode> {
    match action {
        AgentAction::Status { service } => status(json, service),
        AgentAction::Up => up(json),
        AgentAction::Down => down(json),
        AgentAction::Restart => restart(json),
    }
}

fn status(json: bool, service_only: bool) -> Result<ExitCode> {
    let report = collect_report();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_status_human(&report);
    }
    let success = if service_only {
        report.service.installed || report.service.loaded || report.service.enabled
    } else {
        report.ipc.ok
    };
    Ok(if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn up(json: bool) -> Result<ExitCode> {
    let portl = sibling_portl_binary()?;
    let output = ProcessCommand::new(&portl)
        .args(["install", "--apply", "--yes"])
        .output()
        .with_context(|| format!("run {} install --apply --yes", portl.display()))?;
    let ok = output.status.success();
    let report = collect_report();
    let message = if ok {
        "agent service installed and running".to_owned()
    } else {
        format!(
            "failed to install agent service: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    };
    print_action(
        json,
        &AgentActionReport {
            schema: "portl.agent.action.v1",
            action: "up".to_owned(),
            ok,
            changed: ok,
            message,
            status: report,
        },
    )
}

fn down(json: bool) -> Result<ExitCode> {
    let before = collect_report();
    let result = disable_service();
    let ok = result.is_ok();
    let message = match result {
        Ok(()) => "agent service stopped and disabled; state kept".to_owned(),
        Err(err) => format!("failed to disable agent service: {err:#}"),
    };
    let report = collect_report();
    print_action(
        json,
        &AgentActionReport {
            schema: "portl.agent.action.v1",
            action: "down".to_owned(),
            ok,
            changed: before.service.installed || before.service.loaded || before.ipc.ok,
            message,
            status: report,
        },
    )
}

fn restart(json: bool) -> Result<ExitCode> {
    let before = collect_report();
    if !before.service.installed && !before.service.loaded {
        let report = AgentActionReport {
            schema: "portl.agent.action.v1",
            action: "restart".to_owned(),
            ok: false,
            changed: false,
            message: "portl-agent service is not installed; run `portl-agent up`".to_owned(),
            status: before,
        };
        return print_action(json, &report);
    }
    let result = restart_service(&before.service);
    let ok = result.is_ok();
    let message = match result {
        Ok(()) => "agent service restarted".to_owned(),
        Err(err) => format!("failed to restart agent service: {err:#}"),
    };
    let report = collect_report();
    print_action(
        json,
        &AgentActionReport {
            schema: "portl.agent.action.v1",
            action: "restart".to_owned(),
            ok,
            changed: ok,
            message,
            status: report,
        },
    )
}

fn print_action(json: bool, report: &AgentActionReport) -> Result<ExitCode> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.ok {
        println!("service: {}", report.message);
        println!("state:   {}", report.status.service.state);
        if let Some(pid) = report.status.process.pid {
            println!("pid:     {pid}");
        }
        if let Some(version) = &report.status.ipc.version {
            println!("version: {version}");
        }
    } else {
        eprintln!("{}", report.message);
    }
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn collect_report() -> AgentServiceReport {
    let service = service_info();
    let socket = crate::agent_ipc::default_socket_path();
    let ipc = fetch_ipc_info(socket.display().to_string());
    let process = ProcessInfo {
        running: ipc.pid.is_some(),
        pid: ipc.pid,
    };
    AgentServiceReport {
        schema: "portl.agent.status.v1",
        service,
        process,
        ipc,
    }
}

fn fetch_ipc_info(socket: String) -> IpcInfo {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            return IpcInfo {
                ok: false,
                socket,
                pid: None,
                version: None,
                uptime_secs: None,
                error: Some(format!("create runtime: {err}")),
            };
        }
    };
    match runtime.block_on(async { crate::agent_ipc::fetch_status(&PathBuf::from(&socket)).await })
    {
        Ok(status) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(status.agent.started_at_unix);
            IpcInfo {
                ok: true,
                socket,
                pid: Some(status.agent.pid),
                version: Some(status.agent.version),
                uptime_secs: Some(now.saturating_sub(status.agent.started_at_unix)),
                error: None,
            }
        }
        Err(err) => IpcInfo {
            ok: false,
            socket,
            pid: None,
            version: None,
            uptime_secs: None,
            error: Some(err.to_string()),
        },
    }
}

fn print_status_human(report: &AgentServiceReport) {
    println!(
        "service:  {} {}",
        report.service.state, report.service.scope
    );
    println!("manager:  {}", report.service.manager);
    println!("enabled:  {}", yes_no(report.service.enabled));
    println!("loaded:   {}", yes_no(report.service.loaded));
    if let Some(path) = &report.service.path {
        println!("path:     {path}");
    }
    if let Some(program) = &report.service.program {
        println!("program:  {program}");
    }
    if report.ipc.ok {
        if let Some(pid) = report.process.pid {
            println!("pid:      {pid}");
        }
        if let Some(version) = &report.ipc.version {
            println!("version:  {version}");
        }
        if let Some(uptime) = report.ipc.uptime_secs {
            println!(
                "uptime:   {}",
                humantime::format_duration(Duration::from_secs(uptime))
            );
        }
        println!("socket:   ok");
    } else {
        println!("socket:   unavailable");
        if let Some(err) = &report.ipc.error {
            println!("error:    {err}");
        }
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn service_info() -> ServiceInfo {
    match std::env::consts::OS {
        "macos" => launchd_service_info(),
        "linux" => systemd_service_info(),
        other => ServiceInfo {
            manager: other.to_owned(),
            scope: "unsupported".to_owned(),
            installed: false,
            loaded: false,
            enabled: false,
            state: "unsupported".to_owned(),
            path: None,
            program: None,
        },
    }
}

fn launchd_service_info() -> ServiceInfo {
    let uid = Uid::effective().as_raw();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let user_path = home
        .as_ref()
        .map(|home| home.join("Library/LaunchAgents/com.portl.agent.plist"));
    let system_path = PathBuf::from("/Library/LaunchDaemons/com.portl.agent.plist");
    let (scope, domain, path) = if uid == 0 && system_path.exists() {
        ("system".to_owned(), "system".to_owned(), Some(system_path))
    } else {
        (
            "user LaunchAgent".to_owned(),
            format!("gui/{uid}"),
            user_path,
        )
    };
    let loaded_output = ProcessCommand::new("launchctl")
        .args(["print", &format!("{domain}/{LABEL}")])
        .output();
    let loaded = loaded_output.as_ref().is_ok_and(|out| out.status.success());
    let stdout = loaded_output
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    let installed = path.as_ref().is_some_and(|path| path.exists());
    let running = loaded && stdout.contains("state = running");
    ServiceInfo {
        manager: "launchd".to_owned(),
        scope,
        installed,
        loaded,
        enabled: installed,
        state: if running {
            "running".to_owned()
        } else if loaded {
            "loaded".to_owned()
        } else if installed {
            "installed".to_owned()
        } else {
            "down".to_owned()
        },
        path: path.map(|path| path.display().to_string()),
        program: parse_launchd_program(&stdout),
    }
}

fn parse_launchd_program(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed.strip_prefix("program = ").map(ToOwned::to_owned)
    })
}

fn systemd_service_info() -> ServiceInfo {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let path = home.map(|home| home.join(".config/systemd/user/portl-agent.service"));
    let enabled = ProcessCommand::new("systemctl")
        .args(["--user", "is-enabled", UNIT])
        .output()
        .is_ok_and(|out| out.status.success());
    let active = ProcessCommand::new("systemctl")
        .args(["--user", "is-active", UNIT])
        .output()
        .is_ok_and(|out| out.status.success());
    let installed = path.as_ref().is_some_and(|path| path.exists()) || enabled;
    ServiceInfo {
        manager: "systemd".to_owned(),
        scope: "user".to_owned(),
        installed,
        loaded: enabled || active,
        enabled,
        state: if active {
            "running".to_owned()
        } else if enabled {
            "enabled".to_owned()
        } else if installed {
            "installed".to_owned()
        } else {
            "down".to_owned()
        },
        path: path.map(|path| path.display().to_string()),
        program: None,
    }
}

fn disable_service() -> Result<()> {
    match std::env::consts::OS {
        "macos" => disable_launchd(),
        "linux" => disable_systemd(),
        other => bail!("unsupported service manager on {other}"),
    }
}

fn restart_service(service: &ServiceInfo) -> Result<()> {
    match service.manager.as_str() {
        "launchd" => restart_launchd(service),
        "systemd" => run_checked("systemctl", &["--user", "restart", UNIT]),
        manager => bail!("unsupported service manager: {manager}"),
    }
}

fn disable_launchd() -> Result<()> {
    let uid = Uid::effective().as_raw();
    let system_path = PathBuf::from("/Library/LaunchDaemons/com.portl.agent.plist");
    let (domain, path) = if uid == 0 && system_path.exists() {
        ("system".to_owned(), system_path)
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is required for user LaunchAgent management"))?;
        (
            format!("gui/{uid}"),
            home.join("Library/LaunchAgents/com.portl.agent.plist"),
        )
    };
    let _ = ProcessCommand::new("launchctl")
        .args(["bootout", &format!("{domain}/{LABEL}")])
        .status();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

fn restart_launchd(service: &ServiceInfo) -> Result<()> {
    let domain = if service.scope == "system" {
        "system".to_owned()
    } else {
        format!("gui/{}", Uid::effective().as_raw())
    };
    run_checked(
        "launchctl",
        &["kickstart", "-k", &format!("{domain}/{LABEL}")],
    )
}

fn disable_systemd() -> Result<()> {
    let _ = ProcessCommand::new("systemctl")
        .args(["--user", "disable", "--now", UNIT])
        .status();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let path = home.join(".config/systemd/user/portl-agent.service");
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("remove {}", path.display())),
        }
    }
    let _ = ProcessCommand::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    Ok(())
}

fn sibling_portl_binary() -> Result<PathBuf> {
    let mut path = std::env::current_exe().context("resolve current executable")?;
    path.set_file_name("portl");
    Ok(path)
}

fn run_checked(program: &str, args: &[&str]) -> Result<()> {
    let status = ProcessCommand::new(program)
        .args(args)
        .status()
        .with_context(|| format!("run {} {}", program, args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        bail!(
            "{} {} failed with status {}",
            program,
            args.join(" "),
            status
        )
    }
}

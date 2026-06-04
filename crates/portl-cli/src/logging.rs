use std::sync::OnceLock;

use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::{EnvFilter, prelude::*};

static LOGGING_INIT: OnceLock<()> = OnceLock::new();

pub(crate) fn init(verbose: u8, explicit_filter: Option<&str>) {
    let () = *LOGGING_INIT.get_or_init(|| {
        let filter = filter_directive(verbose, explicit_filter);
        let env_filter = match EnvFilter::try_new(&filter) {
            Ok(filter) => filter,
            Err(err) => {
                eprintln!(
                    "warning: invalid log filter {filter:?}: {err}; falling back to portl warnings"
                );
                EnvFilter::new(default_filter(0))
            }
        };
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(env_filter);
        if let Some(writer) = json_file_writer(portl_core::diagnostics::LogKind::Cli) {
            let file_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(EnvFilter::new(file_log_filter()));
            let _ = tracing_subscriber::registry()
                .with(stderr_layer)
                .with(file_layer)
                .try_init();
        } else {
            let _ = tracing_subscriber::registry().with(stderr_layer).try_init();
        }
    });
}

fn json_file_writer(kind: portl_core::diagnostics::LogKind) -> Option<RollingFileAppender> {
    if !portl_core::diagnostics::file_logs_enabled() {
        return None;
    }
    let path = portl_core::diagnostics::log_path(kind);
    if let Err(err) = portl_core::diagnostics::ensure_log_file_ready(&path) {
        eprintln!(
            "warning: could not initialize Portl file log {}: {err:#}",
            path.display()
        );
        return None;
    }
    let parent = path.parent()?;
    let file_name = path.file_name()?.to_str()?;
    Some(tracing_appender::rolling::never(parent, file_name))
}

pub(crate) fn filter_directive(verbose: u8, explicit_filter: Option<&str>) -> String {
    explicit_filter
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("PORTL_LOG").ok())
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| default_filter(verbose))
}

fn file_log_filter() -> &'static str {
    "portl_cli=info,portl_core=info,portl_agent=info,portl_transport=info,iroh=warn,quinn=warn,rustls=warn,h2=warn"
}

fn default_filter(verbose: u8) -> String {
    match verbose {
        0 => "error,portl_transport=off,portl_cli=warn,portl_core=warn,portl_agent=warn"
            .to_owned(),
        1 => "warn,portl_transport=off,portl_cli=info,portl_core=info,portl_agent=info"
            .to_owned(),
        2 => "warn,portl_transport=off,portl_cli=debug,portl_core=debug,portl_agent=debug,iroh=info"
            .to_owned(),
        _ => "debug,portl_transport=off,portl_cli=trace,portl_core=trace,portl_agent=trace,iroh=debug,quinn=info"
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::filter_directive;

    #[test]
    fn explicit_filter_wins_over_verbose_default() {
        assert_eq!(
            filter_directive(3, Some("portl_cli=trace")),
            "portl_cli=trace"
        );
    }

    #[test]
    fn default_filter_keeps_dependency_warnings_quiet() {
        assert_eq!(
            filter_directive(0, None),
            "error,portl_transport=off,portl_cli=warn,portl_core=warn,portl_agent=warn"
        );
    }

    #[test]
    fn cli_log_path_uses_portl_home_logs_dir() {
        let path = portl_core::diagnostics::log_path(portl_core::diagnostics::LogKind::Cli);
        assert!(path.ends_with("logs/cli.ndjson"));
    }

    #[test]
    fn file_log_filter_includes_transport_telemetry() {
        assert!(super::file_log_filter().contains("portl_transport=info"));
    }

    #[test]
    fn default_filters_keep_transport_telemetry_off_stderr() {
        for verbose in 0..=3 {
            assert!(
                super::default_filter(verbose).contains("portl_transport=off"),
                "verbose {verbose} default filter should explicitly disable portl_transport"
            );
        }
    }
}

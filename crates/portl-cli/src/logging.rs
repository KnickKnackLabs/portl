use std::sync::OnceLock;

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
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .try_init();
    });
}

pub(crate) fn filter_directive(verbose: u8, explicit_filter: Option<&str>) -> String {
    explicit_filter
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("PORTL_LOG").ok())
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| default_filter(verbose))
}

fn default_filter(verbose: u8) -> String {
    match verbose {
        0 => "error,portl_cli=warn,portl_core=warn,portl_agent=warn".to_owned(),
        1 => "warn,portl_cli=info,portl_core=info,portl_agent=info".to_owned(),
        2 => "warn,portl_cli=debug,portl_core=debug,portl_agent=debug,iroh=info".to_owned(),
        _ => "debug,portl_cli=trace,portl_core=trace,portl_agent=trace,iroh=debug,quinn=info"
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
            "error,portl_cli=warn,portl_core=warn,portl_agent=warn"
        );
    }
}

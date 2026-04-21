//! Shared helpers for the portl-agent integration tests.
//!
//! Only used by tests under `crates/portl-agent/tests/*`.
//!
//! # Per-binary watchdog
//!
//! When this module is linked into a test binary (any
//! `tests/*.rs` with `mod common;`), the `install_test_watchdog`
//! constructor spawns a background thread that aborts the process
//! after `PORTL_TEST_WATCHDOG_SECS` (default 30s). This prevents a
//! single hung integration test — most often an `iroh` endpoint
//! waiting on the public n0 relay infrastructure — from wedging
//! `cargo test --workspace` for minutes at a time. Set
//! `PORTL_TEST_WATCHDOG_SECS=0` to disable for local debugging.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Per-test-binary timeout. After this many seconds from process
/// start, the watchdog thread calls [`std::process::abort`] so a
/// hung test can't wedge `cargo test`. Override with
/// `PORTL_TEST_WATCHDOG_SECS`; `0` disables the watchdog.
const DEFAULT_WATCHDOG_SECS: u64 = 30;

fn watchdog_seconds() -> u64 {
    match std::env::var("PORTL_TEST_WATCHDOG_SECS") {
        Ok(s) => s.parse().unwrap_or(DEFAULT_WATCHDOG_SECS),
        Err(_) => DEFAULT_WATCHDOG_SECS,
    }
}

#[ctor::ctor]
fn install_test_watchdog() {
    let secs = watchdog_seconds();
    if secs == 0 {
        return;
    }
    // Named thread so stack traces / `ps` output make the source obvious.
    let _ = std::thread::Builder::new()
        .name("portl-test-watchdog".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            eprintln!(
                "\n[portl-test-watchdog] test binary exceeded {secs}s; aborting. \
                 Set PORTL_TEST_WATCHDOG_SECS to override (0 disables)."
            );
            std::process::abort();
        });
}

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::{LookupSpan, Registry};

/// A single captured tracing event. Fields are flattened to strings so
/// tests can assert on them without caring about the underlying tracing
/// Value variant.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub event: String,
    pub fields: HashMap<String, String>,
}

#[derive(Clone, Default)]
pub struct AuditCapture {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl AuditCapture {
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().expect("audit records mutex").clone()
    }

    pub fn clear(&self) {
        self.records.lock().expect("audit records mutex").clear();
    }
}

static CAPTURE: OnceLock<AuditCapture> = OnceLock::new();

/// Install a process-wide tracing subscriber that captures every
/// `tracing::event!` with an `event = "..."` field and returns a
/// handle for snapshotting records. Safe to call from multiple tests
/// in the same binary; only the first call installs the subscriber
/// and every caller sees the same shared capture.
pub fn install_audit_capture() -> AuditCapture {
    let capture = CAPTURE
        .get_or_init(|| {
            let capture = AuditCapture::default();
            let layer = CapturingLayer {
                records: Arc::clone(&capture.records),
            };
            let _ = Registry::default().with(layer).try_init();
            capture
        })
        .clone();
    capture.clear();
    capture
}

struct CapturingLayer {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl<S> Layer<S> for CapturingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        if let Some(event_name) = visitor.fields.remove("event") {
            self.records
                .lock()
                .expect("audit records mutex")
                .push(AuditRecord {
                    event: event_name,
                    fields: visitor.fields,
                });
        }
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: HashMap<String, String>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
}

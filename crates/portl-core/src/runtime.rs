use std::future::Future;
use std::sync::LazyLock;
use std::time::Duration;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use tracing::warn;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SlowTaskLabel {
    label: &'static str,
}

static SLOW_TASKS_TOTAL: LazyLock<Family<SlowTaskLabel, Counter>> = LazyLock::new(Family::default);

pub fn register_metrics(registry: &mut Registry) {
    registry.register(
        "slow_tasks_total",
        "Number of completed slow_task-wrapped blocking tasks by label",
        SLOW_TASKS_TOTAL.clone(),
    );
}

pub async fn slow_task<F, T>(label: &'static str, fut: F) -> T
where
    F: Future<Output = T>,
{
    let started_at = tokio::time::Instant::now();
    let mut warned = false;
    tokio::pin!(fut);

    loop {
        tokio::select! {
            output = &mut fut => {
                if warned {
                    SLOW_TASKS_TOTAL.get_or_create(&SlowTaskLabel { label }).inc();
                }
                return output;
            }
            () = tokio::time::sleep(Duration::from_mins(1)), if !warned => {
                warned = true;
                warn!(label, elapsed_ms = started_at.elapsed().as_millis(), "slow task exceeded 60s");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::{LookupSpan, Registry as SubscriberRegistry};

    use super::slow_task;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn slow_task_warns_after_60s() {
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let subscriber = SubscriberRegistry::default().with(WarningCaptureLayer {
            warnings: Arc::clone(&warnings),
        });
        let _guard = tracing::subscriber::set_default(subscriber);

        let task = tokio::spawn(slow_task("warn_after_60s", async {
            tokio::time::sleep(Duration::from_secs(61)).await;
        }));

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_mins(1)).await;
        tokio::task::yield_now().await;

        let warnings = warnings.lock().expect("warnings mutex").clone();
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("warn_after_60s"))
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        task.await.expect("slow_task join");
    }

    #[tokio::test]
    async fn fast_task_does_not_increment_slow_counter() {
        let before = slow_task_count("fast_counter");
        slow_task("fast_counter", async {}).await;
        assert_eq!(slow_task_count("fast_counter"), before);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn slow_task_increments_counter_on_return_after_warning() {
        let before = slow_task_count("counter_increment");
        let task = tokio::spawn(slow_task("counter_increment", async {
            tokio::time::sleep(Duration::from_secs(61)).await;
        }));

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_mins(1)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await.expect("slow_task join");

        assert_eq!(slow_task_count("counter_increment"), before + 1);
    }

    fn slow_task_count(label: &'static str) -> u64 {
        super::SLOW_TASKS_TOTAL
            .get_or_create(&super::SlowTaskLabel { label })
            .get()
    }

    struct WarningCaptureLayer {
        warnings: Arc<Mutex<Vec<String>>>,
    }

    impl<S> Layer<S> for WarningCaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            let mut visitor = WarningVisitor::default();
            event.record(&mut visitor);
            self.warnings
                .lock()
                .expect("warnings mutex")
                .push(visitor.label.unwrap_or_default());
        }
    }

    #[derive(Default)]
    struct WarningVisitor {
        label: Option<String>,
    }

    impl Visit for WarningVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "label" {
                self.label = Some(format!("{value:?}"));
            }
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "label" {
                self.label = Some(value.to_owned());
            }
        }
    }
}

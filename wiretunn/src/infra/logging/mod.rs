//! Logging facilities

use std::{env, io};

use tracing::{
    dispatcher::{set_default, set_global_default},
    subscriber::DefaultGuard,
    Dispatch, Level,
};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan, time::ChronoLocal, writer::MakeWriterExt, MakeWriter},
    layer::SubscriberExt,
    EnvFilter,
};

use crate::config::LogConfig;

mod rolling_file;

pub struct LogGuard {
    pub default_guard: DefaultGuard,
    pub non_blocking_guard: Option<WorkerGuard>,
}

pub fn init_with_config(config: &LogConfig) -> LogGuard {
    let level = config.log_level();
    let filter: Option<&str> = config.log_filter().as_deref();
    let mut non_blocking_guard: Option<WorkerGuard> = None;

    let dispatch = if let Some(log_file) = config.log_file() {
        let file_appender = rolling_file::RollingFile::new(
            log_file,
            config.log_size(),
            config.log_num(),
            #[cfg(unix)]
            None,
        );
        let (non_blocking_file, guard) = NonBlocking::new(file_appender);
        non_blocking_guard = Some(guard);
        make_dispatch(level, filter, non_blocking_file.and(io::stdout))
    } else {
        make_dispatch(level, filter, io::stdout)
    };

    let default_guard = set_default(&dispatch);
    if let Err(e) = set_global_default(dispatch) {
        tracing::debug!("Initialize set trace dispatcher error: {}", e);
    }

    LogGuard {
        default_guard,
        non_blocking_guard,
    }
}

pub fn default(console_level: Level) -> DefaultGuard {
    set_default(&make_dispatch(console_level, None, io::stdout))
}

fn make_dispatch<W: for<'writer> MakeWriter<'writer> + 'static + Send + Sync>(
    level: Level,
    filter: Option<&str>,
    writer: W,
) -> Dispatch {
    let timer = ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f%z".to_string());
    // NOTE: ansi is enabled by default.
    // Could be disabled by `NO_COLOR` environment variable.
    // https://no-color.org/
    let mut format = fmt::format().with_ansi(false);
    if level.cmp(&Level::DEBUG).is_ge() {
        format = format
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true);

        if level.cmp(&Level::TRACE).is_eq() {
            format = format.with_file(true).with_line_number(true);
        }
    } else {
        format = format
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false);
    }

    cfg_if::cfg_if! {
        if #[cfg(target_os = "android")] {
            let logcat = match tracing_android::layer("Wiretunn") {
                Ok(layer) => Some(layer),
                Err(_) => None,
            };

            Dispatch::from(
                tracing_subscriber::registry()
                    .with(fmt::layer().event_format(format).with_timer(timer).with_writer(writer).with_span_events(FmtSpan::CLOSE))
                    .with(logcat)
                    .with(make_filter(level, filter)),
            )
        } else {
            Dispatch::from(
                tracing_subscriber::registry()
                    .with(fmt::layer()
                    .event_format(format).with_timer(timer)
                    .with_writer(writer)
                    .with_span_events(FmtSpan::CLOSE))
                    .with(make_filter(level, filter))
            )
        }
    }
}

fn make_filter(level: Level, filter: Option<&str>) -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(Level::WARN.into())
        .parse(default_filter(level, filter))
        .expect("Failed to configure tracing/logging")
}

#[inline]
fn default_filter(level: impl ToString, filter: Option<&str>) -> String {
    filter
        .unwrap_or("wiretunn_cli={level},wiretunn={level},{env}")
        .replace("{level}", level.to_string().to_uppercase().as_str())
        .replace("{env}", env::var("RUST_LOG").unwrap_or_default().as_str())
}

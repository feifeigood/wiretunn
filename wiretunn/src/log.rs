use std::{env, io, path::Path, sync::OnceLock};

use tracing::{
    dispatcher::{set_default, set_global_default},
    subscriber::DefaultGuard,
    Dispatch, Level,
};
use tracing_subscriber::{
    fmt::{time::ChronoLocal, writer::MakeWriterExt, MakeWriter},
    layer::SubscriberExt,
    EnvFilter,
};

static CONSOLE_LEVEL: OnceLock<Level> = OnceLock::new();

type MappedFile = crate::infra::mapped_file::MutexMappedFile;

pub fn init_global_default<P: AsRef<Path>>(
    path: P,
    level: Level,
    filter: Option<&str>,
    size: u64,
    num: u64,
    #[cfg(unix)] mode: Option<u32>,
    to_console: bool,
) -> DefaultGuard {
    let file = MappedFile::open(
        path.as_ref(),
        size,
        Some(num as usize),
        #[cfg(unix)]
        mode,
    );

    let writable = file
        .0
        .lock()
        .unwrap()
        .touch()
        .map(|_| true)
        .unwrap_or_else(|err| {
            tracing::warn!("{:?}, {:?}", path.as_ref(), err);
            false
        });

    let console_level = if to_console {
        level
    } else {
        *CONSOLE_LEVEL.get_or_init(|| Level::INFO)
    };
    let console_writer = io::stdout.with_max_level(console_level);

    let dispatch = if writable {
        // log hello
        // {
        //     let writer = file.with_max_level(level);
        //     let dispatch = make_dispatch(level, filter, writer);

        //     let _guard = set_default(&dispatch);
        //     crate::hello_starting();
        // }

        let file_writer = MappedFile::open(
            path.as_ref(),
            size,
            Some(num as usize),
            #[cfg(unix)]
            mode,
        )
        .with_max_level(level);

        make_dispatch(
            level.max(console_level),
            filter,
            file_writer.and(console_writer),
        )
    } else {
        make_dispatch(console_level, filter, console_writer)
    };

    let guard = set_default(&dispatch);

    if let Err(e) = set_global_default(dispatch) {
        tracing::debug!("Initialize set trace dispatcher error: {}", e);
    }
    guard
}

pub fn default(console_level: Level) -> DefaultGuard {
    CONSOLE_LEVEL.get_or_init(|| console_level);
    let console_writer = io::stdout.with_max_level(console_level);
    set_default(&make_dispatch(console_level, None, console_writer))
}

#[inline]
fn make_dispatch<W: for<'writer> MakeWriter<'writer> + 'static + Send + Sync>(
    level: Level,
    filter: Option<&str>,
    writer: W,
) -> Dispatch {
    let timer = ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f%z".to_string());
    let layer = tracing_subscriber::fmt::layer()
        .with_timer(timer)
        .with_ansi(false)
        .with_writer(writer);

    Dispatch::from(
        tracing_subscriber::registry()
            .with(layer)
            .with(make_filter(level, filter)),
    )
}

#[inline]
fn make_filter(level: Level, filter: Option<&str>) -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(Level::WARN.into())
        .parse(all_wiretunn(level, filter))
        .expect("Failed to configure tracing/logging")
}

#[inline]
fn all_wiretunn(level: impl ToString, filter: Option<&str>) -> String {
    filter
        .unwrap_or("wiretunn_cli={level},wiretunn={level},boringtun={level},{env}")
        .replace("{level}", level.to_string().to_uppercase().as_str())
        .replace("{env}", get_env().as_str())
}

#[inline]
fn get_env() -> String {
    env::var("RUST_LOG").unwrap_or_default()
}

impl<'a> MakeWriter<'a> for MappedFile {
    type Writer = &'a MappedFile;
    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

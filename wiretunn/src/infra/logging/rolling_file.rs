use std::{io, path::Path};

use file_rotate::{compression::Compression, suffix::AppendCount, ContentLimit, FileRotate};
use parking_lot::Mutex;
use tracing_subscriber::fmt::MakeWriter;

/// RollingFile represents the rotate files at a fixed size and numbers.
pub struct RollingFile {
    writer: Mutex<FileRotate<AppendCount>>,
}

impl RollingFile {
    pub fn new<P: AsRef<Path>>(
        path: P,
        limit_bytes: u64,
        max_files: Option<u64>,
        #[cfg(unix)] mode: Option<u32>,
    ) -> RollingFile {
        let writer = Mutex::new(FileRotate::new(
            path,
            AppendCount::new(max_files.unwrap_or(3) as usize),
            ContentLimit::BytesSurpassed(limit_bytes as usize),
            Compression::None,
            #[cfg(unix)]
            mode,
        ));

        RollingFile { writer }
    }
}

impl io::Write for RollingFile {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.get_mut().write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.get_mut().flush()
    }
}

impl io::Write for &RollingFile {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.lock().write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.lock().flush()
    }
}

impl<'a> MakeWriter<'a> for RollingFile {
    type Writer = &'a RollingFile;

    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use chrono::Local;
    use io::Write;
    use std::env;

    #[test]
    pub fn test_rolling_file() -> io::Result<()> {
        let file_path = format!(
            "{}logs/abc-{:#x}.txt",
            env::temp_dir().display(),
            Local::now().timestamp()
        );

        let mut file = RollingFile::new(
            file_path,
            2,
            Some(3),
            #[cfg(unix)]
            Default::default(),
        );
        file.write_all(b"aa")?;
        assert_eq!(file.writer.lock().log_paths().len(), 0);
        file.write_all(b"bb")?;
        assert_eq!(file.writer.lock().log_paths().len(), 1);
        file.write_all(b"cc")?;
        assert_eq!(file.writer.lock().log_paths().len(), 2);
        file.write_all(b"dd")?;
        assert_eq!(file.writer.lock().log_paths().len(), 3);
        file.write_all(b"ee")?;

        Ok(())
    }
}

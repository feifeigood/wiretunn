use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use byte_unit::Byte;
use serde::Deserialize;

use crate::{device::WgDeviceConfig, Error};

#[derive(Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "log")]
    log: LogConfig,
    #[serde(rename = "wireguard")]
    wg_devices: HashMap<String, WgDeviceConfig>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: Option<P>) -> Result<Config, Error> {
        if let Some(ref conf) = path {
            let path = conf.as_ref();

            Config::load_from_file(path)
        } else {
            let candidate_path = [
                "./wiretunn.toml",
                "/etc/wiretunn.toml",
                "/etc/wiretunn/wiretunn.toml",
                "/usr/local/etc/wiretunn.toml",
                "/usr/local/etc/wiretunn/wiretunn.toml",
            ];

            candidate_path
                .iter()
                .map(Path::new)
                .filter(|p| p.exists())
                .map(Config::load_from_file)
                .next()
                .expect("No configuration file found.")
        }
    }

    fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
        let path = path.as_ref();
        if !path.exists() {
            panic!("Configuration file {:?} not exist.", path);
        }

        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    #[inline]
    pub fn log_config(&self) -> &LogConfig {
        &self.log
    }

    #[inline]
    pub fn log_enabled(&self) -> bool {
        self.log_num() > 0
    }

    pub fn log_level(&self) -> tracing::Level {
        use tracing::Level;
        match self.log.level.as_deref().unwrap_or("info") {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" | "notice" => Level::INFO,
            "warn" => Level::WARN,
            "error" | "fatal" => Level::ERROR,
            _ => Level::ERROR,
        }
    }

    pub fn log_file(&self) -> PathBuf {
        match self.log.file.as_ref() {
            Some(f) => f.to_owned(),
            None => {
                cfg_if::cfg_if! {
                    if #[cfg(target_os = "windows")] {
                        let mut path = std::env::temp_dir();
                        path.push("wiretunn");
                        path.push("wiretunn.log");
                        path
                    } else {
                        PathBuf::from(r"/var/log/wiretunn/wiretunn.log")
                    }
                }
            }
        }
    }

    #[inline]
    pub fn log_size(&self) -> u64 {
        self.log
            .size
            .unwrap_or_else(|| Byte::from_u64_with_unit(128, byte_unit::Unit::KB).unwrap())
            .as_u64()
    }

    #[inline]
    pub fn log_num(&self) -> u64 {
        self.log.num.unwrap_or(2)
    }

    #[inline]
    pub fn wg_devices(&self) -> &HashMap<String, WgDeviceConfig> {
        &self.wg_devices
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct LogConfig {
    /// enable output log to console
    pub console: Option<bool>,

    /// set log level
    pub level: Option<String>,

    /// file path of log file.
    pub file: Option<PathBuf>,

    /// size of each log file, support k,m,g
    pub size: Option<Byte>,

    /// number of logs, 0 means disable log
    pub num: Option<u64>,
}

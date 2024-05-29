use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use boringtun::x25519;
use byte_unit::Byte;
use ipnet::IpNet;
use serde::Deserialize;

use crate::Error;

#[derive(Deserialize, Clone)]
pub struct Config {
    // interface_name: Option<String>,
    external_controller: Option<SocketAddr>,
    #[serde(default)]
    log: LogConfig,
    #[serde(rename = "wireguard", default = "HashMap::new")]
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

        Self::load_from_str(&fs::read_to_string(path)?)
    }

    pub fn load_from_str(s: &str) -> Result<Config, Error> {
        Ok(toml::from_str(s)?)
    }

    #[inline]
    pub fn external_controller(&self) -> Option<SocketAddr> {
        self.external_controller
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

#[derive(Deserialize, Clone)]
pub struct WgDeviceConfig {
    #[serde(deserialize_with = "deserialize::wg_private_key")]
    pub private_key: x25519::StaticSecret,
    pub listen_port: Option<u16>,
    pub address: IpNet,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fwmark: Option<u32>,
    pub mtu: Option<i32>,
    #[serde(default)]
    pub use_connected_socket: bool,
    #[cfg(unix)]
    pub tun_fd: Option<i32>,
    #[cfg(unix)]
    pub tun_fd_close_on_drop: Option<bool>,
    #[serde(rename = "peer", default = "Vec::new")]
    pub wg_peers: Vec<WgPeerConfig>,
}

#[derive(Deserialize, Clone)]
pub struct WgPeerConfig {
    #[serde(deserialize_with = "deserialize::wg_public_key")]
    pub public_key: x25519::PublicKey,
    #[serde(default, deserialize_with = "deserialize::wg_preshared_key")]
    pub preshared_key: Option<[u8; 32]>,
    #[serde(deserialize_with = "deserialize::wg_allowed_ips")]
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
    #[serde(deserialize_with = "deserialize::wg_endpoint")]
    pub endpoint: Option<SocketAddr>,
}

pub mod deserialize {
    use std::net::{SocketAddr, ToSocketAddrs};

    use base64::prelude::*;
    use boringtun::x25519;
    use ipnet::IpNet;
    use serde::{Deserialize, Deserializer};

    pub fn wg_private_key<'de, D>(deserializer: D) -> Result<x25519::StaticSecret, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let bytes: [u8; 32] = BASE64_STANDARD
            .decode(&key)
            .map_err(|_| {
                serde::de::Error::custom(format!(
                    "Key is not the correct length or format: {}",
                    key
                ))
            })?
            .try_into()
            .unwrap();

        Ok(x25519::StaticSecret::from(bytes))
    }

    pub fn wg_public_key<'de, D>(deserializer: D) -> Result<x25519::PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let bytes: [u8; 32] = BASE64_STANDARD
            .decode(&key)
            .map_err(|_| {
                serde::de::Error::custom(format!(
                    "Key is not the correct length or format: {}",
                    key
                ))
            })?
            .try_into()
            .unwrap();

        Ok(x25519::PublicKey::from(bytes))
    }

    pub fn wg_preshared_key<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let bytes: [u8; 32] = BASE64_STANDARD
            .decode(&key)
            .map_err(|_| {
                serde::de::Error::custom(format!(
                    "Key is not the correct length or format: {}",
                    key
                ))
            })?
            .try_into()
            .unwrap();

        Ok(Some(bytes))
    }

    pub fn wg_allowed_ips<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut allowed_ips = Vec::new();
        for allowed_ip in String::deserialize(deserializer)?
            .split(',')
            .map(str::trim)
            .collect::<Vec<&str>>()
        {
            allowed_ips.push(allowed_ip.parse::<IpNet>().map_err(|_| {
                serde::de::Error::custom(format!("Unable to parse IP address: {}", allowed_ip))
            })?);
        }

        Ok(allowed_ips)
    }

    pub fn wg_endpoint<'de, D>(deserializer: D) -> Result<Option<SocketAddr>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let endpoint = String::deserialize(deserializer)?;
        match endpoint.parse::<SocketAddr>() {
            Ok(saddr) => Ok(Some(saddr)),
            Err(_) => {
                // maybe endpoint is domain, try resolve it
                Ok(endpoint
                    .to_socket_addrs()
                    .map_err(|_| {
                        serde::de::Error::custom(format!("Unable to parse Endpoint: {}", endpoint))
                    })?
                    .next())
            }
        }
    }
}
